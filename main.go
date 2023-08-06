package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/songgao/water"
)

const MTU_SIZE = 1500

func main() {
	cfg := water.Config{
		DeviceType: water.TUN,
	}
	tun, err := water.New(cfg)
	if err != nil {
		panic(err)
	}

	defer tun.Close()
	buffer := make([]byte, MTU_SIZE)

	for {
		n, err := tun.Read(buffer)
		if err != nil {
			panic(err)
		}
		ipv4, err := parseIPv4(buffer[:n])
		if err != nil {
			panic(err)
		}
		if ipv4.Proto == 1 { // ICMP
			icmp, err := parseICMP(ipv4.Payload)
			if err != nil {
				panic(err)
			}
			if icmp.Type == 8 { // echo request
				icmpResp := ICMP{
					Id:      icmp.Id,
					Seq:     icmp.Seq,
					Payload: icmp.Payload,
				}

				p, _ := icmpResp.Marshal()
				icmpResp.Checksum = checksum(p)

				icmpRespPkt, err := icmpResp.Marshal()
				if err != nil {
					panic(err)
				}

				// ip header
				ipv4Resp := IPv4{
					Version: 4,
					IHL:     5,
					Length:  uint16(20 + len(icmpRespPkt)),
					TTL:     64,
					Proto:   1,
					SrcIP:   ipv4.DstIP,
					DstIP:   ipv4.SrcIP,
					Payload: icmpRespPkt,
				}

				ipv4RespPkt, err := ipv4Resp.Marshal()
				if err != nil {
					panic(err)
				}

				_, err = tun.Write(ipv4RespPkt)
				if err != nil {
					panic(err)
				}
			}
		} else if ipv4.Proto == 6 { // TCP
			tcp, err := parseTCP(ipv4.Payload)
			if err != nil {
				panic(err)
			}
			// must validate checksum
			if err = validateTCP(ipv4, tcp); err != nil {
				panic(err)
			}

			// for now, check if it's a syn packet and try to acknowledge it.
			if tcp.Control&0x02 == 0x02 {
				tcpResp := TCP{
					srcPort:  tcp.destPort,
					destPort: tcp.srcPort,
					Seq:      34301,
					Ack:      tcp.Seq + 1,
					Offset:   5,
					Control:  0x12, // SYN,ACK
					Window:   0x7FFF,
					Checksum: 0,
					Urgent:   0,
				}
				m, _ := tcpResp.Marshal()

				// RFC 9293 3.1: pseudo header to be prepended to the tcp packet for checksum calculation
				pseudo := make([]byte, 12)
				copy(pseudo[0:4], ipv4.SrcIP)
				copy(pseudo[4:8], ipv4.DstIP)
				pseudo[8] = 0
				pseudo[9] = ipv4.Proto
				binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(m)))

				tcpResp.Checksum = checksum(append(pseudo, m...))
				tcpRespPkt, err := tcpResp.Marshal()
				if err != nil {
					panic(err)
				}
				
				ipv4Response := IPv4{
					Version:  4,
					IHL:      5,
					TOS:      0,
					Length:   uint16(20 + len(tcpRespPkt)),
					Id:       0,
					Flags:    0,
					Offset:   0,
					TTL:      64,
					Proto:    6, // TCP
					Checksum: 0,
					SrcIP:    ipv4.DstIP,
					DstIP:    ipv4.SrcIP,
					Payload:  tcpRespPkt,
				}

				ipv4RespPkt, err := ipv4Response.Marshal()
				if err != nil {
					panic(err)
				}
				_, err = tun.Write(ipv4RespPkt)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}

func checksum(bytes []byte) uint16 {
	var csum int
	if len(bytes)%2 != 0 {
		bytes = append(bytes, 0)
	}
	for i := 0; i < len(bytes); i += 2 {
		csum += int(binary.BigEndian.Uint16(bytes[i : i+2]))
	}
	for {
		if csum <= 0xFFFF {
			break
		}
		csum = (csum >> 16) + int(uint16(csum)) // must cast to uint16, otherwise it will overflow
	}
	return ^uint16(csum)
}

func validateTCP(ipv4 IPv4, tcp TCP) error {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], ipv4.SrcIP)
	copy(pseudo[4:8], ipv4.DstIP)
	pseudo[8] = 0
	pseudo[9] = ipv4.Proto
	m, _ := tcp.Marshal()
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(m)))

	check := tcp.Checksum
	tcp.Checksum = 0
	m, _ = tcp.Marshal()
	calc := checksum(append(pseudo, m...))
	if check != calc {
		return fmt.Errorf("Checksum mismatch. Expected %d, got %d", check, calc)
	}
	return nil
}

type IPv4 struct {
	Version  uint8
	IHL      uint8
	TOS      uint8
	Length   uint16
	Id       uint16
	Flags    uint16 // TODO(ben): will need to figure out an appropriate type.
	Offset   uint16
	TTL      uint8
	Proto    uint8
	Checksum uint16
	SrcIP    net.IP
	DstIP    net.IP
	Payload  []byte
}

func parseIPv4(buf []byte) (IPv4, error) {
	packet := IPv4{
		Version:  buf[0] >> 4,
		IHL:      buf[0] & 0x0F,
		TOS:      buf[1],
		Length:   binary.BigEndian.Uint16(buf[2:4]),
		Id:       binary.BigEndian.Uint16(buf[4:6]),
		Flags:    uint16(buf[6] >> 5),
		Offset:   binary.BigEndian.Uint16(buf[6:8]) & 0x1FFF,
		TTL:      buf[8],
		Proto:    buf[9],
		Checksum: binary.BigEndian.Uint16(buf[10:12]),
		SrcIP:    net.IP(buf[12:16]),
		DstIP:    net.IP(buf[16:20]),
		Payload:  buf[20:],
	}
	return packet, nil
}

func (p IPv4) Marshal() ([]byte, error) {
	buffer := make([]byte, 20+len(p.Payload))
	buffer[0] = (p.Version << 4) | p.IHL
	buffer[1] = p.TOS
	binary.BigEndian.PutUint16(buffer[2:4], p.Length)
	binary.BigEndian.PutUint16(buffer[4:6], p.Id)
	binary.BigEndian.PutUint16(buffer[6:8], uint16(p.Flags)<<13|p.Offset)
	buffer[8] = p.TTL
	buffer[9] = p.Proto
	copy(buffer[12:16], p.SrcIP)
	copy(buffer[16:20], p.DstIP)
	copy(buffer[20:], p.Payload)
	return buffer, nil
}

type ICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Id       uint16
	Seq      uint16
	Payload  []byte
}

func parseICMP(buf []byte) (ICMP, error) {
	packet := ICMP{
		Type:     buf[0],
		Code:     buf[1],
		Checksum: binary.BigEndian.Uint16(buf[2:4]),
		Id:       binary.BigEndian.Uint16(buf[4:6]),
		Seq:      binary.BigEndian.Uint16(buf[6:8]),
		Payload:  buf[8:],
	}
	return packet, nil
}

func (p ICMP) Marshal() ([]byte, error) {
	buf := make([]byte, 8+len(p.Payload))
	buf[0] = p.Type
	buf[1] = p.Code
	binary.BigEndian.PutUint16(buf[2:4], p.Checksum)
	binary.BigEndian.PutUint16(buf[4:6], p.Id)
	binary.BigEndian.PutUint16(buf[6:8], p.Seq)
	copy(buf[8:], p.Payload)
	return buf, nil
}

type TCP struct {
	srcPort  uint16
	destPort uint16
	Seq      uint32
	Ack      uint32
	Offset   uint8
	Control  uint8
	Window   uint16
	Checksum uint16
	Urgent   uint16
	Payload  []byte
}

func parseTCP(buf []byte) (TCP, error) {
	packet := TCP{
		srcPort:  binary.BigEndian.Uint16(buf[0:2]),
		destPort: binary.BigEndian.Uint16(buf[2:4]),
		Seq:      binary.BigEndian.Uint32(buf[4:8]),
		Ack:      binary.BigEndian.Uint32(buf[8:12]),
		Offset:   buf[12] >> 4,
		Control:  buf[13],
		Window:   binary.BigEndian.Uint16(buf[14:16]),
		Checksum: binary.BigEndian.Uint16(buf[16:18]),
		Urgent:   binary.BigEndian.Uint16(buf[18:20]),
		Payload:  buf[20:],
	}
	return packet, nil
}

func (p TCP) Marshal() ([]byte, error) {
	buf := make([]byte, 20+len(p.Payload))
	binary.BigEndian.PutUint16(buf[0:2], p.srcPort)
	binary.BigEndian.PutUint16(buf[2:4], p.destPort)
	binary.BigEndian.PutUint32(buf[4:8], p.Seq)
	binary.BigEndian.PutUint32(buf[8:12], p.Ack)
	buf[12] = p.Offset << 4
	buf[13] = p.Control
	binary.BigEndian.PutUint16(buf[14:16], p.Window)
	binary.BigEndian.PutUint16(buf[16:18], p.Checksum)
	binary.BigEndian.PutUint16(buf[18:20], p.Urgent)
	copy(buf[20:], p.Payload)
	return buf, nil
}
