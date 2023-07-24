package main

import (
	"encoding/binary"
	"net"
	"time"

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
	c := time.Tick(1 * time.Second)
	for range c {
		buffer := make([]byte, MTU_SIZE)
		n, err := tun.Read(buffer)
		if err != nil {
			panic(err)
		}
		ipv4Packet, err := parseIPv4Packet(buffer[:n])
		if err != nil {
			panic(err)
		}
		if ipv4Packet.Protocol == 1 { // ICMP
			icmp, err := parseICMPEchoRequest(ipv4Packet.Payload)
			if err != nil {
				panic(err)
			}
			if icmp.Type == 8 { // echo request
				icmpResponse := ICMPEchoPacket{
					Type:     0, // echo reply
					Code:     0,
					Checksum: 0, // will be computed later
					Id:       icmp.Id,
					Seq:      icmp.Seq,
					Payload:  icmp.Payload,
				}

				m, _ := icmpResponse.Marshal()
				icmpResponse.Checksum = checksum(m)

				icmpSendPacket, err := icmpResponse.Marshal()
				if err != nil {
					panic(err)
				}

				// ip header
				ipv4Response := IPv4Packet{
					Version:    4,
					IHL:        5,
					TOS:        0,
					Length:     uint16(20 + len(icmpSendPacket)),
					Id:         0,
					Flags:      0,
					FragOffset: 0,
					TTL:        64,
					Protocol:   1,
					Checksum:   0,
					SrcIP:      ipv4Packet.DstIP,
					DstIP:      ipv4Packet.SrcIP,
					Payload:    icmpSendPacket,
				}

				ipv4SendPacket, err := ipv4Response.Marshal()
				if err != nil {
					panic(err)
				}

				_, err = tun.Write(ipv4SendPacket)
				if err != nil {
					panic(err)
				}
			}
		}
	}
}

type IPv4Packet struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	Id         uint16
	Flags      uint16 // TODO(ben): will need to figure out an appropriate type.
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
	Payload    []byte
}

func parseIPv4Packet(buffer []byte) (IPv4Packet, error) {
	packet := IPv4Packet{
		Version:    buffer[0] >> 4,
		IHL:        buffer[0] & 0x0F,
		TOS:        buffer[1],
		Length:     binary.BigEndian.Uint16(buffer[2:4]),
		Id:         binary.BigEndian.Uint16(buffer[4:6]),
		Flags:      uint16(buffer[6] >> 5),
		FragOffset: binary.BigEndian.Uint16(buffer[6:8]) & 0x1FFF,
		TTL:        buffer[8],
		Protocol:   buffer[9],
		Checksum:   binary.BigEndian.Uint16(buffer[10:12]),
		SrcIP:      net.IP(buffer[12:16]),
		DstIP:      net.IP(buffer[16:20]),
		Payload:    buffer[20:],
	}
	return packet, nil
}

func (p IPv4Packet) Marshal() ([]byte, error) {
	buffer := make([]byte, 20+len(p.Payload))
	buffer[0] = byte((p.Version << 4) | p.IHL)
	buffer[1] = byte(p.TOS)
	binary.BigEndian.PutUint16(buffer[2:4], uint16(p.Length))
	binary.BigEndian.PutUint16(buffer[4:6], uint16(p.Id))
	binary.BigEndian.PutUint16(buffer[6:8], uint16(p.Flags<<13)|uint16(p.FragOffset))
	buffer[8] = byte(p.TTL)
	buffer[9] = byte(p.Protocol)
	copy(buffer[12:16], p.SrcIP)
	copy(buffer[16:20], p.DstIP)
	copy(buffer[20:], p.Payload)
	return buffer, nil
}

type ICMPEchoPacket struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Id       uint16
	Seq      uint16
	Payload  []byte
}

func parseICMPEchoRequest(buffer []byte) (ICMPEchoPacket, error) {
	packet := ICMPEchoPacket{
		Type:     buffer[0],
		Code:     buffer[1],
		Checksum: binary.BigEndian.Uint16(buffer[2:4]),
		Id:       binary.BigEndian.Uint16(buffer[4:6]),
		Seq:      binary.BigEndian.Uint16(buffer[6:8]),
		Payload:  buffer[8:],
	}
	return packet, nil
}

func (p ICMPEchoPacket) Marshal() ([]byte, error) {
	buffer := make([]byte, 8+len(p.Payload))
	buffer[0] = byte(p.Type)
	buffer[1] = byte(p.Code)
	binary.BigEndian.PutUint16(buffer[2:4], uint16(p.Checksum))
	binary.BigEndian.PutUint16(buffer[4:6], uint16(p.Id))
	binary.BigEndian.PutUint16(buffer[6:8], uint16(p.Seq))
	copy(buffer[8:], p.Payload)
	return buffer, nil
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
