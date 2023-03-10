package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/songgao/water"
	"log"
)

func main() {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Interface name: %s\n", ifce.Name())
	raw := make([]byte, 1500)

	synFlag := false
	for {
		_, err := ifce.Read(raw)
		if err != nil {
			log.Fatal(err)
		}
		if synFlag {
			continue
		}

		packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				tcp_resp := &layers.TCP{
					SrcPort:    tcp.DstPort,
					DstPort:    tcp.SrcPort,
					DataOffset: 5,
					Seq:        300,
					Ack:        tcp.Seq + 1,
					SYN:        true,
					ACK:        true,
					Window:     100,
				}

				ip_resp := &layers.IPv4{
					SrcIP:    ip.DstIP,
					DstIP:    ip.SrcIP,
					TTL:      64,
					Version:  4,
					IHL:      5,
					Protocol: layers.IPProtocolTCP,
					Length:   20 + 20, // should be calculated
				}

				_ = tcp_resp.SetNetworkLayerForChecksum(ip_resp)

				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					ComputeChecksums: true,
					FixLengths:       true,
				}
				gopacket.SerializeLayers(buf, opts,
					ip_resp,
					tcp_resp,
				)

				ifce.Write(buf.Bytes())
				synFlag = true
				continue
			}
		}

	}
}
