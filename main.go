package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	ip := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     20,
		Protocol:   1,
		Flags:      0,
		FragOffset: 0,
		Id:         123,
		TTL:        64,
		SrcIP:      net.IP{10, 0, 0, 30},
		DstIP:      net.IP{10, 0, 0, 2},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err = ip.SerializeTo(buf, opts)
	if err != nil {
		panic(err)
	}
	packet := buf.Bytes()

	c := time.Tick(1 * time.Second)
	for next := range c {
		fmt.Printf("%v: writing %v\n", next, packet)
		_, err := tun.Write(packet)
		if err != nil {
			panic(err)
		}
		// packet := make([]byte, MTU_SIZE)
		// _, err = tun.Read(packet)
		// if err != nil {
		// 	panic(err)
		// }
		// // Reminder IFF_NO_PI is not set (nor is it able to be set on darwin) so the packet
		// // will be prefixed with a 4 byte header (2 byte flag + 2 byte proto). This gets stripped.
		// packet := packet[4:]
	}
}
