package main

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	fd, err := createTun()
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	ip := &layers.IPv4{
		SrcIP: net.IP{192, 168, 1, 1},
		DstIP: net.IP{192, 168, 1, 2},
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
	}

	// Create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ip, tcp)
	if err != nil {
		log.Fatal(err)
	}

	outgoingPacket := buffer.Bytes()

	// Send our packet
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}

	// Start reading packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		fmt.Println(packet)
	}

}

const (
	_CTLIOCGINFO      = 3223348741
	_SYSPROTO_CONTROL = 2
	UTUN_CONTROL_NAME = "com.apple.net.utun_control"
)

// thanks goes to Jonathan Levin for providing example code on how to create a utun device on macOS.
// (http://newosxbook.com/src.jl?tree=listings&file=17-15-utun.c)
func createTun() (int, error) {
	ctlInfo := struct {
		ctlId   uint32
		ctlName [96]byte
	}{
		0,
		[96]byte{},
	}
	copy(ctlInfo.ctlName[:], UTUN_CONTROL_NAME)

	sockAddrCtl := struct {
		sc_id       uint32
		sc_len      uint32
		sc_family   uint32
		ss_sysaddr  [128]byte
		sc_unit     uint32
		sc_reserved [32]byte
	}{}

	fd, err := syscall.Socket(
		syscall.AF_SYSTEM, // PF_SYSTEM == AF_SYSTEM
		syscall.SOCK_DGRAM,
		_SYSPROTO_CONTROL,
	)
	if err != nil {
		return -1, err
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(_CTLIOCGINFO),
		uintptr(unsafe.Pointer(&ctlInfo)),
	)
	if errno != 0 {
		return -1, err
	}

	if err := syscall.Connect(fd, unsafe.Pointer(&sockAddrCtl)); err != nil {
		return -1, err
	}
}
