package bpf

import (
	"fmt"
	"net"
	"testing"

	// "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var icmpPayload = []byte{
	0xe0, 0x57, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
}

func generateInput(t *testing.T) []byte {
	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()

	srcIP := net.ParseIP("2001:db8::1")
	dstIP := net.ParseIP("2001:db8::2")
	srcMAC, _ := net.ParseMAC("02:42:ac:11:00:02")
	dstMAC, _ := net.ParseMAC("02:42:ac:11:00:03")
	srcPort := layers.UDPPort(12345)
	dstPort := layers.UDPPort(54321)

	// Define the SRv6 segment list
	segmentList := []net.IP{
		net.ParseIP("2001:db8:dead:beef::1"),
		net.ParseIP("2001:db8:dead:beef::2"),
	}

	// Create the Ethernet layer
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	// Create the IPv6 layer
	ipv6Layer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		HopLimit:   64,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	// Create the SRv6 extension header layer
	seg6layer := &Srv6Layer{
		NextHeader:   uint8(layers.IPProtocolUDP),
		HdrExtLen:    uint8((8+16*len(segmentList))/8 - 1),
		RoutingType:  4, // SRH
		SegmentsLeft: uint8(len(segmentList)),
		LastEntry:    uint8(len(segmentList) - 1),
		Flags:        0,
		Tag:          0,
		Segments:     segmentList,
	}
	// Create the UDP layer
	udpLayer := &layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	udpLayer.SetNetworkLayerForChecksum(ipv6Layer)

	err := gopacket.SerializeLayers(buf, opts,
		ethernetLayer, ipv6Layer, seg6layer, udpLayer,
		gopacket.Payload([]byte("Hello, SRv6!")),
	)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func generateOutput(t *testing.T) []byte {
	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()
	iph := &layers.IPv4{
		Version: 4, Protocol: layers.IPProtocolUDP, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1212,
		SrcIP: net.IP{192, 168, 10, 1}, DstIP: net.IP{192, 168, 10, 5},
	}
	udp := &layers.UDP{SrcPort: 2152, DstPort: 2152}
	udp.SetNetworkLayerForChecksum(iph)
	err := gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{DstMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x02}, SrcMAC: []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x01}, EthernetType: layers.EthernetTypeIPv4},
		iph, udp,
		&layers.GTPv1U{Version: 1, ProtocolType: 1, Reserved: 0, ExtensionHeaderFlag: false, SequenceNumberFlag: false, NPDUFlag: false, MessageType: 255, MessageLength: 76, TEID: 2},
		&layers.IPv4{
			Version: 4, Protocol: layers.IPProtocolICMPv4, Flags: layers.IPv4DontFragment, TTL: 64, IHL: 5, Id: 1160,
			SrcIP: net.IP{192, 168, 100, 200}, DstIP: net.IP{192, 168, 30, 1},
		},
		&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 1, Seq: 1},
		gopacket.Payload(icmpPayload),
	)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestXDPProg(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	objs := &xdpObjects{}
	err := loadXdpObjects(objs, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	ret, _, err := objs.XdpProg.Test(generateInput(t))
	if err != nil {
		t.Error(err)
	}

	// retern code should be XDP_PASS
	if ret != 2 {
		t.Errorf("got %d want %d", ret, 2)
	}

	var entry xdpProbeData
	var count uint64
	iter := objs.IpfixProbeMap.Iterate()
	for iter.Next(&entry, &count) {
		PrintEntrys(entry, count)
	}
	if err := iter.Err(); err != nil {
		fmt.Printf("Failed to iterate map: %v\n", err)
	}
}

func createEntry[T any](v T, num int) []T {
	r := make([]T, num)
	for i := 0; i < num; i++ {
		r[i] = v
	}
	return r
}
