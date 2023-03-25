package bpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags -target xdp ../../src/main.c -- -I /usr/include/x86_64-linux-gnu -I ../../src/

func ReadXdpObjects(ops *ebpf.CollectionOptions) (*xdpObjects, error) {
	obj := &xdpObjects{}
	err := loadXdpObjects(obj, ops)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// TODO: BPF log level remove hardcoding. yaml in config
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return obj, nil
}

const (
	XDP_ABORTED uint32 = iota
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

func PrintEntrys(entry xdpProbeData, count uint64) {
	mac := func(mac [6]uint8) string {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}
	saddr := net.IP(entry.V6Srcaddr.In6U.U6Addr8[:]).String()
	daddr := net.IP(entry.V6Dstaddr.In6U.U6Addr8[:]).String()

	fmt.Printf("H_dest: %s, H_source: %v, H_proto: %v, V6Dstaddr: %v, V6Srcaddr: %v -> count: %v\n",
		mac(entry.H_dest), mac(entry.H_source), entry.H_proto, daddr, saddr, count)
}
