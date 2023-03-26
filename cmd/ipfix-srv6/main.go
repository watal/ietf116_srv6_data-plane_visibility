// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/watal/ietf116_srv6_data-plane_visibility/pkg/bpf"
	"github.com/watal/ietf116_srv6_data-plane_visibility/pkg/exporter"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// XDPプログラムを読み込む
	objs, err := bpf.ReadXdpObjects(nil)
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		var entry bpf.XdpProbeData
		var count uint64
		iter := objs.IpfixProbeMap.Iterate()
		for iter.Next(&entry, &count) {
			bpf.PrintEntrys(entry, count)
			message := exporter.NewMessage(entry))
			exporter.SendMessage(message)
		}
		if err := iter.Err(); err != nil {
			fmt.Printf("Failed to iterate map: %v\n", err)
		}
	}
}
