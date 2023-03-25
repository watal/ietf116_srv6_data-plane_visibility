// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/watal/ietf116_srv6_data-plane_visibility/pkg/bpf"
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

	// // Print the contents of the BPF hash map (source IP address -> packet count).
	// ticker := time.NewTicker(1 * time.Second)
	// defer ticker.Stop()
	// for range ticker.C {
	// 	s, err := formatMapContents(objs.XdpStatsMap)
	// 	if err != nil {
	// 		log.Printf("Error reading map: %s", err)
	// 		continue
	// 	}
	// 	log.Printf("Map contents:\n%s", s)
	// }
}
