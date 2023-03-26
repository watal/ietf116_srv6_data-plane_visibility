// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package exporter

import (
	"log"
	"net"
	"os"

	"github.com/watal/ietf116_srv6_data-plane_visibility/pkg/bpf"
	"github.com/watal/ietf116_srv6_data-plane_visibility/pkg/packet/ipfix"
)

func NewMessage(entry bpf.XdpProbeData) ipfix.Message {
	// for skyline ここ頼む
	message := ipfix.Message{
		Version:        10,
		Length:         16,
		ExportTime:     0,
		SequenceNumber: 0,
		DomainID:       0,
		Records: []ipfix.Record{
			{
				TemplateID: 256,
				Fields: []ipfix.Field{
					{
						EnterpriseID:         0,
						Length:               4,
						InformationElementID: 8,
						Value:                entry.SrcIP,
					},
					{
						EnterpriseID:         0,
						Length:               4,
						InformationElementID: 12,
						Value:                entry.DstIP,
					},
					{
						EnterpriseID:         0,
						Length:               4,
						InformationElementID: 14,
						Value:                entry.SrcPort,
					},
					{
						EnterpriseID:         0,
						Length:               4,
						InformationElementID: 15,
						Value:                entry.DstPort,
					},
					{
						EnterpriseID:         0,
						Length:               4,
						InformationElementID: 4,
						Value:                entry.Protocol,
					},
					{
						EnterpriseID:         0,
						Length:               4,
						InformationElementID: 1,
						Value:                entry.Packets,
					},
					{
						EnterpriseID:         0,
						Length:               4,
						InformationElementID: 2,
						Value:                entry.Bytes,
					},
				},
			},
		},
	}
	return messageIPFIX
}

func SendMessage(message ipfix.Message) {
	byteMessage := message.Serialize()
	conn, err := net.Dial("udp", "[fd00:0:1::2]:4739")
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
	defer conn.Close()

	_, err = conn.Write(byteMessage)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
}
