// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package ipfix

import "encoding/binary"

type MessageHeader struct { // RFC7011 3.1
	Version             uint16
	Length              uint16
	ExportTime          uint32
	SequenceNumber      uint32
	ObsarvationDomainID uint32
}

func (h *MessageHeader) DecodeFromBytes(header []uint8) error {
	h.Version = binary.BigEndian.Uint16(header[0:2])
	h.Length = binary.BigEndian.Uint16(header[2:4])
	h.ExportTime = binary.BigEndian.Uint32(header[4:8])
	h.SequenceNumber = binary.BigEndian.Uint32(header[8:12])
	h.ObsarvationDomainID = binary.BigEndian.Uint32(header[12:16])
	return nil
}

func (h *MessageHeader) Serialize() []uint8 {
	buf := make([]uint8, 0, 16)
	uint8Buf := make([]uint8, 2)
	binary.BigEndian.PutUint16(uint8Buf, h.Version)
	buf = append(buf, uint8Buf...)
	binary.BigEndian.PutUint16(uint8Buf, h.Length)
	buf = append(buf, uint8Buf...)
	binary.BigEndian.PutUint32(uint8Buf, h.ExportTime)
	buf = append(buf, uint8Buf...)
	binary.BigEndian.PutUint32(uint8Buf, h.SequenceNumber)
	buf = append(buf, uint8Buf...)
	binary.BigEndian.PutUint32(uint8Buf, h.ObsarvationDomainID)
	buf = append(buf, uint8Buf...)
	return buf
}

func NewCommonHeader(messageType uint8, messageLength uint16) *MessageHeader {
	h := &MessageHeader{
		Version:             uint16(1),
		Length:              uint16(0),
		ExportTime:          uint32(0),
		SequenceNumber:      uint32(0),
		ObsarvationDomainID: uint32(0),
	}
	return h
}

type FieldSpecifier struct {
	E                    bool
	InformationElementID uint16
	FieldLength          uint16
	EnterpriseNumber     uint32
}

func (s *FieldSpecifier) DecodeFromBytes(buf []uint8) error {
	s.E = buf[0]>>7 == 1
	s.InformationElementID = binary.BigEndian.Uint16(buf[0:2])
	s.FieldLength = binary.BigEndian.Uint16(buf[2:4])
	if s.E {
		s.EnterpriseNumber = binary.BigEndian.Uint32(buf[4:8])
	}
	return nil
}

func (s *FieldSpecifier) Serialize() []uint8 {
	buf := make([]uint8, 0, 8)
	uint8Buf := make([]uint8, 2)
	if s.E {
		uint8Buf[0] = 1 << 7
	}
	binary.BigEndian.PutUint16(uint8Buf, s.InformationElementID)
	buf = append(buf, uint8Buf...)
	binary.BigEndian.PutUint16(uint8Buf, s.FieldLength)
	buf = append(buf, uint8Buf...)
	if s.E {
		binary.BigEndian.PutUint32(uint8Buf, s.EnterpriseNumber)
		buf = append(buf, uint8Buf...)
	}
	return buf
}

func NewFieldSpecifier(messageType uint8, messageLength uint16) *MessageHeader {
	h := &MessageHeader{
		Version:             uint16(1),
		Length:              uint16(0),
		ExportTime:          uint32(0),
		SequenceNumber:      uint32(0),
		ObsarvationDomainID: uint32(0),
	}
	return h
}

type SetHeader struct {
	SetID  uint16
	Length uint16
}

func (h *SetHeader) DecodeFromBytes(header []uint8) error {
	h.SetID = binary.BigEndian.Uint16(header[0:2])
	h.Length = binary.BigEndian.Uint16(header[2:4])
	return nil
}

func (h *SetHeader) Serialize() []uint8 {
	buf := make([]uint8, 0, 4)
	uint8Buf := make([]uint8, 2)
	binary.BigEndian.PutUint16(uint8Buf, h.SetID)
	buf = append(buf, uint8Buf...)
	binary.BigEndian.PutUint16(uint8Buf, h.Length)
	buf = append(buf, uint8Buf...)
	return buf
}

func NewSetHeader(setID uint16, length uint16) *SetHeader {
	return &SetHeader{
		SetID:  setID,
		Length: length,
	}
}
