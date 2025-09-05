package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// header, question, answer, authority, and an additional space.
type Message struct {
	Header    MessageHeader
	Questions []Question
	Answers   []ResourceRecord
	// Authority  []ResourceRecord
	// Additional []ResourceRecord
}

type BinaryMarshaler interface {
	MarshalBinary() (data []byte, err error)
}
type MessageHeader struct {
	// DNS Message Header Format
	//
	// Id: Packet Identifier (16 bits)
	Id uint16
	// Flags: All flag fields packed into 16 bits
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Helper methods for flag access
func (h *MessageHeader) GetQR() uint8 {
	return uint8((h.Flags >> 15) & 1)
}

func (h *MessageHeader) SetQR(qr uint8) {
	h.Flags = (h.Flags &^ (1 << 15)) | (uint16(qr&1) << 15)
}

// Opcode is 4 bits (bits 11-14)
func (h *MessageHeader) GetOpcode() uint8 {
	return uint8((h.Flags >> 11) & 0xF)
}

func (h *MessageHeader) SetOpcode(opcode uint8) {
	h.Flags = (h.Flags &^ (0xF << 11)) | (uint16(opcode&0xF) << 11)
}

// AA is 1 bit (bit 10)
func (h *MessageHeader) GetAA() uint8 {
	return uint8((h.Flags >> 10) & 1)
}

func (h *MessageHeader) SetAA(aa uint8) {
	h.Flags = (h.Flags &^ (1 << 10)) | (uint16(aa&1) << 10)
}

// TC is 1 bit (bit 9)
func (h *MessageHeader) GetTC() uint8 {
	return uint8((h.Flags >> 9) & 1)
}

func (h *MessageHeader) SetTC(tc uint8) {
	h.Flags = (h.Flags &^ (1 << 9)) | (uint16(tc&1) << 9)
}

// RD is 1 bit (bit 8)
func (h *MessageHeader) GetRD() uint8 {
	return uint8((h.Flags >> 8) & 1)
}

func (h *MessageHeader) SetRD(rd uint8) {
	h.Flags = (h.Flags &^ (1 << 8)) | (uint16(rd&1) << 8)
}

// RA is 1 bit (bit 7)
func (h *MessageHeader) GetRA() uint8 {
	return uint8((h.Flags >> 7) & 1)
}

func (h *MessageHeader) SetRA(ra uint8) {
	h.Flags = (h.Flags &^ (1 << 7)) | (uint16(ra&1) << 7)
}

// Z is 3 bits (bits 4-6)
func (h *MessageHeader) GetZ() uint8 {
	return uint8((h.Flags >> 4) & 0x7)
}

func (h *MessageHeader) SetZ(z uint8) {
	h.Flags = (h.Flags &^ (0x7 << 4)) | (uint16(z&0x7) << 4)
}

// Rcode is 4 bits (bits 0-3)
func (h *MessageHeader) GetRcode() uint8 {
	return uint8(h.Flags & 0xF)
}

func (h *MessageHeader) SetRcode(rcode uint8) {
	h.Flags = (h.Flags &^ 0xF) | (uint16(rcode & 0xF))
}

func (h *MessageHeader) MarshalBinary() ([]byte, error) {
	b := make([]byte, 12)
	b[0] = byte(h.Id >> 8)
	b[1] = byte(h.Id)
	b[2] = byte(h.Flags >> 8)
	b[3] = byte(h.Flags)
	b[4] = byte(h.QDCount >> 8)
	b[5] = byte(h.QDCount)
	b[6] = byte(h.ANCount >> 8)
	b[7] = byte(h.ANCount)
	b[8] = byte(h.NSCount >> 8)
	b[9] = byte(h.NSCount)
	b[10] = byte(h.ARCount >> 8)
	b[11] = byte(h.ARCount)
	return b, nil
}

func (h *MessageHeader) UnmarshalBinary(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("data too short to unmarshal MessageHeader")
	}
	h.Id = binary.BigEndian.Uint16(data[0:2])
	h.Flags = binary.BigEndian.Uint16(data[2:4])
	h.QDCount = binary.BigEndian.Uint16(data[4:6])
	h.ANCount = binary.BigEndian.Uint16(data[6:8])
	h.NSCount = binary.BigEndian.Uint16(data[8:10])
	h.ANCount = binary.BigEndian.Uint16(data[10:12])
	return nil
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q *Question) MarshalBinary() ([]byte, error) {
	// Implement DNS question serialization here
	buf := new(bytes.Buffer)
	// Encode q.Name as DNS label format (e.g., "www.example.com" -> 3www7example3com0)
	labels := bytes.Split([]byte(q.Name), []byte("."))
	for _, label := range labels {
		if len(label) > 63 {
			return nil, fmt.Errorf("label too long: %s", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.Write(label)
	}
	buf.WriteByte(0) // End of name

	// write Type and Class
	err := binary.Write(buf, binary.BigEndian, q.Type)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, q.Class)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (q *Question) UnmarshalBinary(data []byte) error {
	// Implement DNS question deserialization here
	// read Name in DNS label format
	var nameParts []string
	i := 0
	for {
		if i >= len(data) {
			return fmt.Errorf("data too short while reading question name")
		}
		length := int(data[i])
		if length == 0 {
			i++
			break
		}
		if i+length >= len(data) {
			return fmt.Errorf("data too short while reading question name")
		}
		nameParts = append(nameParts, string(data[i+1:i+1+length]))
		i += length + 1
	}
	q.Name = strings.Join(nameParts, ".")

	if i+4 > len(data) {
		return fmt.Errorf("data too short to read Type and Class")
	}
	q.Type = binary.BigEndian.Uint16(data[i : i+2])
	q.Class = binary.BigEndian.Uint16(data[i+2 : i+4])
	return nil
}

type ResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

func (rr *ResourceRecord) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	// Encode rr.Name as DNS label format
	labels := bytes.Split([]byte(rr.Name), []byte("."))
	for _, label := range labels {
		if len(label) > 63 {
			return nil, fmt.Errorf("label too long: %s", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.Write(label)
	}
	buf.WriteByte(0) // End of name

	// Write Type, Class, TTL, RDLength, and RData
	err := binary.Write(buf, binary.BigEndian, rr.Type)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, rr.Class)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, rr.TTL)
	if err != nil {
		return nil, err
	}
	rr.RDLength = uint16(len(rr.RData))
	err = binary.Write(buf, binary.BigEndian, rr.RDLength)
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(rr.RData)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
