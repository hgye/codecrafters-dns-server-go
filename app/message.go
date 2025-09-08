package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// DNS protocol constants
const (
	DNSHeaderSize     = 12
	MaxDNSPacketSize  = 512
	MaxLabelLength    = 63
	MaxDomainLength   = 253
	
	// DNS record types
	RecordTypeA     = 1
	RecordTypeNS    = 2
	RecordTypeCNAME = 5
	
	// DNS classes
	ClassIN = 1
	
	// DNS response codes
	RCodeNoError      = 0
	RCodeFormatError  = 1
	RCodeServerFail   = 2
	RCodeNameError    = 3
	RCodeNotImpl      = 4
	RCodeRefused      = 5
)

// encodeDNSName encodes a domain name into DNS wire format
func encodeDNSName(name string, buf *bytes.Buffer) error {
	// Validate total domain name length
	if len(name) > MaxDomainLength {
		return fmt.Errorf("domain name too long: %d bytes (max %d)", len(name), MaxDomainLength)
	}
	
	// Encode name as DNS label format (e.g., "www.example.com" -> 3www7example3com0)
	labels := bytes.Split([]byte(name), []byte("."))
	for _, label := range labels {
		if len(label) > MaxLabelLength {
			return fmt.Errorf("label too long: %s (max %d bytes)", label, MaxLabelLength)
		}
		if len(label) == 0 {
			continue // Skip empty labels
		}
		buf.WriteByte(byte(len(label)))
		buf.Write(label)
	}
	buf.WriteByte(0) // End of name marker
	return nil
}

// decodeDNSName decodes a domain name from DNS wire format
func decodeDNSName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", 0, fmt.Errorf("offset %d exceeds data length %d", offset, len(data))
	}
	
	var nameParts []string
	i := offset
	totalLength := 0
	
	for {
		if i >= len(data) {
			return "", 0, fmt.Errorf("data too short while reading DNS name at offset %d", offset)
		}
		
		length := int(data[i])
		if length == 0 {
			i++
			break
		}
		
		// Validate length doesn't exceed max label length
		if length > MaxLabelLength {
			return "", 0, fmt.Errorf("label length %d exceeds maximum %d", length, MaxLabelLength)
		}
		
		// Check bounds for label data
		if i+1+length > len(data) {
			return "", 0, fmt.Errorf("data too short while reading DNS name label at offset %d", i)
		}
		
		nameParts = append(nameParts, string(data[i+1:i+1+length]))
		totalLength += length + 1 // +1 for length byte
		i += length + 1
		
		// Check total domain name length limit
		if totalLength > MaxDomainLength {
			return "", 0, fmt.Errorf("domain name too long: %d bytes (max %d)", totalLength, MaxDomainLength)
		}
	}
	
	return strings.Join(nameParts, "."), i, nil
}

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
	b := make([]byte, DNSHeaderSize)
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
	if len(data) < DNSHeaderSize {
		return fmt.Errorf("data too short to unmarshal MessageHeader: got %d bytes, need %d", len(data), DNSHeaderSize)
	}
	h.Id = binary.BigEndian.Uint16(data[0:2])
	h.Flags = binary.BigEndian.Uint16(data[2:4])
	h.QDCount = binary.BigEndian.Uint16(data[4:6])
	h.ANCount = binary.BigEndian.Uint16(data[6:8])
	h.NSCount = binary.BigEndian.Uint16(data[8:10])
	h.ARCount = binary.BigEndian.Uint16(data[10:12])
	return nil
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

func (q *Question) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	// Encode DNS name
	if err := encodeDNSName(q.Name, buf); err != nil {
		return nil, fmt.Errorf("failed to encode DNS name: %w", err)
	}

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
	// Decode DNS name
	name, bytesRead, err := decodeDNSName(data, 0)
	if err != nil {
		return fmt.Errorf("failed to decode DNS name: %w", err)
	}
	q.Name = name
	i := bytesRead

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
	
	// Encode DNS name
	if err := encodeDNSName(rr.Name, buf); err != nil {
		return nil, fmt.Errorf("failed to encode DNS name: %w", err)
	}

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
