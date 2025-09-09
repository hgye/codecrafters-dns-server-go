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
	
	// DNS compression constants
	CompressionMask   = 0xC0 // 11000000 - identifies a compression pointer
	CompressionOffset = 0x3FFF // 00111111 11111111 - mask for 14-bit offset
	MaxCompressionJumps = 5 // Prevent infinite loops in compression
	
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

// CompressionMap tracks domain name positions for compression
type CompressionMap map[string]int

// encodeDNSName encodes a domain name into DNS wire format
func encodeDNSName(name string, buf *bytes.Buffer) error {
	// For backward compatibility, call the compression-aware version with nil map
	return encodeDNSNameWithCompression(name, buf, nil, 0)
}

// encodeDNSNameWithCompression encodes a domain name with optional compression
func encodeDNSNameWithCompression(name string, buf *bytes.Buffer, compressionMap CompressionMap, msgStart int) error {
	// Validate total domain name length
	if len(name) > MaxDomainLength {
		return fmt.Errorf("domain name too long: %d bytes (max %d)", len(name), MaxDomainLength)
	}
	
	// Split the name into labels
	labels := strings.Split(name, ".")
	
	// Process each label
	for i, label := range labels {
		// Skip empty labels
		if len(label) == 0 {
			continue
		}
		
		// Build the suffix from current position (e.g., "example.com" from "www.example.com")
		suffix := strings.Join(labels[i:], ".")
		
		// Check if we can use compression for this suffix
		if compressionMap != nil {
			if offset, found := compressionMap[suffix]; found {
				// Write compression pointer
				pointer := CompressionMask<<8 | (offset & CompressionOffset)
				binary.Write(buf, binary.BigEndian, uint16(pointer))
				return nil // Done after writing pointer
			}
			
			// Record this position for future compression
			currentPos := msgStart + buf.Len()
			compressionMap[suffix] = currentPos
		}
		
		// Validate label length
		if len(label) > MaxLabelLength {
			return fmt.Errorf("label too long: %s (max %d bytes)", label, MaxLabelLength)
		}
		
		// Write label length and label data
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	
	// Write terminating zero
	buf.WriteByte(0)
	return nil
}

// decodeDNSName decodes a domain name from DNS wire format with compression support
func decodeDNSName(data []byte, offset int) (string, int, error) {
	return decodeDNSNameWithCompression(data, offset, 0)
}

// decodeDNSNameWithCompression decodes a DNS name with compression pointer support
// jumps parameter tracks compression jumps to prevent infinite loops
func decodeDNSNameWithCompression(data []byte, offset int, jumps int) (string, int, error) {
	if offset >= len(data) {
		return "", 0, fmt.Errorf("offset %d exceeds data length %d", offset, len(data))
	}
	
	if jumps > MaxCompressionJumps {
		return "", 0, fmt.Errorf("too many compression jumps, possible loop detected")
	}
	
	var nameParts []string
	i := offset
	totalLength := 0
	savedOffset := -1 // Saved position after first compression pointer
	
	for {
		if i >= len(data) {
			return "", 0, fmt.Errorf("data too short while reading DNS name at offset %d", offset)
		}
		
		lengthByte := data[i]
		
		// Check for compression pointer (first 2 bits are 11)
		if lengthByte&CompressionMask == CompressionMask {
			// This is a compression pointer
			if i+1 >= len(data) {
				return "", 0, fmt.Errorf("data too short for compression pointer at offset %d", i)
			}
			
			// Calculate the offset to jump to (14-bit value)
			pointerOffset := int(binary.BigEndian.Uint16(data[i:i+2])) & CompressionOffset
			
			// Save current position if this is the first pointer we encounter
			if savedOffset == -1 {
				savedOffset = i + 2
			}
			
			// Recursively decode the name at the pointer location
			pointedName, _, err := decodeDNSNameWithCompression(data, pointerOffset, jumps+1)
			if err != nil {
				return "", 0, fmt.Errorf("failed to follow compression pointer: %w", err)
			}
			
			// Append the pointed name parts
			if pointedName != "" {
				nameParts = append(nameParts, pointedName)
			}
			
			// We're done after following a pointer
			break
		}
		
		length := int(lengthByte)
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
	
	// Return the saved offset if we encountered a compression pointer
	// Otherwise return the current position
	if savedOffset != -1 {
		i = savedOffset
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

// MarshalBinary serializes the entire DNS message with compression support
func (m *Message) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	compressionMap := make(CompressionMap)
	
	// Marshal header
	headerData, err := m.Header.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	buf.Write(headerData)
	
	// Marshal questions with compression
	for i, q := range m.Questions {
		qBuf := new(bytes.Buffer)
		
		// Encode name with compression
		if err := encodeDNSNameWithCompression(q.Name, qBuf, compressionMap, buf.Len()); err != nil {
			return nil, fmt.Errorf("failed to encode question %d name: %w", i, err)
		}
		
		// Write Type and Class
		binary.Write(qBuf, binary.BigEndian, q.Type)
		binary.Write(qBuf, binary.BigEndian, q.Class)
		
		buf.Write(qBuf.Bytes())
	}
	
	// Marshal answers with compression
	for i, rr := range m.Answers {
		rrBuf := new(bytes.Buffer)
		
		// Encode name with compression
		if err := encodeDNSNameWithCompression(rr.Name, rrBuf, compressionMap, buf.Len()); err != nil {
			return nil, fmt.Errorf("failed to encode answer %d name: %w", i, err)
		}
		
		// Write Type, Class, TTL, RDLength, and RData
		binary.Write(rrBuf, binary.BigEndian, rr.Type)
		binary.Write(rrBuf, binary.BigEndian, rr.Class)
		binary.Write(rrBuf, binary.BigEndian, rr.TTL)
		binary.Write(rrBuf, binary.BigEndian, uint16(len(rr.RData)))
		rrBuf.Write(rr.RData)
		
		buf.Write(rrBuf.Bytes())
	}
	
	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes a DNS message with compression support
func (m *Message) UnmarshalBinary(data []byte) error {
	if len(data) < DNSHeaderSize {
		return fmt.Errorf("data too short for DNS message: %d bytes", len(data))
	}
	
	// Unmarshal header
	if err := m.Header.UnmarshalBinary(data[:DNSHeaderSize]); err != nil {
		return fmt.Errorf("failed to unmarshal header: %w", err)
	}
	
	
	offset := DNSHeaderSize
	
	// Unmarshal questions
	m.Questions = make([]Question, m.Header.QDCount)
	for i := uint16(0); i < m.Header.QDCount; i++ {
		name, bytesRead, err := decodeDNSName(data, offset)
		if err != nil {
			return fmt.Errorf("failed to decode question %d name: %w", i, err)
		}
		
		// The bytesRead from decodeDNSName tells us the new position AFTER the name
		nameEndOffset := bytesRead
		
		if nameEndOffset+4 > len(data) {
			return fmt.Errorf("data too short for question %d type/class: need %d bytes, have %d", i, nameEndOffset+4, len(data))
		}
		
		m.Questions[i] = Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[nameEndOffset : nameEndOffset+2]),
			Class: binary.BigEndian.Uint16(data[nameEndOffset+2 : nameEndOffset+4]),
		}
		offset = nameEndOffset + 4
	}
	
	// Unmarshal answers
	m.Answers = make([]ResourceRecord, m.Header.ANCount)
	for i := uint16(0); i < m.Header.ANCount; i++ {
		name, nameEndOffset, err := decodeDNSName(data, offset)
		if err != nil {
			return fmt.Errorf("failed to decode answer %d name: %w", i, err)
		}
		
		if nameEndOffset+10 > len(data) {
			return fmt.Errorf("data too short for answer %d fields", i)
		}
		
		rr := ResourceRecord{
			Name:     name,
			Type:     binary.BigEndian.Uint16(data[nameEndOffset : nameEndOffset+2]),
			Class:    binary.BigEndian.Uint16(data[nameEndOffset+2 : nameEndOffset+4]),
			TTL:      binary.BigEndian.Uint32(data[nameEndOffset+4 : nameEndOffset+8]),
			RDLength: binary.BigEndian.Uint16(data[nameEndOffset+8 : nameEndOffset+10]),
		}
		offset = nameEndOffset + 10
		
		if offset+int(rr.RDLength) > len(data) {
			return fmt.Errorf("data too short for answer %d RData", i)
		}
		
		rr.RData = make([]byte, rr.RDLength)
		copy(rr.RData, data[offset:offset+int(rr.RDLength)])
		offset += int(rr.RDLength)
		
		m.Answers[i] = rr
	}
	
	return nil
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

func (rr *ResourceRecord) UnmarshalBinary(data []byte) error {
	// Decode DNS name with compression support
	name, bytesRead, err := decodeDNSName(data, 0)
	if err != nil {
		return fmt.Errorf("failed to decode DNS name: %w", err)
	}
	rr.Name = name
	i := bytesRead
	
	// Need at least 10 bytes for Type, Class, TTL, and RDLength
	if i+10 > len(data) {
		return fmt.Errorf("data too short to read resource record fields")
	}
	
	rr.Type = binary.BigEndian.Uint16(data[i : i+2])
	rr.Class = binary.BigEndian.Uint16(data[i+2 : i+4])
	rr.TTL = binary.BigEndian.Uint32(data[i+4 : i+8])
	rr.RDLength = binary.BigEndian.Uint16(data[i+8 : i+10])
	i += 10
	
	// Read RData
	if i+int(rr.RDLength) > len(data) {
		return fmt.Errorf("data too short to read RData: need %d bytes, have %d", rr.RDLength, len(data)-i)
	}
	
	rr.RData = make([]byte, rr.RDLength)
	copy(rr.RData, data[i:i+int(rr.RDLength)])
	
	return nil
}
