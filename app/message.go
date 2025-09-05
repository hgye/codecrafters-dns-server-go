package main

type Message struct{}

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
