package main

// DNS protocol related constants
const (
	DNSHeaderSize    = 12
	MaxDNSPacketSize = 512 // classic UDP DNS size without EDNS0
)

// Opcode values
const (
	OpcodeQuery  uint8 = 0 // Standard Query
	OpcodeIQuery uint8 = 1 // Inverse Query (obsolete)
	OpcodeStatus uint8 = 2 // Server Status Request
)

// Record Types
const (
	RecordTypeA     uint16 = 1
	RecordTypeNS    uint16 = 2
	RecordTypeCNAME uint16 = 5
	RecordTypeSOA   uint16 = 6
	RecordTypePTR   uint16 = 12
	RecordTypeMX    uint16 = 15
	RecordTypeTXT   uint16 = 16
	RecordTypeAAAA  uint16 = 28
)

// Class codes
const (
	ClassIN uint16 = 1
)

// RCODE values
const (
	RCodeNoError  uint8 = 0
	RCodeFormat   uint8 = 1
	RCodeServFail uint8 = 2
	RCodeNXDomain uint8 = 3
	RCodeNotImpl  uint8 = 4
	RCodeRefused  uint8 = 5
)
