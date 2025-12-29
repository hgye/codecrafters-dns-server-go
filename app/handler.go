package main

import "fmt"

// mockDNSRecords is a map of domain names to their IP addresses for testing
var mockDNSRecords = map[string][]byte{
	"stackoverflow.com":    {151, 101, 129, 69},
	"stackoverflow.design": {151, 101, 1, 69},
	"def.codecrafters.io":  {76, 76, 21, 21},
	"mail.example.com":     {192, 168, 0, 2},
}

// defaultMockIP is used when a domain is not found in the mock records
var defaultMockIP = []byte{8, 8, 8, 8}

// DNSHandler processes DNS requests and builds responses
type DNSHandler struct {
	requestData []byte   // raw request data
	request     *Message // parsed request message
	response    *Message // built response message
}

// NewDNSHandler creates a new handler for the given request data
func NewDNSHandler(requestData []byte) *DNSHandler {
	return &DNSHandler{
		requestData: requestData,
	}
}

// parseRequest parses the raw request data into a Message struct
func (h *DNSHandler) parseRequest() error {
	var header MessageHeader
	if err := header.UnmarshalBinary(h.requestData); err != nil {
		return fmt.Errorf("failed to parse DNS header: %w", err)
	}

	fmt.Printf("Request Header: ID=%d, QR=%d, Opcode=%d, QDCount=%d, ANCount=%d\n",
		header.Id, header.GetQR(), header.GetOpcode(),
		header.QDCount, header.ANCount)
	fmt.Printf("Request Header Details: RD=%d, TC=%d, AA=%d, Z=%d, RA=%d, RCode=%d\n",
		header.GetRD(), header.GetTC(), header.GetAA(),
		header.GetZ(), header.GetRA(), header.GetRcode())

	fmt.Printf("Parsing %d questions starting at offset %d\n", header.QDCount, DNSHeaderSize)
	questions := make([]Question, 0, header.QDCount)
	offset := DNSHeaderSize
	for i := 0; i < int(header.QDCount); i++ {
		var q Question
		newOffset, err := q.UnmarshalFrom(h.requestData, offset)
		if err != nil {
			return fmt.Errorf("failed to parse question #%d: %w", i+1, err)
		}
		questions = append(questions, q)
		fmt.Printf("Question %d: Name=%s, Type=%d, Class=%d (parsed %d bytes, next offset: %d)\n",
			i+1, q.Name, q.Type, q.Class, newOffset-offset, newOffset)
		offset = newOffset
	}
	fmt.Printf("Finished parsing questions, next offset: %d\n", offset)

	h.request = &Message{
		Header:    header,
		Questions: questions,
	}
	return nil
}

// forward sends a single question to upstream DNS server and returns the response
// For now, this is a mimic that returns hardcoded responses from mockDNSRecords
func (h *DNSHandler) forward(q Question) ([]ResourceRecord, error) {
	fmt.Printf("Forwarding question: %s (Type=%d, Class=%d)\n", q.Name, q.Type, q.Class)

	// Look up the IP address from mock records
	ip, found := mockDNSRecords[q.Name]
	if !found {
		ip = defaultMockIP
		fmt.Printf("Domain %s not found in mock records, using default IP\n", q.Name)
	} else {
		fmt.Printf("Found mock record for %s: %d.%d.%d.%d\n", q.Name, ip[0], ip[1], ip[2], ip[3])
	}

	// Return a single answer record for the question
	answer := ResourceRecord{
		Name:  q.Name,
		Type:  RecordTypeA,
		Class: q.Class,
		TTL:   60,
		RData: ip,
	}
	return []ResourceRecord{answer}, nil
}

// buildResponseHeader creates the response header based on the request and answers
func (h *DNSHandler) buildResponseHeader(answers []ResourceRecord) MessageHeader {
	reqHeader := h.request.Header

	responseHeader := MessageHeader{
		Id:      reqHeader.Id,
		QDCount: reqHeader.QDCount,
		ANCount: uint16(len(answers)),
		NSCount: 0,
		ARCount: 0,
	}
	responseHeader.SetQR(1)
	responseHeader.SetOpcode(reqHeader.GetOpcode())
	responseHeader.SetRD(reqHeader.GetRD())

	if reqHeader.GetOpcode() == 0 {
		responseHeader.SetRcode(RCodeNoError)
	} else {
		responseHeader.SetRcode(RCodeNotImpl)
	}

	return responseHeader
}

// Handle processes the DNS request and returns the binary response
func (h *DNSHandler) Handle() ([]byte, error) {
	// Step 1: Parse the request
	if err := h.parseRequest(); err != nil {
		return nil, err
	}

	// Step 2: Forward each question to upstream and collect answers
	allAnswers := make([]ResourceRecord, 0)
	for i, q := range h.request.Questions {
		fmt.Printf("Forwarding question %d/%d to upstream\n", i+1, len(h.request.Questions))
		answers, err := h.forward(q)
		if err != nil {
			return nil, fmt.Errorf("failed to forward question #%d: %w", i+1, err)
		}
		allAnswers = append(allAnswers, answers...)
	}
	fmt.Printf("Collected %d answers from upstream\n", len(allAnswers))

	// Step 3: Build the response
	h.response = &Message{
		Header:    h.buildResponseHeader(allAnswers),
		Questions: h.request.Questions,
		Answers:   allAnswers,
	}

	// Step 4: Marshal the response to binary
	fmt.Printf("Marshalling response with %d questions and %d answers\n",
		len(h.response.Questions), len(h.response.Answers))
	response, err := h.response.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	fmt.Printf("Response marshalled successfully: %d bytes\n", len(response))
	return response, nil
}
