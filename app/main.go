package main

import (
	"fmt"
	"net"
)

// handleDNSRequest processes a single DNS request and returns the response
func handleDNSRequest(requestData []byte) ([]byte, error) {
	// Parse the full DNS message with compression support
	var reqMsg Message
	err := reqMsg.UnmarshalBinary(requestData)
	if err != nil {
		// Fallback to legacy method for compatibility
		return handleDNSRequestLegacy(requestData)
	}
	
	fmt.Printf("Request Header: %+v\n", reqMsg.Header)
	fmt.Printf("Request Questions: %+v\n", reqMsg.Questions)
	
	// Validate we have at least one question
	if len(reqMsg.Questions) == 0 {
		return nil, fmt.Errorf("DNS message has no questions")
	}
	
	// Create response message
	responseMsg := Message{
		Header: MessageHeader{
			Id:      reqMsg.Header.Id,
			QDCount: reqMsg.Header.QDCount,
			ANCount: uint16(len(reqMsg.Questions)), // One answer per question
			NSCount: 0,
			ARCount: 0,
		},
		Questions: make([]Question, len(reqMsg.Questions)),
		Answers:   make([]ResourceRecord, len(reqMsg.Questions)),
	}
	
	// Set response flags
	responseMsg.Header.SetQR(1) // Response
	responseMsg.Header.SetOpcode(reqMsg.Header.GetOpcode())
	responseMsg.Header.SetRD(reqMsg.Header.GetRD())
	
	if reqMsg.Header.GetOpcode() == 0 {
		responseMsg.Header.SetRcode(RCodeNoError)
	} else {
		responseMsg.Header.SetRcode(RCodeNotImpl)
	}
	
	// Copy questions and create answers
	for i, q := range reqMsg.Questions {
		// Copy question
		responseMsg.Questions[i] = Question{
			Name:  q.Name,
			Type:  q.Type,
			Class: q.Class,
		}
		
		// Create answer (only handle A record queries for now)
		responseMsg.Answers[i] = ResourceRecord{
			Name:  q.Name,
			Type:  RecordTypeA,
			Class: ClassIN,
			TTL:   60,
			RData: []byte{127, 0, 0, 1}, // localhost
		}
	}
	
	// Marshal the complete response with compression
	response, err := responseMsg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response message: %w", err)
	}
	
	return response, nil
}

// handleDNSRequestLegacy processes a single DNS request using the legacy method (for compatibility)
func handleDNSRequestLegacy(requestData []byte) ([]byte, error) {
	var reqHeader MessageHeader
	
	err := reqHeader.UnmarshalBinary(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal request header: %w", err)
	}
	
	fmt.Printf("Request Header: %+v\n", reqHeader)
	
	var reqQuestion Question
	err = reqQuestion.UnmarshalBinary(requestData[DNSHeaderSize:])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal request question: %w", err)
	}
	
	fmt.Printf("Request Question: %+v\n", reqQuestion)
	
	// Create response header
	responseHeader := MessageHeader{
		Id:      reqHeader.Id,
		QDCount: reqHeader.QDCount,
		ANCount: 1, // One answer record
		NSCount: reqHeader.NSCount,
		ARCount: reqHeader.ARCount,
	}
	
	// Set response flags
	responseHeader.SetQR(1) // Response
	responseHeader.SetOpcode(reqHeader.GetOpcode())
	responseHeader.SetRD(reqHeader.GetRD())
	
	if reqHeader.GetOpcode() == 0 {
		responseHeader.SetRcode(RCodeNoError)
	} else {
		responseHeader.SetRcode(RCodeNotImpl)
	}
	
	// Marshal response header
	response, err := responseHeader.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response header: %w", err)
	}
	
	// Add question section to response
	question := Question{
		Name:  reqQuestion.Name,
		Type:  RecordTypeA,
		Class: ClassIN,
	}
	
	qData, err := question.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal question: %w", err)
	}
	response = append(response, qData...)
	
	// Add answer section
	answer := ResourceRecord{
		Name:     reqQuestion.Name,
		Type:     RecordTypeA,
		Class:    ClassIN,
		TTL:      60,
		RDLength: 4,
		RData:    []byte{127, 0, 0, 1}, // localhost
	}
	
	aData, err := answer.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal answer: %w", err)
	}
	response = append(response, aData...)
	
	return response, nil
}

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// Uncomment this block to pass the first stage
	//
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, MaxDNSPacketSize)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := buf[:size]
		fmt.Printf("Received %d bytes from %s\n", size, source)
		
		// Basic validation: DNS messages must be at least header size
		if size < DNSHeaderSize {
			fmt.Printf("Packet too small: %d bytes (minimum %d required)\n", size, DNSHeaderSize)
			continue
		}

		// Process the DNS request
		response, err := handleDNSRequest(receivedData)
		if err != nil {
			fmt.Printf("Failed to handle DNS request: %v\n", err)
			continue
		}

		// Send response back to client
		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
