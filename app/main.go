package main

import (
	"fmt"
	"net"
)

// handleDNSRequest processes a single DNS request and returns the response
func handleDNSRequest(requestData []byte) ([]byte, error) {
	// Step 1: Parse the header
	var requestHeader MessageHeader
	if err := requestHeader.UnmarshalBinary(requestData); err != nil {
		return nil, fmt.Errorf("failed to parse DNS header: %w", err)
	}

	fmt.Printf("Request Header: ID=%d, QR=%d, Opcode=%d, QDCount=%d, ANCount=%d\n",
		requestHeader.Id, requestHeader.GetQR(), requestHeader.GetOpcode(),
		requestHeader.QDCount, requestHeader.ANCount)
	fmt.Printf("Request Header Details: RD=%d, TC=%d, AA=%d, Z=%d, RA=%d, RCode=%d\n",
		requestHeader.GetRD(), requestHeader.GetTC(), requestHeader.GetAA(),
		requestHeader.GetZ(), requestHeader.GetRA(), requestHeader.GetRcode())

	// Step 2: Parse the questions
	fmt.Printf("Parsing %d questions starting at offset %d\n", requestHeader.QDCount, DNSHeaderSize)
	questions := make([]Question, 0, requestHeader.QDCount)
	offset := DNSHeaderSize // Start reading after the header
	for i := 0; i < int(requestHeader.QDCount); i++ {
		var q Question
		newOffset, err := q.UnmarshalFrom(requestData, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse question #%d: %w", i+1, err)
		}
		questions = append(questions, q)
		fmt.Printf("Question %d: Name=%s, Type=%d, Class=%d (parsed %d bytes, next offset: %d)\n",
			i+1, q.Name, q.Type, q.Class, newOffset-offset, newOffset)
		offset = newOffset
	}
	fmt.Printf("Finished parsing questions, next offset: %d\n", offset)

	// Step 3: Create the response message
	responseHeader := MessageHeader{
		Id:      requestHeader.Id,
		QDCount: requestHeader.QDCount,
		ANCount: requestHeader.QDCount, // For each question, we'll provide one answer
		NSCount: 0,
		ARCount: 0,
	}
	responseHeader.SetQR(1)
	responseHeader.SetOpcode(requestHeader.GetOpcode())
	responseHeader.SetRD(requestHeader.GetRD())
	if requestHeader.GetOpcode() == 0 {
		responseHeader.SetRcode(RCodeNoError)
	} else {
		responseHeader.SetRcode(RCodeNotImpl)
	}

	fmt.Printf("Response Header: ID=%d, QR=%d, Opcode=%d, RCode=%d, QDCount=%d, ANCount=%d\n",
		responseHeader.Id, responseHeader.GetQR(), responseHeader.GetOpcode(),
		responseHeader.GetRcode(), responseHeader.QDCount, responseHeader.ANCount)

	fmt.Printf("Building %d answers for questions\n", len(questions))
	answers := make([]ResourceRecord, 0, len(questions))
	for i, q := range questions {
		answer := ResourceRecord{
			Name:  q.Name,
			Type:  RecordTypeA,
			Class: q.Class,
			TTL:   60,
			RData: []byte{8, 8, 8, 8}, // Google DNS
		}
		answers = append(answers, answer)
		fmt.Printf("Answer %d: Name=%s, Type=%d, Class=%d, TTL=%d, RData=%v\n",
			i+1, answer.Name, answer.Type, answer.Class, answer.TTL, answer.RData)
	}

	responseMessage := Message{
		Header:    responseHeader,
		Questions: questions,
		Answers:   answers,
	}

	// Step 4: Marshal the response message to binary
	fmt.Printf("Marshalling complete response message with %d questions and %d answers\n", len(questions), len(answers))
	response, err := responseMessage.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	fmt.Printf("Response marshalled successfully: %d bytes\n", len(response))
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
		fmt.Printf("Raw request data: %x\n", receivedData)

		// Basic validation: DNS messages must be at least header size
		if size < DNSHeaderSize {
			fmt.Printf("Packet too small: %d bytes (minimum %d required)\n", size, DNSHeaderSize)
			continue
		}

		fmt.Println("--- Processing DNS Request ---")

		// Process the DNS request
		response, err := handleDNSRequest(receivedData)
		if err != nil {
			fmt.Printf("Failed to handle DNS request: %v\n", err)
			continue
		}

		fmt.Printf("Sending %d bytes response back to %s\n", len(response), source)
		fmt.Printf("Raw response data: %x\n", response)

		// Send response back to client
		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}

		fmt.Println("--- Request completed ---")
	}
}
