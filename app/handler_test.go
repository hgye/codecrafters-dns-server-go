package main

import (
	"testing"
)

// buildTestDNSQuery builds a DNS query with the given questions
func buildTestDNSQuery(id uint16, questions []Question) []byte {
	header := MessageHeader{
		Id:      id,
		QDCount: uint16(len(questions)),
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}
	header.SetQR(0) // Query
	header.SetOpcode(0)
	header.SetRD(1)

	msg := Message{
		Header:    header,
		Questions: questions,
	}

	data, _ := msg.MarshalBinary()
	return data
}

func TestDNSHandler_SingleQuestion(t *testing.T) {
	// Build a DNS query with a single question
	questions := []Question{
		{
			Name:  "stackoverflow.com",
			Type:  RecordTypeA,
			Class: ClassIN,
		},
	}
	queryData := buildTestDNSQuery(0x1234, questions)

	// Create handler and process request
	handler := NewDNSHandler(queryData)
	response, err := handler.Handle()
	if err != nil {
		t.Fatalf("Handle() failed: %v", err)
	}

	// Parse the response
	var respMsg Message
	if err := respMsg.UnmarshalBinary(response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify response header
	if respMsg.Header.Id != 0x1234 {
		t.Errorf("Response ID = %d, want %d", respMsg.Header.Id, 0x1234)
	}
	if respMsg.Header.GetQR() != 1 {
		t.Errorf("Response QR = %d, want 1 (response)", respMsg.Header.GetQR())
	}
	if respMsg.Header.QDCount != 1 {
		t.Errorf("Response QDCount = %d, want 1", respMsg.Header.QDCount)
	}
	if respMsg.Header.ANCount != 1 {
		t.Errorf("Response ANCount = %d, want 1", respMsg.Header.ANCount)
	}

	// Verify question is echoed back
	if len(respMsg.Questions) != 1 {
		t.Fatalf("Response has %d questions, want 1", len(respMsg.Questions))
	}
	if respMsg.Questions[0].Name != "stackoverflow.com" {
		t.Errorf("Response question name = %s, want stackoverflow.com", respMsg.Questions[0].Name)
	}

	// Verify answer
	if len(respMsg.Answers) != 1 {
		t.Fatalf("Response has %d answers, want 1", len(respMsg.Answers))
	}
	if respMsg.Answers[0].Name != "stackoverflow.com" {
		t.Errorf("Answer name = %s, want stackoverflow.com", respMsg.Answers[0].Name)
	}
	// Check IP address: 151.101.129.69
	expectedIP := []byte{151, 101, 129, 69}
	if len(respMsg.Answers[0].RData) != 4 {
		t.Errorf("Answer RData length = %d, want 4", len(respMsg.Answers[0].RData))
	} else {
		for i, b := range expectedIP {
			if respMsg.Answers[0].RData[i] != b {
				t.Errorf("Answer RData[%d] = %d, want %d", i, respMsg.Answers[0].RData[i], b)
			}
		}
	}

	t.Logf("Single question test passed: %s -> %d.%d.%d.%d",
		respMsg.Answers[0].Name,
		respMsg.Answers[0].RData[0], respMsg.Answers[0].RData[1],
		respMsg.Answers[0].RData[2], respMsg.Answers[0].RData[3])
}

func TestDNSHandler_MultipleQuestions(t *testing.T) {
	// Build a DNS query with multiple questions
	questions := []Question{
		{
			Name:  "stackoverflow.com",
			Type:  RecordTypeA,
			Class: ClassIN,
		},
		{
			Name:  "def.codecrafters.io",
			Type:  RecordTypeA,
			Class: ClassIN,
		},
		{
			Name:  "unknown.com",
			Type:  RecordTypeA,
			Class: ClassIN,
		},
	}
	queryData := buildTestDNSQuery(0x5678, questions)

	// Create handler and process request
	handler := NewDNSHandler(queryData)
	response, err := handler.Handle()
	if err != nil {
		t.Fatalf("Handle() failed: %v", err)
	}

	// Parse the response
	var respMsg Message
	if err := respMsg.UnmarshalBinary(response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify response header
	if respMsg.Header.Id != 0x5678 {
		t.Errorf("Response ID = %d, want %d", respMsg.Header.Id, 0x5678)
	}
	if respMsg.Header.GetQR() != 1 {
		t.Errorf("Response QR = %d, want 1 (response)", respMsg.Header.GetQR())
	}
	if respMsg.Header.QDCount != 3 {
		t.Errorf("Response QDCount = %d, want 3", respMsg.Header.QDCount)
	}
	if respMsg.Header.ANCount != 3 {
		t.Errorf("Response ANCount = %d, want 3", respMsg.Header.ANCount)
	}

	// Verify all 3 questions are echoed back
	if len(respMsg.Questions) != 3 {
		t.Fatalf("Response has %d questions, want 3", len(respMsg.Questions))
	}

	expectedNames := []string{"stackoverflow.com", "def.codecrafters.io", "unknown.com"}
	for i, name := range expectedNames {
		if respMsg.Questions[i].Name != name {
			t.Errorf("Response question[%d] name = %s, want %s", i, respMsg.Questions[i].Name, name)
		}
	}

	// Verify all 3 answers (each question forwarded separately)
	if len(respMsg.Answers) != 3 {
		t.Fatalf("Response has %d answers, want 3", len(respMsg.Answers))
	}

	// Expected IPs from mockDNSRecords
	expectedIPs := [][]byte{
		{151, 101, 129, 69}, // stackoverflow.com
		{76, 76, 21, 21},    // def.codecrafters.io
		{8, 8, 8, 8},        // unknown.com (default)
	}

	for i, name := range expectedNames {
		if respMsg.Answers[i].Name != name {
			t.Errorf("Answer[%d] name = %s, want %s", i, respMsg.Answers[i].Name, name)
		}
		if len(respMsg.Answers[i].RData) != 4 {
			t.Errorf("Answer[%d] RData length = %d, want 4", i, len(respMsg.Answers[i].RData))
		} else {
			for j, b := range expectedIPs[i] {
				if respMsg.Answers[i].RData[j] != b {
					t.Errorf("Answer[%d] RData[%d] = %d, want %d", i, j, respMsg.Answers[i].RData[j], b)
				}
			}
		}
		t.Logf("Answer %d: %s -> %d.%d.%d.%d",
			i+1, respMsg.Answers[i].Name,
			respMsg.Answers[i].RData[0], respMsg.Answers[i].RData[1],
			respMsg.Answers[i].RData[2], respMsg.Answers[i].RData[3])
	}

	t.Logf("Multiple questions test passed: %d questions -> %d answers", len(questions), len(respMsg.Answers))
}
