package main

import (
	"fmt"
	"net"
)

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

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		var reqHeader MessageHeader

		err = reqHeader.UnmarshalBinary([]byte(receivedData))
		if err != nil {
			fmt.Println("Failed to unmarshal request header:", err)
			continue
		}

		fmt.Printf("Request Header: %+v\n", reqHeader)

		var reQuestion Question

		err = reQuestion.UnmarshalBinary([]byte(receivedData[12:])) // Skip header (12 bytes)
		if err != nil {
			fmt.Println("Failed to unmarshal request question:", err)
			continue
		}

		fmt.Printf("Request Question: %+v\n", reQuestion)

		// Create a DNS response header
		header := MessageHeader{
			Id:      reqHeader.Id, // from request
			QDCount: reqHeader.QDCount,
			ANCount: 1, // hardcoded for now, should be number of answers, not from request
			NSCount: reqHeader.NSCount,
			ARCount: reqHeader.ARCount,
		}

		// Set QR to 1 (response)
		header.SetQR(1)
		header.SetOpcode(reqHeader.GetOpcode())
		header.SetRD(reqHeader.GetRD())

		if reqHeader.GetOpcode() == 0 { // No error
			header.SetRcode(0) // No error
		} else {
			header.SetRcode(4) // Not Implemented
		}

		// Set other fields as needed, e.g. Opcode, AA, etc.
		response, _ := header.MarshalBinary()

		q := Question{
			Name:  reQuestion.Name,
			Type:  1, // A record
			Class: 1, // IN class
		}
		qData, _ := q.MarshalBinary()
		response = append(response, qData...)

		answer := ResourceRecord{
			Name:     reQuestion.Name,
			Type:     1, // A record
			Class:    1, // IN class
			TTL:      60,
			RDLength: 4,
			RData:    []byte{127, 0, 0, 1}, // Example IP address
		}

		aData, _ := answer.MarshalBinary()
		response = append(response, aData...)

		// fmt.Printf("qData: (length %d)%v\n", len(qData), qData)
		// fmt.Printf("aData: (length %d)%v\n", len(aData), aData)

		// fmt.Printf("Sending response to %s: (length %d)%v\n", source, len(response), response)

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
