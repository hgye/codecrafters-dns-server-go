package main

import (
	"fmt"
	"net"
)

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
		handler := NewDNSHandler(receivedData)
		response, err := handler.Handle()
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
