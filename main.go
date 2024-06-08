package main

import (
	"encoding/base64"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	udpAddress := os.Getenv("ADDRESS")
	// Listen for incoming UDP packets
	pc, err := net.ListenPacket("udp", udpAddress)
	if err != nil {
		fmt.Printf("Error starting UDP listener: %v\n", err)
		return
	}
	defer pc.Close()
	fmt.Printf("Listening on %s\n", udpAddress)

	for {
		handleClient(pc)
	}
}

func handleClient(pc net.PacketConn) {
	buf := make([]byte, 512)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		fmt.Printf("Error reading UDP packet: %v\n", err)
		return
	}

	// Decode the DNS query
	dnsQuery := buf[:n]

	// Forward the DNS query to the DoH server
	dohResponse, err := queryDoH(dnsQuery)
	if err != nil {
		fmt.Printf("Error querying DoH server: %v\n", err)
		return
	}

	// Send the DoH response back to the client
	_, err = pc.WriteTo(dohResponse, addr)
	if err != nil {
		fmt.Printf("Error sending response to client: %v\n", err)
	}
}

func queryDoH(dnsQuery []byte) ([]byte, error) {
	dohServerURL := os.Getenv("DOH_URL")
	fmt.Println("received request for", dnsQuery)
	// Encode the DNS query in Base64URL format
	encodedQuery := base64.RawURLEncoding.EncodeToString(dnsQuery)

	// Create the DoH request
	req, err := http.NewRequest("GET", dohServerURL+"?dns="+encodedQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DoH request: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read the DoH response
	dohResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %v", err)
	}

	return dohResponse, nil
}
