package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

type Cache struct {
	client *redis.Client
	expiry time.Duration
}

func (c *Cache) Get(name string) []byte {
	fmt.Println(name)
	msg, err := c.client.Get(context.Background(), name).Bytes()

	if err != nil {
		fmt.Println("miss cache ", name)
		return nil
	}

	return msg
}

func (c *Cache) Set(name string, response *[]byte) {
	err := c.client.Set(context.Background(), name, *response, c.expiry).Err()

	if err != nil {
		fmt.Println("failed to cache")
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	redisAddr := os.Getenv("REDIS_ADDR")

	rdb := redis.NewClient(&redis.Options{
		Password: "",
		Addr:     redisAddr,
		DB:       0,
	})

	_, err = rdb.Ping(context.Background()).Result()
	if err != nil {
		panic(err)
	}

	cache := Cache{client: rdb, expiry: 15 * time.Minute}

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
		handleClient(pc, &cache)
	}
}

func GetDnsQuery(msg []byte) string {
	packet := new(dns.Msg)
	err := packet.Unpack(msg)

	if err != nil {
		fmt.Println("failed to unpack buffer to a msg struct")
		return ""
	}

	if len(packet.Question) == 0 {
		return ""
	}

	question := packet.Question[0]
	return question.String()
}

func GetMsgId(msg []byte) uint16 {
	packet := new(dns.Msg)
	err := packet.Unpack(msg)

	if err != nil {
		fmt.Println("failed to unpack message")
		return 0
	}

	return packet.Id
}

func SetMsgId(msg []byte, id uint16) []byte {
	packet := new(dns.Msg)
	err := packet.Unpack(msg)

	if err != nil {
		return msg
	}

	packet.Id = id
	packed, err := packet.Pack()

	if err != nil {
		return msg
	}

	return packed
}

func handleClient(pc net.PacketConn, cache *Cache) {
	buf := make([]byte, 2048)
	n, addr, err := pc.ReadFrom(buf)

	if err != nil {
		fmt.Printf("Error reading UDP packet: %v\n", err)
		return
	}

	// Decode the DNS query
	dnsQuery := buf[:n]
	cacheKey := GetDnsQuery(buf)
	dohResponse := cache.Get(cacheKey)

	if dohResponse == nil {
		// Forward the DNS query to the DoH server
		dohResponse, err = queryDoH(dnsQuery)
		cache.Set(cacheKey, &dohResponse)
		if err != nil {
			fmt.Printf("Error querying DoH server: %v\n", err)
			return
		}
	} else {
		dohResponse = SetMsgId(dohResponse, GetMsgId(buf))
	}

	// Send the DoH response back to the client
	_, err = pc.WriteTo(dohResponse, addr)
	if err != nil {
		fmt.Printf("Error sending response to client: %v\n", err)
	}
}

func queryDoH(dnsQuery []byte) ([]byte, error) {
	dohServerURL := os.Getenv("DOH_URL")
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
