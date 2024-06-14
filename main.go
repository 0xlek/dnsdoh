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
	"strings"
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
		log.Println("miss cache ", name)
		return nil
	}

	return msg
}

func (c *Cache) Set(name string, response *[]byte) {
	err := c.client.Set(context.Background(), name, *response, c.expiry).Err()

	if err != nil {
		log.Println("failed to cache")
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

	cachePeriod, err := time.ParseDuration(os.Getenv("CACHE_PERIOD"))
	if err != nil {
		panic(err)
	}
	cache := Cache{client: rdb, expiry: cachePeriod}

	udpAddress := os.Getenv("ADDRESS")
	// Listen for incoming UDP packets
	pc, err := net.ListenPacket("udp", udpAddress)
	if err != nil {
		log.Printf("Error starting UDP listener: %v\n", err)
		return
	}

	defer pc.Close()

	if os.Getenv("REFRESH_INSTANCE") == "true" {
		go httpCacheRefresh(&cache)
	}

	log.Printf("Listening on %s\n", udpAddress)
	for {
		handleClient(pc, &cache)
	}
}

func GetDnsQuery(msg []byte) string {
	packet := new(dns.Msg)
	err := packet.Unpack(msg)

	if err != nil {
		log.Println("failed to unpack buffer to a msg struct")
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
		log.Println("failed to unpack message")
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
	buf := make([]byte, 4096)
	n, addr, err := pc.ReadFrom(buf)

	if err != nil {
		log.Printf("Error reading UDP packet: %v\n", err)
		return
	}

	// Decode the DNS query
	dnsQuery := buf[:n]
	cacheKey := GetDnsQuery(buf)
	dohResponse := cache.Get(cacheKey)

	if dohResponse == nil {
		// Forward the DNS query to the DoH server
		dohResponse, err = queryDoH(dnsQuery)
		if err != nil {
			log.Printf("Error querying DoH server: %v\n", err)
			return
		}

		ips := strings.Split(os.Getenv("IP_TO_CATCH"), ",")
		shouldReplace, _ := shouldReplaceIP(dohResponse, ips)
		if shouldReplace {
			dohResponse = answerWith(dohResponse, os.Getenv("IP_TO_REPLACE_WITH"))
		}

		cache.Set(cacheKey, &dohResponse)
	} else {
		dohResponse = SetMsgId(dohResponse, GetMsgId(buf))
	}
	go logHistory(dohResponse)

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

func answerWith(msg []byte, ip string) []byte {
	packet := new(dns.Msg)
	err := packet.Unpack(msg)

	if err != nil {
		return msg
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Println("Invalid custom IP address:", ip)
		return msg
	}

	for i, answer := range packet.Answer {
		if a, ok := answer.(*dns.A); ok {
			a.A = parsedIP.To4()
			packet.Answer[i] = a
		}
	}

	packed, err := packet.Pack()
	if err != nil {
		return msg
	}

	return packed
}

func shouldReplaceIP(rawDNSResponse []byte, ipsToCheck []string) (bool, error) {
	// Parse the DNS message
	var msg dns.Msg
	err := msg.Unpack(rawDNSResponse)
	if err != nil {
		return false, fmt.Errorf("failed to unpack DNS message: %v", err)
	}

	// Convert the slice of IP addresses to a map for quick lookup
	ipMap := make(map[string]struct{})
	for _, ip := range ipsToCheck {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return false, fmt.Errorf("invalid IP address in the slice: %v", ip)
		}
		ipMap[parsedIP.String()] = struct{}{}
	}

	// Check if any answer contains an IP that matches one in the map
	for _, answer := range msg.Answer {
		if a, ok := answer.(*dns.A); ok {
			if _, exists := ipMap[a.A.String()]; exists {
				return true, nil
			}
		}
	}

	return false, nil
}

func httpCacheRefresh(cache *Cache) {
	recordHandler := func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		name := q.Get("name")
		qtype := q.Get("type")

		if name == "" || qtype == "" {
			log.Println("Invalid url, cache refresh skipped.")
			return
		}

		msg := new(dns.Msg)

		intQType, err := stringToType(qtype)
		if err != nil {
			log.Println("Wrong query type", err)
			return
		}
		// Set the DNS message header
		msg.SetQuestion(dns.Fqdn(name), intQType)

		// Optional: Set the message ID, recursion desired, etc.
		msg.Id = dns.Id()
		msg.RecursionDesired = true
		packedMsg, err := msg.Pack()
		if err != nil {
			log.Println("Could not pack the query msg", err)
			return
		}

		dohResponse, err := queryDoH(packedMsg)
		if err != nil {
			log.Println("Failed to query DoH ", err)
			return
		}

		ips := strings.Split(os.Getenv("IP_TO_CATCH"), ",")
		shouldReplace, _ := shouldReplaceIP(dohResponse, ips)
		if shouldReplace {
			dohResponse = answerWith(dohResponse, os.Getenv("IP_TO_REPLACE_WITH"))
		}

		cacheKey := GetDnsQuery(dohResponse)
		cache.Set(cacheKey, &dohResponse)
		log.Println("Updated successfully " + name)
		fmt.Fprintf(w, "Updated successfully %s", name)
	}

	http.HandleFunc("/refresh", recordHandler)

	log.Printf("Listening on %s\n", "0.0.0.0:8083")
	log.Fatal(http.ListenAndServe(":8083", nil))
}

func stringToType(qtype string) (uint16, error) {
	switch qtype {
	case "A":
		return dns.TypeA, nil
	case "AAAA":
		return dns.TypeAAAA, nil
	case "CNAME":
		return dns.TypeCNAME, nil
	case "MX":
		return dns.TypeMX, nil
	case "TXT":
		return dns.TypeTXT, nil
	case "NS":
		return dns.TypeNS, nil
	case "SOA":
		return dns.TypeSOA, nil
	case "PTR":
		return dns.TypePTR, nil
	default:
		return 0, fmt.Errorf("unsupported query type: %s", qtype)
	}
}

func logHistory(msg []byte) {
	packet := new(dns.Msg)
	err := packet.Unpack(msg)
	if err != nil {
		log.Println("Failed to unpack the message", err)
		return
	}

	if len(packet.Question) == 0 {
		log.Println("No questions in the DNS message")
		return
	}

	question := packet.Question[0]
	qname := question.Name
	qtype := dns.TypeToString[question.Qtype]

	historyLogURL := os.Getenv("HISTORY_URL")
	req, err := http.NewRequest("GET", historyLogURL+"?name="+qname+"&type="+qtype, nil)
	if err != nil {
		log.Println("Could not build request for logging", err)
		return
	}

	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		log.Println("Failed to log to history "+qname, err)
		return
	}
	log.Println("Logged to history " + qname)
}
