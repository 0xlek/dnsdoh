package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

type Cache struct {
	client    *redis.Client
	expiry    time.Duration
	Available bool
}

func (c *Cache) Get(ctx context.Context, name string) []byte {
	if !c.Available {
		fmt.Println("cache is not available")
		return nil
	}

	msg, err := c.client.Get(ctx, name).Bytes()

	if err != nil {
		log.Println("miss cache ", name)
		return nil
	}

	return msg
}

func (c *Cache) Set(ctx context.Context, name string, response *[]byte) {
	if !c.Available {
		fmt.Println("cache is not available")
		return
	}

	err := c.client.Set(ctx, name, *response, c.expiry).Err()

	if err != nil {
		log.Println("failed to cache")
	}
}

var sharedClient = &http.Client{} // Shared HTTP client
var packetPool = sync.Pool{
	New: func() interface{} {
		return new(dns.Msg)
	},
}

func getPacket() *dns.Msg {
	return packetPool.Get().(*dns.Msg)
}

func putPacket(msg *dns.Msg) {
	resetPacket(msg)
	packetPool.Put(msg)
}

func resetPacket(msg *dns.Msg) {
	msg.MsgHdr = dns.MsgHdr{}
	msg.Compress = false
	msg.Question = nil
	msg.Answer = nil
	msg.Ns = nil
	msg.Extra = nil
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

	cacheAvailable := true
	_, err = rdb.Ping(context.Background()).Result()
	if err != nil {
		fmt.Println(err)
		cacheAvailable = false
	}

	cachePeriod, err := time.ParseDuration(os.Getenv("CACHE_PERIOD"))
	if err != nil {
		panic(err)
	}
	cache := Cache{client: rdb, expiry: cachePeriod, Available: cacheAvailable}

	udpAddress := os.Getenv("ADDRESS")
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
	packet := getPacket()
	defer putPacket(packet)

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
	packet := getPacket()
	defer putPacket(packet)

	err := packet.Unpack(msg)
	if err != nil {
		log.Println("failed to unpack message")
		return 0
	}

	return packet.Id
}

func SetMsgId(msg []byte, id uint16) []byte {
	packet := getPacket()
	defer putPacket(packet)

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

	dnsQuery := buf[:n]
	cacheKey := GetDnsQuery(buf)
	ctx := context.Background()
	dohResponse := cache.Get(ctx, cacheKey)

	if dohResponse == nil {
		dohResponse, err = queryDoH(dnsQuery)
		dohResponse = updateTtl(dohResponse, cache)
		if err != nil {
			log.Printf("Error querying DoH server: %v\n", err)
			return
		}

		ips := strings.Split(os.Getenv("IP_TO_CATCH"), ",")
		shouldReplace, _ := shouldReplaceIP(dohResponse, ips)
		if shouldReplace {
			dohResponse = answerWith(dohResponse, os.Getenv("IP_TO_REPLACE_WITH"))
		}

		cache.Set(ctx, cacheKey, &dohResponse)
	} else {
		dohResponse = SetMsgId(dohResponse, GetMsgId(buf))
	}
	go logHistory(dohResponse)

	_, err = pc.WriteTo(dohResponse, addr)
	if err != nil {
		fmt.Printf("Error sending response to client: %v\n", err)
	}
}

func queryDoH(dnsQuery []byte) ([]byte, error) {
	dohServerURL := os.Getenv("DOH_URL")
	encodedQuery := base64.RawURLEncoding.EncodeToString(dnsQuery)

	req, err := http.NewRequest("GET", dohServerURL+"?dns="+encodedQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DoH request: %v", err)
	}

	req.Header.Set("Accept", "application/dns-message")
	resp, err := sharedClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %v", err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %v", err)
	}
	dohResponse := buf.Bytes()

	return dohResponse, nil
}

func updateTtl(msg []byte, c *Cache) []byte {
	packet := new(dns.Msg)
	err := packet.Unpack(msg)

	if err != nil {
		return msg
	}
	ttl := uint32(c.expiry.Seconds())

	for _, answer := range packet.Answer {
		if a, ok := answer.(*dns.A); ok {
			a.Hdr.Ttl = ttl
		}
	}

	data, err := packet.Pack()
	if err != nil {
		log.Println("failed to update ttl of the message")
		return msg
	}

	return data

}

func answerWith(msg []byte, ip string) []byte {
	packet := getPacket()
	defer putPacket(packet)

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
	var msg dns.Msg
	err := msg.Unpack(rawDNSResponse)
	if err != nil {
		return false, fmt.Errorf("failed to unpack DNS message: %v", err)
	}

	ipMap := make(map[string]struct{})
	for _, ip := range ipsToCheck {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return false, fmt.Errorf("invalid IP address in the slice: %v", ip)
		}
		ipMap[parsedIP.String()] = struct{}{}
	}

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
	var wg sync.WaitGroup
	recordHandler := func(w http.ResponseWriter, req *http.Request) {
		wg.Add(1)
		defer wg.Done()

		q := req.URL.Query()
		name := q.Get("name")
		qtype := q.Get("type")

		if name == "" || qtype == "" {
			log.Println("Invalid url, cache refresh skipped.")
			return
		}

		msg := getPacket()
		defer putPacket(msg)

		intQType, err := stringToType(qtype)
		if err != nil {
			log.Println("Wrong query type", err)
			return
		}

		msg.SetQuestion(dns.Fqdn(name), intQType)
		msg.Id = dns.Id()
		msg.RecursionDesired = true
		packedMsg, err := msg.Pack()
		if err != nil {
			log.Println("Could not pack the query msg", err)
			return
		}

		dohResponse, err := queryDoH(packedMsg)
		dohResponse = updateTtl(dohResponse, cache)

		if err != nil {
			log.Println("Failed to query DoH ", err)
			return
		}

		ips := strings.Split(os.Getenv("IP_TO_CATCH"), ",")
		shouldReplace, _ := shouldReplaceIP(dohResponse, ips)
		if shouldReplace {
			dohResponse = answerWith(dohResponse, os.Getenv("IP_TO_REPLACE_WITH"))
		}

		ctx := context.Background()
		cacheKey := GetDnsQuery(dohResponse)
		cache.Set(ctx, cacheKey, &dohResponse)
		log.Println("Updated successfully " + name)
		fmt.Fprintf(w, "Updated successfully %s", name)
	}

	http.HandleFunc("/refresh", recordHandler)

	log.Printf("Listening on %s\n", "0.0.0.0:8083")
	log.Fatal(http.ListenAndServe(":8083", nil))

	wg.Wait()
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
	case "HTTPS":
		return dns.TypeHTTPS, nil
	default:
		return 0, fmt.Errorf("unsupported query type: %s", qtype)
	}
}

func logHistory(msg []byte) {
	historyLogURL := os.Getenv("HISTORY_URL")
	if historyLogURL == "" {
		return
	}

	packet := getPacket()
	defer putPacket(packet)

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

	req, err := http.NewRequest("GET", historyLogURL+"?name="+qname+"&type="+qtype, nil)
	if err != nil {
		log.Println("Could not build request for logging", err)
		return
	}

	resp, err := sharedClient.Do(req)
	if err != nil {
		log.Println("Failed to log to history "+qname, err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Unexpected status code while logging to history %s: %d", qname, resp.StatusCode)
	}

	log.Println("Logged to history " + qname)
}
