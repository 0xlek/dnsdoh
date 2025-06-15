package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
		log.Println("cache is not available")
		return nil
	}

	msg, err := c.client.Get(ctx, name).Bytes()

	if err != nil {
		log.Printf("miss cache for %s: %v", name, err)
		return nil
	}
	log.Printf("hit cache for %s", name)
	return msg
}

func (c *Cache) Set(ctx context.Context, name string, response *[]byte) {
	if !c.Available {
		log.Println("cache is not available, not setting for", name)
		return
	}

	err := c.client.Set(ctx, name, *response, c.expiry).Err()

	if err != nil {
		log.Printf("failed to cache %s: %v", name, err)
	} else {
		log.Printf("cached %s for %v", name, c.expiry)
	}
}

var sharedClient *http.Client
var packetPool = sync.Pool{
	New: func() interface{} {
		return new(dns.Msg)
	},
}

const udpBufferSize = 4096 // Max UDP DNS packet size, also used as a sanity limit for DoT messages

var udpBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, udpBufferSize)
		return &b
	},
}

// Fail2Ban Logging specific variables
var (
	fail2BanLogFile  *os.File
	fail2BanLogMutex sync.Mutex
	fail2BanEnabled  bool
)

func getUDPBuffer() *[]byte {
	return udpBufferPool.Get().(*[]byte)
}

func putUDPBuffer(buf *[]byte) {
	udpBufferPool.Put(buf)
}

func getPacket() *dns.Msg {
	return packetPool.Get().(*dns.Msg)
}

func putPacket(msg *dns.Msg) {
	if msg == nil {
		return
	}
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

func setupFail2BanLogger() {
	logPath := os.Getenv("FAIL2BAN_LOG_PATH")
	if logPath == "" {
		log.Println("FAIL2BAN_LOG_PATH not set. Fail2ban specific file logging disabled.")
		fail2BanEnabled = false
		return
	}

	var err error
	fail2BanLogFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening fail2ban log file %s: %v. Fail2ban specific file logging disabled.", logPath, err)
		fail2BanEnabled = false
		return
	}
	log.Printf("Fail2ban specific file logging enabled. Writing to %s", logPath)
	fail2BanEnabled = true
}

func writeFail2BanLog(clientAddr net.Addr, eventType string, details string) {
	if !fail2BanEnabled || fail2BanLogFile == nil {
		return
	}

	clientIP := "unknown"
	if addr, ok := clientAddr.(*net.UDPAddr); ok {
		clientIP = addr.IP.String()
	} else if addr, ok := clientAddr.(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	} else {
		host, _, err := net.SplitHostPort(clientAddr.String())
		if err == nil {
			clientIP = host
		} else {
			clientIP = clientAddr.String()
		}
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	logEntry := fmt.Sprintf("%s FAIL2BAN_DNS: Client [%s] Event: [%s] Details: [%s]\n",
		timestamp, clientIP, eventType, details)

	fail2BanLogMutex.Lock()
	defer fail2BanLogMutex.Unlock()
	if _, err := fail2BanLogFile.WriteString(logEntry); err != nil {
		log.Printf("CRITICAL: Error writing to fail2ban log file: %v.", err)
	}
}

// processQuery is the core DNS processing logic.
// It returns the response bytes, the parsed request message (for context, especially for error reporting by caller),
// and an error if processing failed at a point where the caller should send a DNS error.
// The caller is responsible for calling putPacket(requestMsgForContext) if it's not nil.
func processQuery(clientQueryBytes []byte, cache *Cache, clientAddr net.Addr) (responseBytes []byte, requestMsgForContext *dns.Msg, errForClient error) {
	requestMsg := getPacket() // Get packet from pool

	if err := requestMsg.Unpack(clientQueryBytes); err != nil {
		putPacket(requestMsg) // Return packet to pool as it's not valid
		return nil, nil, fmt.Errorf("failed to unpack client DNS query: %w", err)
	}

	// If unpack succeeded, requestMsg is valid.
	// Fail2Ban logging for REQUEST_RECEIVED is now done by the caller (handleClientUDP/handleDoTConnection)

	if len(requestMsg.Question) == 0 {
		// requestMsg is valid but has no questions. Return it for FORMERR context.
		return nil, requestMsg, fmt.Errorf("client DNS query has no questions")
	}

	cacheKey := requestMsg.Question[0].String()
	ctx := context.Background()
	var dohFinalResponseBytes []byte

	cachedResponse := cache.Get(ctx, cacheKey)

	if cachedResponse == nil {
		log.Printf("Cache miss for %s from %s", cacheKey, clientAddr.String())

		var errDoHQuery error
		// clientQueryBytes already has the original client's ID. DoH server should echo it.
		dohFinalResponseBytes, errDoHQuery = queryDoH(clientQueryBytes)
		if errDoHQuery != nil {
			log.Printf("Error querying DoH server for %s: %v.", cacheKey, errDoHQuery)
			return nil, requestMsg, fmt.Errorf("DoH query failed: %w", errDoHQuery)
		}

		// Ensure the DoH response ID matches the client's original query ID (requestMsg.Id).
		tempRespMsg := getPacket()
		if errUnpack := tempRespMsg.Unpack(dohFinalResponseBytes); errUnpack == nil {
			if tempRespMsg.Id != requestMsg.Id {
				log.Printf("Correcting ID mismatch. DoH Response ID: %d, Client Query ID: %d for %s", tempRespMsg.Id, requestMsg.Id, cacheKey)
				tempRespMsg.Id = requestMsg.Id
				if packed, errPack := tempRespMsg.Pack(); errPack == nil {
					dohFinalResponseBytes = packed
				} else {
					log.Printf("Failed to pack DoH response after ID correction for %s: %v. Using original DoH response.", cacheKey, errPack)
				}
			}
		} else {
			log.Printf("Failed to unpack DoH response for ID check for %s: %v. Using original DoH response.", cacheKey, errUnpack)
		}
		putPacket(tempRespMsg)

		dohFinalResponseBytes = updateTtl(dohFinalResponseBytes, cache)

		ipsToCatch := strings.Split(os.Getenv("IP_TO_CATCH"), ",")
		if len(ipsToCatch) > 0 && ipsToCatch[0] != "" {
			shouldReplace, errShouldReplace := shouldReplaceIP(dohFinalResponseBytes, ipsToCatch)
			if errShouldReplace != nil {
				log.Printf("Error checking if IP should be replaced for %s: %v", cacheKey, errShouldReplace)
			} else if shouldReplace {
				ipToReplaceWith := os.Getenv("IP_TO_REPLACE_WITH")
				log.Printf("Replacing IP in response for %s with %s", cacheKey, ipToReplaceWith)
				dohFinalResponseBytes = answerWith(dohFinalResponseBytes, ipToReplaceWith)
			}
		}
		cache.Set(ctx, cacheKey, &dohFinalResponseBytes)
	} else {
		log.Printf("Cache hit for %s from %s", cacheKey, clientAddr.String())
		dohFinalResponseBytes = SetMsgId(cachedResponse, requestMsg.Id)
	}

	if len(dohFinalResponseBytes) > 0 {
		go logHistory(dohFinalResponseBytes)
		return dohFinalResponseBytes, requestMsg, nil
	}

	log.Printf("No response to send for %s to %s after processing.", cacheKey, clientAddr.String())
	return nil, requestMsg, fmt.Errorf("no response generated")
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	setupFail2BanLogger()
	if fail2BanEnabled && fail2BanLogFile != nil {
		defer func() {
			log.Println("Closing fail2ban log file.")
			if err := fail2BanLogFile.Close(); err != nil {
				log.Printf("Error closing fail2ban log file: %v", err)
			}
		}()
	}

	httpClientTimeoutStr := os.Getenv("HTTP_CLIENT_TIMEOUT")
	httpClientTimeout, err := time.ParseDuration(httpClientTimeoutStr)
	if err != nil {
		log.Printf("Invalid or no HTTP_CLIENT_TIMEOUT set, using default 10s. Error: %v", err)
		httpClientTimeout = 10 * time.Second
	}
	sharedClient = &http.Client{Timeout: httpClientTimeout}

	redisAddr := os.Getenv("REDIS_ADDR")
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr, Password: "", DB: 0})
	cacheAvailable := true
	if _, err = rdb.Ping(context.Background()).Result(); err != nil {
		log.Printf("Redis ping failed: %v. Cache will be unavailable.", err)
		cacheAvailable = false
	}

	cachePeriodStr := os.Getenv("CACHE_PERIOD")
	cachePeriod, err := time.ParseDuration(cachePeriodStr)
	if err != nil {
		log.Fatalf("Error parsing CACHE_PERIOD: %v", err)
	}
	cache := Cache{client: rdb, expiry: cachePeriod, Available: cacheAvailable}

	// UDP Listener
	udpAddress := os.Getenv("ADDRESS")
	udpListenerActive := false
	if udpAddress != "" {
		pc, err := net.ListenPacket("udp", udpAddress)
		if err != nil {
			log.Fatalf("Error starting UDP listener on %s: %v\n", udpAddress, err)
		}
		defer pc.Close()
		log.Printf("Listening for DNS over UDP on %s\n", udpAddress)
		go func() {
			for {
				handleClientUDP(pc, &cache)
			}
		}()
		udpListenerActive = true
	} else {
		log.Println("ADDRESS (for UDP) not set. UDP listener disabled.")
	}

	// DoT Listener
	dotAddress := os.Getenv("DOT_ADDRESS")
	tlsCertPath := os.Getenv("TLS_CERT_PATH")
	tlsKeyPath := os.Getenv("TLS_KEY_PATH")
	dotListenerActive := false

	if dotAddress != "" && tlsCertPath != "" && tlsKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
		if err != nil {
			log.Fatalf("Error loading TLS certificate/key for DoT: %v", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		listener, err := tls.Listen("tcp", dotAddress, tlsConfig)
		if err != nil {
			log.Fatalf("Error starting DoT listener on %s: %v", dotAddress, err)
		}
		defer listener.Close()
		log.Printf("Listening for DNS over TLS (DoT) on %s\n", dotAddress)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					log.Printf("Error accepting DoT connection: %v", err)
					// Check if the listener was closed, e.g. net.ErrClosed
					if opError, ok := err.(*net.OpError); ok && opError.Err.Error() == "use of closed network connection" {
						log.Println("DoT listener closed, stopping accept loop.")
						return
					}
					continue
				}
				go handleDoTConnection(conn, &cache)
			}
		}()
		dotListenerActive = true
	} else {
		log.Println("DOT_ADDRESS, TLS_CERT_PATH, or TLS_KEY_PATH not set. DoT listener disabled.")
	}

	if os.Getenv("REFRESH_INSTANCE") == "true" {
		go httpCacheRefresh(&cache)
	}

	if !udpListenerActive && !dotListenerActive {
		log.Println("No DNS listeners configured. Exiting.")
		return
	}
	log.Println("DNS server started. Waiting for queries...")
	select {} // Block forever to keep main goroutine alive
}

func handleClientUDP(pc net.PacketConn, cache *Cache) {
	bufPtr := getUDPBuffer()
	defer putUDPBuffer(bufPtr)
	buf := *bufPtr

	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		log.Printf("Error reading UDP packet: %v\n", err)
		return
	}

	clientQueryBytes := buf[:n]
	var queryIdForLog uint16
	if n >= 2 {
		queryIdForLog = binary.BigEndian.Uint16(clientQueryBytes[0:2])
	}
	// Log every UDP request immediately for Fail2Ban
	writeFail2BanLog(addr, "REQUEST_RECEIVED_UDP", fmt.Sprintf("ID %d, Size %d", queryIdForLog, n))

	if n < 12 { // Minimum DNS header size
		log.Printf("Received undersized UDP packet (%d bytes) from %s. Dropping.", n, addr.String())
		// No DNS response can be formed from an undersized packet.
		// No Fail2Ban error log here as per new requirement.
		return
	}

	responseBytes, requestMsgForContext, processErr := processQuery(clientQueryBytes, cache, addr)
	defer putPacket(requestMsgForContext) // Always return the packet if processQuery returned one

	if processErr != nil {
		log.Printf("Error processing query from %s (UDP): %v", addr.String(), processErr)
		if requestMsgForContext != nil {
			if strings.Contains(processErr.Error(), "client DNS query has no questions") {
				sendDnsErrorResponse(pc, addr, requestMsgForContext, dns.RcodeFormatError)
			} else {
				sendDnsErrorResponse(pc, addr, requestMsgForContext, dns.RcodeServerFailure)
			}
		} else {
			// Unpack error inside processQuery (requestMsgForContext is nil)
			// No Fail2Ban error log here.
			sendMinimalDnsErrorResponse(pc, addr, queryIdForLog, dns.RcodeFormatError)
		}
		return
	}

	if len(responseBytes) > 0 {
		_, err = pc.WriteTo(responseBytes, addr)
		if err != nil {
			log.Printf("Error sending UDP response to client %s: %v\n", addr.String(), err)
		}
	} else {
		log.Printf("No response to send for UDP query from %s and no error reported by processQuery. Sending SERVFAIL.", addr.String())
		if requestMsgForContext != nil {
			sendDnsErrorResponse(pc, addr, requestMsgForContext, dns.RcodeServerFailure)
		} else {
			sendMinimalDnsErrorResponse(pc, addr, queryIdForLog, dns.RcodeServerFailure)
		}
	}
}

func handleDoTConnection(conn net.Conn, cache *Cache) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr()
	log.Printf("Accepted DoT connection from %s", clientAddr.String())

	for {
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(conn, lenBuf)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("Error reading length prefix from DoT client %s: %v", clientAddr.String(), err)
			} else {
				log.Printf("DoT client %s disconnected (reading length).", clientAddr.String())
			}
			return
		}
		msgLen := binary.BigEndian.Uint16(lenBuf)

		if msgLen == 0 {
			log.Printf("DoT client %s sent zero length message. Closing connection.", clientAddr.String())
			// No Fail2Ban error log here.
			return
		}
		if msgLen > udpBufferSize { // Reusing udpBufferSize as a practical limit
			log.Printf("DoT client %s sent oversized message (len %d). Closing connection.", clientAddr.String(), msgLen)
			// No Fail2Ban error log here.
			return
		}

		queryBytes := make([]byte, msgLen)
		_, err = io.ReadFull(conn, queryBytes)
		if err != nil {
			log.Printf("Error reading message body from DoT client %s: %v", clientAddr.String(), err)
			return
		}

		var queryIdForLog uint16
		if msgLen >= 2 {
			queryIdForLog = binary.BigEndian.Uint16(queryBytes[0:2])
		}
		// Log every DoT request immediately for Fail2Ban
		writeFail2BanLog(clientAddr, "REQUEST_RECEIVED_DOT", fmt.Sprintf("ID %d, Size %d", queryIdForLog, msgLen))

		responseBytes, requestMsgForContext, processErr := processQuery(queryBytes, cache, clientAddr)
		defer putPacket(requestMsgForContext) // Always return the packet

		var finalResponseBytes []byte
		var packErr error

		if processErr != nil {
			log.Printf("Error processing query from %s (DoT): %v", clientAddr.String(), processErr)
			errRespMsg := getPacket()
			if requestMsgForContext != nil {
				if strings.Contains(processErr.Error(), "client DNS query has no questions") {
					errRespMsg.SetRcode(requestMsgForContext, dns.RcodeFormatError)
				} else {
					errRespMsg.SetRcode(requestMsgForContext, dns.RcodeServerFailure)
				}
			} else {
				log.Printf("Cannot form DNS error for DoT client %s due to severe unpack error: %v", clientAddr.String(), processErr)
				// No Fail2Ban error log here.
				putPacket(errRespMsg)
				return // Close connection
			}
			finalResponseBytes, packErr = errRespMsg.Pack()
			putPacket(errRespMsg)
			if packErr != nil {
				log.Printf("Error packing DNS error response for DoT client %s: %v", clientAddr.String(), packErr)
				return
			}
		} else if len(responseBytes) > 0 {
			finalResponseBytes = responseBytes
		} else {
			log.Printf("No response to send for DoT query from %s and no error reported. Sending SERVFAIL.", clientAddr.String())
			errRespMsg := getPacket()
			if requestMsgForContext != nil {
				errRespMsg.SetRcode(requestMsgForContext, dns.RcodeServerFailure)
			} else {
				log.Printf("Cannot form DNS error for DoT client %s (unexpected no response, no requestMsg)", clientAddr.String())
				// No Fail2Ban error log here.
				putPacket(errRespMsg)
				return
			}
			finalResponseBytes, packErr = errRespMsg.Pack()
			putPacket(errRespMsg)
			if packErr != nil {
				log.Printf("Error packing unexpected SERVFAIL DNS error response for DoT client %s: %v", clientAddr.String(), packErr)
				return
			}
		}

		if len(finalResponseBytes) > 0 {
			respLenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(respLenBuf, uint16(len(finalResponseBytes)))
			if _, err = conn.Write(respLenBuf); err != nil {
				log.Printf("Error writing response length to DoT client %s: %v", clientAddr.String(), err)
				return
			}
			if _, err = conn.Write(finalResponseBytes); err != nil {
				log.Printf("Error writing response body to DoT client %s: %v", clientAddr.String(), err)
				return
			}
		}
		// Loop for next query on this connection
	}
}

func sendMinimalDnsErrorResponse(pc net.PacketConn, raddr net.Addr, queryID uint16, rcode int) {
	errResp := getPacket()
	defer putPacket(errResp)

	errResp.Id = queryID
	errResp.Response = true
	errResp.Rcode = rcode

	packedErrResp, err := errResp.Pack()
	if err != nil {
		log.Printf("Error packing minimal DNS error response (rcode %d) for query ID %d: %v", rcode, queryID, err)
		return
	}

	_, err = pc.WriteTo(packedErrResp, raddr)
	if err != nil {
		log.Printf("Error sending minimal DNS error response (rcode %d) to %s for query ID %d: %v", rcode, raddr.String(), queryID, err)
	} else {
		log.Printf("Sent minimal DNS error response (rcode %d) to %s for query ID %d", rcode, raddr.String(), queryID)
		// No Fail2Ban error log here.
	}
}

func sendDnsErrorResponse(pc net.PacketConn, raddr net.Addr, clientQuery *dns.Msg, rcode int) {
	errResp := getPacket()
	defer putPacket(errResp)

	errResp.SetRcode(clientQuery, rcode)

	packedErrResp, err := errResp.Pack()
	queryName := "[unknown question]"
	// queryID := clientQuery.Id // clientQuery.Id is already set by SetRcode
	if len(clientQuery.Question) > 0 {
		queryName = clientQuery.Question[0].String()
	}

	if err != nil {
		log.Printf("Error packing DNS error response (rcode %d) for %s: %v", rcode, queryName, err)
		return
	}

	_, err = pc.WriteTo(packedErrResp, raddr)
	if err != nil {
		log.Printf("Error sending DNS error response (rcode %d) to %s for %s: %v", rcode, raddr.String(), queryName, err)
	} else {
		log.Printf("Sent DNS error response (rcode %d) to %s for %s", rcode, raddr.String(), queryName)
		// No Fail2Ban error log here.
	}
}

func SetMsgId(msg []byte, id uint16) []byte {
	packet := getPacket()
	defer putPacket(packet)

	err := packet.Unpack(msg)
	if err != nil {
		log.Printf("SetMsgId: failed to unpack message: %v. Returning original message.", err)
		return msg
	}

	packet.Id = id
	packed, err := packet.Pack()
	if err != nil {
		log.Printf("SetMsgId: failed to pack message: %v. Returning original message.", err)
		return msg
	}

	return packed
}

func queryDoH(dnsQuery []byte) ([]byte, error) {
	dohServerURL := os.Getenv("DOH_URL")
	if dohServerURL == "" {
		return nil, fmt.Errorf("DOH_URL not set")
	}
	encodedQuery := base64.RawURLEncoding.EncodeToString(dnsQuery)

	req, err := http.NewRequest("GET", dohServerURL+"?dns="+encodedQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DoH request: %w", err)
	}

	req.Header.Set("Accept", "application/dns-message")
	resp, err := sharedClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Try to read body for more info
		return nil, fmt.Errorf("DoH request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}
	return buf.Bytes(), nil
}

func updateTtl(msgBytes []byte, c *Cache) []byte {
	packet := getPacket()
	defer putPacket(packet)

	err := packet.Unpack(msgBytes)
	if err != nil {
		log.Printf("updateTtl: failed to unpack message: %v. Returning original message.", err)
		return msgBytes
	}

	ttl := uint32(c.expiry.Seconds())

	for i := range packet.Answer {
		if packet.Answer[i] != nil && packet.Answer[i].Header() != nil {
			packet.Answer[i].Header().Ttl = ttl
		}
	}
	for i := range packet.Ns {
		if packet.Ns[i] != nil && packet.Ns[i].Header() != nil {
			packet.Ns[i].Header().Ttl = ttl
		}
	}

	data, err := packet.Pack()
	if err != nil {
		log.Printf("updateTtl: failed to pack message: %v. Returning original message.", err)
		return msgBytes
	}
	return data
}

func answerWith(msgBytes []byte, ip string) []byte {
	packet := getPacket()
	defer putPacket(packet)

	err := packet.Unpack(msgBytes)
	if err != nil {
		log.Printf("answerWith: failed to unpack message: %v. Returning original message.", err)
		return msgBytes
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Printf("Invalid custom IP address for answerWith: %s. Returning original message.", ip)
		return msgBytes
	}
	parsedIPv4 := parsedIP.To4()
	if parsedIPv4 == nil {
		log.Printf("Custom IP address is not an IPv4 address: %s. Returning original message.", ip)
		return msgBytes
	}

	for i, answer := range packet.Answer {
		if a, ok := answer.(*dns.A); ok {
			a.A = parsedIPv4
			packet.Answer[i] = a
		}
	}

	packed, err := packet.Pack()
	if err != nil {
		log.Printf("answerWith: failed to pack message: %v. Returning original message.", err)
		return msgBytes
	}
	return packed
}

func shouldReplaceIP(rawDNSResponse []byte, ipsToCheck []string) (bool, error) {
	msg := getPacket()
	defer putPacket(msg)

	err := msg.Unpack(rawDNSResponse)
	if err != nil {
		return false, fmt.Errorf("failed to unpack DNS message for shouldReplaceIP: %w", err)
	}

	ipMap := make(map[string]struct{})
	for _, ipStr := range ipsToCheck {
		trimmedIP := strings.TrimSpace(ipStr)
		if trimmedIP == "" {
			continue
		}
		parsedIP := net.ParseIP(trimmedIP)
		if parsedIP == nil {
			log.Printf("Invalid IP address in IP_TO_CATCH list: %v", trimmedIP)
			continue
		}
		ipMap[parsedIP.String()] = struct{}{}
	}

	if len(ipMap) == 0 {
		return false, nil
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
	mux := http.NewServeMux()

	recordHandler := func(w http.ResponseWriter, req *http.Request) {
		wg.Add(1)
		defer wg.Done()

		q := req.URL.Query()
		name := q.Get("name")
		qtypeStr := strings.ToUpper(q.Get("type"))

		if name == "" || qtypeStr == "" {
			log.Println("CacheRefresh: Invalid url (name or type missing), cache refresh skipped.")
			http.Error(w, "Invalid parameters: name and type are required", http.StatusBadRequest)
			return
		}

		msg := getPacket()
		defer putPacket(msg)

		intQType, err := stringToType(qtypeStr)
		if err != nil {
			log.Printf("CacheRefresh: Wrong query type '%s': %v", qtypeStr, err)
			http.Error(w, fmt.Sprintf("Unsupported query type: %s", qtypeStr), http.StatusBadRequest)
			return
		}

		fqdnName := dns.Fqdn(name)
		msg.SetQuestion(fqdnName, intQType)
		msg.Id = dns.Id()
		msg.RecursionDesired = true

		packedMsg, err := msg.Pack()
		if err != nil {
			log.Printf("CacheRefresh: Could not pack query msg for %s/%s: %v", name, qtypeStr, err)
			http.Error(w, "Internal server error: failed to pack query", http.StatusInternalServerError)
			return
		}

		cacheKey := fmt.Sprintf("%s\t%s\t%s", fqdnName, "IN", qtypeStr) // Class IN assumed
		log.Printf("CacheRefresh: Attempting to refresh cache for key: %s (query: %s %s)", cacheKey, name, qtypeStr)

		dohResponse, err := queryDoH(packedMsg)
		if err != nil {
			log.Printf("CacheRefresh: Failed to query DoH for %s/%s: %v", name, qtypeStr, err)
			http.Error(w, "Internal server error: DoH query failed", http.StatusInternalServerError)
			return
		}

		dohResponse = updateTtl(dohResponse, cache)
		ipsToCatch := strings.Split(os.Getenv("IP_TO_CATCH"), ",")
		if len(ipsToCatch) > 0 && ipsToCatch[0] != "" {
			shouldReplace, errShouldReplace := shouldReplaceIP(dohResponse, ipsToCatch)
			if errShouldReplace != nil {
				log.Printf("CacheRefresh: Error checking IP replacement for %s: %v", name, errShouldReplace)
			} else if shouldReplace {
				ipToReplaceWith := os.Getenv("IP_TO_REPLACE_WITH")
				log.Printf("CacheRefresh: Replacing IP for %s with %s", name, ipToReplaceWith)
				dohResponse = answerWith(dohResponse, ipToReplaceWith)
			}
		}

		ctx := context.Background()
		cache.Set(ctx, cacheKey, &dohResponse)
		log.Printf("CacheRefresh: Cache updated for %s %s (key: %s)", name, qtypeStr, cacheKey)
		fmt.Fprintf(w, "Updated successfully %s %s", name, qtypeStr)
	}
	mux.HandleFunc("/refresh", recordHandler)

	listenAddr := "0.0.0.0:8083"
	server := &http.Server{Addr: listenAddr, Handler: mux}
	log.Printf("HTTP cache refresh server listening on %s\n", listenAddr)

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Printf("HTTP cache refresh server ListenAndServe error: %v.", err)
	} else if err == http.ErrServerClosed {
		log.Println("HTTP cache refresh server was closed.")
	}

	log.Println("HTTP cache refresh server stopped. Waiting for active handlers...")
	wg.Wait()
	log.Println("All active handlers for cache refresh server completed.")
}

func stringToType(qtype string) (uint16, error) {
	val, ok := dns.StringToType[strings.ToUpper(qtype)]
	if !ok {
		return 0, fmt.Errorf("unsupported query type: %s", qtype)
	}
	return val, nil
}

func logHistory(msgBytes []byte) {
	historyLogURL := os.Getenv("HISTORY_URL")
	if historyLogURL == "" {
		return
	}

	packet := getPacket()
	defer putPacket(packet)

	err := packet.Unpack(msgBytes)
	if err != nil {
		log.Printf("logHistory: Failed to unpack message: %v", err)
		return
	}

	if len(packet.Question) == 0 {
		log.Println("logHistory: No questions in DNS message to log.")
		return
	}

	question := packet.Question[0]
	qname := question.Name
	qtype := dns.TypeToString[question.Qtype]

	// Construct URL carefully
	targetURL, err := url.Parse(historyLogURL)
	if err != nil {
		log.Printf("logHistory: Invalid HISTORY_URL '%s': %v", historyLogURL, err)
		return
	}
	queryValues := targetURL.Query()
	queryValues.Set("name", qname)
	queryValues.Set("type", qtype)
	targetURL.RawQuery = queryValues.Encode()

	req, err := http.NewRequest("GET", targetURL.String(), nil)
	if err != nil {
		log.Printf("logHistory: Could not build request for logging %s %s: %v", qname, qtype, err)
		return
	}

	// Use a client with a timeout for logging to prevent indefinite hangs
	loggingClient := &http.Client{Timeout: 5 * time.Second} // Short timeout for logging
	resp, err := loggingClient.Do(req)
	if err != nil {
		log.Printf("logHistory: Failed to log to history for %s %s: %v", qname, qtype, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("logHistory: Unexpected status code %d while logging %s %s to history", resp.StatusCode, qname, qtype)
	} else {
		log.Printf("Logged to history: %s %s", qname, qtype)
	}
}
