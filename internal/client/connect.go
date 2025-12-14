package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
)

// ConnectClient implements the UDP-to-HTTP/2 wrapper for game clients.
// It listens on a local UDP port and forwards packets to the proxy via HTTP/2.
type ConnectClient struct {
	TunnelID   string // The tunnel ID to connect to
	LocalAddr  string // Local UDP address to listen on (e.g., "localhost:25566")
	ProxyAddr  string // Proxy server address (e.g., "https://proxy.tunn.to:8443")
	SkipVerify bool   // Skip TLS certificate verification
	httpClient *http.Client
	udpConn    *net.UDPConn
	sessions   map[string]*udpSession // Track active UDP "sessions" by source address
	sessionsMu sync.RWMutex
}

// udpSession tracks a UDP "connection" (really just a source address we're routing to)
type udpSession struct {
	sourceAddr   *net.UDPAddr
	lastSeen     time.Time
	responseChan chan []byte
}

// Run starts the UDP listener and forwards packets to the proxy
func (c *ConnectClient) Run(ctx context.Context) error {
	// Create HTTP/2 client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.SkipVerify,
		},
		// Force HTTP/2
		ForceAttemptHTTP2: true,
	}
	c.httpClient = &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	// Initialize sessions map
	c.sessions = make(map[string]*udpSession)

	// Parse local UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", c.LocalAddr)
	if err != nil {
		return fmt.Errorf("invalid local address: %w", err)
	}

	// Start UDP listener
	c.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer c.udpConn.Close()

	common.LogInfo("UDP connect started",
		"local_addr", c.LocalAddr,
		"tunnel_id", c.TunnelID,
		"proxy_addr", c.ProxyAddr)

	// Start session cleanup goroutine
	go c.cleanupSessions(ctx)

	// Read UDP packets
	buf := make([]byte, 65535) // Max UDP packet size
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set read deadline to check context periodically
		c.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))

		n, sourceAddr, err := c.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Read deadline, check context
			}
			return fmt.Errorf("UDP read error: %w", err)
		}

		// Handle packet
		go c.handlePacket(ctx, sourceAddr, buf[:n])
	}
}

// handlePacket forwards a UDP packet to the proxy via HTTP/2
func (c *ConnectClient) handlePacket(ctx context.Context, sourceAddr *net.UDPAddr, data []byte) {
	// Get or create session for this source
	addrStr := sourceAddr.String()
	c.sessionsMu.Lock()
	session, exists := c.sessions[addrStr]
	if !exists {
		session = &udpSession{
			sourceAddr:   sourceAddr,
			lastSeen:     time.Now(),
			responseChan: make(chan []byte, 100),
		}
		c.sessions[addrStr] = session

		// Start response listener for this session
		go c.handleResponses(ctx, session)
	} else {
		session.lastSeen = time.Now()
	}
	c.sessionsMu.Unlock()

	// Forward packet to proxy via HTTP/2
	url := fmt.Sprintf("%s/udp/%s", c.ProxyAddr, c.TunnelID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		common.LogError("failed to create HTTP request", "error", err)
		return
	}

	// Add source address as header for response routing
	req.Header.Set("X-UDP-Source", addrStr)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		common.LogError("failed to send packet to proxy", "error", err, "source", addrStr)
		return
	}
	defer resp.Body.Close()

	// Read response (if any)
	responseData, err := io.ReadAll(resp.Body)
	if err != nil {
		common.LogError("failed to read response", "error", err)
		return
	}

	// If we got a response, send it back to the game client
	if len(responseData) > 0 {
		select {
		case session.responseChan <- responseData:
		default:
			common.LogError("response channel full, dropping packet", "source", addrStr)
		}
	}

	common.LogDebug("packet forwarded",
		"source", addrStr,
		"bytes_sent", len(data),
		"bytes_received", len(responseData))
}

// handleResponses sends response packets back to the game client
func (c *ConnectClient) handleResponses(ctx context.Context, session *udpSession) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-session.responseChan:
			_, err := c.udpConn.WriteToUDP(data, session.sourceAddr)
			if err != nil {
				common.LogError("failed to send response to client",
					"error", err,
					"dest", session.sourceAddr.String())
			} else {
				common.LogDebug("response sent to client",
					"dest", session.sourceAddr.String(),
					"bytes", len(data))
			}
		}
	}
}

// cleanupSessions removes stale UDP sessions
func (c *ConnectClient) cleanupSessions(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sessionsMu.Lock()
			now := time.Now()
			for addr, session := range c.sessions {
				// Remove sessions inactive for > 5 minutes
				if now.Sub(session.lastSeen) > 5*time.Minute {
					delete(c.sessions, addr)
					common.LogDebug("cleaned up stale session", "addr", addr)
				}
			}
			c.sessionsMu.Unlock()
		}
	}
}
