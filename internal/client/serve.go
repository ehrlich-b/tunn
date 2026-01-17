package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// ServeClient is the new gRPC-based tunnel client for "tunn serve"
type ServeClient struct {
	TunnelID         string
	TargetURL        string
	ServerAddr       string
	AuthToken        string
	TunnelKey        string
	AllowedEmails    []string
	SkipVerify       bool
	Protocol         string // "http", "udp", or "both"
	UDPTargetAddress string // For UDP tunnels (e.g., "localhost:25565")

	// Reconnection settings
	MaxReconnectDelay time.Duration // Maximum delay between reconnects (default: 30s)
	InitialDelay      time.Duration // Initial delay for exponential backoff (default: 1s)

	// HTTP client settings
	HTTPTimeout time.Duration // Timeout for HTTP requests to local target (default: 30s)

	// UDP connection management
	udpConn *net.UDPConn
	udpMu   sync.Mutex
}

// Run establishes a gRPC tunnel with automatic reconnection on failure.
// It will retry with exponential backoff until the context is canceled.
func (s *ServeClient) Run(ctx context.Context) error {
	// Set defaults for reconnection settings
	if s.InitialDelay == 0 {
		s.InitialDelay = 1 * time.Second
	}
	if s.MaxReconnectDelay == 0 {
		s.MaxReconnectDelay = 30 * time.Second
	}

	delay := s.InitialDelay
	attempts := 0

	for {
		attempts++
		err := s.runOnce(ctx)

		// Check if context was canceled (intentional shutdown)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// If runOnce returned nil (clean shutdown), exit
		if err == nil {
			return nil
		}

		// Log the error and prepare for reconnection
		common.LogError("tunnel connection lost", "error", err, "attempt", attempts)

		// Wait before reconnecting
		common.LogInfo("reconnecting", "delay", delay.String())

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}

		// Exponential backoff with cap
		delay = delay * 2
		if delay > s.MaxReconnectDelay {
			delay = s.MaxReconnectDelay
		}
	}
}

// runOnce establishes a single gRPC tunnel connection and handles messages until disconnection
func (s *ServeClient) runOnce(ctx context.Context) error {
	// Create TLS credentials
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.SkipVerify,
	}
	creds := credentials.NewTLS(tlsConfig)

	// Connect to the gRPC server
	common.LogInfo("connecting to proxy", "server", s.ServerAddr)
	conn, err := grpc.NewClient(s.ServerAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Create tunnel service client
	client := pb.NewTunnelServiceClient(conn)

	// Establish the bidirectional stream
	stream, err := client.EstablishTunnel(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish tunnel: %w", err)
	}

	common.LogInfo("gRPC stream established")

	// Extract email from JWT (skip if no token)
	var creatorEmail string
	if s.AuthToken != "" {
		var err error
		creatorEmail, err = common.ExtractEmailFromJWT(s.AuthToken)
		if err != nil {
			return fmt.Errorf("failed to extract email from JWT: %w", err)
		}
		common.LogInfo("extracted creator email", "email", creatorEmail)
	} else {
		common.LogInfo("no auth token - using public mode")
		creatorEmail = ""
	}

	// Determine protocol (default to "http" if not specified)
	protocol := s.Protocol
	if protocol == "" {
		protocol = "http"
	}

	// Send registration message
	regMsg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:         s.TunnelID,
				TargetUrl:        s.TargetURL,
				AuthToken:        s.AuthToken,
				CreatorEmail:     creatorEmail,
				AllowedEmails:    s.AllowedEmails,
				TunnelKey:        s.TunnelKey,
				Protocol:         protocol,
				UdpTargetAddress: s.UDPTargetAddress,
			},
		},
	}

	if err := stream.Send(regMsg); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	common.LogInfo("registration sent", "tunnel_id", s.TunnelID, "target", s.TargetURL)

	// Wait for registration response
	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive registration response: %w", err)
	}

	regResp := msg.GetRegisterResponse()
	if regResp == nil {
		return fmt.Errorf("expected RegisterResponse, got %T", msg.Message)
	}

	if !regResp.Success {
		return fmt.Errorf("registration failed: %s", regResp.ErrorMessage)
	}

	common.LogInfo("tunnel registered successfully", "public_url", regResp.PublicUrl)
	fmt.Printf("%s -> %s\n", regResp.PublicUrl, s.TargetURL)

	// Start health check sender
	go s.sendHealthChecks(ctx, stream)

	// Enter message processing loop
	return s.processMessages(ctx, stream)
}

// processMessages handles incoming messages from the server
func (s *ServeClient) processMessages(ctx context.Context, stream pb.TunnelService_EstablishTunnelClient) error {
	for {
		select {
		case <-ctx.Done():
			common.LogInfo("context canceled, closing stream")
			return ctx.Err()
		default:
		}

		msg, err := stream.Recv()
		if err == io.EOF {
			common.LogInfo("server closed stream")
			return nil
		}
		if err != nil {
			return fmt.Errorf("stream receive error: %w", err)
		}

		switch m := msg.Message.(type) {
		case *pb.TunnelMessage_HttpRequest:
			// Handle HTTP request from proxy - make request to local target and send response
			go s.handleHttpRequest(stream, m.HttpRequest)

		case *pb.TunnelMessage_UdpPacket:
			// Handle UDP packet from proxy - forward to local UDP target and send response
			go s.handleUdpPacket(stream, m.UdpPacket)

		case *pb.TunnelMessage_HealthCheckResponse:
			// Calculate RTT
			rtt := time.Now().UnixMilli() - m.HealthCheckResponse.Timestamp
			common.LogDebug("health check response", "rtt_ms", rtt)

		default:
			common.LogInfo("unexpected message type", "type", fmt.Sprintf("%T", m))
		}
	}
}

// handleHttpRequest handles an HTTP request from the proxy, makes a request to the local target, and sends back the response
func (s *ServeClient) handleHttpRequest(stream pb.TunnelService_EstablishTunnelClient, httpReq *pb.HttpRequest) {
	common.LogDebug("http request received",
		"connection_id", httpReq.ConnectionId,
		"method", httpReq.Method,
		"path", httpReq.Path)

	// Build the target URL
	targetURL := s.TargetURL + httpReq.Path

	// Create HTTP request
	req, err := http.NewRequest(httpReq.Method, targetURL, bytes.NewReader(httpReq.Body))
	if err != nil {
		common.LogError("failed to create http request", "error", err)
		s.sendErrorResponse(stream, httpReq.ConnectionId, http.StatusBadGateway, "Failed to create request")
		return
	}

	// Copy headers
	for key, value := range httpReq.Headers {
		req.Header.Set(key, value)
	}

	// Make the request to local target
	timeout := s.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		common.LogError("failed to make http request to target", "error", err, "target", targetURL)
		s.sendErrorResponse(stream, httpReq.ConnectionId, http.StatusBadGateway, "Failed to reach local target")
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		common.LogError("failed to read response body", "error", err)
		s.sendErrorResponse(stream, httpReq.ConnectionId, http.StatusBadGateway, "Failed to read response")
		return
	}

	// Convert headers to map (join multi-value headers per HTTP spec)
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	// Send HttpResponse back
	httpResp := &pb.HttpResponse{
		ConnectionId: httpReq.ConnectionId,
		StatusCode:   int32(resp.StatusCode),
		Headers:      headers,
		Body:         body,
	}

	msg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_HttpResponse{
			HttpResponse: httpResp,
		},
	}

	if err := stream.Send(msg); err != nil {
		common.LogError("failed to send http response", "error", err)
		return
	}

	common.LogDebug("http response sent",
		"connection_id", httpReq.ConnectionId,
		"status", resp.StatusCode,
		"body_size", len(body))
}

// sendErrorResponse sends an error response back to the proxy
func (s *ServeClient) sendErrorResponse(stream pb.TunnelService_EstablishTunnelClient, connectionID string, statusCode int, message string) {
	httpResp := &pb.HttpResponse{
		ConnectionId: connectionID,
		StatusCode:   int32(statusCode),
		Headers: map[string]string{
			"Content-Type": "text/plain",
		},
		Body: []byte(message),
	}

	msg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_HttpResponse{
			HttpResponse: httpResp,
		},
	}

	if err := stream.Send(msg); err != nil {
		common.LogError("failed to send error response", "error", err)
	}
}

// handleUdpPacket handles a UDP packet from the proxy, forwards it to the local UDP target, and sends back the response
func (s *ServeClient) handleUdpPacket(stream pb.TunnelService_EstablishTunnelClient, udpPkt *pb.UdpPacket) {
	common.LogDebug("udp packet received",
		"tunnel_id", udpPkt.TunnelId,
		"source", udpPkt.SourceAddress,
		"bytes", len(udpPkt.Data))

	// Ensure we have a UDP connection
	s.udpMu.Lock()
	if s.udpConn == nil {
		// Create UDP connection to local target
		targetAddr, err := net.ResolveUDPAddr("udp", s.UDPTargetAddress)
		if err != nil {
			common.LogError("failed to resolve UDP target address", "error", err, "target", s.UDPTargetAddress)
			s.udpMu.Unlock()
			return
		}

		// Create a UDP connection (not bound to local address, will use any available port)
		conn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			common.LogError("failed to create UDP connection", "error", err, "target", s.UDPTargetAddress)
			s.udpMu.Unlock()
			return
		}

		s.udpConn = conn
		common.LogInfo("UDP connection established", "target", s.UDPTargetAddress)
	}
	conn := s.udpConn
	s.udpMu.Unlock()

	// Send packet to local UDP target
	_, err := conn.Write(udpPkt.Data)
	if err != nil {
		common.LogError("failed to send UDP packet to target", "error", err)
		return
	}

	common.LogDebug("udp packet sent to local target", "bytes", len(udpPkt.Data))

	// Wait for response with timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 65535) // Max UDP packet size
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout is OK for UDP - not all protocols are request-response
			common.LogDebug("udp read timeout (no response from target)")
			return
		}
		common.LogError("failed to read UDP response from target", "error", err)
		return
	}

	responseData := buf[:n]
	common.LogDebug("udp response received from local target", "bytes", n)

	// Send response back to proxy
	respPacket := &pb.UdpPacket{
		TunnelId:           udpPkt.TunnelId,
		SourceAddress:      udpPkt.DestinationAddress, // Swap: response goes back to original source
		DestinationAddress: udpPkt.SourceAddress,      // Swap: from our target back to original source
		Data:               responseData,
		FromClient:         true, // From client to proxy
		TimestampMs:        udpPkt.TimestampMs,
	}

	msg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_UdpPacket{
			UdpPacket: respPacket,
		},
	}

	if err := stream.Send(msg); err != nil {
		common.LogError("failed to send UDP response", "error", err)
		return
	}

	common.LogDebug("udp response sent to proxy", "bytes", len(responseData))
}

// sendHealthChecks periodically sends health check pings
func (s *ServeClient) sendHealthChecks(ctx context.Context, stream pb.TunnelService_EstablishTunnelClient) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			msg := &pb.TunnelMessage{
				Message: &pb.TunnelMessage_HealthCheck{
					HealthCheck: &pb.HealthCheck{
						Timestamp: time.Now().UnixMilli(),
					},
				},
			}

			if err := stream.Send(msg); err != nil {
				common.LogError("failed to send health check", "error", err)
				return
			}

			common.LogDebug("health check sent")
		}
	}
}
