package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// MaxResponseBodySize is the maximum response body size from local targets (100 MB).
// Prevents memory exhaustion from large responses.
const MaxResponseBodySize = 100 * 1024 * 1024

// MaxConcurrentRequests is the maximum number of concurrent HTTP requests being processed.
// Prevents goroutine exhaustion from flood of requests.
const MaxConcurrentRequests = 100

// messageSender is the interface for sending tunnel messages.
// This allows for thread-safe sending and testing with mocks.
type messageSender interface {
	Send(msg *pb.TunnelMessage) error
}

// streamSender wraps a gRPC stream with a mutex to make Send() thread-safe.
// gRPC streams are NOT safe for concurrent Send() calls.
type streamSender struct {
	stream pb.TunnelService_EstablishTunnelClient
	mu     sync.Mutex
}

// Send sends a message on the stream in a thread-safe manner.
func (s *streamSender) Send(msg *pb.TunnelMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(msg)
}

// ServeClient is the new gRPC-based tunnel client for "tunn serve"
type ServeClient struct {
	TunnelID      string
	TargetURL     string
	ServerAddr    string
	AuthToken     string
	TunnelKey     string
	AllowedEmails []string
	SkipVerify    bool

	// Reconnection settings
	MaxReconnectDelay time.Duration // Maximum delay between reconnects (default: 30s)
	InitialDelay      time.Duration // Initial delay for exponential backoff (default: 1s)

	// HTTP client settings
	HTTPTimeout time.Duration // Timeout for HTTP requests to local target (default: 30s)
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
		start := time.Now()
		err := s.runOnce(ctx)
		duration := time.Since(start)

		// Check if context was canceled (intentional shutdown)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// If runOnce returned nil (clean shutdown), exit
		if err == nil {
			return nil
		}

		// Reset backoff if connection was stable for at least 30 seconds
		if duration > 30*time.Second {
			delay = s.InitialDelay
			attempts = 1
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

	// Connect to the gRPC server with keepalive
	common.LogInfo("connecting to proxy", "server", s.ServerAddr)
	conn, err := grpc.NewClient(s.ServerAddr,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second, // Ping server every 10s
			Timeout:             5 * time.Second,  // Wait 5s for pong
			PermitWithoutStream: true,             // Ping even without active streams
		}),
	)
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

	// Send registration message
	regMsg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:      s.TunnelID,
				TargetUrl:     s.TargetURL,
				AuthToken:     s.AuthToken,
				CreatorEmail:  creatorEmail,
				AllowedEmails: s.AllowedEmails,
				TunnelKey:     s.TunnelKey,
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

	// Warn if tunnel is open to the internet (no --allow specified)
	if len(s.AllowedEmails) == 0 {
		fmt.Println("Warning: Tunnel is open to the internet. Use --allow to restrict access.")
	}

	// Wrap stream with mutex for thread-safe sends
	sender := &streamSender{stream: stream}

	// Create a derived context that we cancel when this connection ends
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel() // Cancel health check goroutine when connection ends

	// Start health check sender
	go s.sendHealthChecks(connCtx, sender)

	// Enter message processing loop
	return s.processMessages(ctx, stream, sender)
}

// processMessages handles incoming messages from the server
func (s *ServeClient) processMessages(ctx context.Context, stream pb.TunnelService_EstablishTunnelClient, sender messageSender) error {
	// Semaphore to limit concurrent HTTP request handlers
	sem := make(chan struct{}, MaxConcurrentRequests)

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
			// Acquire semaphore slot (blocks if at capacity)
			select {
			case sem <- struct{}{}:
				// Got a slot, spawn handler
				go func(req *pb.HttpRequest) {
					defer func() { <-sem }() // Release slot when done
					s.handleHttpRequest(sender, req)
				}(m.HttpRequest)
			case <-ctx.Done():
				common.LogInfo("context canceled while waiting for semaphore")
				return ctx.Err()
			}

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
func (s *ServeClient) handleHttpRequest(sender messageSender, httpReq *pb.HttpRequest) {
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
		s.sendErrorResponse(sender, httpReq.ConnectionId, http.StatusBadGateway, "Failed to create request")
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
		s.sendErrorResponse(sender, httpReq.ConnectionId, http.StatusBadGateway, "Failed to reach local target")
		return
	}
	defer resp.Body.Close()

	// Read response body with size limit to prevent memory exhaustion
	// Read one extra byte to detect if body exceeds limit
	limitedBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodySize+1))
	if err != nil {
		common.LogError("failed to read response body", "error", err)
		s.sendErrorResponse(sender, httpReq.ConnectionId, http.StatusBadGateway, "Failed to read response")
		return
	}
	if int64(len(limitedBody)) > MaxResponseBodySize {
		common.LogError("response body too large", "size", len(limitedBody), "max", MaxResponseBodySize)
		s.sendErrorResponse(sender, httpReq.ConnectionId, http.StatusBadGateway, "Response too large")
		return
	}
	body := limitedBody

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

	if err := sender.Send(msg); err != nil {
		common.LogError("failed to send http response", "error", err)
		return
	}

	common.LogDebug("http response sent",
		"connection_id", httpReq.ConnectionId,
		"status", resp.StatusCode,
		"body_size", len(body))
}

// sendErrorResponse sends an error response back to the proxy
func (s *ServeClient) sendErrorResponse(sender messageSender, connectionID string, statusCode int, message string) {
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

	if err := sender.Send(msg); err != nil {
		common.LogError("failed to send error response", "error", err)
	}
}

// sendHealthChecks periodically sends health check pings
func (s *ServeClient) sendHealthChecks(ctx context.Context, sender messageSender) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Send initial health check immediately
	s.sendOneHealthCheck(sender)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sendOneHealthCheck(sender)
		}
	}
}

// sendOneHealthCheck sends a single health check message
func (s *ServeClient) sendOneHealthCheck(sender messageSender) {
	msg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_HealthCheck{
			HealthCheck: &pb.HealthCheck{
				Timestamp: time.Now().UnixMilli(),
			},
		},
	}

	if err := sender.Send(msg); err != nil {
		common.LogError("failed to send health check", "error", err)
		return
	}

	common.LogDebug("health check sent")
}
