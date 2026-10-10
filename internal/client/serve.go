package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// MaxResponseBodySize is the maximum response body size from local targets (100 MB).
// Prevents memory exhaustion from large responses.
const MaxResponseBodySize = 100 * 1024 * 1024

// MaxConcurrentRequests is the maximum number of concurrent HTTP requests being processed.
// Prevents goroutine exhaustion from flood of requests.
const MaxConcurrentRequests = common.MaxConcurrentConnections

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

type permanentTunnelError struct {
	err  error
	kind FailureKind
}

func (e *permanentTunnelError) Error() string { return e.err.Error() }
func (e *permanentTunnelError) Unwrap() error { return e.err }

// Send sends a message on the stream in a thread-safe manner.
func (s *streamSender) Send(msg *pb.TunnelMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(msg)
}

// ServeClient is the new gRPC-based tunnel client for "tunn serve"
type ServeClient struct {
	TunnelID           string
	TargetURL          string
	DisplayTarget      string // Optional redacted target shown in the CLI
	PublicPath         string // Optional path appended to the registered public URL
	UpstreamPath       string // Optional path replacing PublicPath at the target
	UpstreamRawQuery   string // Optional fixed query appended at the target
	ServerAddr         string
	AuthToken          string
	CreatorEmail       string                                                  // Optional identity for non-JWT/self-hosted auth
	AccessTokenSHA256  []byte                                                  // Optional endpoint-scoped access-token digest
	EndpointTokenPath  string                                                  // Optional local token path shown after registration
	EndpointProtocol   string                                                  // "http" (default) or "tcp"
	TargetNetwork      string                                                  // "tcp" (default) or "unix" for raw endpoints
	DialAddress        string                                                  // Optional transport address when TargetURL is only an HTTP origin
	DialContext        func(context.Context, string, string) (net.Conn, error) // Optional embedded transport dialer
	LocalDialContext   func(context.Context, string, string) (net.Conn, error) // Optional HTTP origin transport, separate from relay
	RelayTLSConfig     *tls.Config
	LocalTLSConfig     *tls.Config
	TunnelKey          string
	AllowedEmails      []string
	Insecure           bool // Skip TLS verification for proxy gRPC connection
	SkipLocalTLSVerify bool // Skip TLS verification for local HTTPS target

	// Host-mode lifecycle hooks; called serially by Run.
	HostID            string
	Quiet             bool
	Persistent        bool
	OnState           func(online bool)
	OnLifecycle       func(LifecycleEvent)
	ValidatePublicURL func(string) error
	Logger            *slog.Logger // nil keeps the CLI logger; never changes process logging
	SafeLogs          bool         // Emit static messages only, without remote errors or private target data

	// Reconnection settings
	MaxReconnectDelay time.Duration // Maximum delay between reconnects (default: 30s)
	InitialDelay      time.Duration // Initial delay for exponential backoff (default: 1s)
	ReconnectLimit    *int          // nil keeps CLI retries unlimited; otherwise bounds retries
	ConnectTimeout    time.Duration // Bounds connection and registration, not an established tunnel

	// HTTP client settings
	HTTPTimeout         time.Duration // Timeout for HTTP requests to local target (default: 30s)
	Inspector           *Inspector    // Optional local, short-lived HTTP request inspector
	WebSocket           *common.WebSocketOptions
	RequireUpstreamAuth bool // Require an application Authorization header after tunn auth is stripped
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

	backoffAttempt := 0
	attempts := 0

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.lifecycle(LifecycleEvent{State: StateConnecting})
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
		var permanent *permanentTunnelError
		if errors.As(err, &permanent) {
			return err
		}
		// Reset backoff if connection was stable for at least 30 seconds
		if duration > 30*time.Second {
			backoffAttempt = 0
			attempts = 1
		}
		if s.ReconnectLimit != nil && attempts > *s.ReconnectLimit {
			return err
		}

		// Log the error and prepare for reconnection
		s.log(slog.LevelError, "tunnel connection lost", "error", err, "attempt", attempts)

		delay := ReconnectDelay(s.InitialDelay, s.MaxReconnectDelay, backoffAttempt)
		s.lifecycle(LifecycleEvent{State: StateReconnecting, Err: err, RetryDelay: delay})

		// Wait before reconnecting
		s.log(slog.LevelInfo, "reconnecting", "delay", delay.String())

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}

		// Exponential backoff with cap
		backoffAttempt++
		s.Inspector.reconnected()
	}
}

// runOnce establishes a single gRPC tunnel connection and handles messages until disconnection
func (s *ServeClient) runOnce(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	var connectTimer *time.Timer
	if s.ConnectTimeout > 0 {
		connectTimer = time.AfterFunc(s.ConnectTimeout, cancel)
		defer connectTimer.Stop()
	}
	// Create TLS credentials
	tlsConfig := &tls.Config{
		InsecureSkipVerify: s.Insecure,
	}
	if s.RelayTLSConfig != nil {
		tlsConfig = s.RelayTLSConfig.Clone()
	}
	creds := credentials.NewTLS(tlsConfig)

	// Connect to the gRPC server with keepalive
	s.log(slog.LevelInfo, "connecting to proxy", "server", s.ServerAddr)
	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second, // Ping server every 10s
			Timeout:             5 * time.Second,  // Wait 5s for pong
			PermitWithoutStream: true,             // Ping even without active streams
		}),
	}
	if s.DialContext != nil {
		dialOptions = append(dialOptions, grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			return s.DialContext(ctx, "tcp", address)
		}))
	}
	conn, err := grpc.NewClient(s.ServerAddr, dialOptions...)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Create tunnel service client
	client := pb.NewTunnelServiceClient(conn)

	// Establish the bidirectional stream
	if s.HostID != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "tunn-host-id", s.HostID)
	}
	stream, err := client.EstablishTunnel(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish tunnel: %w", err)
	}

	s.log(slog.LevelInfo, "gRPC stream established")

	// Extract email from JWT (skip if no token)
	creatorEmail := s.CreatorEmail
	if creatorEmail == "" {
		if s.AuthToken != "" {
			if email, err := common.ExtractEmailFromJWT(s.AuthToken); err == nil {
				creatorEmail = email
				s.log(slog.LevelInfo, "extracted creator email", "email", creatorEmail)
			} else {
				// Self-hosted client secrets and per-user tokens are not JWTs. The
				// server derives their identity from its own trusted configuration.
				s.log(slog.LevelDebug, "auth token has no JWT email; server will derive identity")
			}
		} else {
			s.log(slog.LevelInfo, "no auth token - using public mode")
		}
	}

	accessTokenDigest := s.AccessTokenSHA256
	if s.EndpointTokenPath != "" {
		accessTokenDigest, err = endpointTokenDigestFromFile(s.EndpointTokenPath)
		if err != nil {
			return &permanentTunnelError{err: fmt.Errorf("load endpoint token before registration: %w", err)}
		}
	}

	// Send registration message
	regMsg := &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:          s.TunnelID,
				TargetUrl:         s.registrationTarget(),
				AuthToken:         s.AuthToken,
				CreatorEmail:      creatorEmail,
				AllowedEmails:     s.AllowedEmails,
				TunnelKey:         s.TunnelKey,
				AccessTokenSha256: accessTokenDigest,
				Capabilities: []string{
					common.CapabilityHTTPStreamV1,
					common.CapabilityConnectionStreamV1,
					common.CapabilityWebSocketV1,
				},
				EndpointProtocol: s.EndpointProtocol,
			},
		},
	}

	if err := stream.Send(regMsg); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	s.log(slog.LevelInfo, "registration sent", "tunnel_id", s.TunnelID, "protocol", s.registrationTarget())

	// Wait for registration response
	msg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive registration response: %w", err)
	}

	regResp := msg.GetRegisterResponse()
	if regResp == nil {
		return &permanentTunnelError{err: fmt.Errorf("expected RegisterResponse, got %T", msg.Message), kind: FailureProtocol}
	}

	if !regResp.Success {
		return &permanentTunnelError{err: fmt.Errorf("registration failed: %s", regResp.ErrorMessage), kind: FailureRegistration}
	}
	if s.ValidatePublicURL != nil {
		if err := s.ValidatePublicURL(regResp.PublicUrl); err != nil {
			return &permanentTunnelError{err: err, kind: FailureProtocol}
		}
	}
	if connectTimer != nil {
		connectTimer.Stop()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.EndpointProtocol == "tcp" && !containsString(regResp.Capabilities, common.CapabilityConnectionStreamV1) {
		return &permanentTunnelError{err: fmt.Errorf("relay does not support raw connection streams")}
	}
	if s.RequireUpstreamAuth && !containsString(regResp.Capabilities, common.CapabilityWebSocketV1) {
		return &permanentTunnelError{err: fmt.Errorf("relay must support websocket-v1 for --require-upstream-auth"), kind: FailureProtocol}
	}

	if s.OnState != nil {
		s.OnState(true)
		defer s.OnState(false)
	}
	s.lifecycle(LifecycleEvent{State: StateReady, PublicURL: regResp.PublicUrl + s.PublicPath})

	s.log(slog.LevelInfo, "tunnel registered successfully", "public_url", regResp.PublicUrl)
	publicURL := regResp.PublicUrl + s.PublicPath
	displayTarget := s.TargetURL
	if s.DisplayTarget != "" {
		displayTarget = s.DisplayTarget
	}
	if !s.Quiet {
		fmt.Printf("%s -> %s\n", publicURL, displayTarget)
		if s.PublicPath == "/mcp" {
			fmt.Printf("Connector URL: %s\n", publicURL)
			fmt.Println("Paste this URL into Claude.ai or ChatGPT's MCP connector settings.")
		}

		// Warn if tunnel is open to the internet (no --allow specified)
		if len(s.AllowedEmails) == 0 && len(accessTokenDigest) == 0 {
			fmt.Println("Warning: Tunnel is open to the internet. Use --allow=email@example.com to restrict access.")
		} else if s.PublicPath == "/mcp" {
			fmt.Println("Access: private. Sign in to tunn and approve the connector's access to this tunnel.")
			if s.EndpointTokenPath != "" {
				fmt.Printf("Endpoint token: %s (mode 0600)\n", s.EndpointTokenPath)
			}
		} else if s.EndpointProtocol == "tcp" {
			fmt.Printf("Access: private. Run tunn connect --token-file %s %s\n", s.EndpointTokenPath, s.TunnelID)
		} else if s.EndpointTokenPath != "" {
			fmt.Println("Access: private. Use the endpoint token as Tunn-Authorization: Bearer <token>.")
			fmt.Printf("Endpoint token: %s (mode 0600)\n", s.EndpointTokenPath)
		}

	}

	// Wrap stream with mutex for thread-safe sends
	sender := &streamSender{stream: stream}

	// Create a derived context that we cancel when this connection ends
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel() // Cancel health check goroutine when connection ends

	// Start health check sender
	workers.Add(1)
	go func() { defer workers.Done(); s.sendHealthChecks(connCtx, sender) }()
	if s.EndpointTokenPath != "" {
		workers.Add(1)
		go func() { defer workers.Done(); s.watchEndpointToken(connCtx, sender, accessTokenDigest, time.Second) }()
	}

	// Enter message processing loop
	return s.processMessagesOwned(ctx, stream, sender, cancel)
}

func (s *ServeClient) watchEndpointToken(ctx context.Context, sender messageSender, current []byte, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	current = append([]byte(nil), current...)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			digest, err := endpointTokenDigestFromFile(s.EndpointTokenPath)
			if err != nil {
				s.log(slog.LevelError, "failed to read endpoint token for rotation", "error", err)
				continue
			}
			if bytes.Equal(digest, current) {
				continue
			}
			if err := sender.Send(&pb.TunnelMessage{
				Message: &pb.TunnelMessage_UpdateAccessToken{
					UpdateAccessToken: &pb.UpdateAccessToken{AccessTokenSha256: digest},
				},
			}); err != nil {
				s.log(slog.LevelError, "failed to rotate endpoint token at relay", "error", err)
				return
			}
			current = digest
			s.log(slog.LevelInfo, "endpoint access token rotated")
		}
	}
}

func (s *ServeClient) registrationTarget() string {
	if s.TargetNetwork == "unix" && s.EndpointProtocol != "tcp" {
		return "unix-http"
	}
	if s.EndpointProtocol == "tcp" {
		if s.TargetNetwork == "unix" {
			return "unix"
		}
		return "tcp"
	}
	if s.PublicPath == "/mcp" {
		return "mcp"
	}
	return "http"
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// processMessages handles incoming messages from the server
func (s *ServeClient) processMessages(ctx context.Context, stream pb.TunnelService_EstablishTunnelClient, sender messageSender) error {
	return s.processMessagesOwned(ctx, stream, sender, func() {})
}

func (s *ServeClient) processMessagesOwned(ctx context.Context, stream pb.TunnelService_EstablishTunnelClient, sender messageSender, cancelStream context.CancelFunc) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	// Semaphore to limit concurrent HTTP request handlers
	sem := make(chan struct{}, MaxConcurrentRequests)
	connections := newInboundConnectionManager()
	defer func() {
		cancel()
		connections.closeAll(fmt.Errorf("tunnel connection closed"))
		// Cancel the stream before joining workers: a send can be blocked on
		// relay backpressure. CloseSend is not safe alongside those sends.
		cancelStream()
		workers.Wait()
		connections.workers.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			s.log(slog.LevelInfo, "context canceled, closing stream")
			return ctx.Err()
		default:
		}

		msg, err := stream.Recv()
		if err == io.EOF {
			s.log(slog.LevelInfo, "server closed stream")
			if s.Persistent {
				return fmt.Errorf("relay closed persistent tunnel")
			}
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
				workers.Add(1)
				go func(req *pb.HttpRequest) {
					defer workers.Done()
					defer func() { <-sem }() // Release slot when done
					s.handleHTTPRequestContext(ctx, sender, req)
				}(m.HttpRequest)
			case <-ctx.Done():
				s.log(slog.LevelInfo, "context canceled while waiting for semaphore")
				return ctx.Err()
			}

		case *pb.TunnelMessage_HealthCheckResponse:
			// Calculate RTT
			rtt := time.Now().UnixMilli() - m.HealthCheckResponse.Timestamp
			s.log(slog.LevelDebug, "health check response", "rtt_ms", rtt)

		case *pb.TunnelMessage_ConnectionOpen:
			connections.open(ctx, s, sender, m.ConnectionOpen)

		case *pb.TunnelMessage_ConnectionData:
			connections.write(m.ConnectionData.ConnectionId, m.ConnectionData.Data)

		case *pb.TunnelMessage_ConnectionHalfClose:
			connections.halfClose(m.ConnectionHalfClose.ConnectionId)

		case *pb.TunnelMessage_ConnectionClose:
			connections.close(m.ConnectionClose.ConnectionId, m.ConnectionClose.ErrorMessage)

		case *pb.TunnelMessage_RegisterResponse:
			return &permanentTunnelError{err: fmt.Errorf("duplicate registration response"), kind: FailureProtocol}

		default:
			s.log(slog.LevelInfo, "unexpected message type", "type", fmt.Sprintf("%T", m))
		}
	}
}

// handleHttpRequest handles an HTTP request from the proxy, makes a request to the local target, and sends back the response
func (s *ServeClient) handleHttpRequest(sender messageSender, httpReq *pb.HttpRequest) {
	s.handleHTTPRequestContext(context.Background(), sender, httpReq)
}

func (s *ServeClient) handleHTTPRequestContext(ctx context.Context, sender messageSender, httpReq *pb.HttpRequest) {
	var capture *inspectionCapture
	if s.Inspector != nil {
		capture = s.Inspector.beginConnection(httpReq.ConnectionId, "http", httpReq.Method, httpReq.Path, httpReq.Headers)
		_, _ = capture.Write(httpReq.Body)
		capture.complete()
	}
	status, responseBytes, reason := http.StatusBadGateway, int64(0), "target_error"
	if capture != nil {
		defer func() { capture.finishReason(status, responseBytes, reason) }()
	}
	s.log(slog.LevelDebug, "http request received",
		"connection_id", httpReq.ConnectionId,
		"method", httpReq.Method)

	// Build the target URL. Protocol adapters can expose one stable public path
	// while forwarding to a differently named local endpoint.
	targetURL := s.targetURL(httpReq.Path)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, httpReq.Method, targetURL, bytes.NewReader(httpReq.Body))
	if err != nil {
		s.log(slog.LevelError, "failed to create http request", "connection_id", httpReq.ConnectionId)
		s.sendErrorResponse(sender, httpReq.ConnectionId, http.StatusBadGateway, "Failed to create request")
		return
	}

	// Copy headers
	for key, value := range httpReq.Headers {
		req.Header.Set(key, value)
	}
	req.Host = req.Header.Get("Host")
	req.Header.Del("Host")
	if s.RequireUpstreamAuth && strings.TrimSpace(req.Header.Get("Authorization")) == "" {
		status, reason = http.StatusUnauthorized, "auth_required"
		s.Inspector.denied()
		s.sendErrorResponse(sender, httpReq.ConnectionId, http.StatusUnauthorized, "Upstream Authorization required")
		return
	}

	// Make the request to local target
	timeout := s.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	transport := &http.Transport{
		DialContext:     s.localDialContext(),
		TLSClientConfig: s.localTLSConfig(),
		// Custom TLSClientConfig disables HTTP/2 by default; re-enable it
		// so we can talk to local HTTPS servers that require HTTP/2 via ALPN.
		ForceAttemptHTTP2: true,
	}
	if s.TargetNetwork == "unix" {
		dialAddress := s.DialAddress
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", dialAddress)
		}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	resp, err := client.Do(req)
	if err != nil {
		s.log(slog.LevelError, "failed to make http request to target", "connection_id", httpReq.ConnectionId)
		s.sendErrorResponse(sender, httpReq.ConnectionId, http.StatusBadGateway, "Failed to reach local target")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	status = resp.StatusCode
	reason = "complete"
	if capture != nil && strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		capture.setProtocol("sse")
	}

	// Read response body with size limit to prevent memory exhaustion
	// Read one extra byte to detect if body exceeds limit
	limitedBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodySize+1))
	if err != nil {
		status, reason = http.StatusBadGateway, "response_error"
		responseBytes = int64(len(limitedBody))
		s.log(slog.LevelError, "failed to read response body", "connection_id", httpReq.ConnectionId)
		s.sendErrorResponse(sender, httpReq.ConnectionId, http.StatusBadGateway, "Failed to read response")
		return
	}
	if int64(len(limitedBody)) > MaxResponseBodySize {
		status, reason = http.StatusBadGateway, "response_limit"
		responseBytes = int64(len(limitedBody))
		s.log(slog.LevelError, "response body too large", "size", len(limitedBody), "max", MaxResponseBodySize)
		s.sendErrorResponse(sender, httpReq.ConnectionId, http.StatusBadGateway, "Response too large")
		return
	}
	body := limitedBody
	responseBytes = int64(len(body))

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
		reason = "relay_error"
		s.log(slog.LevelError, "failed to send http response", "error", err)
		return
	}

	s.log(slog.LevelDebug, "http response sent",
		"connection_id", httpReq.ConnectionId,
		"status", resp.StatusCode,
		"body_size", len(body))
}

func (s *ServeClient) targetURL(requestPath string) string {
	if s.PublicPath != "" && s.UpstreamPath != "" {
		requestPath = rewritePublicPath(requestPath, s.PublicPath, s.UpstreamPath, s.UpstreamRawQuery)
	}
	return s.TargetURL + requestPath
}

func rewritePublicPath(requestURI, publicPath, upstreamPath, upstreamRawQuery string) string {
	path, rawQuery, found := strings.Cut(requestURI, "?")
	if path == publicPath || strings.HasPrefix(path, strings.TrimSuffix(publicPath, "/")+"/") {
		suffix := strings.TrimPrefix(path, publicPath)
		path = strings.TrimSuffix(upstreamPath, "/") + suffix
		if path == "" {
			path = "/"
		}
	}

	queries := make([]string, 0, 2)
	if upstreamRawQuery != "" {
		queries = append(queries, upstreamRawQuery)
	}
	if found && rawQuery != "" {
		queries = append(queries, rawQuery)
	}
	if len(queries) > 0 {
		return path + "?" + strings.Join(queries, "&")
	}
	return path
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
		s.log(slog.LevelError, "failed to send error response", "error", err)
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
		s.log(slog.LevelError, "failed to send health check", "error", err)
		return
	}

	s.log(slog.LevelDebug, "health check sent")
}
