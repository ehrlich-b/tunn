package host

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc/metadata"
)

func TestProxyHTTPOverGRPC(t *testing.T) {
	// Create a mock stream that captures sent messages and simulates responses
	stream := &mockWebProxyStream{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	// Create tunnel connection with mock stream
	tunnel := &TunnelConnection{
		TunnelID:        "test123",
		TargetURL:       "http://localhost:8000",
		Stream:          stream,
		pendingRequests: make(map[string]chan *pb.HttpResponse),
	}

	// Create minimal ProxyServer (only need it for method call)
	proxy := &ProxyServer{}

	// Create test HTTP request
	body := []byte("test request body")
	req := httptest.NewRequest("POST", "/api/test?foo=bar", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom-Header", "custom-value")

	// Create response recorder
	rec := httptest.NewRecorder()

	// Simulate client responding - watch for HttpRequest and respond
	go func() {
		// Wait for request to be sent
		time.Sleep(10 * time.Millisecond)

		stream.mu.Lock()
		if len(stream.sentMsgs) == 0 {
			stream.mu.Unlock()
			return
		}
		httpReq := stream.sentMsgs[0].GetHttpRequest()
		stream.mu.Unlock()

		if httpReq == nil {
			return
		}

		// Inject response into pending requests
		tunnel.pendingMu.RLock()
		respChan, exists := tunnel.pendingRequests[httpReq.ConnectionId]
		tunnel.pendingMu.RUnlock()

		if exists {
			respChan <- &pb.HttpResponse{
				ConnectionId: httpReq.ConnectionId,
				StatusCode:   200,
				Headers: map[string]string{
					"Content-Type": "application/json",
					"X-Response":   "test",
				},
				Body: []byte(`{"status":"ok"}`),
			}
		}
	}()

	// Call proxyHTTPOverGRPC
	err := proxy.proxyHTTPOverGRPC(rec, req, tunnel)
	if err != nil {
		t.Fatalf("proxyHTTPOverGRPC failed: %v", err)
	}

	// Verify response
	if rec.Code != 200 {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", rec.Header().Get("Content-Type"))
	}

	if rec.Header().Get("X-Response") != "test" {
		t.Errorf("Expected X-Response header 'test', got %s", rec.Header().Get("X-Response"))
	}

	if rec.Body.String() != `{"status":"ok"}` {
		t.Errorf("Expected body '{\"status\":\"ok\"}', got %s", rec.Body.String())
	}

	// Verify request was sent correctly
	stream.mu.Lock()
	defer stream.mu.Unlock()

	if len(stream.sentMsgs) != 1 {
		t.Fatalf("Expected 1 message sent, got %d", len(stream.sentMsgs))
	}

	httpReq := stream.sentMsgs[0].GetHttpRequest()
	if httpReq == nil {
		t.Fatal("Expected HttpRequest message")
	}

	if httpReq.Method != "POST" {
		t.Errorf("Expected method POST, got %s", httpReq.Method)
	}

	if httpReq.Path != "/api/test?foo=bar" {
		t.Errorf("Expected path '/api/test?foo=bar', got %s", httpReq.Path)
	}

	if httpReq.Headers["Content-Type"] != "application/json" {
		t.Errorf("Expected Content-Type header, got %s", httpReq.Headers["Content-Type"])
	}

	if string(httpReq.Body) != "test request body" {
		t.Errorf("Expected body 'test request body', got %s", string(httpReq.Body))
	}
}

func TestProxyHTTPOverGRPCSendError(t *testing.T) {
	// Create a mock stream that fails on Send
	stream := &mockWebProxyStreamWithError{
		sendErr: io.EOF,
	}

	tunnel := &TunnelConnection{
		TunnelID:        "test123",
		Stream:          stream,
		pendingRequests: make(map[string]chan *pb.HttpResponse),
	}

	proxy := &ProxyServer{}

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	err := proxy.proxyHTTPOverGRPC(rec, req, tunnel)
	if err == nil {
		t.Error("Expected error when stream.Send fails")
	}
}

func TestAllowListCheck(t *testing.T) {
	tests := []struct {
		name          string
		userEmail     string
		allowedEmails []string
		wantAllowed   bool
	}{
		{
			name:          "user on allow-list",
			userEmail:     "alice@example.com",
			allowedEmails: []string{"alice@example.com", "bob@example.com"},
			wantAllowed:   true,
		},
		{
			name:          "user not on allow-list",
			userEmail:     "eve@example.com",
			allowedEmails: []string{"alice@example.com", "bob@example.com"},
			wantAllowed:   false,
		},
		{
			name:          "empty allow-list",
			userEmail:     "alice@example.com",
			allowedEmails: []string{},
			wantAllowed:   false,
		},
		{
			name:          "creator only",
			userEmail:     "creator@example.com",
			allowedEmails: []string{"creator@example.com"},
			wantAllowed:   true,
		},
		{
			name:          "case insensitive email",
			userEmail:     "Alice@Example.com",
			allowedEmails: []string{"alice@example.com"},
			wantAllowed:   true, // Emails are case-insensitive
		},
		// Domain wildcard tests
		{
			name:          "domain wildcard match",
			userEmail:     "alice@company.com",
			allowedEmails: []string{"@company.com"},
			wantAllowed:   true,
		},
		{
			name:          "domain wildcard no match",
			userEmail:     "alice@other.com",
			allowedEmails: []string{"@company.com"},
			wantAllowed:   false,
		},
		{
			name:          "domain wildcard case insensitive",
			userEmail:     "alice@COMPANY.COM",
			allowedEmails: []string{"@company.com"},
			wantAllowed:   true,
		},
		{
			name:          "mixed exact and wildcard - exact match",
			userEmail:     "external@gmail.com",
			allowedEmails: []string{"@company.com", "external@gmail.com"},
			wantAllowed:   true,
		},
		{
			name:          "mixed exact and wildcard - wildcard match",
			userEmail:     "alice@company.com",
			allowedEmails: []string{"@company.com", "external@gmail.com"},
			wantAllowed:   true,
		},
		{
			name:          "mixed exact and wildcard - no match",
			userEmail:     "hacker@evil.com",
			allowedEmails: []string{"@company.com", "external@gmail.com"},
			wantAllowed:   false,
		},
		{
			name:          "subdomain does not match wildcard",
			userEmail:     "alice@sub.company.com",
			allowedEmails: []string{"@company.com"},
			wantAllowed:   false, // @company.com should not match sub.company.com
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := isEmailAllowed(tt.userEmail, tt.allowedEmails)

			if allowed != tt.wantAllowed {
				t.Errorf("isEmailAllowed(%q, %v) = %v, want %v",
					tt.userEmail, tt.allowedEmails, allowed, tt.wantAllowed)
			}
		})
	}
}

func TestProxyHTTPOverGRPCMultiValueHeaders(t *testing.T) {
	stream := &mockWebProxyStream{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	tunnel := &TunnelConnection{
		TunnelID:        "test123",
		Stream:          stream,
		pendingRequests: make(map[string]chan *pb.HttpResponse),
	}

	proxy := &ProxyServer{}

	// Create request with multi-value headers
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Add("Accept", "text/html")
	req.Header.Add("Accept", "application/json")

	rec := httptest.NewRecorder()

	// Respond immediately
	go func() {
		time.Sleep(10 * time.Millisecond)
		stream.mu.Lock()
		if len(stream.sentMsgs) == 0 {
			stream.mu.Unlock()
			return
		}
		httpReq := stream.sentMsgs[0].GetHttpRequest()
		stream.mu.Unlock()

		if httpReq == nil {
			return
		}

		tunnel.pendingMu.RLock()
		respChan, exists := tunnel.pendingRequests[httpReq.ConnectionId]
		tunnel.pendingMu.RUnlock()

		if exists {
			respChan <- &pb.HttpResponse{
				ConnectionId: httpReq.ConnectionId,
				StatusCode:   200,
				Headers:      map[string]string{},
				Body:         []byte("ok"),
			}
		}
	}()

	err := proxy.proxyHTTPOverGRPC(rec, req, tunnel)
	if err != nil {
		t.Fatalf("proxyHTTPOverGRPC failed: %v", err)
	}

	// Verify multi-value headers were joined
	stream.mu.Lock()
	httpReq := stream.sentMsgs[0].GetHttpRequest()
	stream.mu.Unlock()

	acceptHeader := httpReq.Headers["Accept"]
	if acceptHeader != "text/html, application/json" {
		t.Errorf("Expected Accept header 'text/html, application/json', got %s", acceptHeader)
	}
}

// mockWebProxyStream implements pb.TunnelService_EstablishTunnelServer for webproxy testing
type mockWebProxyStream struct {
	mu       sync.Mutex
	sentMsgs []*pb.TunnelMessage
}

func (m *mockWebProxyStream) Send(msg *pb.TunnelMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}

func (m *mockWebProxyStream) Recv() (*pb.TunnelMessage, error) {
	return nil, io.EOF
}

func (m *mockWebProxyStream) SetHeader(md metadata.MD) error  { return nil }
func (m *mockWebProxyStream) SendHeader(md metadata.MD) error { return nil }
func (m *mockWebProxyStream) SetTrailer(md metadata.MD)       {}
func (m *mockWebProxyStream) Context() context.Context        { return context.Background() }
func (m *mockWebProxyStream) SendMsg(msg interface{}) error   { return nil }
func (m *mockWebProxyStream) RecvMsg(msg interface{}) error   { return nil }

// mockWebProxyStreamWithError returns an error on Send
type mockWebProxyStreamWithError struct {
	sendErr error
}

func (m *mockWebProxyStreamWithError) Send(msg *pb.TunnelMessage) error {
	return m.sendErr
}

func (m *mockWebProxyStreamWithError) Recv() (*pb.TunnelMessage, error) {
	return nil, io.EOF
}

func (m *mockWebProxyStreamWithError) SetHeader(md metadata.MD) error  { return nil }
func (m *mockWebProxyStreamWithError) SendHeader(md metadata.MD) error { return nil }
func (m *mockWebProxyStreamWithError) SetTrailer(md metadata.MD)       {}
func (m *mockWebProxyStreamWithError) Context() context.Context        { return context.Background() }
func (m *mockWebProxyStreamWithError) SendMsg(msg interface{}) error   { return nil }
func (m *mockWebProxyStreamWithError) RecvMsg(msg interface{}) error   { return nil }

func TestGenerateConnectionID(t *testing.T) {
	// Generate multiple IDs and verify uniqueness
	ids := make(map[string]bool)

	for i := 0; i < 100; i++ {
		id, err := generateConnectionID()
		if err != nil {
			t.Fatalf("generateConnectionID failed: %v", err)
		}

		// Should be 32 hex chars (16 bytes = 32 hex digits)
		if len(id) != 32 {
			t.Errorf("Expected 32 char ID, got %d chars: %s", len(id), id)
		}

		// Check uniqueness
		if ids[id] {
			t.Errorf("Duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestExtractTunnelIDFromHost(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		domain string
		wantID string
	}{
		{
			name:   "simple subdomain",
			host:   "abc123.tunn.to",
			domain: "tunn.to",
			wantID: "abc123",
		},
		{
			name:   "apex domain",
			host:   "tunn.to",
			domain: "tunn.to",
			wantID: "",
		},
		{
			name:   "with port",
			host:   "test.tunn.to:8443",
			domain: "tunn.to",
			wantID: "test",
		},
		{
			name:   "nip.io domain",
			host:   "myapp.tunn.local.127.0.0.1.nip.io",
			domain: "tunn.local.127.0.0.1.nip.io",
			wantID: "myapp",
		},
		{
			name:   "different domain",
			host:   "test.example.com",
			domain: "tunn.to",
			wantID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTunnelID(tt.host, tt.domain)
			if got != tt.wantID {
				t.Errorf("extractTunnelID(%q, %q) = %q, want %q", tt.host, tt.domain, got, tt.wantID)
			}
		})
	}
}

func TestHandleWebProxyTunnelNotFound(t *testing.T) {
	tunnelServer := NewTunnelServer("test-key", false, "tunn.to")

	proxy := &ProxyServer{
		Domain:       "tunn.to",
		tunnelServer: tunnelServer,
		nodeClients:  make(map[string]internalv1.InternalServiceClient), // empty - no other nodes
		tunnelCache:  make(map[string]string),
	}

	req := httptest.NewRequest("GET", "https://nonexistent.tunn.to/test", nil)
	req.Host = "nonexistent.tunn.to"
	rec := httptest.NewRecorder()

	proxy.handleWebProxy(rec, req)

	if rec.Code != 503 {
		t.Errorf("Expected status 503, got %d", rec.Code)
	}

	if !bytes.Contains(rec.Body.Bytes(), []byte("Tunnel not found")) {
		t.Errorf("Expected 'Tunnel not found' in body, got: %s", rec.Body.String())
	}
}
