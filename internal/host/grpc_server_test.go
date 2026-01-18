package host

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc/metadata"
)

// testConfig returns a config suitable for testing
func testConfig() *config.Config {
	return &config.Config{
		WellKnownKey: "test-key",
		PublicMode:   false,
		Domain:       "tunn.to",
		ClientSecret: "",
		JWTSecret:    "test-jwt-secret",
	}
}

// createTestJWT creates a valid JWT for testing
func createTestJWT(email string, secret string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func TestNewTunnelServer(t *testing.T) {
	srv := NewTunnelServer(testConfig(), nil, nil, nil)
	if srv == nil {
		t.Fatal("Expected non-nil server")
	}

	if srv.tunnels == nil {
		t.Error("Expected tunnels map to be initialized")
	}

	if len(srv.tunnels) != 0 {
		t.Errorf("Expected empty tunnels map, got %d entries", len(srv.tunnels))
	}
}

func TestTunnelServerRegistration(t *testing.T) {
	srv := NewTunnelServer(testConfig(), nil, nil, nil)

	// Create a mock stream
	stream := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	// Create a valid JWT for registration
	testJWT := createTestJWT("test@example.com", "test-jwt-secret")

	// Send registration message with valid JWT
	stream.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:  "test123",
				TargetUrl: "http://localhost:8000",
				TunnelKey: "test-key",
				AuthToken: testJWT, // JWT required for authentication
			},
		},
	}

	// Send a health check after registration
	stream.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_HealthCheck{
			HealthCheck: &pb.HealthCheck{
				Timestamp: time.Now().UnixMilli(),
			},
		},
	}

	// Close the stream after messages
	close(stream.recvQueue)

	// Run EstablishTunnel
	err := srv.EstablishTunnel(stream)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify registration response was sent
	if len(stream.sentMsgs) < 1 {
		t.Fatal("Expected at least one message to be sent")
	}

	regResp := stream.sentMsgs[0].GetRegisterResponse()
	if regResp == nil {
		t.Fatal("Expected RegisterResponse message")
	}

	if !regResp.Success {
		t.Errorf("Expected successful registration, got error: %s", regResp.ErrorMessage)
	}

	if regResp.PublicUrl != "https://test123.tunn.to" {
		t.Errorf("Expected public URL https://test123.tunn.to, got %s", regResp.PublicUrl)
	}

	// Verify health check response was sent
	if len(stream.sentMsgs) < 2 {
		t.Fatal("Expected health check response to be sent")
	}

	hcResp := stream.sentMsgs[1].GetHealthCheckResponse()
	if hcResp == nil {
		t.Error("Expected HealthCheckResponse message")
	}
}

func TestTunnelServerDuplicateRegistration(t *testing.T) {
	srv := NewTunnelServer(testConfig(), nil, nil, nil)

	// First stream
	stream1 := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	testJWT := createTestJWT("test@example.com", "test-jwt-secret")

	stream1.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:  "duplicate",
				TargetUrl: "http://localhost:8000",
				TunnelKey: "test-key",
				AuthToken: testJWT,
			},
		},
	}

	// Run first connection in background
	go func() {
		srv.EstablishTunnel(stream1)
	}()

	// Give it time to register
	time.Sleep(100 * time.Millisecond)

	// Second stream with same tunnel ID
	stream2 := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	stream2.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:  "duplicate",
				TargetUrl: "http://localhost:9000",
				TunnelKey: "test-key",
				AuthToken: testJWT,
			},
		},
	}
	close(stream2.recvQueue)

	// Second registration should fail
	err := srv.EstablishTunnel(stream2)
	if err == nil {
		t.Error("Expected error for duplicate tunnel ID")
	}

	// Verify error response was sent
	if len(stream2.sentMsgs) < 1 {
		t.Fatal("Expected error response to be sent")
	}

	regResp := stream2.sentMsgs[0].GetRegisterResponse()
	if regResp == nil {
		t.Fatal("Expected RegisterResponse message")
	}

	if regResp.Success {
		t.Error("Expected registration to fail")
	}

	// Cleanup first stream
	close(stream1.recvQueue)
}

func TestGetTunnel(t *testing.T) {
	srv := NewTunnelServer(testConfig(), nil, nil, nil)

	// Add a tunnel directly
	conn := &TunnelConnection{
		TunnelID:  "test456",
		TargetURL: "http://localhost:8000",
		Connected: time.Now(),
	}

	srv.mu.Lock()
	srv.tunnels["test456"] = conn
	srv.mu.Unlock()

	// Retrieve it
	retrieved, exists := srv.GetTunnel("test456")
	if !exists {
		t.Fatal("Expected tunnel to exist")
	}

	if retrieved.TunnelID != "test456" {
		t.Errorf("Expected tunnel ID test456, got %s", retrieved.TunnelID)
	}

	// Try non-existent tunnel
	_, exists = srv.GetTunnel("nonexistent")
	if exists {
		t.Error("Expected tunnel to not exist")
	}
}

func TestListTunnels(t *testing.T) {
	srv := NewTunnelServer(testConfig(), nil, nil, nil)

	// Add multiple tunnels
	for i := 0; i < 3; i++ {
		conn := &TunnelConnection{
			TunnelID:  string(rune('a' + i)),
			TargetURL: "http://localhost:8000",
			Connected: time.Now(),
		}
		srv.mu.Lock()
		srv.tunnels[conn.TunnelID] = conn
		srv.mu.Unlock()
	}

	tunnels := srv.ListTunnels()
	if len(tunnels) != 3 {
		t.Errorf("Expected 3 tunnels, got %d", len(tunnels))
	}
}

// mockTunnelStream implements pb.TunnelService_EstablishTunnelServer for testing
type mockTunnelStream struct {
	recvQueue chan *pb.TunnelMessage
	sentMsgs  []*pb.TunnelMessage
}

func (m *mockTunnelStream) Send(msg *pb.TunnelMessage) error {
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}

func (m *mockTunnelStream) Recv() (*pb.TunnelMessage, error) {
	msg, ok := <-m.recvQueue
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

func (m *mockTunnelStream) SetHeader(md metadata.MD) error  { return nil }
func (m *mockTunnelStream) SendHeader(md metadata.MD) error { return nil }
func (m *mockTunnelStream) SetTrailer(md metadata.MD)       {}
func (m *mockTunnelStream) Context() context.Context        { return context.Background() }
func (m *mockTunnelStream) SendMsg(msg interface{}) error   { return nil }
func (m *mockTunnelStream) RecvMsg(msg interface{}) error   { return nil }

func TestIsReservedSubdomain(t *testing.T) {
	tests := []struct {
		subdomain string
		expected  bool
	}{
		// Infrastructure
		{"www", true},
		{"api", true},
		{"admin", true},
		{"login", true},
		{"health", true},

		// Phishing targets
		{"google", true},
		{"paypal", true},
		{"github", true},
		{"amazon", true},

		// Case insensitive
		{"GOOGLE", true},
		{"PayPal", true},
		{"GitHub", true},

		// Allowed
		{"myapp", false},
		{"test123", false},
		{"mycoolproject", false},
		{"abc123xyz", false},
	}

	for _, tt := range tests {
		t.Run(tt.subdomain, func(t *testing.T) {
			if got := isReservedSubdomain(tt.subdomain); got != tt.expected {
				t.Errorf("isReservedSubdomain(%q) = %v, want %v", tt.subdomain, got, tt.expected)
			}
		})
	}
}

func TestValidDNSLabel(t *testing.T) {
	tests := []struct {
		tunnelID string
		valid    bool
	}{
		// Valid labels
		{"myapp", true},
		{"test123", true},
		{"my-app", true},
		{"a", true},
		{"1", true},
		{"a1b2c3", true},
		{"my-cool-app", true},

		// Invalid: empty
		{"", false},

		// Invalid: too long (64 chars)
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},

		// Invalid: starts with hyphen
		{"-myapp", false},

		// Invalid: ends with hyphen
		{"myapp-", false},

		// Invalid: uppercase (should be normalized before check)
		{"MyApp", false},

		// Invalid: contains dot
		{"my.app", false},

		// Invalid: contains underscore
		{"my_app", false},

		// Invalid: contains space
		{"my app", false},

		// Invalid: contains special chars
		{"my@app", false},
	}

	for _, tt := range tests {
		t.Run(tt.tunnelID, func(t *testing.T) {
			if got := isValidDNSLabel(tt.tunnelID); got != tt.valid {
				t.Errorf("isValidDNSLabel(%q) = %v, want %v", tt.tunnelID, got, tt.valid)
			}
		})
	}
}

func TestTunnelServerReservedSubdomain(t *testing.T) {
	srv := NewTunnelServer(testConfig(), nil, nil, nil)

	stream := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	// Try to register a reserved subdomain
	stream.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:     "google",
				TargetUrl:    "http://localhost:8000",
				TunnelKey:    "test-key",
				CreatorEmail: "attacker@evil.com",
			},
		},
	}
	close(stream.recvQueue)

	err := srv.EstablishTunnel(stream)
	if err == nil {
		t.Error("Expected error for reserved subdomain")
	}

	if len(stream.sentMsgs) < 1 {
		t.Fatal("Expected error response to be sent")
	}

	regResp := stream.sentMsgs[0].GetRegisterResponse()
	if regResp == nil {
		t.Fatal("Expected RegisterResponse message")
	}

	if regResp.Success {
		t.Error("Expected registration to fail")
	}

	if regResp.ErrorMessage == "" {
		t.Error("Expected error message")
	}
}

func TestTunnelServerClientSecretAuth(t *testing.T) {
	// Server with client secret configured
	cfg := testConfig()
	cfg.ClientSecret = "my-secret-key"
	srv := NewTunnelServer(cfg, nil, nil, nil)

	// Test 1: Valid client secret should work
	stream := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	stream.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:  "test123",
				TargetUrl: "http://localhost:8000",
				TunnelKey: "test-key",
				AuthToken: "my-secret-key", // Client secret as auth token
			},
		},
	}
	close(stream.recvQueue)

	err := srv.EstablishTunnel(stream)
	if err != nil {
		t.Errorf("Expected no error with valid client secret, got %v", err)
	}

	if len(stream.sentMsgs) < 1 {
		t.Fatal("Expected response to be sent")
	}

	regResp := stream.sentMsgs[0].GetRegisterResponse()
	if regResp == nil {
		t.Fatal("Expected RegisterResponse message")
	}

	if !regResp.Success {
		t.Errorf("Expected successful registration, got error: %s", regResp.ErrorMessage)
	}

	// Test 2: Wrong client secret should fail
	stream2 := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	stream2.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:  "test456",
				TargetUrl: "http://localhost:8000",
				TunnelKey: "test-key",
				AuthToken: "wrong-secret",
			},
		},
	}
	close(stream2.recvQueue)

	err = srv.EstablishTunnel(stream2)
	if err == nil {
		t.Error("Expected error with wrong client secret")
	}
}

func TestTunnelServerUserTokenAuth(t *testing.T) {
	// Server with user tokens configured
	userTokens := map[string]string{
		"alice@example.com": "tunn_sk_alice123",
		"bob@example.com":   "tunn_sk_bob456",
	}
	srv := NewTunnelServer(testConfig(), userTokens, nil, nil)

	// Test: Valid user token should work
	stream := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	stream.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:  "test123",
				TargetUrl: "http://localhost:8000",
				TunnelKey: "test-key",
				AuthToken: "tunn_sk_alice123", // Alice's token
			},
		},
	}
	close(stream.recvQueue)

	err := srv.EstablishTunnel(stream)
	if err != nil {
		t.Errorf("Expected no error with valid user token, got %v", err)
	}

	if len(stream.sentMsgs) < 1 {
		t.Fatal("Expected response to be sent")
	}

	regResp := stream.sentMsgs[0].GetRegisterResponse()
	if regResp == nil {
		t.Fatal("Expected RegisterResponse message")
	}

	if !regResp.Success {
		t.Errorf("Expected successful registration, got error: %s", regResp.ErrorMessage)
	}
}

func TestTunnelServerRejectsForgedJWT(t *testing.T) {
	// Server with JWT secret configured
	srv := NewTunnelServer(testConfig(), nil, nil, nil)

	// Create a forged JWT (signed with wrong key)
	// This simulates an attacker trying to claim they're a different user
	forgedJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImF0dGFja2VyQGV4YW1wbGUuY29tIn0.wrongsignature"

	stream := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	stream.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:  "test789",
				TargetUrl: "http://localhost:8000",
				TunnelKey: "test-key",
				AuthToken: forgedJWT, // Forged JWT
				// Note: no CreatorEmail, forcing JWT validation path
			},
		},
	}
	close(stream.recvQueue)

	err := srv.EstablishTunnel(stream)
	if err == nil {
		t.Error("Expected error for forged JWT")
	}

	if len(stream.sentMsgs) < 1 {
		t.Fatal("Expected error response to be sent")
	}

	regResp := stream.sentMsgs[0].GetRegisterResponse()
	if regResp == nil {
		t.Fatal("Expected RegisterResponse message")
	}

	if regResp.Success {
		t.Error("Expected registration to fail for forged JWT")
	}

	// Error message should mention token issue, not reveal internal details
	if regResp.ErrorMessage == "" {
		t.Error("Expected error message")
	}
}

func TestTunnelServerAcceptsValidJWT(t *testing.T) {
	// Create a valid JWT signed with the test secret
	cfg := testConfig()
	srv := NewTunnelServer(cfg, nil, nil, nil)

	// Create a properly signed JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": "valid@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	validJWT, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	stream := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	stream.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:  "validjwt",
				TargetUrl: "http://localhost:8000",
				TunnelKey: "test-key",
				AuthToken: validJWT,
			},
		},
	}
	close(stream.recvQueue)

	err = srv.EstablishTunnel(stream)
	if err != nil {
		t.Errorf("Expected no error with valid JWT, got %v", err)
	}

	if len(stream.sentMsgs) < 1 {
		t.Fatal("Expected response to be sent")
	}

	regResp := stream.sentMsgs[0].GetRegisterResponse()
	if regResp == nil {
		t.Fatal("Expected RegisterResponse message")
	}

	if !regResp.Success {
		t.Errorf("Expected successful registration with valid JWT, got error: %s", regResp.ErrorMessage)
	}
}
