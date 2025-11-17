package host

import (
	"context"
	"io"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc/metadata"
)

func TestNewTunnelServer(t *testing.T) {
	srv := NewTunnelServer("test-key", false)
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
	srv := NewTunnelServer("test-key", false)

	// Create a mock stream
	stream := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	// Send registration message
	stream.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:     "test123",
				TargetUrl:    "http://localhost:8000",
				TunnelKey:    "test-key",
				CreatorEmail: "test@example.com",
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
	srv := NewTunnelServer("test-key", false)

	// First stream
	stream1 := &mockTunnelStream{
		recvQueue: make(chan *pb.TunnelMessage, 10),
		sentMsgs:  make([]*pb.TunnelMessage, 0),
	}

	stream1.recvQueue <- &pb.TunnelMessage{
		Message: &pb.TunnelMessage_RegisterClient{
			RegisterClient: &pb.RegisterClient{
				TunnelId:     "duplicate",
				TargetUrl:    "http://localhost:8000",
				TunnelKey:    "test-key",
				CreatorEmail: "test@example.com",
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
				TunnelId:     "duplicate",
				TargetUrl:    "http://localhost:9000",
				TunnelKey:    "test-key",
				CreatorEmail: "test@example.com",
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
	srv := NewTunnelServer("test-key", false)

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
	srv := NewTunnelServer("test-key", false)

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
