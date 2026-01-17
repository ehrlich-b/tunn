package host

import (
	"context"
	"testing"
	"time"

	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc/metadata"
)

func TestNewInternalServer(t *testing.T) {
	tunnelServer := NewTunnelServer("test-key", false, "tunn.to", "", nil)
	internalServer := NewInternalServer(tunnelServer, "node1.tunn.to:50051")

	if internalServer == nil {
		t.Fatal("Expected non-nil InternalServer")
	}
	if internalServer.tunnelServer != tunnelServer {
		t.Error("Expected tunnelServer to be set")
	}
	if internalServer.publicAddr != "node1.tunn.to:50051" {
		t.Errorf("Expected publicAddr 'node1.tunn.to:50051', got '%s'", internalServer.publicAddr)
	}
}

func TestFindTunnelExists(t *testing.T) {
	tunnelServer := NewTunnelServer("test-key", false, "tunn.to", "", nil)
	internalServer := NewInternalServer(tunnelServer, "node1.tunn.to:50051")

	// Add a tunnel directly
	tunnelServer.mu.Lock()
	tunnelServer.tunnels["test-tunnel"] = &TunnelConnection{
		TunnelID:  "test-tunnel",
		TargetURL: "http://localhost:8000",
		Connected: time.Now(),
	}
	tunnelServer.mu.Unlock()

	// Test finding the tunnel
	req := &internalv1.FindTunnelRequest{
		TunnelId: "test-tunnel",
	}
	resp, err := internalServer.FindTunnel(context.Background(), req)

	if err != nil {
		t.Fatalf("FindTunnel failed: %v", err)
	}
	if !resp.Found {
		t.Error("Expected tunnel to be found")
	}
	if resp.NodeAddress != "node1.tunn.to:50051" {
		t.Errorf("Expected NodeAddress 'node1.tunn.to:50051', got '%s'", resp.NodeAddress)
	}
}

func TestFindTunnelNotExists(t *testing.T) {
	tunnelServer := NewTunnelServer("test-key", false, "tunn.to", "", nil)
	internalServer := NewInternalServer(tunnelServer, "node1.tunn.to:50051")

	// Test finding a non-existent tunnel
	req := &internalv1.FindTunnelRequest{
		TunnelId: "nonexistent-tunnel",
	}
	resp, err := internalServer.FindTunnel(context.Background(), req)

	if err != nil {
		t.Fatalf("FindTunnel failed: %v", err)
	}
	if resp.Found {
		t.Error("Expected tunnel to NOT be found")
	}
	if resp.NodeAddress != "" {
		t.Errorf("Expected empty NodeAddress, got '%s'", resp.NodeAddress)
	}
}

func TestForwardUdpPacketTunnelNotFound(t *testing.T) {
	tunnelServer := NewTunnelServer("test-key", false, "tunn.to", "", nil)
	internalServer := NewInternalServer(tunnelServer, "node1.tunn.to:50051")

	req := &internalv1.ForwardUdpPacketRequest{
		TunnelId:      "nonexistent",
		SourceAddress: "192.168.1.1:12345",
		Data:          []byte("test data"),
	}

	resp, err := internalServer.ForwardUdpPacket(context.Background(), req)

	if err != nil {
		t.Fatalf("ForwardUdpPacket returned error: %v", err)
	}
	if resp.Success {
		t.Error("Expected Success=false for nonexistent tunnel")
	}
	if resp.ErrorMessage != "tunnel not found on this node" {
		t.Errorf("Expected 'tunnel not found on this node' error, got '%s'", resp.ErrorMessage)
	}
}

func TestForwardUdpPacketSendError(t *testing.T) {
	tunnelServer := NewTunnelServer("test-key", false, "tunn.to", "", nil)
	internalServer := NewInternalServer(tunnelServer, "node1.tunn.to:50051")

	// Create a mock stream that fails on Send
	mockStream := &mockInternalStream{
		sendErr: context.Canceled,
	}

	// Add a tunnel with the mock stream
	tunnelServer.mu.Lock()
	tunnelServer.tunnels["udp-test"] = &TunnelConnection{
		TunnelID:  "udp-test",
		TargetURL: "http://localhost:8000",
		Connected: time.Now(),
		Stream:    mockStream,
	}
	tunnelServer.mu.Unlock()

	req := &internalv1.ForwardUdpPacketRequest{
		TunnelId:      "udp-test",
		SourceAddress: "192.168.1.1:12345",
		Data:          []byte("test data"),
	}

	resp, err := internalServer.ForwardUdpPacket(context.Background(), req)

	if err != nil {
		t.Fatalf("ForwardUdpPacket returned error: %v", err)
	}
	if resp.Success {
		t.Error("Expected Success=false when Send fails")
	}
	if resp.ErrorMessage == "" {
		t.Error("Expected non-empty ErrorMessage when Send fails")
	}
}

func TestForwardUdpPacketContextCancelled(t *testing.T) {
	tunnelServer := NewTunnelServer("test-key", false, "tunn.to", "", nil)
	internalServer := NewInternalServer(tunnelServer, "node1.tunn.to:50051")

	// Create a mock stream that succeeds on Send
	mockStream := &mockInternalStream{}

	// Add a tunnel with the mock stream
	tunnelServer.mu.Lock()
	tunnelServer.tunnels["udp-cancel"] = &TunnelConnection{
		TunnelID:  "udp-cancel",
		TargetURL: "http://localhost:8000",
		Connected: time.Now(),
		Stream:    mockStream,
	}
	tunnelServer.mu.Unlock()

	// Create a pre-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := &internalv1.ForwardUdpPacketRequest{
		TunnelId:      "udp-cancel",
		SourceAddress: "192.168.1.1:12345",
		Data:          []byte("test data"),
	}

	resp, err := internalServer.ForwardUdpPacket(ctx, req)

	if err != nil {
		t.Fatalf("ForwardUdpPacket returned error: %v", err)
	}
	if resp.Success {
		t.Error("Expected Success=false when context is cancelled")
	}
	if resp.ErrorMessage != "context cancelled" {
		t.Errorf("Expected 'context cancelled' error, got '%s'", resp.ErrorMessage)
	}
}

// mockInternalStream implements pb.TunnelService_EstablishTunnelServer for internal testing
type mockInternalStream struct {
	sendErr  error
	sentMsgs []*pb.TunnelMessage
}

func (m *mockInternalStream) Send(msg *pb.TunnelMessage) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}

func (m *mockInternalStream) Recv() (*pb.TunnelMessage, error) {
	return nil, context.Canceled
}

func (m *mockInternalStream) SetHeader(md metadata.MD) error  { return nil }
func (m *mockInternalStream) SendHeader(md metadata.MD) error { return nil }
func (m *mockInternalStream) SetTrailer(md metadata.MD)       {}
func (m *mockInternalStream) Context() context.Context        { return context.Background() }
func (m *mockInternalStream) SendMsg(msg interface{}) error   { return nil }
func (m *mockInternalStream) RecvMsg(msg interface{}) error   { return nil }
