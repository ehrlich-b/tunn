package host

import (
	"context"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
)

func internalTestConfig() *config.Config {
	return &config.Config{
		WellKnownKey: "test-key",
		PublicMode:   false,
		Domain:       "tunn.to",
		JWTSecret:    "test-jwt-secret",
	}
}

func TestNewInternalServer(t *testing.T) {
	tunnelServer := NewTunnelServer(internalTestConfig(), nil, nil, nil)
	internalServer := NewInternalServer(tunnelServer, "node1.tunn.to:50051", false)

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
	tunnelServer := NewTunnelServer(internalTestConfig(), nil, nil, nil)
	internalServer := NewInternalServer(tunnelServer, "node1.tunn.to:50051", false)

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
	tunnelServer := NewTunnelServer(internalTestConfig(), nil, nil, nil)
	internalServer := NewInternalServer(tunnelServer, "node1.tunn.to:50051", false)

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
