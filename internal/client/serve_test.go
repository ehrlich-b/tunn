package client

import (
	"context"
	"sync"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc/metadata"
)

func TestServeClientBasic(t *testing.T) {
	client := &ServeClient{
		TunnelID:   "test123",
		TargetURL:  "http://localhost:8000",
		ServerAddr: "localhost:8443",
		AuthToken:  "secret",
		SkipVerify: true,
	}

	if client.TunnelID != "test123" {
		t.Errorf("Expected tunnel ID test123, got %s", client.TunnelID)
	}

	if client.TargetURL != "http://localhost:8000" {
		t.Errorf("Expected target URL http://localhost:8000, got %s", client.TargetURL)
	}
}

func TestHandleProxyRequest(t *testing.T) {
	client := &ServeClient{
		TunnelID:  "test123",
		TargetURL: "http://localhost:8000",
	}

	stream := &mockEstablishTunnelClient{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	req := &pb.ProxyRequest{
		ConnectionId:  "conn123",
		SourceAddress: "192.168.1.1",
	}

	client.handleProxyRequest(stream, req)

	if stream.getSentCount() != 1 {
		t.Fatalf("Expected 1 message to be sent, got %d", stream.getSentCount())
	}

	msg := stream.getSentMsg(0)
	if msg == nil {
		t.Fatal("Expected message at index 0")
	}

	resp := msg.GetProxyResponse()
	if resp == nil {
		t.Fatal("Expected ProxyResponse message")
	}

	if resp.ConnectionId != "conn123" {
		t.Errorf("Expected connection ID conn123, got %s", resp.ConnectionId)
	}

	if !resp.Success {
		t.Error("Expected successful proxy response")
	}
}

func TestSendHealthChecks(t *testing.T) {
	stream := &mockEstablishTunnelClient{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Run health check sender with very short interval
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
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
				stream.Send(msg)
			}
		}
	}()

	// Wait for context to expire
	<-ctx.Done()

	// Should have sent at least one health check
	if stream.getSentCount() < 1 {
		t.Error("Expected at least one health check to be sent")
	}

	// Verify it's a health check message
	msg := stream.getSentMsg(0)
	if msg == nil {
		t.Fatal("Expected message at index 0")
	}

	hc := msg.GetHealthCheck()
	if hc == nil {
		t.Error("Expected HealthCheck message")
	}

	if hc.Timestamp == 0 {
		t.Error("Expected non-zero timestamp")
	}
}

// mockEstablishTunnelClient implements pb.TunnelService_EstablishTunnelClient for testing
type mockEstablishTunnelClient struct {
	mu       sync.Mutex
	sentMsgs []*pb.TunnelMessage
	recvMsgs []*pb.TunnelMessage
	recvIdx  int
}

func (m *mockEstablishTunnelClient) Send(msg *pb.TunnelMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}

func (m *mockEstablishTunnelClient) getSentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sentMsgs)
}

func (m *mockEstablishTunnelClient) getSentMsg(idx int) *pb.TunnelMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx >= len(m.sentMsgs) {
		return nil
	}
	return m.sentMsgs[idx]
}

func (m *mockEstablishTunnelClient) Recv() (*pb.TunnelMessage, error) {
	if m.recvIdx >= len(m.recvMsgs) {
		return nil, context.Canceled
	}
	msg := m.recvMsgs[m.recvIdx]
	m.recvIdx++
	return msg, nil
}

func (m *mockEstablishTunnelClient) Header() (metadata.MD, error)  { return nil, nil }
func (m *mockEstablishTunnelClient) Trailer() metadata.MD          { return nil }
func (m *mockEstablishTunnelClient) CloseSend() error              { return nil }
func (m *mockEstablishTunnelClient) Context() context.Context      { return context.Background() }
func (m *mockEstablishTunnelClient) SendMsg(msg interface{}) error { return nil }
func (m *mockEstablishTunnelClient) RecvMsg(msg interface{}) error { return nil }
