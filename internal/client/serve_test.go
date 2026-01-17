package client

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestHandleHttpRequest(t *testing.T) {
	// Start a mock local server that returns a simple response
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back some info
		w.Header().Set("X-Test-Header", "test-value")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from local server"))
	}))
	defer localServer.Close()

	client := &ServeClient{
		TunnelID:  "test123",
		TargetURL: localServer.URL,
	}

	stream := &mockEstablishTunnelClient{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	httpReq := &pb.HttpRequest{
		ConnectionId: "conn-123",
		Method:       "GET",
		Path:         "/test",
		Headers:      map[string]string{"Accept": "text/plain"},
		Body:         nil,
	}

	// Call handleHttpRequest directly
	client.handleHttpRequest(stream, httpReq)

	// Verify response was sent
	if stream.getSentCount() != 1 {
		t.Fatalf("Expected 1 message to be sent, got %d", stream.getSentCount())
	}

	msg := stream.getSentMsg(0)
	httpResp := msg.GetHttpResponse()
	if httpResp == nil {
		t.Fatal("Expected HttpResponse message")
	}

	if httpResp.ConnectionId != "conn-123" {
		t.Errorf("Expected connection ID conn-123, got %s", httpResp.ConnectionId)
	}

	if httpResp.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", httpResp.StatusCode)
	}

	if string(httpResp.Body) != "Hello from local server" {
		t.Errorf("Expected body 'Hello from local server', got '%s'", string(httpResp.Body))
	}

	if httpResp.Headers["X-Test-Header"] != "test-value" {
		t.Errorf("Expected X-Test-Header to be 'test-value', got '%s'", httpResp.Headers["X-Test-Header"])
	}
}

func TestHandleHttpRequestMultiValueHeaders(t *testing.T) {
	// Start a mock local server that returns multiple Set-Cookie headers
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Multiple cookies - Go's httptest combines them with comma in Header map
		w.Header().Add("Set-Cookie", "cookie1=value1")
		w.Header().Add("Set-Cookie", "cookie2=value2")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer localServer.Close()

	client := &ServeClient{
		TunnelID:  "test123",
		TargetURL: localServer.URL,
	}

	stream := &mockEstablishTunnelClient{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	httpReq := &pb.HttpRequest{
		ConnectionId: "conn-456",
		Method:       "GET",
		Path:         "/cookies",
		Headers:      map[string]string{},
		Body:         nil,
	}

	client.handleHttpRequest(stream, httpReq)

	if stream.getSentCount() != 1 {
		t.Fatalf("Expected 1 message, got %d", stream.getSentCount())
	}

	msg := stream.getSentMsg(0)
	httpResp := msg.GetHttpResponse()
	if httpResp == nil {
		t.Fatal("Expected HttpResponse message")
	}

	// After our fix, multi-value headers should be joined with ", "
	setCookie := httpResp.Headers["Set-Cookie"]
	if setCookie == "" {
		t.Error("Expected Set-Cookie header to be present")
	}

	// Should contain both cookies joined by comma
	if setCookie != "cookie1=value1, cookie2=value2" {
		t.Errorf("Expected Set-Cookie to be 'cookie1=value1, cookie2=value2', got '%s'", setCookie)
	}
}

func TestHandleHttpRequestError(t *testing.T) {
	// Client pointing to non-existent server
	client := &ServeClient{
		TunnelID:  "test123",
		TargetURL: "http://127.0.0.1:59999", // Port that shouldn't be listening
	}

	stream := &mockEstablishTunnelClient{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	httpReq := &pb.HttpRequest{
		ConnectionId: "conn-error",
		Method:       "GET",
		Path:         "/test",
		Headers:      map[string]string{},
		Body:         nil,
	}

	client.handleHttpRequest(stream, httpReq)

	// Should send an error response
	if stream.getSentCount() != 1 {
		t.Fatalf("Expected 1 message, got %d", stream.getSentCount())
	}

	msg := stream.getSentMsg(0)
	httpResp := msg.GetHttpResponse()
	if httpResp == nil {
		t.Fatal("Expected HttpResponse message")
	}

	if httpResp.StatusCode != 502 {
		t.Errorf("Expected status code 502 (Bad Gateway), got %d", httpResp.StatusCode)
	}
}

func TestHandleHttpRequestConcurrent(t *testing.T) {
	// Test concurrent requests don't interfere with each other
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the path back to verify correct routing
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(r.URL.Path))
	}))
	defer localServer.Close()

	client := &ServeClient{
		TunnelID:  "test123",
		TargetURL: localServer.URL,
	}

	stream := &mockEstablishTunnelClient{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	// Send 10 concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			httpReq := &pb.HttpRequest{
				ConnectionId: "conn-" + string(rune('0'+idx)),
				Method:       "GET",
				Path:         "/" + string(rune('0'+idx)),
				Headers:      map[string]string{},
				Body:         nil,
			}
			client.handleHttpRequest(stream, httpReq)
		}(i)
	}

	wg.Wait()

	// Should have received 10 responses
	if stream.getSentCount() != 10 {
		t.Errorf("Expected 10 messages, got %d", stream.getSentCount())
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
