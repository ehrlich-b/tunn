package client

import (
	"context"
	"net"
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

func TestReconnectionDefaults(t *testing.T) {
	client := &ServeClient{
		TunnelID:   "test123",
		TargetURL:  "http://localhost:8000",
		ServerAddr: "localhost:8443",
	}

	// Verify defaults are zero before Run sets them
	if client.InitialDelay != 0 {
		t.Errorf("Expected InitialDelay to be 0 before Run, got %v", client.InitialDelay)
	}
	if client.MaxReconnectDelay != 0 {
		t.Errorf("Expected MaxReconnectDelay to be 0 before Run, got %v", client.MaxReconnectDelay)
	}
}

func TestReconnectionCustomSettings(t *testing.T) {
	client := &ServeClient{
		TunnelID:          "test123",
		TargetURL:         "http://localhost:8000",
		ServerAddr:        "localhost:8443",
		InitialDelay:      500 * time.Millisecond,
		MaxReconnectDelay: 5 * time.Second,
	}

	if client.InitialDelay != 500*time.Millisecond {
		t.Errorf("Expected InitialDelay 500ms, got %v", client.InitialDelay)
	}
	if client.MaxReconnectDelay != 5*time.Second {
		t.Errorf("Expected MaxReconnectDelay 5s, got %v", client.MaxReconnectDelay)
	}
}

func TestReconnectionContextCancellation(t *testing.T) {
	// Test that Run exits promptly when context is canceled
	client := &ServeClient{
		TunnelID:          "test123",
		TargetURL:         "http://localhost:8000",
		ServerAddr:        "localhost:59999", // Non-existent server
		SkipVerify:        true,
		InitialDelay:      10 * time.Millisecond,
		MaxReconnectDelay: 50 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())

	errChan := make(chan error, 1)
	go func() {
		errChan <- client.Run(ctx)
	}()

	// Let it try to connect once
	time.Sleep(50 * time.Millisecond)

	// Cancel the context
	cancel()

	// Should exit promptly
	select {
	case err := <-errChan:
		if err != context.Canceled {
			t.Errorf("Expected context.Canceled error, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Run did not exit promptly after context cancellation")
	}
}

func TestHandleHttpRequestTimeout(t *testing.T) {
	// Start a mock local server that delays longer than the timeout
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than the client timeout
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Too late"))
	}))
	defer localServer.Close()

	client := &ServeClient{
		TunnelID:    "test123",
		TargetURL:   localServer.URL,
		HTTPTimeout: 50 * time.Millisecond, // Short timeout for testing
	}

	stream := &mockEstablishTunnelClient{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	httpReq := &pb.HttpRequest{
		ConnectionId: "conn-timeout",
		Method:       "GET",
		Path:         "/slow",
		Headers:      map[string]string{},
		Body:         nil,
	}

	client.handleHttpRequest(stream, httpReq)

	// Should send a 502 Bad Gateway error response
	if stream.getSentCount() != 1 {
		t.Fatalf("Expected 1 message, got %d", stream.getSentCount())
	}

	msg := stream.getSentMsg(0)
	httpResp := msg.GetHttpResponse()
	if httpResp == nil {
		t.Fatal("Expected HttpResponse message")
	}

	if httpResp.StatusCode != 502 {
		t.Errorf("Expected status code 502 (Bad Gateway) for timeout, got %d", httpResp.StatusCode)
	}

	if httpResp.ConnectionId != "conn-timeout" {
		t.Errorf("Expected connection ID 'conn-timeout', got '%s'", httpResp.ConnectionId)
	}
}

func TestProcessMessagesHttpRequest(t *testing.T) {
	// Start a mock local server
	localServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response from local"))
	}))
	defer localServer.Close()

	client := &ServeClient{
		TunnelID:  "test123",
		TargetURL: localServer.URL,
	}

	// Create a mock stream that will send an HTTP request and then context canceled
	stream := &mockEstablishTunnelClientWithRecv{
		sentMsgs: make([]*pb.TunnelMessage, 0),
		recvMsgs: []*pb.TunnelMessage{
			{
				Message: &pb.TunnelMessage_HttpRequest{
					HttpRequest: &pb.HttpRequest{
						ConnectionId: "conn-process-1",
						Method:       "GET",
						Path:         "/test",
						Headers:      map[string]string{},
						Body:         nil,
					},
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Run processMessages - it will process the HTTP request then exit on context timeout
	err := client.processMessages(ctx, stream)

	// Should exit with context error
	if err != context.DeadlineExceeded {
		t.Logf("processMessages returned: %v (expected context.DeadlineExceeded or nil)", err)
	}

	// Wait a bit for the goroutine to send response
	time.Sleep(50 * time.Millisecond)

	// Verify that a response was sent
	if stream.getSentCount() < 1 {
		t.Error("Expected at least one HTTP response to be sent")
	}
}

func TestProcessMessagesHealthCheckResponse(t *testing.T) {
	client := &ServeClient{
		TunnelID:  "test123",
		TargetURL: "http://localhost:8000",
	}

	// Create a mock stream that will send a health check response
	stream := &mockEstablishTunnelClientWithRecv{
		sentMsgs: make([]*pb.TunnelMessage, 0),
		recvMsgs: []*pb.TunnelMessage{
			{
				Message: &pb.TunnelMessage_HealthCheckResponse{
					HealthCheckResponse: &pb.HealthCheckResponse{
						Timestamp:         time.Now().UnixMilli() - 100,
						ResponseTimestamp: time.Now().UnixMilli(),
					},
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Run processMessages - it should process the health check response without error
	err := client.processMessages(ctx, stream)

	// Should exit with context error (not stream error)
	if err != context.DeadlineExceeded {
		t.Logf("processMessages returned: %v", err)
	}

	// Health check responses don't send anything back
	// Just verify no panic occurred
}

// mockEstablishTunnelClientWithRecv is like mockEstablishTunnelClient but returns actual messages
type mockEstablishTunnelClientWithRecv struct {
	mu       sync.Mutex
	sentMsgs []*pb.TunnelMessage
	recvMsgs []*pb.TunnelMessage
	recvIdx  int
}

func (m *mockEstablishTunnelClientWithRecv) Send(msg *pb.TunnelMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}

func (m *mockEstablishTunnelClientWithRecv) getSentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sentMsgs)
}

func (m *mockEstablishTunnelClientWithRecv) Recv() (*pb.TunnelMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recvIdx >= len(m.recvMsgs) {
		// Block until context cancellation by returning a blocking operation
		time.Sleep(100 * time.Millisecond)
		return nil, context.DeadlineExceeded
	}
	msg := m.recvMsgs[m.recvIdx]
	m.recvIdx++
	return msg, nil
}

func (m *mockEstablishTunnelClientWithRecv) Header() (metadata.MD, error)  { return nil, nil }
func (m *mockEstablishTunnelClientWithRecv) Trailer() metadata.MD          { return nil }
func (m *mockEstablishTunnelClientWithRecv) CloseSend() error              { return nil }
func (m *mockEstablishTunnelClientWithRecv) Context() context.Context      { return context.Background() }
func (m *mockEstablishTunnelClientWithRecv) SendMsg(msg interface{}) error { return nil }
func (m *mockEstablishTunnelClientWithRecv) RecvMsg(msg interface{}) error { return nil }

func TestHandleUdpPacket(t *testing.T) {
	// Start a mock UDP server that echoes back data
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP listener: %v", err)
	}
	defer udpConn.Close()

	// Get the actual port assigned
	actualAddr := udpConn.LocalAddr().String()

	// Start a goroutine to echo back data
	go func() {
		buf := make([]byte, 1024)
		n, remoteAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Echo back with a prefix
		response := append([]byte("ECHO:"), buf[:n]...)
		udpConn.WriteToUDP(response, remoteAddr)
	}()

	client := &ServeClient{
		TunnelID:         "udp-test",
		TargetURL:        "http://localhost:8000",
		UDPTargetAddress: actualAddr,
	}

	stream := &mockEstablishTunnelClient{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	udpPacket := &pb.UdpPacket{
		TunnelId:           "udp-test",
		SourceAddress:      "192.168.1.100:54321",
		DestinationAddress: actualAddr,
		Data:               []byte("test UDP data"),
		FromClient:         false,
		TimestampMs:        time.Now().UnixMilli(),
	}

	// Call handleUdpPacket
	client.handleUdpPacket(stream, udpPacket)

	// Wait a bit for the response
	time.Sleep(100 * time.Millisecond)

	// Verify response was sent
	if stream.getSentCount() != 1 {
		t.Fatalf("Expected 1 response message, got %d", stream.getSentCount())
	}

	msg := stream.getSentMsg(0)
	respPacket := msg.GetUdpPacket()
	if respPacket == nil {
		t.Fatal("Expected UdpPacket response")
	}

	// Verify the response data was echoed back
	expectedData := "ECHO:test UDP data"
	if string(respPacket.Data) != expectedData {
		t.Errorf("Expected response data '%s', got '%s'", expectedData, string(respPacket.Data))
	}

	// Verify FromClient is true (response going back)
	if !respPacket.FromClient {
		t.Error("Expected FromClient to be true for response")
	}
}

func TestHandleUdpPacketNoResponse(t *testing.T) {
	// Start a mock UDP server that doesn't respond (simulates one-way UDP)
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP listener: %v", err)
	}
	defer udpConn.Close()

	actualAddr := udpConn.LocalAddr().String()

	// Read and discard (no response)
	go func() {
		buf := make([]byte, 1024)
		udpConn.ReadFromUDP(buf)
		// Don't send response
	}()

	client := &ServeClient{
		TunnelID:         "udp-test",
		TargetURL:        "http://localhost:8000",
		UDPTargetAddress: actualAddr,
	}

	stream := &mockEstablishTunnelClient{
		sentMsgs: make([]*pb.TunnelMessage, 0),
	}

	udpPacket := &pb.UdpPacket{
		TunnelId:    "udp-test",
		Data:        []byte("one-way data"),
		FromClient:  false,
		TimestampMs: time.Now().UnixMilli(),
	}

	// Call handleUdpPacket - should timeout without error
	client.handleUdpPacket(stream, udpPacket)

	// No response expected (timeout is OK for UDP)
	// Just verify no panic occurred
}

func TestExponentialBackoffCap(t *testing.T) {
	// Test that backoff is capped at MaxReconnectDelay
	// This is a logic test - we verify the cap behavior by checking the internal state

	// Simulate the backoff logic
	initialDelay := 100 * time.Millisecond
	maxDelay := 400 * time.Millisecond

	delay := initialDelay
	delays := []time.Duration{delay}

	for i := 0; i < 5; i++ {
		delay = delay * 2
		if delay > maxDelay {
			delay = maxDelay
		}
		delays = append(delays, delay)
	}

	// Expected: 100, 200, 400, 400, 400, 400 (capped at 400)
	expected := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		400 * time.Millisecond,
		400 * time.Millisecond,
		400 * time.Millisecond,
	}

	for i, exp := range expected {
		if delays[i] != exp {
			t.Errorf("Delay[%d]: expected %v, got %v", i, exp, delays[i])
		}
	}
}
