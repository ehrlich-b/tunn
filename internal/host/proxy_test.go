package host

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestNewProxyServer(t *testing.T) {
	// Use test certificates from the certs directory
	proxy, err := NewProxyServer("tunn.to", "../../certs/cert.pem", "../../certs/key.pem")
	if err != nil {
		t.Skipf("Skipping test - certificates not available: %v", err)
		return
	}

	if proxy.Domain != "tunn.to" {
		t.Errorf("Expected domain tunn.to, got %s", proxy.Domain)
	}

	if proxy.HTTP2Addr != ":8443" {
		t.Errorf("Expected HTTP2Addr :8443, got %s", proxy.HTTP2Addr)
	}

	if proxy.HTTP3Addr != ":8443" {
		t.Errorf("Expected HTTP3Addr :8443, got %s", proxy.HTTP3Addr)
	}

	if proxy.tlsConfig == nil {
		t.Error("Expected TLS config to be initialized")
	}
}

func TestProxyServerHandler(t *testing.T) {
	proxy := &ProxyServer{
		Domain: "tunn.to",
	}

	handler := proxy.createHandler()

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Use a test response recorder
	rec := &testResponseRecorder{
		header: make(http.Header),
		body:   []byte{},
	}

	handler.ServeHTTP(rec, req)

	if rec.statusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.statusCode)
	}
}

func TestProxyServerHealthCheck(t *testing.T) {
	proxy := &ProxyServer{
		Domain: "tunn.to",
	}

	handler := proxy.createHandler()

	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rec := &testResponseRecorder{
		header: make(http.Header),
		body:   []byte{},
	}

	handler.ServeHTTP(rec, req)

	if rec.statusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.statusCode)
	}

	if string(rec.body) != "ok" {
		t.Errorf("Expected body 'ok', got %s", string(rec.body))
	}
}

func TestProxyServerRun(t *testing.T) {
	// This test verifies that the server can start and stop gracefully
	proxy, err := NewProxyServer("tunn.to", "../../certs/cert.pem", "../../certs/key.pem")
	if err != nil {
		t.Skipf("Skipping test - certificates not available: %v", err)
		return
	}

	// Use non-standard ports for testing to avoid conflicts
	proxy.HTTP2Addr = ":18443"
	proxy.HTTP3Addr = ":18444"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- proxy.Run(ctx)
	}()

	// Give servers time to start
	time.Sleep(500 * time.Millisecond)

	// Try to connect to HTTP/2 server
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 1 * time.Second,
	}

	resp, err := client.Get("https://localhost:18443/health")
	if err != nil {
		t.Logf("HTTP/2 server connection attempt: %v (may be expected in test environment)", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected health check status 200, got %d", resp.StatusCode)
		}
	}

	// Cancel context to trigger shutdown
	cancel()

	// Wait for Run to complete
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			t.Errorf("Unexpected error from Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Server did not shut down within timeout")
	}
}

// testResponseRecorder is a simple implementation of http.ResponseWriter for testing
type testResponseRecorder struct {
	statusCode int
	header     http.Header
	body       []byte
}

func (r *testResponseRecorder) Header() http.Header {
	return r.header
}

func (r *testResponseRecorder) Write(b []byte) (int, error) {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}
	r.body = append(r.body, b...)
	return len(b), nil
}

func (r *testResponseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}
