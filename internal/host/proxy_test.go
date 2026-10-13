package host

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
)

func TestNewProxyServer(t *testing.T) {
	// Use test certificates from the certs directory
	cfg := &config.Config{
		Environment: config.EnvProd,
		Domain:      "tunn.to",
		CertFile:    "../../certs/cert.pem",
		KeyFile:     "../../certs/key.pem",
		HTTP2Addr:   ":18443",
		HTTP3Addr:   ":18443",
		NodeSecret:  "test-secret",
	}

	proxy, err := NewProxyServer(cfg)
	if err != nil {
		t.Skipf("Skipping test - certificates not available: %v", err)
		return
	}

	if proxy.Domain != "tunn.to" {
		t.Errorf("Expected domain tunn.to, got %s", proxy.Domain)
	}

	if proxy.HTTP2Addr != ":18443" {
		t.Errorf("Expected HTTP2Addr :18443, got %s", proxy.HTTP2Addr)
	}

	if proxy.HTTP3Addr != ":18443" {
		t.Errorf("Expected HTTP3Addr :18443, got %s", proxy.HTTP3Addr)
	}

	if proxy.tlsConfig == nil {
		t.Error("Expected TLS config to be initialized")
	}

	if proxy.mockOIDC != nil {
		t.Error("Expected no mock OIDC in prod mode")
	}
}

func TestNewProxyServerDevMode(t *testing.T) {
	// Test dev mode with mock OIDC
	cfg := &config.Config{
		Environment:    config.EnvDev,
		Domain:         "tunn.local.127.0.0.1.nip.io",
		CertFile:       "../../certs/cert.pem",
		KeyFile:        "../../certs/key.pem",
		HTTP2Addr:      ":18443",
		HTTP3Addr:      ":18443",
		NodeSecret:     "test-secret",
		MockOIDCAddr:   ":19000",
		MockOIDCIssuer: "http://localhost:19000",
	}

	proxy, err := NewProxyServer(cfg)
	if err != nil {
		t.Skipf("Skipping test - certificates not available: %v", err)
		return
	}

	if proxy.mockOIDC == nil {
		t.Error("Expected mock OIDC server to be configured in dev mode")
	}

	if proxy.config.IsDev() != true {
		t.Error("Expected IsDev to return true")
	}
}

func TestProxyServerHandler(t *testing.T) {
	cfg := &config.Config{
		Environment:  config.EnvProd,
		Domain:       "tunn.to",
		WellKnownKey: "test-key",
		JWTSecret:    "test-jwt-secret",
	}
	proxy := &ProxyServer{
		Domain:       "tunn.to",
		config:       cfg,
		tunnelServer: NewTunnelServer(cfg, nil, nil, nil),
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
	cfg := &config.Config{
		Environment:  config.EnvProd,
		Domain:       "tunn.to",
		WellKnownKey: "test-key",
		JWTSecret:    "test-jwt-secret",
	}
	proxy := &ProxyServer{
		Domain:       "tunn.to",
		config:       cfg,
		tunnelServer: NewTunnelServer(cfg, nil, nil, nil),
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

func TestHTTP3Advertisement(t *testing.T) {
	proxy := &ProxyServer{HTTP3Addr: "fly-global-services:443"}
	request := httptest.NewRequest(http.MethodGet, "https://example.com/health", nil)
	request.TLS = &tls.ConnectionState{}
	recorder := httptest.NewRecorder()
	proxy.advertiseHTTP3(recorder, request)
	if got := recorder.Header().Get("Alt-Svc"); got != `h3=":443"; ma=3600` {
		t.Fatalf("Alt-Svc = %q", got)
	}
	request.TLS = nil
	recorder = httptest.NewRecorder()
	proxy.advertiseHTTP3(recorder, request)
	if got := recorder.Header().Get("Alt-Svc"); got != "" {
		t.Fatalf("insecure request advertised HTTP/3: %q", got)
	}
}

func TestProxyServerRoutesAuthorityFormConnect(t *testing.T) {
	cfg := &config.Config{
		Environment: config.EnvProd,
		Domain:      "tunn.to",
	}
	proxy := &ProxyServer{
		Domain:       cfg.Domain,
		config:       cfg,
		tunnelServer: NewTunnelServer(cfg, nil, nil, nil),
	}

	request := httptest.NewRequest(http.MethodConnect, "https://offline.tunn.to/_tunn/connect", nil)
	request.Host = "offline.tunn.to"
	request.URL.Path = ""
	request.RequestURI = "offline.tunn.to:443"
	request.Header.Set("Tunn-Protocol", "tcp/1")
	recorder := httptest.NewRecorder()

	proxy.createHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("authority-form CONNECT status = %d, want tunnel router status 503", recorder.Code)
	}
}

func TestProxyServerRun(t *testing.T) {
	// This test verifies that the server can start and stop gracefully
	cfg := &config.Config{
		Environment: config.EnvProd,
		Domain:      "tunn.to",
		CertFile:    "../../certs/cert.pem",
		KeyFile:     "../../certs/key.pem",
		HTTP2Addr:   ":18443",
		HTTP3Addr:   ":18444",
		NodeSecret:  "test-secret",
	}

	proxy, err := NewProxyServer(cfg)
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

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:18443/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = cfg.Domain
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("HTTP/2 server connection attempt: %v (may be expected in test environment)", err)
	} else {
		defer func() { _ = resp.Body.Close() }()
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
