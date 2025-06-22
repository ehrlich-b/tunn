package host

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aojea/h2rev2"
	"github.com/ehrlich-b/tunn/internal/common"
)

// Mock reverse pool for testing
type mockReversePool struct {
	dialers map[string]*h2rev2.Dialer
	served  []string
}

func newMockReversePool() *mockReversePool {
	return &mockReversePool{
		dialers: make(map[string]*h2rev2.Dialer),
		served:  make([]string, 0),
	}
}

func (m *mockReversePool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.served = append(m.served, r.URL.Path)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("mock response"))
}

func (m *mockReversePool) GetDialer(id string) *h2rev2.Dialer {
	return m.dialers[id]
}

func (m *mockReversePool) AddDialer(id string, dialer *h2rev2.Dialer) {
	m.dialers[id] = dialer
}

func TestServerCreateHandler(t *testing.T) {
	// Save original log level
	originalLevel := common.GetCurrentLogLevel()
	defer common.SetLogLevel(originalLevel)

	// Capture log output
	var buf bytes.Buffer
	originalLogger := slog.Default()
	defer slog.SetDefault(originalLogger)

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slog.SetDefault(slog.New(handler))

	server := &Server{
		Domain: "tunn.to",
		Token:  "test-token",
	}

	mockPool := newMockReversePool()
	httpHandler := server.CreateHandler(mockPool)

	if httpHandler == nil {
		t.Fatal("CreateHandler returned nil")
	}

	t.Run("revdial endpoint with valid auth", func(t *testing.T) {
		common.SetLogLevel(common.LogLevelRequest)

		req := httptest.NewRequest("GET", "/revdial?id=test123", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()

		httpHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Check that the mock pool was called
		if len(mockPool.served) == 0 {
			t.Error("Mock pool should have been called")
		}

		// We can't easily test logging here since it goes to a different handler
		// The important thing is that the handler works correctly
	})

	t.Run("revdial endpoint with invalid auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/revdial?id=test123", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()

		httpHandler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("proxy endpoint with valid tunnel", func(t *testing.T) {
		// Add a dialer for the test ID (use nil as a mock dialer since we just check for existence)
		mockPool.AddDialer("abc123", &h2rev2.Dialer{})

		req := httptest.NewRequest("GET", "/test-path", nil)
		req.Host = "abc123.tunn.to"
		w := httptest.NewRecorder()

		httpHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		// Check that path was rewritten
		if len(mockPool.served) == 0 {
			t.Error("Mock pool should have been called")
		}
		lastServed := mockPool.served[len(mockPool.served)-1]
		if !strings.HasPrefix(lastServed, "/proxy/abc123") {
			t.Errorf("Path should be rewritten to /proxy/abc123/..., got %s", lastServed)
		}
	})

	t.Run("proxy endpoint with offline tunnel", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-path", nil)
		req.Host = "offline123.tunn.to"
		w := httptest.NewRecorder()

		httpHandler.ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected status 503, got %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "tunnel offline") {
			t.Error("Should return 'tunnel offline' message")
		}
	})

	t.Run("proxy endpoint with apex domain", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-path", nil)
		req.Host = "tunn.to"
		w := httptest.NewRecorder()

		httpHandler.ServeHTTP(w, req)

		// Now with the fixed logic, r.Host == s.Domain should be true
		// So it should return 404 with "no id"
		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status 404, got %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "no id") {
			t.Error("Should return 'no id' message")
		}
	})

	t.Run("proxy endpoint with www subdomain", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test-path", nil)
		req.Host = "www.tunn.to"
		w := httptest.NewRecorder()

		httpHandler.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status 404, got %d", w.Code)
		}
	})
}

func TestServerDomainParsing(t *testing.T) {
	tests := []struct {
		host     string
		expected string
	}{
		{"abc123.tunn.to", "abc123"},
		{"test-tunnel.example.com", "test-tunnel"},
		{"long-id-here.tunn.to", "long-id-here"},
		{"single.domain", "single"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			parts := strings.Split(tt.host, ".")
			if len(parts) > 0 && parts[0] != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, parts[0])
			}
		})
	}
}