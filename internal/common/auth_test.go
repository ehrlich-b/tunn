package common

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthMiddleware(t *testing.T) {
	// Save original state
	originalLevel := currentLogLevel
	defer func() {
		currentLogLevel = originalLevel
	}()

	token := "test-token-123"
	middleware := AuthMiddleware(token)

	// Test handler that should be called on successful auth
	called := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := middleware(testHandler)

	t.Run("valid token", func(t *testing.T) {
		called = false
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer test-token-123")
		w := httptest.NewRecorder()

		wrappedHandler(w, req)

		if !called {
			t.Error("Handler should have been called with valid token")
		}
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		called = false
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()

		wrappedHandler(w, req)

		if called {
			t.Error("Handler should not have been called with invalid token")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("missing token", func(t *testing.T) {
		called = false
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		wrappedHandler(w, req)

		if called {
			t.Error("Handler should not have been called with missing token")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("malformed authorization header", func(t *testing.T) {
		called = false
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "NotBearer test-token-123")
		w := httptest.NewRecorder()

		wrappedHandler(w, req)

		if called {
			t.Error("Handler should not have been called with malformed auth header")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})
}

func TestLogAuthTransport(t *testing.T) {
	// Save original state
	originalLevel := currentLogLevel
	defer func() {
		currentLogLevel = originalLevel
	}()

	// Capture log output
	var buf bytes.Buffer
	originalLogger := slog.Default()
	defer slog.SetDefault(originalLogger)

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slog.SetDefault(slog.New(handler))

	// Mock transport
	mockTransport := &mockRoundTripper{
		response: &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("test response")),
		},
	}

	transport := &LogAuthTransport{
		Transport: mockTransport,
		Token:     "test-token",
	}

	t.Run("successful request", func(t *testing.T) {
		currentLogLevel = LogLevelTrace
		buf.Reset()

		req := httptest.NewRequest("GET", "https://example.com/test", nil)
		resp, err := transport.RoundTrip(req)

		if err != nil {
			t.Errorf("RoundTrip failed: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		// Check that Authorization header was set
		if auth := req.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("Expected Authorization header 'Bearer test-token', got '%s'", auth)
		}

		// Check logging
		output := buf.String()
		if !strings.Contains(output, "sending request") {
			t.Error("Request logging not working")
		}
		if !strings.Contains(output, "response received") {
			t.Error("Response logging not working")
		}
	})

	t.Run("failed request", func(t *testing.T) {
		currentLogLevel = LogLevelTrace
		buf.Reset()

		failingTransport := &mockRoundTripper{
			error: http.ErrServerClosed,
		}
		transport := &LogAuthTransport{
			Transport: failingTransport,
			Token:     "test-token",
		}

		req := httptest.NewRequest("GET", "https://example.com/test", nil)
		_, err := transport.RoundTrip(req)

		if err == nil {
			t.Error("Expected error from failing transport")
		}

		// Check error logging
		output := buf.String()
		if !strings.Contains(output, "request failed") {
			t.Error("Error logging not working")
		}
	})

	t.Run("unauthorized response", func(t *testing.T) {
		currentLogLevel = LogLevelTrace
		buf.Reset()

		mockTransport := &mockRoundTripper{
			response: &http.Response{
				StatusCode: 401,
				Status:     "401 Unauthorized",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("unauthorized")),
			},
		}

		transport := &LogAuthTransport{
			Transport: mockTransport,
			Token:     "test-token",
		}

		req := httptest.NewRequest("GET", "https://example.com/test", nil)
		resp, err := transport.RoundTrip(req)

		if err != nil {
			t.Errorf("RoundTrip failed: %v", err)
		}
		if resp.StatusCode != 401 {
			t.Errorf("Expected status 401, got %d", resp.StatusCode)
		}

		// Check auth failure logging
		output := buf.String()
		if !strings.Contains(output, "authentication failure") {
			t.Error("Auth failure logging not working")
		}
	})
}

// Mock transport for testing
type mockRoundTripper struct {
	response *http.Response
	error    error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.error != nil {
		return nil, m.error
	}
	return m.response, nil
}