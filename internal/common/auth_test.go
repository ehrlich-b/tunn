package common

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestAuthMiddleware(t *testing.T) {
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
		req := httptest.NewRequest("GET", "https://example.com/test", nil)
		resp, err := transport.RoundTrip(req)

		if err != nil {
			t.Errorf("RoundTrip failed: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("got status %d, want 200", resp.StatusCode)
		}

		if auth := req.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("got auth header %q, want %q", auth, "Bearer test-token")
		}
	})

	t.Run("failed request", func(t *testing.T) {
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
			t.Error("expected error from failing transport")
		}
	})

	t.Run("unauthorized response", func(t *testing.T) {
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
			t.Errorf("got status %d, want 401", resp.StatusCode)
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

func TestExtractEmailFromJWT(t *testing.T) {
	// Helper to create a signed JWT with given claims
	createJWT := func(claims jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Sign with a test key (signature validation is skipped in ExtractEmailFromJWT)
		tokenString, _ := token.SignedString([]byte("test-secret"))
		return tokenString
	}

	t.Run("valid JWT with email", func(t *testing.T) {
		tokenString := createJWT(jwt.MapClaims{
			"email": "user@example.com",
			"sub":   "123456",
		})

		email, err := ExtractEmailFromJWT(tokenString)
		if err != nil {
			t.Fatalf("ExtractEmailFromJWT failed: %v", err)
		}
		if email != "user@example.com" {
			t.Errorf("Expected email 'user@example.com', got '%s'", email)
		}
	})

	t.Run("JWT without email claim", func(t *testing.T) {
		tokenString := createJWT(jwt.MapClaims{
			"sub":  "123456",
			"name": "Test User",
		})

		_, err := ExtractEmailFromJWT(tokenString)
		if err == nil {
			t.Error("Expected error for JWT without email claim")
		}
		if !strings.Contains(err.Error(), "email claim not found") {
			t.Errorf("Expected 'email claim not found' error, got: %v", err)
		}
	})

	t.Run("JWT with empty email", func(t *testing.T) {
		tokenString := createJWT(jwt.MapClaims{
			"email": "",
			"sub":   "123456",
		})

		_, err := ExtractEmailFromJWT(tokenString)
		if err == nil {
			t.Error("Expected error for JWT with empty email")
		}
	})

	t.Run("JWT with non-string email", func(t *testing.T) {
		tokenString := createJWT(jwt.MapClaims{
			"email": 12345, // Not a string
			"sub":   "123456",
		})

		_, err := ExtractEmailFromJWT(tokenString)
		if err == nil {
			t.Error("Expected error for JWT with non-string email")
		}
	})

	t.Run("invalid JWT format", func(t *testing.T) {
		_, err := ExtractEmailFromJWT("not-a-valid-jwt")
		if err == nil {
			t.Error("Expected error for invalid JWT")
		}
		if !strings.Contains(err.Error(), "failed to parse JWT") {
			t.Errorf("Expected 'failed to parse JWT' error, got: %v", err)
		}
	})

	t.Run("malformed JWT segments", func(t *testing.T) {
		// Valid base64 but invalid JWT structure
		_, err := ExtractEmailFromJWT("eyJhbGciOiJIUzI1NiJ9.invalidpayload.signature")
		if err == nil {
			t.Error("Expected error for malformed JWT")
		}
	})

	t.Run("JWT with additional claims", func(t *testing.T) {
		tokenString := createJWT(jwt.MapClaims{
			"email":          "admin@company.com",
			"sub":            "user-id-789",
			"name":           "Admin User",
			"email_verified": true,
			"iss":            "https://auth.example.com",
			"aud":            "tunn-client",
		})

		email, err := ExtractEmailFromJWT(tokenString)
		if err != nil {
			t.Fatalf("ExtractEmailFromJWT failed: %v", err)
		}
		if email != "admin@company.com" {
			t.Errorf("Expected email 'admin@company.com', got '%s'", email)
		}
	})

	t.Run("empty token string", func(t *testing.T) {
		_, err := ExtractEmailFromJWT("")
		if err == nil {
			t.Error("Expected error for empty token string")
		}
	})

	t.Run("JWT with only header and payload (no signature)", func(t *testing.T) {
		// Create a JWT-like string with header.payload but no signature
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"test@test.com"}`))
		tokenString := header + "." + payload + "."

		// This should still work since we use ParseUnverified
		email, err := ExtractEmailFromJWT(tokenString)
		if err != nil {
			t.Fatalf("ExtractEmailFromJWT failed for unsigned JWT: %v", err)
		}
		if email != "test@test.com" {
			t.Errorf("Expected email 'test@test.com', got '%s'", email)
		}
	})
}
