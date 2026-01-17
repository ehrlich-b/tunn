package host

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/mockoidc"
	"github.com/golang-jwt/jwt/v4"
)

func TestCheckJWT(t *testing.T) {
	// Create a mock OIDC server to get a signing key
	mockOIDC, err := mockoidc.New(mockoidc.Config{
		Addr:   ":0", // Use any available port
		Issuer: "http://localhost:9000",
	})
	if err != nil {
		t.Fatalf("Failed to create mock OIDC: %v", err)
	}

	// Create a test proxy server with mock OIDC
	proxy := &ProxyServer{
		Domain:         "tunn.local.127.0.0.1.nip.io",
		config:         &config.Config{Environment: config.EnvDev},
		sessionManager: scs.New(),
		mockOIDC:       mockOIDC,
	}

	// Create a test handler that should be called on successful auth
	var called bool
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := proxy.CheckJWT(testHandler)

	t.Run("valid JWT token", func(t *testing.T) {
		called = false

		// Create a valid JWT token
		claims := jwt.MapClaims{
			"iss":   "http://localhost:9000",
			"sub":   "test@example.com",
			"email": "test@example.com",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(mockOIDC.GetSigningKey())
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if !called {
			t.Error("Handler should have been called with valid JWT")
		}
		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("missing Authorization header", func(t *testing.T) {
		called = false

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if called {
			t.Error("Handler should not have been called without auth header")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("malformed Authorization header", func(t *testing.T) {
		called = false

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "NotBearer token")
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if called {
			t.Error("Handler should not have been called with malformed auth header")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("invalid JWT signature", func(t *testing.T) {
		called = false

		// Create a token with wrong signing key
		claims := jwt.MapClaims{
			"iss":   "http://localhost:9000",
			"sub":   "test@example.com",
			"email": "test@example.com",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("wrong-key"))
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if called {
			t.Error("Handler should not have been called with invalid signature")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("expired JWT token", func(t *testing.T) {
		called = false

		// Create an expired token
		claims := jwt.MapClaims{
			"iss":   "http://localhost:9000",
			"sub":   "test@example.com",
			"email": "test@example.com",
			"exp":   time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
			"iat":   time.Now().Add(-2 * time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(mockOIDC.GetSigningKey())
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if called {
			t.Error("Handler should not have been called with expired token")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("missing email claim", func(t *testing.T) {
		called = false

		// Create a token without email claim
		claims := jwt.MapClaims{
			"iss": "http://localhost:9000",
			"sub": "test@example.com",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(mockOIDC.GetSigningKey())
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if called {
			t.Error("Handler should not have been called without email claim")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("wrong signing method", func(t *testing.T) {
		called = false

		// Try to create a token with RS256 (should fail validation)
		claims := jwt.MapClaims{
			"iss":   "http://localhost:9000",
			"sub":   "test@example.com",
			"email": "test@example.com",
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		}

		// Create a token header that claims to use RS256
		// but we'll still sign with HS256 (simulating a malicious token)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Manually set the header to claim RS256
		token.Header["alg"] = "RS256"
		tokenString, err := token.SignedString(mockOIDC.GetSigningKey())
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if called {
			t.Error("Handler should not have been called with wrong signing method")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})

	t.Run("malformed JWT token", func(t *testing.T) {
		called = false

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer not.a.valid.jwt.token")
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if called {
			t.Error("Handler should not have been called with malformed JWT")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}
	})
}

func TestGetJWTSigningKey(t *testing.T) {
	t.Run("dev mode with mock OIDC", func(t *testing.T) {
		mockOIDC, err := mockoidc.New(mockoidc.Config{
			Addr:   ":0",
			Issuer: "http://localhost:9000",
		})
		if err != nil {
			t.Fatalf("Failed to create mock OIDC: %v", err)
		}

		proxy := &ProxyServer{
			config:   &config.Config{Environment: config.EnvDev},
			mockOIDC: mockOIDC,
		}

		key := proxy.getJWTSigningKey()
		if len(key) == 0 {
			t.Error("Expected non-empty signing key in dev mode")
		}

		// Verify it's the same key as the mock OIDC
		if string(key) != string(mockOIDC.GetSigningKey()) {
			t.Error("Expected signing key to match mock OIDC key")
		}
	})

	t.Run("production mode with JWT secret", func(t *testing.T) {
		proxy := &ProxyServer{
			config: &config.Config{
				Environment: config.EnvProd,
				JWTSecret:   "my-prod-secret",
			},
			mockOIDC: nil,
		}

		key := proxy.getJWTSigningKey()
		if string(key) != "my-prod-secret" {
			t.Errorf("Expected configured secret, got %s", string(key))
		}
	})

	t.Run("production mode without JWT secret", func(t *testing.T) {
		proxy := &ProxyServer{
			config:   &config.Config{Environment: config.EnvProd},
			mockOIDC: nil,
		}

		key := proxy.getJWTSigningKey()
		if len(key) == 0 {
			t.Error("Expected non-empty signing key in prod mode")
		}

		// Without JWT_SECRET, returns fallback
		if string(key) != "unconfigured-jwt-secret" {
			t.Errorf("Expected fallback, got %s", string(key))
		}
	})
}

func TestExtractTunnelID(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		domain   string
		want     string
	}{
		{
			name:     "valid subdomain",
			hostname: "abc123.tunn.to",
			domain:   "tunn.to",
			want:     "abc123",
		},
		{
			name:     "valid subdomain with port",
			hostname: "abc123.tunn.to:8443",
			domain:   "tunn.to",
			want:     "abc123",
		},
		{
			name:     "apex domain",
			hostname: "tunn.to",
			domain:   "tunn.to",
			want:     "",
		},
		{
			name:     "www subdomain",
			hostname: "www.tunn.to",
			domain:   "tunn.to",
			want:     "",
		},
		{
			name:     "different domain",
			hostname: "example.com",
			domain:   "tunn.to",
			want:     "",
		},
		{
			name:     "nested subdomain",
			hostname: "foo.bar.tunn.to",
			domain:   "tunn.to",
			want:     "foo.bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTunnelID(tt.hostname, tt.domain)
			if got != tt.want {
				t.Errorf("extractTunnelID(%q, %q) = %q, want %q",
					tt.hostname, tt.domain, got, tt.want)
			}
		})
	}
}
