// Package mockoidc provides a lightweight mock OIDC provider for local testing.
// It simulates Google login and OAuth Device Authorization Grant flows.
package mockoidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Server is a mock OIDC provider for local testing
type Server struct {
	addr       string
	issuer     string
	signingKey []byte
	mu         sync.RWMutex
	// deviceCodes maps device_code to device auth data
	deviceCodes map[string]*DeviceAuthData
	// userCodes maps user_code to device_code for easy lookup
	userCodes map[string]string
}

// DeviceAuthData stores the state of a device authorization flow
type DeviceAuthData struct {
	DeviceCode      string
	UserCode        string
	VerificationURI string
	ExpiresAt       time.Time
	Interval        int
	// Authorized is true once the user has completed the flow
	Authorized bool
	UserEmail  string
}

// Config configures the mock OIDC server
type Config struct {
	Addr   string
	Issuer string
}

// New creates a new mock OIDC server
func New(cfg Config) (*Server, error) {
	// Generate a random signing key for JWTs
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate signing key: %w", err)
	}

	return &Server{
		addr:        cfg.Addr,
		issuer:      cfg.Issuer,
		signingKey:  key,
		deviceCodes: make(map[string]*DeviceAuthData),
		userCodes:   make(map[string]string),
	}, nil
}

// Start starts the mock OIDC server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// OIDC discovery endpoint
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)

	// OAuth endpoints
	mux.HandleFunc("/oauth/device/code", s.handleDeviceCode)
	mux.HandleFunc("/oauth/token", s.handleToken)
	mux.HandleFunc("/oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth/callback", s.handleCallback)

	// Device verification endpoint (user visits this)
	mux.HandleFunc("/device", s.handleDeviceVerification)

	return http.ListenAndServe(s.addr, mux)
}

// handleDiscovery serves the OIDC discovery document
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/oauth/authorize",
		"token_endpoint":                        s.issuer + "/oauth/token",
		"device_authorization_endpoint":         s.issuer + "/oauth/device/code",
		"userinfo_endpoint":                     s.issuer + "/oauth/userinfo",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"HS256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

// handleDeviceCode implements the device authorization endpoint
func (s *Server) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate codes
	deviceCode := generateCode(32)
	userCode := generateUserCode()

	data := &DeviceAuthData{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: s.issuer + "/device",
		ExpiresAt:       time.Now().Add(15 * time.Minute),
		Interval:        5,
		Authorized:      false,
	}

	s.mu.Lock()
	s.deviceCodes[deviceCode] = data
	s.userCodes[userCode] = deviceCode
	s.mu.Unlock()

	resp := map[string]interface{}{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          data.VerificationURI,
		"verification_uri_complete": fmt.Sprintf("%s?user_code=%s", data.VerificationURI, userCode),
		"expires_in":                int(time.Until(data.ExpiresAt).Seconds()),
		"interval":                  data.Interval,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleToken implements the token endpoint for both device flow and auth code flow
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "urn:ietf:params:oauth:grant-type:device_code":
		s.handleDeviceTokenRequest(w, r)
	case "authorization_code":
		s.handleAuthCodeTokenRequest(w, r)
	default:
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
	}
}

func (s *Server) handleDeviceTokenRequest(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.FormValue("device_code")

	s.mu.RLock()
	data, exists := s.deviceCodes[deviceCode]
	s.mu.RUnlock()

	if !exists {
		errorResp := map[string]string{"error": "invalid_grant"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResp)
		return
	}

	if time.Now().After(data.ExpiresAt) {
		errorResp := map[string]string{"error": "expired_token"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResp)
		return
	}

	if !data.Authorized {
		errorResp := map[string]string{"error": "authorization_pending"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResp)
		return
	}

	// Issue access token
	token := s.issueToken(data.UserEmail)

	resp := map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleAuthCodeTokenRequest(w http.ResponseWriter, r *http.Request) {
	// Simplified auth code flow - just issue a token
	// In a real implementation, you'd validate the auth code
	token := s.issueToken("test@example.com")

	resp := map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleAuthorize handles the web-based OAuth authorization flow
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// For the mock, we auto-approve and redirect back
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")

	if redirectURI == "" {
		http.Error(w, "Missing redirect_uri", http.StatusBadRequest)
		return
	}

	// Generate a fake auth code
	authCode := generateCode(16)

	// Redirect back with the code
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, authCode, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleCallback handles the OAuth callback (for web flows)
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "Authorization successful! Code: %s", code)
}

// handleDeviceVerification shows the device verification page
func (s *Server) handleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		userCode := r.URL.Query().Get("user_code")
		html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><title>Device Verification</title></head>
<body>
<h1>Mock OIDC Device Verification</h1>
<form method="POST">
<label>Enter code: <input type="text" name="user_code" value="%s" required></label><br><br>
<label>Email: <input type="email" name="email" value="test@example.com" required></label><br><br>
<button type="submit">Authorize</button>
</form>
</body>
</html>
`, userCode)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		userCode := r.FormValue("user_code")
		email := r.FormValue("email")

		s.mu.Lock()
		deviceCode, exists := s.userCodes[userCode]
		if exists {
			if data, ok := s.deviceCodes[deviceCode]; ok {
				data.Authorized = true
				data.UserEmail = email
			}
		}
		s.mu.Unlock()

		if !exists {
			http.Error(w, "Invalid user code", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
<!DOCTYPE html>
<html>
<head><title>Success</title></head>
<body>
<h1>Device Authorized!</h1>
<p>You can now close this window and return to your device.</p>
</body>
</html>
`))
	}
}

// issueToken creates a JWT for the given email
func (s *Server) issueToken(email string) string {
	claims := jwt.MapClaims{
		"iss":   s.issuer,
		"sub":   email,
		"email": email,
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(s.signingKey)
	return tokenString
}

// GetSigningKey returns the signing key (for token validation in tests)
func (s *Server) GetSigningKey() []byte {
	return s.signingKey
}

func generateCode(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

func generateUserCode() string {
	// Generate a human-friendly code like "ABCD-EFGH"
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return fmt.Sprintf("%s-%s", string(b[:4]), string(b[4:]))
}
