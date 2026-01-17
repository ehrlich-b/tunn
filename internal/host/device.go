package host

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/golang-jwt/jwt/v4"
)

// DeviceCode represents a pending device authorization
type DeviceCode struct {
	Code      string    `json:"device_code"`
	UserCode  string    `json:"user_code"`
	ExpiresAt time.Time `json:"-"`
	Interval  int       `json:"interval"`

	// Set when user completes browser auth
	Authorized bool   `json:"-"`
	Email      string `json:"-"`
}

// DeviceCodeStore manages pending device codes
// TODO: Replace with SQLite for multi-node support via LiteFS
type DeviceCodeStore struct {
	mu    sync.RWMutex
	codes map[string]*DeviceCode // keyed by device_code
}

// NewDeviceCodeStore creates a new in-memory device code store
func NewDeviceCodeStore() *DeviceCodeStore {
	store := &DeviceCodeStore{
		codes: make(map[string]*DeviceCode),
	}
	// Start cleanup goroutine
	go store.cleanup()
	return store
}

// Create generates a new device code
func (s *DeviceCodeStore) Create() (*DeviceCode, error) {
	deviceCode, err := generateSecureCode(32)
	if err != nil {
		return nil, err
	}

	userCode, err := generateUserCode()
	if err != nil {
		return nil, err
	}

	code := &DeviceCode{
		Code:      deviceCode,
		UserCode:  userCode,
		ExpiresAt: time.Now().Add(3 * time.Minute),
		Interval:  3, // 3 second polling interval
	}

	s.mu.Lock()
	s.codes[deviceCode] = code
	s.mu.Unlock()

	return code, nil
}

// Get retrieves a device code by its code
func (s *DeviceCodeStore) Get(deviceCode string) *DeviceCode {
	s.mu.RLock()
	defer s.mu.RUnlock()

	code := s.codes[deviceCode]
	if code == nil {
		return nil
	}

	// Check expiration
	if time.Now().After(code.ExpiresAt) {
		return nil
	}

	return code
}

// GetByUserCode retrieves a device code by its user code
func (s *DeviceCodeStore) GetByUserCode(userCode string) *DeviceCode {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, code := range s.codes {
		if code.UserCode == userCode && time.Now().Before(code.ExpiresAt) {
			return code
		}
	}
	return nil
}

// Authorize marks a device code as authorized with the user's email
func (s *DeviceCodeStore) Authorize(deviceCode, email string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	code := s.codes[deviceCode]
	if code == nil || time.Now().After(code.ExpiresAt) {
		return false
	}

	code.Authorized = true
	code.Email = email
	return true
}

// Delete removes a device code
func (s *DeviceCodeStore) Delete(deviceCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, deviceCode)
}

// cleanup periodically removes expired codes
func (s *DeviceCodeStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for code, dc := range s.codes {
			if now.After(dc.ExpiresAt) {
				delete(s.codes, code)
			}
		}
		s.mu.Unlock()
	}
}

// generateSecureCode generates a cryptographically secure random string
func generateSecureCode(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:length], nil
}

// generateUserCode generates a short user-friendly code (e.g., "ABC-123")
func generateUserCode() (string, error) {
	// Use uppercase letters and digits, avoiding confusing chars (0, O, I, L)
	const charset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	code := make([]byte, 7) // 3 chars + hyphen + 3 chars
	for i := 0; i < 3; i++ {
		code[i] = charset[int(b[i])%len(charset)]
	}
	code[3] = '-'
	for i := 0; i < 3; i++ {
		code[i+4] = charset[int(b[i+3])%len(charset)]
	}

	return string(code), nil
}

// handleDeviceCode handles POST /api/device/code - creates a new device code
func (p *ProxyServer) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code, err := p.deviceCodes.Create()
	if err != nil {
		common.LogError("failed to create device code", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Build verification URLs
	scheme := "https"
	verificationURI := fmt.Sprintf("%s://%s/login", scheme, p.config.PublicAddr)
	verificationURIComplete := fmt.Sprintf("%s?code=%s", verificationURI, code.UserCode)

	resp := struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}{
		DeviceCode:              code.Code,
		UserCode:                code.UserCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		ExpiresIn:               180, // 3 minutes
		Interval:                code.Interval,
	}

	common.LogInfo("created device code", "user_code", code.UserCode)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		common.LogError("failed to encode device code response", "error", err)
	}
}

// handleDeviceToken handles GET /api/device/token - polls for token
func (p *ProxyServer) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	deviceCode := r.URL.Query().Get("code")
	if deviceCode == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing_code"})
		return
	}

	code := p.deviceCodes.Get(deviceCode)
	if code == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
		return
	}

	if !code.Authorized {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
		return
	}

	// Generate JWT for the authorized user
	token, err := p.generateJWT(code.Email)
	if err != nil {
		common.LogError("failed to generate JWT", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Clean up the device code
	p.deviceCodes.Delete(deviceCode)

	common.LogInfo("device code authorized", "email", code.Email)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   86400, // 24 hours
	}); err != nil {
		common.LogError("failed to encode token response", "error", err)
	}
}

// handleLoginPage handles GET /login - shows login page with device code
func (p *ProxyServer) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("code")

	// Verify the device code exists
	if userCode != "" {
		code := p.deviceCodes.GetByUserCode(userCode)
		if code == nil {
			http.Error(w, "Invalid or expired code", http.StatusBadRequest)
			return
		}
	}

	// Store device code in session for after OAuth
	if userCode != "" {
		p.sessionManager.Put(r.Context(), "device_user_code", userCode)
	}

	// Build GitHub OAuth URL and redirect
	p.handleLogin(w, r)
}

// generateJWT creates a signed JWT for the user
func (p *ProxyServer) generateJWT(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"sub":   email,
		"iss":   "tunn",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(p.getJWTSigningKey())
}

