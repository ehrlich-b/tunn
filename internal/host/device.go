package host

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/golang-jwt/jwt/v4"
)

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

	// Store device code in session for after OAuth/magic link
	if userCode != "" {
		p.sessionManager.Put(r.Context(), "device_user_code", userCode)
	}

	// Show the login page (with both GitHub and email options)
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
