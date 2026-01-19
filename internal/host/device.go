package host

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/golang-jwt/jwt/v4"
)

// Device code rate limiting constants
const (
	deviceCodeRateWindow   = 5 * time.Minute
	deviceCodeRateMaxCount = 5 // 5 device codes per 5 minutes per IP
)

// handleDeviceCode handles POST /api/device/code - creates a new device code
func (p *ProxyServer) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit by IP address
	clientIP := extractClientIP(r)
	if !p.checkDeviceCodeRateLimit(clientIP) {
		common.LogInfo("device code rate limit exceeded", "ip", clientIP)
		http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
		return
	}

	if !p.storage.Available() {
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	code, err := p.storage.CreateDeviceCode(r.Context())
	if err != nil {
		common.LogError("failed to create device code", "error", err)
		if err == storage.ErrNotAvailable {
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
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

	if !p.storage.Available() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "service_unavailable"})
		return
	}

	code, err := p.storage.GetDeviceCode(r.Context(), deviceCode)
	if err != nil {
		common.LogError("failed to get device code", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal_error"})
		return
	}
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

	// Device code will expire naturally - no explicit delete needed

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
		if !p.storage.Available() {
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		deviceCode, err := p.storage.GetDeviceCodeByUserCode(r.Context(), userCode)
		if err != nil {
			common.LogError("failed to get device code", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if deviceCode == nil {
			http.Error(w, "Invalid or expired code", http.StatusBadRequest)
			return
		}

		// If user is already logged in, show device authorization page
		if p.isAuthenticated(r) {
			p.showDeviceAuthorizePage(w, r, userCode)
			return
		}

		// Not logged in - redirect to login with device_user_code in URL
		// The OAuth flow will carry it through via the state JWT
		loginURL := fmt.Sprintf("/auth/login?device_user_code=%s", url.QueryEscape(userCode))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Show the login page (with both GitHub and email options)
	p.handleLogin(w, r)
}

// showDeviceAuthorizePage shows the "Authorize this device?" confirmation page
func (p *ProxyServer) showDeviceAuthorizePage(w http.ResponseWriter, r *http.Request, userCode string) {
	email := p.getAuthEmail(r)

	w.Header().Set("Content-Type", "text/html")
	writePageStart(w, "tunn - Authorize Device")
	fmt.Fprintf(w, `
<h1 class="page-title">Authorize Device</h1>
<p class="page-subtitle">A device is requesting access to your account.</p>
<div class="device-info">
<p><strong>Code:</strong> <code>%s</code></p>
<p><strong>Account:</strong> %s</p>
</div>
<form method="POST" action="/auth/device/authorize">
<input type="hidden" name="code" value="%s">
<button type="submit" class="btn btn-github">Authorize</button>
</form>
<p style="margin-top: 1rem;"><a href="/">Cancel</a></p>
`, userCode, email, userCode)
	writePageEnd(w)
}

// handleDeviceAuthorize handles POST /auth/device/authorize - authorizes a device code
func (p *ProxyServer) handleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Must be authenticated
	email, authenticated := p.getAuthFromCookie(r)
	if !authenticated {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	userCode := r.FormValue("code")

	if userCode == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	if !p.storage.Available() {
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	deviceCode, err := p.storage.GetDeviceCodeByUserCode(r.Context(), userCode)
	if err != nil || deviceCode == nil {
		http.Error(w, "Invalid or expired code", http.StatusBadRequest)
		return
	}

	if _, err := p.storage.AuthorizeDeviceCode(r.Context(), deviceCode.Code, email); err != nil {
		common.LogError("failed to authorize device code", "error", err)
		http.Error(w, "Failed to authorize device", http.StatusInternalServerError)
		return
	}

	common.LogInfo("device code authorized", "user_code", userCode, "email", email)

	w.Header().Set("Content-Type", "text/html")
	writeSuccessPage(w, "Device Authorized", "Return to your terminal.")
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

// checkDeviceCodeRateLimit checks if an IP can create a device code.
// Returns true if allowed, false if rate limited.
// Also records the request if allowed.
func (p *ProxyServer) checkDeviceCodeRateLimit(ip string) bool {
	p.deviceCodeRateMu.Lock()
	defer p.deviceCodeRateMu.Unlock()

	now := time.Now()
	windowStart := now.Add(-deviceCodeRateWindow)

	// Get existing requests and filter to current window
	requests := p.deviceCodeRateByIP[ip]
	var validRequests []time.Time
	for _, t := range requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	// Check if rate limited
	if len(validRequests) >= deviceCodeRateMaxCount {
		p.deviceCodeRateByIP[ip] = validRequests
		return false
	}

	// Record this request
	validRequests = append(validRequests, now)
	p.deviceCodeRateByIP[ip] = validRequests
	return true
}

// extractClientIP extracts the client IP from the request, handling proxies.
func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (set by proxies like Fly.io)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain (original client)
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr (strip port if present)
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
