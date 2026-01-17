package host

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/golang-jwt/jwt/v4"
)

// handleMagicLinkRequest handles POST /auth/magic - sends magic link email
func (p *ProxyServer) handleMagicLinkRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if email sender is configured
	if p.emailSender == nil {
		http.Error(w, "Email login not available", http.StatusServiceUnavailable)
		return
	}

	// Parse request body
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		http.Error(w, "Invalid email address", http.StatusBadRequest)
		return
	}

	// Generate magic link JWT (5 minute expiry)
	token, err := p.generateMagicLinkToken(email)
	if err != nil {
		common.LogError("failed to generate magic link token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Build magic link URL
	magicLinkURL := fmt.Sprintf("https://%s/auth/verify?token=%s", p.config.PublicAddr, token)

	// Check for device code in session (for CLI login flow)
	deviceUserCode := p.sessionManager.GetString(r.Context(), "device_user_code")
	if deviceUserCode != "" {
		magicLinkURL += "&device_code=" + deviceUserCode
	}

	// Send email
	if err := p.emailSender.SendMagicLink(email, magicLinkURL); err != nil {
		common.LogError("failed to send magic link email", "email", email, "error", err)
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}

	common.LogInfo("sent magic link", "email", email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Check your email for a login link",
	})
}

// handleMagicLinkVerify handles GET /auth/verify - verifies magic link token
func (p *ProxyServer) handleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	tokenString := r.URL.Query().Get("token")
	if tokenString == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// Verify the magic link token
	email, err := p.verifyMagicLinkToken(tokenString)
	if err != nil {
		common.LogError("invalid magic link token", "error", err)
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	common.LogInfo("magic link verified", "email", email)

	// Check if this is a device code flow (CLI login)
	deviceUserCode := r.URL.Query().Get("device_code")
	if deviceUserCode != "" {
		// Find the device code and authorize it
		code := p.deviceCodes.GetByUserCode(deviceUserCode)
		if code != nil {
			p.deviceCodes.Authorize(code.Code, email)
			common.LogInfo("device code authorized via magic link", "email", email, "user_code", deviceUserCode)

			// Show success page
			w.Header().Set("Content-Type", "text/html")
			writePageStart(w, "tunn - Login Successful")
			fmt.Fprint(w, `<div class="message success">You're logged in!</div>
<h1 class="page-title">Login Successful</h1>
<p class="page-subtitle">You can close this window and return to your terminal.</p>`)
			writePageEnd(w)
			return
		}
	}

	// Create session for browser auth
	p.sessionManager.Put(r.Context(), "email", email)
	p.sessionManager.Put(r.Context(), "authenticated", true)

	// Redirect to original destination or home
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}

	http.Redirect(w, r, returnTo, http.StatusFound)
}

// generateMagicLinkToken creates a JWT for magic link authentication
func (p *ProxyServer) generateMagicLinkToken(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"type":  "magic_link",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(p.getJWTSigningKey())
}

// verifyMagicLinkToken verifies a magic link JWT and returns the email
func (p *ProxyServer) verifyMagicLinkToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.getJWTSigningKey(), nil
	})

	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	// Verify token type
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "magic_link" {
		return "", fmt.Errorf("invalid token type")
	}

	// Extract email
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return "", fmt.Errorf("missing email claim")
	}

	return email, nil
}
