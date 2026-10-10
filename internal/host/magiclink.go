package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
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
	if !p.requireAuthOrigin(w, r, false) {
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
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	email := common.NormalizeEmail(strings.TrimSpace(req.Email))
	parsed, parseErr := mail.ParseAddress(email)
	if len(email) > 254 || parseErr != nil || parsed.Address != email || strings.ContainsAny(email, "\r\n") {
		http.Error(w, "Invalid email address", http.StatusBadRequest)
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		http.Error(w, "Expected one request", 400)
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if !p.checkDeviceCodeRateLimit(ip) {
		http.Error(w, "Too many requests", 429)
		return
	}

	// Check rate limit via login node
	if p.storage != nil && p.storage.Available() {
		allowed, _, _, err := p.storage.CheckMagicLinkRateLimit(r.Context(), email)
		if err != nil {
			common.LogError("failed to check magic link rate limit", "email", email, "error", err)
			http.Error(w, "Login rate limiter unavailable", 503)
			return
		} else if !allowed {
			common.LogInfo("magic link rate limited", "email", email)
			http.Error(w, "Too many requests. Please try again in a few minutes.", http.StatusTooManyRequests)
			return
		}
	} else {
		http.Error(w, "Login service unavailable", 503)
		return
	}

	// Generate magic link JWT (5 minute expiry)
	token, err := p.generateMagicLinkTokenForReturnTo(email, p.sanitizeReturnTo(r.URL.Query().Get("return_to")))
	if err != nil {
		common.LogError("failed to generate magic link token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Build magic link URL
	magicLinkURL := fmt.Sprintf("https://%s/auth/verify?token=%s", p.config.PublicAddr, token)

	// Check for device code in URL params (for CLI login flow)
	deviceUserCode := r.URL.Query().Get("device_user_code")
	if len(deviceUserCode) > 64 {
		http.Error(w, "Invalid device code", 400)
		return
	}
	if deviceUserCode != "" {
		magicLinkURL += "&device_code=" + url.QueryEscape(deviceUserCode)
	}

	// Send email
	if err := p.emailSender.SendMagicLink(email, magicLinkURL); err != nil {
		common.LogError("failed to send magic link email", "email", email, "error", err)
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}

	common.LogInfo("sent magic link", "email", email)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
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
	email, err := p.verifyMagicLinkToken(r.Context(), tokenString)
	if err != nil {
		common.LogError("invalid magic link token", "error", err)
		http.Error(w, "Invalid or expired link", http.StatusBadRequest)
		return
	}

	common.LogInfo("magic link verified", "email", email)

	// Create or update account in database (if storage available)
	if p.storage.Available() {
		_, err := p.storage.FindOrCreateByEmails(r.Context(), []string{email}, "magic_link")
		if err != nil {
			common.LogError("failed to create account", "email", email, "error", err)
			// Continue anyway - JWT auth still works without DB record
		}
	}

	// Set JWT auth cookie (stateless, survives restarts)
	if err := p.setAuthCookie(w, email); err != nil {
		common.LogError("failed to set auth cookie", "error", err)
		http.Error(w, "Failed to complete login", http.StatusInternalServerError)
		return
	}

	// Check if this is a device code flow (CLI login) - redirect to confirmation page
	deviceUserCode := r.URL.Query().Get("device_code")
	if deviceUserCode != "" && p.storage.Available() {
		code, err := p.storage.GetDeviceCodeByUserCode(r.Context(), deviceUserCode)
		if err == nil && code != nil {
			http.Redirect(w, r, "/login?code="+deviceUserCode, http.StatusFound)
			return
		}
	}

	// Redirect to account page
	verified, err := jwt.Parse(tokenString, func(*jwt.Token) (any, error) { return p.getJWTSigningKey(), nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err == nil && verified.Valid {
		if claims, ok := verified.Claims.(jwt.MapClaims); ok {
			if returnTo, ok := claims["return_to"].(string); ok && returnTo != "" && returnTo != "/" {
				http.Redirect(w, r, p.sanitizeReturnTo(returnTo), http.StatusFound)
				return
			}
		}
	}
	http.Redirect(w, r, "/account", http.StatusFound)
}

// generateMagicLinkToken creates a JWT for magic link authentication
func (p *ProxyServer) generateMagicLinkToken(email string) (string, error) {
	return p.generateMagicLinkTokenForReturnTo(email, "")
}

func (p *ProxyServer) generateMagicLinkTokenForReturnTo(email, returnTo string) (string, error) {
	// Generate unique token ID to prevent replay attacks
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("failed to generate jti: %w", err)
	}
	jti := hex.EncodeToString(jtiBytes)

	claims := jwt.MapClaims{
		"email": email,
		"type":  "magic_link",
		"jti":   jti,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	}
	if returnTo != "" {
		claims["return_to"] = p.sanitizeReturnTo(returnTo)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(p.getJWTSigningKey())
}

// verifyMagicLinkToken verifies a magic link JWT and returns the email
// Each token can only be used once (replay protection via JTI tracking on login node)
func (p *ProxyServer) verifyMagicLinkToken(ctx context.Context, tokenString string) (string, error) {
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

	// Extract and verify JTI (replay protection)
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return "", fmt.Errorf("missing jti claim")
	}

	// Get expiry time for cleanup tracking
	exp, ok := claims["exp"].(float64)
	if !ok {
		return "", fmt.Errorf("missing exp claim")
	}
	expiry := time.Unix(int64(exp), 0)

	// Mark token as used via login node (returns false if already used)
	// This ensures cross-node replay protection
	if !p.storage.Available() {
		return "", fmt.Errorf("login service temporarily unavailable")
	}
	wasUnused, err := p.storage.MarkMagicTokenUsed(ctx, jti, expiry)
	if err != nil {
		common.LogError("failed to check magic token usage", "error", err)
		return "", fmt.Errorf("failed to verify token")
	}
	if !wasUnused {
		return "", fmt.Errorf("token already used")
	}

	// Extract email
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return "", fmt.Errorf("missing email claim")
	}

	return email, nil
}
