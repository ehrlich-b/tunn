package host

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ehrlich-b/tunn/internal/common"
)

// handleLogin initiates the OIDC authentication flow
func (p *ProxyServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state parameter for CSRF protection
	state, err := generateRandomState()
	if err != nil {
		common.LogError("failed to generate state", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store state in session
	p.sessionManager.Put(r.Context(), "oauth_state", state)

	// Store original URL to redirect back after auth
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	p.sessionManager.Put(r.Context(), "return_to", returnTo)

	// Get OIDC issuer URL
	issuerURL := p.getOIDCIssuerURL()

	// Build authorization URL
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=tunn&redirect_uri=%s&state=%s",
		issuerURL,
		url.QueryEscape(p.getCallbackURL()),
		state)

	common.LogInfo("redirecting to OIDC provider", "url", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback handles the OIDC callback
func (p *ProxyServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state parameter
	storedState := p.sessionManager.GetString(r.Context(), "oauth_state")
	receivedState := r.URL.Query().Get("state")

	if storedState == "" || storedState != receivedState {
		common.LogError("invalid state parameter", "stored", storedState, "received", receivedState)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Remove state from session
	p.sessionManager.Remove(r.Context(), "oauth_state")

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		common.LogError("missing authorization code")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	token, err := p.exchangeCodeForToken(code)
	if err != nil {
		common.LogError("failed to exchange code", "error", err)
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	// Validate and extract user info from token
	userInfo, err := p.validateToken(token)
	if err != nil {
		common.LogError("failed to validate token", "error", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Store user info in session
	p.sessionManager.Put(r.Context(), "user_email", userInfo["email"])
	p.sessionManager.Put(r.Context(), "authenticated", true)

	common.LogInfo("user authenticated", "email", userInfo["email"])

	// Redirect to original URL
	returnTo := p.sessionManager.PopString(r.Context(), "return_to")
	if returnTo == "" {
		returnTo = "/"
	}

	http.Redirect(w, r, returnTo, http.StatusFound)
}

// exchangeCodeForToken exchanges an authorization code for an access token
func (p *ProxyServer) exchangeCodeForToken(code string) (string, error) {
	issuerURL := p.getOIDCIssuerURL()
	tokenURL := issuerURL + "/token"

	// Prepare token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", p.getCallbackURL())
	data.Set("client_id", "tunn")

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request returned status %d: %s", resp.StatusCode, string(body))
	}

	// For simplicity in V1, we'll just return the code as the token
	// In production, parse the JSON response and extract access_token
	return code, nil
}

// validateToken validates the token and extracts user information
func (p *ProxyServer) validateToken(token string) (map[string]string, error) {
	// In V1 with mock OIDC, we'll just return a mock user
	// In production, validate JWT signature and extract claims
	return map[string]string{
		"email": "user@example.com",
	}, nil
}

// getOIDCIssuerURL returns the OIDC issuer URL
func (p *ProxyServer) getOIDCIssuerURL() string {
	if p.config.IsDev() && p.config.MockOIDCIssuer != "" {
		return p.config.MockOIDCIssuer
	}
	// In production, use real OIDC provider (e.g., Google)
	return "https://accounts.google.com"
}

// getCallbackURL returns the callback URL for this server
func (p *ProxyServer) getCallbackURL() string {
	scheme := "https"
	if p.config.IsDev() {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/auth/callback", scheme, p.Domain)
}

// generateRandomState generates a random state parameter for CSRF protection
func generateRandomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// CheckAuth is a middleware that checks for a valid session
func (p *ProxyServer) CheckAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is authenticated
		authenticated := p.sessionManager.GetBool(r.Context(), "authenticated")
		if !authenticated {
			// Build login URL with return_to parameter
			returnTo := r.URL.String()
			loginURL := fmt.Sprintf("/auth/login?return_to=%s", url.QueryEscape(returnTo))

			common.LogInfo("unauthenticated request, redirecting to login", "path", r.URL.Path, "return_to", returnTo)
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		// User is authenticated, proceed to handler
		userEmail := p.sessionManager.GetString(r.Context(), "user_email")
		common.LogInfo("authenticated request", "email", userEmail, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// extractTunnelID extracts the tunnel ID from the hostname
// e.g., "abc123.tunn.to" -> "abc123"
func extractTunnelID(hostname, domain string) string {
	// Remove port if present
	host := hostname
	if idx := strings.Index(hostname, ":"); idx != -1 {
		host = hostname[:idx]
	}

	// Check if this is a subdomain
	suffix := "." + domain
	if !strings.HasSuffix(host, suffix) {
		return ""
	}

	// Extract subdomain
	tunnelID := strings.TrimSuffix(host, suffix)
	if tunnelID == "" || tunnelID == "www" {
		return ""
	}

	return tunnelID
}
