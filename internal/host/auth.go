package host

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/golang-jwt/jwt/v4"
)

const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubUserURL      = "https://api.github.com/user"
	githubEmailsURL    = "https://api.github.com/user/emails"
)

// handleLogin initiates the GitHub OAuth flow
func (p *ProxyServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Check if GitHub OAuth is configured
	if p.config.GitHubClientID == "" {
		// Fall back to mock OIDC in dev mode
		if p.config.IsDev() && p.config.MockOIDCIssuer != "" {
			p.handleMockLogin(w, r)
			return
		}
		common.LogError("GitHub OAuth not configured")
		http.Error(w, "OAuth not configured", http.StatusInternalServerError)
		return
	}

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

	// Build GitHub authorization URL
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		githubAuthorizeURL,
		url.QueryEscape(p.config.GitHubClientID),
		url.QueryEscape(p.getCallbackURL()),
		url.QueryEscape("user:email"),
		url.QueryEscape(state))

	common.LogInfo("redirecting to GitHub", "url", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback handles the GitHub OAuth callback
func (p *ProxyServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Check if this is mock OIDC callback
	if p.config.GitHubClientID == "" && p.config.IsDev() && p.config.MockOIDCIssuer != "" {
		p.handleMockCallback(w, r)
		return
	}

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

	// Exchange code for access token
	accessToken, err := p.exchangeGitHubCode(code)
	if err != nil {
		common.LogError("failed to exchange code", "error", err)
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	// Get user email from GitHub
	email, err := p.getGitHubEmail(accessToken)
	if err != nil {
		common.LogError("failed to get user email", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Store user info in session
	p.sessionManager.Put(r.Context(), "user_email", email)
	p.sessionManager.Put(r.Context(), "authenticated", true)

	common.LogInfo("user authenticated via GitHub", "email", email)

	// Redirect to original URL
	returnTo := p.sessionManager.PopString(r.Context(), "return_to")
	if returnTo == "" {
		returnTo = "/"
	}

	http.Redirect(w, r, returnTo, http.StatusFound)
}

// exchangeGitHubCode exchanges an authorization code for an access token
func (p *ProxyServer) exchangeGitHubCode(code string) (string, error) {
	data := url.Values{}
	data.Set("client_id", p.config.GitHubClientID)
	data.Set("client_secret", p.config.GitHubClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", p.getCallbackURL())

	req, err := http.NewRequest("POST", githubTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.Error != "" {
		return "", fmt.Errorf("GitHub error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access token in response")
	}

	return tokenResp.AccessToken, nil
}

// getGitHubEmail fetches the user's primary email from GitHub
func (p *ProxyServer) getGitHubEmail(accessToken string) (string, error) {
	req, err := http.NewRequest("GET", githubEmailsURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("email request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("email request returned status %d: %s", resp.StatusCode, string(body))
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("failed to decode email response: %w", err)
	}

	// Find primary verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	// Fall back to first verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	// Fall back to first email
	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", fmt.Errorf("no email found")
}

// handleMockLogin handles login via mock OIDC (dev only)
func (p *ProxyServer) handleMockLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateRandomState()
	if err != nil {
		common.LogError("failed to generate state", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	p.sessionManager.Put(r.Context(), "oauth_state", state)

	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	p.sessionManager.Put(r.Context(), "return_to", returnTo)

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=tunn&redirect_uri=%s&state=%s",
		p.config.MockOIDCIssuer,
		url.QueryEscape(p.getCallbackURL()),
		state)

	common.LogInfo("redirecting to mock OIDC", "url", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleMockCallback handles callback from mock OIDC (dev only)
func (p *ProxyServer) handleMockCallback(w http.ResponseWriter, r *http.Request) {
	storedState := p.sessionManager.GetString(r.Context(), "oauth_state")
	receivedState := r.URL.Query().Get("state")

	if storedState == "" || storedState != receivedState {
		common.LogError("invalid state parameter", "stored", storedState, "received", receivedState)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	p.sessionManager.Remove(r.Context(), "oauth_state")

	code := r.URL.Query().Get("code")
	if code == "" {
		common.LogError("missing authorization code")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// For mock OIDC, just use a test email
	email := "dev@example.com"

	p.sessionManager.Put(r.Context(), "user_email", email)
	p.sessionManager.Put(r.Context(), "authenticated", true)

	common.LogInfo("user authenticated via mock OIDC", "email", email)

	returnTo := p.sessionManager.PopString(r.Context(), "return_to")
	if returnTo == "" {
		returnTo = "/"
	}

	http.Redirect(w, r, returnTo, http.StatusFound)
}

// getCallbackURL returns the callback URL for this server
func (p *ProxyServer) getCallbackURL() string {
	scheme := "https"
	if p.config.IsDev() {
		scheme = "https" // Still use https even in dev for OAuth callbacks
	}
	return fmt.Sprintf("%s://%s/auth/callback", scheme, p.config.PublicAddr)
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

// CheckJWT is a middleware that validates JWT bearer tokens
func (p *ProxyServer) CheckJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			common.LogError("missing authorization header", "path", r.URL.Path)
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Check for Bearer token
		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			common.LogError("invalid authorization header format", "header", authHeader)
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, bearerPrefix)

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Get signing key
			return p.getJWTSigningKey(), nil
		})

		if err != nil {
			common.LogError("failed to parse JWT", "error", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			common.LogError("invalid JWT token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			common.LogError("failed to extract JWT claims")
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		// Extract user email from claims
		email, ok := claims["email"].(string)
		if !ok || email == "" {
			common.LogError("missing email claim in JWT")
			http.Error(w, "Invalid token: missing email", http.StatusUnauthorized)
			return
		}

		common.LogInfo("authenticated JWT request", "email", email, "path", r.URL.Path)

		// Token is valid, proceed to handler
		next.ServeHTTP(w, r)
	})
}

// getJWTSigningKey returns the signing key for JWT validation
func (p *ProxyServer) getJWTSigningKey() []byte {
	// In dev mode with mock OIDC, use mock signing key
	if p.config.IsDev() && p.mockOIDC != nil {
		return p.mockOIDC.GetSigningKey()
	}

	// Use configured JWT secret
	if p.config.JWTSecret != "" {
		return []byte(p.config.JWTSecret)
	}

	// Fallback for dev (should never happen in prod)
	common.LogError("JWT_SECRET not configured")
	return []byte("unconfigured-jwt-secret")
}
