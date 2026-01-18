package host

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/golang-jwt/jwt/v4"
)

const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubUserURL      = "https://api.github.com/user"
	githubEmailsURL    = "https://api.github.com/user/emails"
)

// sanitizeReturnTo validates and sanitizes a return_to URL parameter.
// Only allows relative paths starting with "/" to prevent open redirect attacks.
// Returns "/" if the input is empty or invalid.
func sanitizeReturnTo(returnTo string) string {
	if returnTo == "" {
		return "/"
	}
	// Reject absolute URLs (contain "://")
	if strings.Contains(returnTo, "://") {
		return "/"
	}
	// Reject protocol-relative URLs ("//example.com")
	if strings.HasPrefix(returnTo, "//") {
		return "/"
	}
	// Must start with "/" for safety
	if !strings.HasPrefix(returnTo, "/") {
		return "/"
	}
	return returnTo
}

// handleLogin shows the login page with OAuth and email options
func (p *ProxyServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Store sanitized return_to in session for after auth (prevents open redirect)
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))
	p.sessionManager.Put(r.Context(), "return_to", returnTo)

	// Build login page
	hasGitHub := p.config.GitHubClientID != ""
	hasMockOIDC := p.config.IsDev() && p.config.MockOIDCIssuer != ""
	hasEmail := p.emailSender != nil
	hasOAuth := hasGitHub || hasMockOIDC

	w.Header().Set("Content-Type", "text/html")
	writePageStart(w, "tunn - Login")
	fmt.Fprint(w, `<h1 class="page-title">Sign in to tunn</h1>
<p class="page-subtitle">Access your tunnels and account settings.</p>
<div id="message"></div>`)

	// Show OAuth button (GitHub in prod, Mock OIDC in dev)
	if hasGitHub {
		fmt.Fprintf(w, `<a href="/auth/github?return_to=%s" class="btn btn-github">Continue with GitHub</a>`, url.QueryEscape(returnTo))
	} else if hasMockOIDC {
		fmt.Fprintf(w, `<a href="/auth/mock?return_to=%s" class="btn btn-github">Continue with Mock Login</a>`, url.QueryEscape(returnTo))
	}

	if hasOAuth && hasEmail {
		fmt.Fprint(w, `<div class="divider"><span>or</span></div>`)
	}

	if hasEmail {
		fmt.Fprint(w, `
<form id="email-form">
<input type="email" name="email" placeholder="you@example.com" required>
<button type="submit" class="btn btn-secondary">Continue with Email</button>
</form>
<script>
document.getElementById('email-form').addEventListener('submit', async (e) => {
	e.preventDefault();
	const email = e.target.email.value;
	const msgEl = document.getElementById('message');
	const btn = e.target.querySelector('button');
	btn.disabled = true;
	btn.textContent = 'Sending...';
	try {
		const resp = await fetch('/auth/magic', {
			method: 'POST',
			headers: {'Content-Type': 'application/json'},
			body: JSON.stringify({email})
		});
		if (resp.ok) {
			msgEl.className = 'message success';
			msgEl.textContent = 'Check your email for a login link!';
			e.target.style.display = 'none';
		} else {
			const data = await resp.text();
			msgEl.className = 'message error';
			msgEl.textContent = data || 'Failed to send email';
			btn.disabled = false;
			btn.textContent = 'Continue with Email';
		}
	} catch (err) {
		msgEl.className = 'message error';
		msgEl.textContent = 'Network error';
		btn.disabled = false;
		btn.textContent = 'Continue with Email';
	}
});
</script>`)
	}

	if !hasOAuth && !hasEmail {
		fmt.Fprint(w, `<p>No login methods configured. Contact your administrator.</p>`)
	}

	writePageEnd(w)
}

// handleGitHubLogin initiates the GitHub OAuth flow
func (p *ProxyServer) handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	// Check if GitHub OAuth is configured
	if p.config.GitHubClientID == "" {
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

	// Store sanitized return_to URL (from query or session) - prevents open redirect
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))
	if returnTo == "/" {
		// Try session if query was empty/invalid
		sessionReturnTo := p.sessionManager.GetString(r.Context(), "return_to")
		if sessionReturnTo != "" {
			returnTo = sanitizeReturnTo(sessionReturnTo)
		}
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

	if storedState == "" || subtle.ConstantTimeCompare([]byte(storedState), []byte(receivedState)) != 1 {
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

	// Create or update account in database (if storage available)
	if p.storage.Available() {
		_, err := p.storage.FindOrCreateByEmails(r.Context(), []string{email}, "github")
		if err != nil {
			common.LogError("failed to create account", "email", email, "error", err)
			// Continue anyway - session auth still works without DB record
		}
	}

	// Check if this is a device code flow (CLI login)
	deviceUserCode := p.sessionManager.PopString(r.Context(), "device_user_code")
	if deviceUserCode != "" && p.storage.Available() {
		code, err := p.storage.GetDeviceCodeByUserCode(r.Context(), deviceUserCode)
		if err == nil && code != nil {
			p.storage.AuthorizeDeviceCode(r.Context(), code.Code, email)
			common.LogInfo("device code authorized via OAuth", "user_code", deviceUserCode, "email", email)
			// Show success page for device flow
			w.Header().Set("Content-Type", "text/html")
			writeSuccessPage(w, "Login successful", "Return to your terminal.")
			return
		}
	}

	// Redirect to return_to if set (e.g., accessing a tunnel), otherwise account page
	returnTo := p.sessionManager.PopString(r.Context(), "return_to")
	if returnTo == "" || returnTo == "/" {
		returnTo = "/account"
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

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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

	// Sanitize return_to to prevent open redirect
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))
	p.sessionManager.Put(r.Context(), "return_to", returnTo)

	authURL := fmt.Sprintf("%s/oauth/authorize?response_type=code&client_id=tunn&redirect_uri=%s&state=%s",
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

	if storedState == "" || subtle.ConstantTimeCompare([]byte(storedState), []byte(receivedState)) != 1 {
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

	// Create or update account in database (if storage available)
	if p.storage.Available() {
		_, err := p.storage.FindOrCreateByEmails(r.Context(), []string{email}, "mock_oidc")
		if err != nil {
			common.LogError("failed to create account", "email", email, "error", err)
		}
	}

	// Check if this is a device code flow (CLI login)
	deviceUserCode := p.sessionManager.PopString(r.Context(), "device_user_code")
	if deviceUserCode != "" && p.storage.Available() {
		dc, err := p.storage.GetDeviceCodeByUserCode(r.Context(), deviceUserCode)
		if err == nil && dc != nil {
			p.storage.AuthorizeDeviceCode(r.Context(), dc.Code, email)
			common.LogInfo("device code authorized via mock OIDC", "user_code", deviceUserCode, "email", email)
			// Show success page for device flow
			w.Header().Set("Content-Type", "text/html")
			writeSuccessPage(w, "Login successful", "Return to your terminal.")
			return
		}
	}

	returnTo := p.sessionManager.PopString(r.Context(), "return_to")
	if returnTo == "" || returnTo == "/" {
		returnTo = "/account"
	}

	http.Redirect(w, r, returnTo, http.StatusFound)
}

// getCallbackURL returns the callback URL for this server
func (p *ProxyServer) getCallbackURL() string {
	return fmt.Sprintf("https://%s/auth/callback", p.config.PublicAddr)
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
	// Use configured JWT secret if set (takes precedence over mock OIDC)
	if p.config.JWTSecret != "" {
		return []byte(p.config.JWTSecret)
	}

	// In dev mode with mock OIDC but no explicit secret, use mock signing key
	if p.config.IsDev() && p.mockOIDC != nil {
		return p.mockOIDC.GetSigningKey()
	}

	// In dev mode, allow fallback to weak secret (for testing without full config)
	if p.config.IsDev() {
		common.LogError("JWT_SECRET not configured - using weak dev fallback")
		return []byte("dev-jwt-secret-do-not-use-in-prod")
	}

	// In production, refuse to operate without JWT_SECRET
	panic("FATAL: JWT_SECRET environment variable is required in production")
}

// handleLogout clears the session and redirects to home
func (p *ProxyServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	p.sessionManager.Destroy(r.Context())
	http.Redirect(w, r, "/", http.StatusFound)
}

// AccountPageData holds data for the account page template
type AccountPageData struct {
	Email             string
	Plan              string
	UsageBytes        int64
	QuotaBytes        int64
	UsagePercent      int
	UsageFormatted    string
	QuotaFormatted    string
	StripeCheckoutURL string
}

// handleAccount shows the account dashboard page
func (p *ProxyServer) handleAccount(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	authenticated := p.sessionManager.GetBool(r.Context(), "authenticated")
	if !authenticated {
		loginURL := fmt.Sprintf("/auth/login?return_to=%s", url.QueryEscape(r.URL.String()))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	email := p.sessionManager.GetString(r.Context(), "user_email")

	// Get account info
	plan := "free"
	var usageBytes int64 = 0
	var quotaBytes int64 = 100 * 1000 * 1000 // 100 MB free tier

	if p.storage.Available() {
		// Try to get account info
		if account, err := p.storage.GetAccountByEmail(r.Context(), email); err == nil && account != nil {
			plan = account.Plan
			if plan == "pro" {
				quotaBytes = 50 * 1000 * 1000 * 1000 // 50 GB
			}
			// Get usage (by account ID, not email)
			if usage, err := p.storage.GetMonthlyUsage(r.Context(), account.ID); err == nil {
				usageBytes = usage
			}
		}
	}

	// Calculate percentage
	usagePercent := 0
	if quotaBytes > 0 {
		usagePercent = int((usageBytes * 100) / quotaBytes)
		if usagePercent > 100 {
			usagePercent = 100
		}
	}

	// Format bytes
	usageFormatted := formatBytes(usageBytes)
	quotaFormatted := formatBytes(quotaBytes)

	// Stripe checkout URL - use Stripe Payment Links for simplicity
	stripeCheckoutURL := p.config.StripeCheckoutURL
	if stripeCheckoutURL == "" {
		stripeCheckoutURL = "#" // Placeholder if not configured
	}

	data := AccountPageData{
		Email:             email,
		Plan:              plan,
		UsageBytes:        usageBytes,
		QuotaBytes:        quotaBytes,
		UsagePercent:      usagePercent,
		UsageFormatted:    usageFormatted,
		QuotaFormatted:    quotaFormatted,
		StripeCheckoutURL: stripeCheckoutURL,
	}

	// Render template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, err := template.New("account").Parse(accountHTML)
	if err != nil {
		common.LogError("failed to parse account template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		common.LogError("failed to execute account template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// formatBytes formats bytes as a human-readable string using SI decimal units
// (1 GB = 1,000,000,000 bytes, not 1 GiB = 1,073,741,824 bytes)
func formatBytes(bytes int64) string {
	const (
		KB = 1000
		MB = KB * 1000
		GB = MB * 1000
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
