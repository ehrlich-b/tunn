package host

import (
	"crypto/rand"
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

	// JWT auth cookie name - survives server restarts
	authCookieName = "tunn_auth"
	// JWT auth cookie lifetime (7 days)
	authCookieLifetime = 7 * 24 * time.Hour
)

// setAuthCookie creates and sets a signed JWT auth cookie
func (p *ProxyServer) setAuthCookie(w http.ResponseWriter, email string) error {
	// Create JWT claims
	claims := jwt.MapClaims{
		"email": email,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(authCookieLifetime).Unix(),
	}

	// Create and sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(p.getJWTSigningKey())
	if err != nil {
		return fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Set the cookie
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    tokenString,
		Path:     "/",
		Domain:   "." + p.config.Domain,
		MaxAge:   int(authCookieLifetime.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

// getAuthFromCookie reads and validates the JWT auth cookie, returning the email if valid
func (p *ProxyServer) getAuthFromCookie(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(authCookieName)
	if err != nil {
		return "", false
	}

	// Parse and validate the token
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.getJWTSigningKey(), nil
	})
	if err != nil || !token.Valid {
		return "", false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", false
	}

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return "", false
	}

	return email, true
}

// clearAuthCookie removes the JWT auth cookie
func (p *ProxyServer) clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		Domain:   "." + p.config.Domain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// OAuthState contains the data encoded in the OAuth state parameter
type OAuthState struct {
	State          string `json:"state"`            // Random CSRF token
	ReturnTo       string `json:"return_to"`        // Where to redirect after login
	DeviceUserCode string `json:"device_user_code"` // For device auth flow
}

// createOAuthState creates a signed JWT containing OAuth flow state
func (p *ProxyServer) createOAuthState(returnTo, deviceUserCode string) (string, error) {
	// Generate random CSRF token
	state, err := generateRandomState()
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"state":            state,
		"return_to":        returnTo,
		"device_user_code": deviceUserCode,
		"exp":              time.Now().Add(10 * time.Minute).Unix(), // Short-lived
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(p.getJWTSigningKey())
}

// parseOAuthState parses and validates the OAuth state JWT
func (p *ProxyServer) parseOAuthState(stateToken string) (*OAuthState, error) {
	token, err := jwt.Parse(stateToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.getJWTSigningKey(), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid state token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	state := &OAuthState{}
	if s, ok := claims["state"].(string); ok {
		state.State = s
	}
	if r, ok := claims["return_to"].(string); ok {
		state.ReturnTo = r
	}
	if d, ok := claims["device_user_code"].(string); ok {
		state.DeviceUserCode = d
	}

	return state, nil
}

// isAuthenticated checks if the request has valid auth (JWT cookie)
func (p *ProxyServer) isAuthenticated(r *http.Request) bool {
	_, ok := p.getAuthFromCookie(r)
	return ok
}

// getAuthEmail returns the authenticated user's email, or empty string if not authenticated
func (p *ProxyServer) getAuthEmail(r *http.Request) string {
	email, _ := p.getAuthFromCookie(r)
	return email
}

// sanitizeReturnTo validates and sanitizes a return_to URL parameter.
// Allows relative paths starting with "/" or absolute URLs on the same domain.
// Returns "/" if the input is empty or invalid.
func (p *ProxyServer) sanitizeReturnTo(returnTo string) string {
	if returnTo == "" {
		return "/"
	}

	// Allow relative paths
	if strings.HasPrefix(returnTo, "/") && !strings.HasPrefix(returnTo, "//") {
		return returnTo
	}

	// Allow absolute URLs on our domain or subdomains
	if strings.HasPrefix(returnTo, "https://") {
		parsed, err := url.Parse(returnTo)
		if err != nil {
			return "/"
		}
		// Check if it's our domain or a subdomain
		if parsed.Host == p.config.Domain || strings.HasSuffix(parsed.Host, "."+p.config.Domain) {
			return returnTo
		}
	}

	return "/"
}

// handleLogin shows the login page with OAuth and email options
func (p *ProxyServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Sanitize return_to (prevents open redirect) - passed via URL to OAuth endpoint
	returnTo := p.sanitizeReturnTo(r.URL.Query().Get("return_to"))
	deviceUserCode := r.URL.Query().Get("device_user_code")

	// Check if this is a tunnel access login
	tunnelID := r.URL.Query().Get("tunnel")

	// Build login page
	hasGitHub := p.config.GitHubClientID != ""
	hasMockOIDC := p.config.IsDev() && p.config.MockOIDCIssuer != ""
	hasEmail := p.emailSender != nil
	hasOAuth := hasGitHub || hasMockOIDC

	// Build OAuth URL with return_to and device_user_code
	oauthParams := fmt.Sprintf("return_to=%s", url.QueryEscape(returnTo))
	if deviceUserCode != "" {
		oauthParams += "&device_user_code=" + url.QueryEscape(deviceUserCode)
	}

	w.Header().Set("Content-Type", "text/html")
	writePageStart(w, "tunn - Login")

	if tunnelID != "" {
		fmt.Fprint(w, `<h1 class="page-title">Sign in to access tunnel</h1>
<p class="page-subtitle">This tunnel requires authentication.</p>
<div id="message"></div>`)
	} else {
		fmt.Fprint(w, `<h1 class="page-title">Sign in to tunn</h1>
<p class="page-subtitle">Access your tunnels and account settings.</p>
<div id="message"></div>`)
	}

	// Show OAuth button (GitHub in prod, Mock OIDC in dev)
	if hasGitHub {
		fmt.Fprintf(w, `<a href="/auth/github?%s" class="btn btn-github">Continue with GitHub</a>`, oauthParams)
	} else if hasMockOIDC {
		fmt.Fprintf(w, `<a href="/auth/mock?%s" class="btn btn-github">Continue with Mock Login</a>`, oauthParams)
	}

	if hasOAuth && hasEmail {
		fmt.Fprint(w, `<div class="divider"><span>or</span></div>`)
	}

	if hasEmail {
		// Pass device_user_code as URL param to magic link endpoint
		magicURL := "/auth/magic"
		if deviceUserCode != "" {
			magicURL += "?device_user_code=" + url.QueryEscape(deviceUserCode)
		}
		fmt.Fprintf(w, `
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
		const resp = await fetch('%s', {
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
</script>`, magicURL)
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

	// Get return_to and device_user_code from URL params
	returnTo := p.sanitizeReturnTo(r.URL.Query().Get("return_to"))
	deviceUserCode := r.URL.Query().Get("device_user_code")

	// Create signed state JWT containing return_to and device_user_code
	stateToken, err := p.createOAuthState(returnTo, deviceUserCode)
	if err != nil {
		common.LogError("failed to create OAuth state", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Build GitHub authorization URL
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		githubAuthorizeURL,
		url.QueryEscape(p.config.GitHubClientID),
		url.QueryEscape(p.getCallbackURL()),
		url.QueryEscape("user:email"),
		url.QueryEscape(stateToken))

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

	// Parse and validate the state JWT (contains CSRF token, return_to, device_user_code)
	stateToken := r.URL.Query().Get("state")
	oauthState, err := p.parseOAuthState(stateToken)
	if err != nil {
		common.LogError("invalid state parameter", "error", err)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

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

	// Get all verified emails from GitHub
	emails, err := p.getGitHubEmails(accessToken)
	if err != nil {
		common.LogError("failed to get user emails", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Primary email is first in the list
	primaryEmail := emails[0]

	// Set JWT auth cookie (stateless, survives restarts)
	if err := p.setAuthCookie(w, primaryEmail); err != nil {
		common.LogError("failed to set auth cookie", "error", err)
		http.Error(w, "Failed to complete login", http.StatusInternalServerError)
		return
	}

	common.LogInfo("user authenticated via GitHub", "email", primaryEmail, "all_emails", emails)

	// Create or update account in database with ALL emails (enables account merging)
	if p.storage.Available() {
		_, err := p.storage.FindOrCreateByEmails(r.Context(), emails, "github")
		if err != nil {
			common.LogError("failed to create account", "emails", emails, "error", err)
			// Continue anyway - JWT auth still works without DB record
		}
	}

	// Check if this is a device code flow (CLI login) - redirect to confirmation page
	if oauthState.DeviceUserCode != "" && p.storage.Available() {
		dc, err := p.storage.GetDeviceCodeByUserCode(r.Context(), oauthState.DeviceUserCode)
		if err == nil && dc != nil {
			http.Redirect(w, r, "/login?code="+oauthState.DeviceUserCode, http.StatusFound)
			return
		}
	}

	// Redirect to return_to if set (e.g., accessing a tunnel), otherwise account page
	returnTo := oauthState.ReturnTo
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

// getGitHubEmails fetches all verified emails from GitHub, with primary first
func (p *ProxyServer) getGitHubEmails(accessToken string) ([]string, error) {
	req, err := http.NewRequest("GET", githubEmailsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("email request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("email request returned status %d: %s", resp.StatusCode, string(body))
	}

	var ghEmails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghEmails); err != nil {
		return nil, fmt.Errorf("failed to decode email response: %w", err)
	}

	// Collect all verified emails, primary first
	var primaryEmail string
	var emails []string
	for _, e := range ghEmails {
		if e.Verified {
			if e.Primary {
				primaryEmail = e.Email
			} else {
				emails = append(emails, e.Email)
			}
		}
	}

	// Put primary first
	if primaryEmail != "" {
		emails = append([]string{primaryEmail}, emails...)
	}

	if len(emails) == 0 {
		return nil, fmt.Errorf("no verified emails found")
	}

	return emails, nil
}

// handleMockLogin handles login via mock OIDC (dev only)
func (p *ProxyServer) handleMockLogin(w http.ResponseWriter, r *http.Request) {
	// Get return_to and device_user_code from URL params
	returnTo := p.sanitizeReturnTo(r.URL.Query().Get("return_to"))
	deviceUserCode := r.URL.Query().Get("device_user_code")

	// Create signed state JWT
	stateToken, err := p.createOAuthState(returnTo, deviceUserCode)
	if err != nil {
		common.LogError("failed to create OAuth state", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	authURL := fmt.Sprintf("%s/oauth/authorize?response_type=code&client_id=tunn&redirect_uri=%s&state=%s",
		p.config.MockOIDCIssuer,
		url.QueryEscape(p.getCallbackURL()),
		stateToken)

	common.LogInfo("redirecting to mock OIDC", "url", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleMockCallback handles callback from mock OIDC (dev only)
func (p *ProxyServer) handleMockCallback(w http.ResponseWriter, r *http.Request) {
	// Parse and validate the state JWT
	stateToken := r.URL.Query().Get("state")
	oauthState, err := p.parseOAuthState(stateToken)
	if err != nil {
		common.LogError("invalid state parameter", "error", err)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		common.LogError("missing authorization code")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// For mock OIDC, just use a test email
	email := "dev@example.com"

	// Set JWT auth cookie
	if err := p.setAuthCookie(w, email); err != nil {
		common.LogError("failed to set auth cookie", "error", err)
		http.Error(w, "Failed to complete login", http.StatusInternalServerError)
		return
	}

	common.LogInfo("user authenticated via mock OIDC", "email", email)

	// Create or update account in database (if storage available)
	if p.storage.Available() {
		_, err := p.storage.FindOrCreateByEmails(r.Context(), []string{email}, "mock_oidc")
		if err != nil {
			common.LogError("failed to create account", "email", email, "error", err)
		}
	}

	// Check if this is a device code flow (CLI login) - redirect to confirmation page
	if oauthState.DeviceUserCode != "" && p.storage.Available() {
		dc, err := p.storage.GetDeviceCodeByUserCode(r.Context(), oauthState.DeviceUserCode)
		if err == nil && dc != nil {
			http.Redirect(w, r, "/login?code="+oauthState.DeviceUserCode, http.StatusFound)
			return
		}
	}

	returnTo := oauthState.ReturnTo
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

// CheckAuth is a middleware that checks for a valid JWT auth cookie
func (p *ProxyServer) CheckAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is authenticated via JWT cookie
		email, authenticated := p.getAuthFromCookie(r)
		if !authenticated {
			// Build login URL with return_to parameter
			returnTo := r.URL.String()
			loginURL := fmt.Sprintf("/auth/login?return_to=%s", url.QueryEscape(returnTo))

			common.LogInfo("unauthenticated request, redirecting to login", "path", r.URL.Path, "return_to", returnTo)
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		// User is authenticated, proceed to handler
		common.LogInfo("authenticated request", "email", email, "path", r.URL.Path)
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

// handleLogout clears the auth cookie and redirects to home
func (p *ProxyServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	p.clearAuthCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// AccountPageData holds data for the account page template
type AccountPageData struct {
	Email                    string
	Plan                     string
	UsageBytes               int64
	QuotaBytes               int64
	UsagePercent             int
	UsageFormatted           string
	QuotaFormatted           string
	StripeCheckoutURLMonthly string
	StripeCheckoutURLYearly  string
	StripeBillingPortalURL   string
}

// handleAccount shows the account dashboard page
func (p *ProxyServer) handleAccount(w http.ResponseWriter, r *http.Request) {
	// Check authentication via JWT cookie
	email, authenticated := p.getAuthFromCookie(r)
	if !authenticated {
		loginURL := fmt.Sprintf("/auth/login?return_to=%s", url.QueryEscape(r.URL.String()))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Get account info
	plan := "free"
	var usageBytes int64 = 0

	if p.storage.Available() {
		// Try to get account info
		if account, err := p.storage.GetAccountByEmail(r.Context(), email); err == nil && account != nil {
			plan = account.Plan
			// Get usage (by account ID, not email)
			if usage, err := p.storage.GetMonthlyUsage(r.Context(), account.ID); err == nil {
				usageBytes = usage
			}
		}
	}

	// Calculate percentage (quota defined in limits.go)
	quotaBytes := GetQuotaBytes(plan)
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

	// Stripe checkout URLs - append prefilled_email to auto-fill customer email
	stripeMonthly := p.config.StripeCheckoutURLMonthly
	if stripeMonthly == "" {
		stripeMonthly = "#"
	} else if u, err := url.Parse(stripeMonthly); err == nil {
		q := u.Query()
		q.Set("prefilled_email", email)
		u.RawQuery = q.Encode()
		stripeMonthly = u.String()
	}
	stripeYearly := p.config.StripeCheckoutURLYearly
	if stripeYearly == "" {
		stripeYearly = "#"
	} else if u, err := url.Parse(stripeYearly); err == nil {
		q := u.Query()
		q.Set("prefilled_email", email)
		u.RawQuery = q.Encode()
		stripeYearly = u.String()
	}
	stripePortal := p.config.StripePortalURL
	if stripePortal == "" {
		stripePortal = "#"
	} else if u, err := url.Parse(stripePortal); err == nil {
		q := u.Query()
		q.Set("prefilled_email", email)
		u.RawQuery = q.Encode()
		stripePortal = u.String()
	}

	data := AccountPageData{
		Email:                    email,
		Plan:                     plan,
		UsageBytes:               usageBytes,
		QuotaBytes:               quotaBytes,
		UsagePercent:             usagePercent,
		UsageFormatted:           usageFormatted,
		QuotaFormatted:           quotaFormatted,
		StripeCheckoutURLMonthly: stripeMonthly,
		StripeCheckoutURLYearly:  stripeYearly,
		StripeBillingPortalURL:   stripePortal,
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
