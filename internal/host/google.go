package host

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/golang-jwt/jwt/v4"
)

const googleAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
const googleTokenURL = "https://oauth2.googleapis.com/token"
const googleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
const googleStateCookie = "__Host-tunn_google"

func (p *ProxyServer) googleCallbackURL() string {
	// Match the registered redirect URI while keeping PublicAddr a valid host:port.
	return "https://" + strings.TrimSuffix(p.config.PublicAddr, ":443") + "/auth/google/callback"
}
func (p *ProxyServer) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	if org := r.URL.Query().Get("org"); org != "" {
		configured, found := p.config.OIDCOrg(org)
		if !found || configured.Provider != "google" {
			http.NotFound(w, r)
			return
		}
		p.handleOrgOIDCFor(w, r, org, false)
		return
	}
	if p.config.GoogleClientID == "" || p.config.GoogleClientSecret == "" {
		http.Error(w, "Google login is not configured", 503)
		return
	}
	verifier, err := newOIDCPKCEVerifier()
	if err != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	state, err := p.createOAuthState(p.sanitizeReturnTo(r.URL.Query().Get("return_to")), r.URL.Query().Get("device_user_code"))
	if err != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	// Provider and PKCE verifier are bound in a separate signed browser cookie.
	claims := jwt.MapClaims{"type": "google_pkce", "state": state, "verifier": verifier, "exp": time.Now().Add(10 * time.Minute).Unix()}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: googleStateCookie, Value: signed, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	setOAuthCookie(w, state, 600)
	digest := sha256.Sum256([]byte(verifier))
	params := url.Values{"client_id": {p.config.GoogleClientID}, "redirect_uri": {p.googleCallbackURL()}, "response_type": {"code"}, "scope": {"openid email"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"}}
	http.Redirect(w, r, googleAuthorizeURL+"?"+params.Encode(), 302)
}

// The consumer and Workspace flows use the same random S256 verifier format.
func newOIDCPKCEVerifier() (string, error) {
	verifier, err := generateRandomState()
	return strings.TrimRight(verifier, "="), err
}
func (p *ProxyServer) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if p.config.GoogleClientID == "" || p.config.GoogleClientSecret == "" {
		p.writeAuthError(w, r, "Google login is not configured", 503, "Sign in with an email link instead.")
		return
	}
	state := r.URL.Query().Get("state")
	oauth, err := p.parseOAuthState(state)
	if err != nil || !requireOAuthBrowser(w, r, state) {
		if err != nil {
			p.writeAuthError(w, r, "Invalid Google login state", 400, "Sign in again to start a new Google login.")
		}
		return
	}
	cookie, err := r.Cookie(googleStateCookie)
	if err != nil {
		p.writeAuthError(w, r, "Missing Google login binding", 400, "Sign in again to start a new Google login.")
		return
	}
	token, err := jwt.Parse(cookie.Value, func(*jwt.Token) (interface{}, error) { return p.getJWTSigningKey(), nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !token.Valid {
		p.writeAuthError(w, r, "Invalid Google login binding", 400, "Sign in again to start a new Google login.")
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["type"] != "google_pkce" || claims["state"] != state {
		p.writeAuthError(w, r, "Invalid Google login binding", 400, "Sign in again to start a new Google login.")
		return
	}
	verifier, _ := claims["verifier"].(string)
	http.SetCookie(w, &http.Cookie{Name: googleStateCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	code := r.URL.Query().Get("code")
	if code == "" || verifier == "" {
		p.writeAuthError(w, r, "Missing Google authorization", 400, "Sign in again to start a new Google login.")
		return
	}
	h := p.googleHTTPClient
	if h == nil {
		h = &http.Client{Timeout: 10 * time.Second}
	}
	values := url.Values{"client_id": {p.config.GoogleClientID}, "client_secret": {p.config.GoogleClientSecret}, "redirect_uri": {p.googleCallbackURL()}, "grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(r.Context(), "POST", googleTokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		p.writeAuthError(w, r, "Google login unavailable", 502, "Sign in again to start a new Google login.")
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.Do(req)
	if err != nil {
		p.writeAuthError(w, r, "Google login unavailable", 502, "Sign in again to start a new Google login.")
		return
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&result)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || result.AccessToken == "" {
		p.writeAuthError(w, r, "Google authorization refused", 401, "Sign in again to start a new Google login.")
		return
	}
	req, err = http.NewRequestWithContext(r.Context(), "GET", googleUserInfoURL, nil)
	if err != nil {
		p.writeAuthError(w, r, "Google login unavailable", 502, "Sign in again to start a new Google login.")
		return
	}
	req.Header.Set("Authorization", "Bearer "+result.AccessToken)
	resp, err = h.Do(req)
	if err != nil {
		p.writeAuthError(w, r, "Google identity unavailable", 502, "Sign in again to start a new Google login.")
		return
	}
	var identity struct {
		Sub          string `json:"sub"`
		Email        string `json:"email"`
		Verified     bool   `json:"email_verified"`
		HostedDomain string `json:"hd"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&identity)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || identity.Sub == "" || !identity.Verified || identity.Email == "" {
		p.writeAuthError(w, r, "A verified Google email is required", 403, "Sign in again to start a new Google login.")
		return
	}
	if !validGoogleEmail(identity.Email) {
		p.writeAuthError(w, r, "Invalid Google email", 403, "Sign in again to start a new Google login.")
		return
	}
	email := strings.ToLower(identity.Email)
	if p.storage == nil || !p.storage.Available() {
		p.writeAuthError(w, r, "Account authority unavailable", 503, "Sign in again to start a new Google login.")
		return
	}
	if !common.GoogleAuthoritativeEmail(email, identity.HostedDomain, identity.Verified) {
		p.writeAuthError(w, r, "Google does not verify current ownership of this email; sign in with a fresh email link", 403, "Sign in again to start a new Google login.")
		return
	}
	identityStore, ok := p.storage.(storage.GoogleIdentityStorage)
	if !ok {
		p.writeAuthError(w, r, "Account identity authority unavailable", 503, "Sign in with an email link instead.")
		return
	}
	account, err := identityStore.FindOrCreateGoogleIdentity(r.Context(), identity.Sub, email, identity.HostedDomain, identity.Verified)
	if err != nil {
		p.writeAuthError(w, r, "Google identity cannot be linked; sign in with a fresh email link", 403, "Sign in again to start a new Google login.")
		return
	}
	if err = p.signedPlatformSession(w, r, jwt.MapClaims{"account_id": account.ID, "email": email, "sub": identity.Sub, "provider": "google", "email_verified": true, "google_authoritative": true, "issuer": common.GoogleIssuer}); err != nil {
		p.writeAuthError(w, r, "Login unavailable", 500, "Sign in again to start a new Google login.")
		return
	}
	if oauth.DeviceUserCode != "" {
		http.Redirect(w, r, "/login?code="+url.QueryEscape(oauth.DeviceUserCode), 302)
		return
	}
	target := p.sanitizeReturnTo(oauth.ReturnTo)
	if target == "" || target == "/" {
		target = "/account"
	}
	http.Redirect(w, r, target, 302)
}

// Google emails must be ASCII; normalization must not turn a lookalike into an owner.
func validGoogleEmail(email string) bool {
	if strings.Count(email, "@") != 1 || strings.TrimSpace(email) != email {
		return false
	}
	for _, c := range email {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	parts := strings.Split(email, "@")
	return parts[0] != "" && strings.Contains(parts[1], ".")
}
