package host

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const oauthCookieName = "__Host-tunn_oauth"

// httpsAuthority compares exact origins, including the effective HTTPS port.
// Tunnel subdomains never inherit the platform origin's trust.
func httpsAuthority(authority string) string {
	u, err := url.Parse("https://" + authority)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

func (p *ProxyServer) isPlatformHost(host string) bool {
	authority := httpsAuthority(host)
	if authority == "" {
		return false
	}
	if authority == httpsAuthority(p.config.PublicAddr) {
		return true
	}
	// The apex domain may be used instead of PublicAddr (localhost in dev),
	// but must use the same configured port.
	publicURL, err := url.Parse("https://" + p.config.PublicAddr)
	if err != nil {
		return false
	}
	port := publicURL.Port()
	if port == "" {
		port = "443"
	}
	return authority == httpsAuthority(net.JoinHostPort(p.config.Domain, port))
}

func (p *ProxyServer) requireAuthOrigin(w http.ResponseWriter, r *http.Request, allowCLI bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" && allowCLI && r.Header.Get("Cookie") == "" && r.Header.Get("Sec-Fetch-Site") == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err == nil && u.Scheme == "https" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && p.isPlatformHost(r.Host) && httpsAuthority(u.Host) == httpsAuthority(r.Host) {
		return true
	}
	http.Error(w, "Invalid request origin", http.StatusForbidden)
	return false
}

func (p *ProxyServer) createCSRFToken(r *http.Request, action string) (string, error) {
	cookie, err := r.Cookie(authCookieName)
	if err != nil {
		return "", err
	}
	nonce, err := generateRandomState()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(cookie.Value))
	claims := jwt.MapClaims{
		"type": "csrf", "session": fmt.Sprintf("%x", digest), "action": action,
		"nonce": nonce, "exp": time.Now().Add(10 * time.Minute).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
}

func (p *ProxyServer) requireCSRFToken(w http.ResponseWriter, r *http.Request, action string) bool {
	if !p.requireAuthOrigin(w, r, false) {
		return false
	}
	cookie, err := r.Cookie(authCookieName)
	if err != nil {
		http.Error(w, "Missing session", http.StatusForbidden)
		return false
	}
	token, err := jwt.Parse(r.PostFormValue("csrf_token"), func(*jwt.Token) (interface{}, error) {
		return p.getJWTSigningKey(), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err == nil && token.Valid {
		claims, ok := token.Claims.(jwt.MapClaims)
		session, _ := claims["session"].(string)
		digest := sha256.Sum256([]byte(cookie.Value))
		if ok && claims["type"] == "csrf" && claims["action"] == action && claims.VerifyExpiresAt(time.Now().Unix(), true) && subtle.ConstantTimeCompare([]byte(session), []byte(fmt.Sprintf("%x", digest))) == 1 {
			return true
		}
	}
	http.Error(w, "Invalid CSRF token", http.StatusForbidden)
	return false
}

func setOAuthCookie(w http.ResponseWriter, state string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: oauthCookieName, Value: state, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func requireOAuthBrowser(w http.ResponseWriter, r *http.Request, state string) bool {
	cookie, err := r.Cookie(oauthCookieName)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		writeBrowserAuthError(w, r, "Invalid login state", http.StatusBadRequest, "Sign in again in this browser to start a new login.", "")
		return false
	}
	setOAuthCookie(w, "", -1)
	return true
}
