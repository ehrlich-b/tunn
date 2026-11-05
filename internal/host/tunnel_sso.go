package host

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Built-in tunnels are untrusted browser origins, just like customer apps.
// A parent-domain cookie lets their JavaScript plant another account's signed
// credential. __Host cookies and a nonce-bound handoff keep each origin isolated.
func (p *ProxyServer) builtinTunnelHost(host string) bool {
	name := requestHostname(host)
	label := extractTunnelID(name, p.Domain)
	return label != "" && !strings.Contains(label, ".") && !p.isPlatformHost(host)
}

func (p *ProxyServer) tunnelAuthority(host string) string {
	u, _ := url.Parse("https://" + p.loginAuthority())
	if u.Port() != "" {
		return net.JoinHostPort(host, u.Port())
	}
	return host
}

// Return false only for customer-domain SSO, which has its own route authority.
func (p *ProxyServer) handleTunnelLogin(w http.ResponseWriter, r *http.Request) bool {
	request, ok := p.parseDomainToken(r.URL.Query().Get("request"), "domain_login_request")
	host, _ := request["host"].(string)
	if !p.builtinTunnelHost(host) {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	path, _ := request["path"].(string)
	nonce, _ := request["nonce"].(string)
	if r.Method != "GET" || !p.isPlatformHost(r.Host) || !ok || nonce == "" || !validAppReturn(path) {
		http.Error(w, "Invalid tunnel login", 400)
		return true
	}
	cookie, err := r.Cookie(authCookieName)
	var session jwt.MapClaims
	if err == nil {
		token, parseErr := jwt.Parse(cookie.Value, func(*jwt.Token) (interface{}, error) { return p.getJWTSigningKey(), nil }, jwt.WithValidMethods([]string{"HS256"}))
		if parseErr == nil && token.Valid {
			session, _ = token.Claims.(jwt.MapClaims)
		}
	}
	_, authenticated := p.getAuthFromCookie(r)
	if !authenticated || session["aud"] != nil && session["aud"] != "" {
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape("https://"+p.loginAuthority()+r.URL.RequestURI()), 302)
		return true
	}
	if session["type"] != "org_session" {
		account, err := p.browserSessionAccount(w, r, session)
		if err != nil {
			http.Error(w, "Account authority unavailable", 503)
			return true
		}
		if account == nil || account.OperationalState != "active" {
			http.Error(w, "Access denied", 403)
			return true
		}
	}
	session["aud"] = host
	handoff := jwt.MapClaims{"type": "tunnel_handoff", "aud": host, "nonce": nonce, "path": path, "session": session, "exp": p.currentTime().Add(time.Minute).Unix()}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, handoff).SignedString(p.getJWTSigningKey())
	if err != nil {
		http.Error(w, "Login unavailable", 503)
		return true
	}
	http.Redirect(w, r, "https://"+p.tunnelAuthority(host)+appCallback+"?token="+url.QueryEscape(raw), 302)
	return true
}

func (p *ProxyServer) handleTunnelCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	claims, ok := p.parseDomainToken(r.URL.Query().Get("token"), "tunnel_handoff")
	nonce, err := r.Cookie(appNonceCookie)
	path, _ := claims["path"].(string)
	rawSession, _ := claims["session"].(map[string]interface{})
	session := jwt.MapClaims(rawSession)
	if r.Method != "GET" || !ok || err != nil || nonce.Value == "" || claims["nonce"] != nonce.Value || claims["aud"] != requestHostname(r.Host) || !validAppReturn(path) || session == nil {
		http.Error(w, "Invalid login binding", 400)
		return
	}
	// The handoff never contains the platform bearer credential. Its embedded
	// claims already carry the destination audience, including inside the URL.
	if session["aud"] != requestHostname(r.Host) {
		http.Error(w, "Invalid audience", 400)
		return
	}
	if p.storage == nil || !p.storage.Available() {
		http.Error(w, "Login authority unavailable", 503)
		return
	}
	if session["type"] == "org_session" {
		if _, valid := p.orgSessionClaims(session); !valid {
			http.Error(w, "Access denied", 403)
			return
		}
	} else {
		account, err := p.sessionAccount(r, session)
		if err != nil {
			http.Error(w, "Account authority unavailable", 503)
			return
		}
		if !validAccountClaims(session) || account == nil || account.OperationalState != "active" {
			http.Error(w, "Access denied", 403)
			return
		}
	}
	unused, err := p.storage.MarkMagicTokenUsed(r.Context(), "tunnel-sso:"+nonce.Value, time.Now().Add(5*time.Minute))
	if err != nil {
		http.Error(w, "Login authority unavailable", 503)
		return
	}
	if !unused {
		http.Error(w, "Login already consumed", 400)
		return
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, session).SignedString(p.getJWTSigningKey())
	if err != nil {
		http.Error(w, "Login unavailable", 503)
		return
	}
	exp, _ := session["exp"].(float64)
	lifetime := int(exp - float64(p.currentTime().Unix()))
	if lifetime <= 0 {
		http.Error(w, "Login expired", 400)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: authCookieName, Value: raw, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: lifetime})
	http.SetCookie(w, &http.Cookie{Name: appNonceCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.Redirect(w, r, path, 302)
}
