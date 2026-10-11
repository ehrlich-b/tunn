package host

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/identity"
	"github.com/ehrlich-b/tunn/internal/storage"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"github.com/golang-jwt/jwt/v4"
)

const appCookie = "__Host-tunn_app"
const appNonceCookie = "__Host-tunn_sso"
const appCallback = "/.tunn/sso/callback"

func (p *ProxyServer) signedSession(w http.ResponseWriter, claims jwt.MapClaims, name, domain string, lifetime time.Duration) error {
	claims["type"] = "session"
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(lifetime).Unix()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: raw, Domain: domain, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(lifetime.Seconds())})
	return nil
}
func (p *ProxyServer) googleSession(r *http.Request) (jwt.MapClaims, bool) {
	name := authCookieName
	if p.customerHost(r.Host) {
		name = appCookie
	}
	cookie, err := r.Cookie(name)
	if err != nil || !p.visitorJWTConfigured() {
		return nil, false
	}
	claims, ok := p.parseDomainToken(cookie.Value, "session")
	if !ok || claims["provider"] != "google" || claims["email_verified"] != true {
		return nil, false
	}
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return nil, false
	}
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, false
	}
	if name == appCookie && claims["aud"] != requestHostname(r.Host) {
		return nil, false
	}
	return claims, true
}
func (p *ProxyServer) parseDomainToken(raw, kind string) (jwt.MapClaims, bool) {
	if !p.visitorJWTConfigured() {
		return nil, false
	}
	token, err := jwt.Parse(raw, func(*jwt.Token) (interface{}, error) { return p.getJWTSigningKey(), nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !token.Valid {
		return nil, false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	return claims, ok && claims["type"] == kind
}
func (p *ProxyServer) startDomainSSO(w http.ResponseWriter, r *http.Request) {
	nonce, err := generateConnectionID()
	if err != nil {
		http.Error(w, "Login unavailable", 503)
		return
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"type": "domain_login_request", "host": requestHostname(r.Host), "nonce": nonce, "path": r.URL.RequestURI(), "exp": time.Now().Add(5 * time.Minute).Unix()}).SignedString(p.getJWTSigningKey())
	if err != nil {
		http.Error(w, "Login unavailable", 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: appNonceCookie, Value: nonce, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "https://"+p.loginAuthority()+"/auth/domain?request="+url.QueryEscape(raw), 302)
}
func (p *ProxyServer) handleDomainLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	claims, ok := p.parseDomainToken(r.URL.Query().Get("request"), "domain_login_request")
	host, _ := claims["host"].(string)
	nonce, _ := claims["nonce"].(string)
	path, _ := claims["path"].(string)
	if !p.isPlatformHost(r.Host) || !ok || host == "" || nonce == "" || !validAppReturn(path) || p.domains == nil {
		http.Error(w, "Invalid app login", 400)
		return
	}
	binding, err := p.domains.Route(r.Context(), &domainpb.Domain{Name: host})
	if err != nil || !strings.HasPrefix(binding.Name, "*.") {
		http.Error(w, "App domain unavailable", 403)
		return
	}
	session, ok := p.googleSession(r)
	if !ok {
		// Keep the redirect on the platform origin; arbitrary customer return URLs
		// never enter the ordinary OAuth sanitizer.
		target := "https://" + p.loginAuthority() + r.URL.RequestURI()
		http.Redirect(w, r, "/auth/login?google_only=1&return_to="+url.QueryEscape(target), 302)
		return
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"type": "domain_handoff", "aud": host, "nonce": nonce, "path": path, "email": session["email"], "sub": session["sub"], "provider": "google", "email_verified": true, "exp": time.Now().Add(time.Minute).Unix()}).SignedString(p.getJWTSigningKey())
	if err != nil {
		http.Error(w, "Login unavailable", 503)
		return
	}
	http.Redirect(w, r, "https://"+host+appCallback+"?token="+url.QueryEscape(token), 302)
}
func validAppReturn(path string) bool {
	return strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && !strings.ContainsAny(path, "\\\r\n") && !strings.HasPrefix(path, appCallback)
}
func (p *ProxyServer) handleDomainCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != "GET" || p.domains == nil {
		http.Error(w, "Invalid login", 400)
		return
	}
	claims, ok := p.parseDomainToken(r.URL.Query().Get("token"), "domain_handoff")
	nonce, err := r.Cookie(appNonceCookie)
	path, _ := claims["path"].(string)
	if !ok || err != nil || claims["nonce"] != nonce.Value || nonce.Value == "" || claims["aud"] != requestHostname(r.Host) || claims["provider"] != "google" || claims["email_verified"] != true || !validAppReturn(path) {
		http.Error(w, "Invalid login binding", 400)
		return
	}
	binding, err := p.domains.Route(r.Context(), &domainpb.Domain{Name: requestHostname(r.Host)})
	if err != nil || !strings.HasPrefix(binding.Name, "*.") {
		http.Error(w, "App domain unavailable", 403)
		return
	}
	// Durable authority consumes the nonce once across every relay node.
	if p.storage == nil || !p.storage.Available() {
		http.Error(w, "Login authority unavailable", 503)
		return
	}
	unused, err := p.storage.MarkMagicTokenUsed(r.Context(), "domain-sso:"+nonce.Value, time.Now().Add(5*time.Minute))
	if err != nil {
		http.Error(w, "Login authority unavailable", 503)
		return
	}
	if !unused {
		http.Error(w, "Login already consumed", 400)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: appNonceCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if err := p.signedSession(w, jwt.MapClaims{"email": claims["email"], "sub": claims["sub"], "provider": "google", "email_verified": true, "aud": requestHostname(r.Host)}, appCookie, "", time.Hour); err != nil {
		http.Error(w, "Login unavailable", 503)
		return
	}
	http.Redirect(w, r, path, 302)
}

// The wildcard gate precedes every bearer/capability/grant path and applies even
// when a publisher opts into public mode or adds other email permissions.
func (p *ProxyServer) authorizeDomainApp(w http.ResponseWriter, r *http.Request, account *storage.Account) (string, string, bool) {
	session, ok := p.googleSession(r)
	if !ok {
		p.startDomainSSO(w, r)
		return "", "", false
	}
	email, _ := session["email"].(string)
	subject, _ := session["sub"].(string)
	// ASCII exact comparison deliberately avoids alias buckets and NFKC lookalikes.
	if account == nil || !validGoogleEmail(email) || !strings.EqualFold(email, account.PrimaryEmail) {
		http.Error(w, "Access denied", 403)
		return "", "", false
	}
	return strings.ToLower(email), subject, true
}
func stripIdentityHeaders(r *http.Request) *http.Request {
	// Keep the server's request object: streaming upload cleanup replaces its
	// Body, which net/http must observe. Only the header map needs isolation.
	r.Header = r.Header.Clone()
	for key := range r.Header {
		if strings.EqualFold(key, identity.Header) || strings.EqualFold(key, identity.EmailHeader) {
			delete(r.Header, key)
		}
	}

	// Remove client nominations of the headers the relay will inject. Keep upgrade
	// nominations so authenticated WebSockets retain their normal behavior.
	for key, values := range r.Header {
		if strings.EqualFold(key, "Connection") {
			var kept []string
			for _, value := range values {
				for _, part := range strings.Split(value, ",") {
					part = strings.TrimSpace(part)
					if !strings.EqualFold(part, identity.Header) && !strings.EqualFold(part, identity.EmailHeader) {
						kept = append(kept, part)
					}
				}
			}
			delete(r.Header, key)
			if len(kept) > 0 {
				r.Header.Set("Connection", strings.Join(kept, ", "))
			}
		}
	}
	return r
}
func (p *ProxyServer) appAssertion(host, subject, email string) (string, error) {
	if p.config == nil {
		return "", fmt.Errorf("identity unavailable")
	}
	ring, err := identity.Load(p.config.IdentityKeysFile)
	if err != nil {
		return "", err
	}
	return ring.Sign("https://"+p.loginAuthority(), host, subject, email, time.Now())
}
func (p *ProxyServer) handleIdentityJWKS(w http.ResponseWriter, r *http.Request) {
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Invalid issuer", 403)
		return
	}
	ring, err := identity.Load(p.config.IdentityKeysFile)
	if err != nil {
		http.Error(w, "Identity keys unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = json.NewEncoder(w).Encode(ring.JWKS())
}
