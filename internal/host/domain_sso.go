package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
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

// accountSession accepts only sessions issued after a supported provider resolved
// its verified identity to a durable tunn account. Legacy email-only cookies must
// sign in again: their provider and account binding cannot be reconstructed.
func (p *ProxyServer) accountSession(r *http.Request) (jwt.MapClaims, bool) {
	name := authCookieName
	if p.customerHost(r.Host) {
		name = appCookie
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		return nil, false
	}
	claims, ok := p.parseDomainToken(cookie.Value, "session")
	if !ok || !validAccountClaims(claims) {
		return nil, false
	}
	if name == appCookie && claims["aud"] != requestHostname(r.Host) {
		return nil, false
	}
	return claims, true
}
func validAccountClaims(claims jwt.MapClaims) bool {
	id, _ := claims["account_id"].(string)
	email, _ := claims["email"].(string)
	provider, _ := claims["provider"].(string)
	if id == "" || !validGoogleEmail(email) || claims["email_verified"] != true {
		return false
	}
	switch provider {
	case "github", "magic_link":
		return true
	case "google":
		return claims["google_authoritative"] == true && claims["issuer"] == common.GoogleIssuer
	default:
		return false
	}
}

// Resolve the signed UUID, never an email lookup, then require the verified
// mailbox to remain in that account. Explicit verified account merges are
// resolved by storage; an email move cannot silently rebind an old session.
func (p *ProxyServer) sessionAccount(r *http.Request, claims jwt.MapClaims) (*storage.Account, error) {
	if p.storage == nil || !p.storage.Available() {
		return nil, storage.ErrNotAvailable
	}
	id, _ := claims["account_id"].(string)
	account, err := p.storage.GetAccount(r.Context(), id)
	if err != nil || account == nil {
		return nil, err
	}
	email, _ := claims["email"].(string)
	for _, e := range account.Emails {
		if strings.EqualFold(e.Email, email) {
			return account, nil
		}
	}
	return nil, nil
}
func (p *ProxyServer) setAccountCookie(w http.ResponseWriter, account *storage.Account, email, provider string) error {
	if account == nil || account.ID == "" || !validGoogleEmail(email) {
		return fmt.Errorf("verified account required")
	}
	claims := jwt.MapClaims{"account_id": account.ID, "email": strings.ToLower(email), "provider": provider, "email_verified": true}
	return p.signedSession(w, claims, authCookieName, "."+p.config.Domain, authCookieLifetime)
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
	_, hasExpiry := claims["exp"].(float64)
	return claims, ok && hasExpiry && claims["type"] == kind
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
	session, ok := p.accountSession(r)
	if !ok {
		// Keep the redirect on the platform origin; arbitrary customer return URLs
		// never enter the ordinary OAuth sanitizer.
		target := "https://" + p.loginAuthority() + r.URL.RequestURI()
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(target), 302)
		return
	}
	account, err := p.sessionAccount(r, session)
	if err != nil {
		http.Error(w, "Account authority unavailable", 503)
		return
	}
	if account == nil || account.OperationalState != "active" {
		http.Error(w, "Access denied", 403)
		return
	}
	handoff := jwt.MapClaims{"type": "domain_handoff", "aud": host, "nonce": nonce, "path": path, "account_id": account.ID, "email": session["email"], "provider": session["provider"], "email_verified": true, "google_authoritative": session["google_authoritative"], "issuer": session["issuer"], "exp": time.Now().Add(time.Minute).Unix()}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, handoff).SignedString(p.getJWTSigningKey())
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
	if !ok || err != nil || claims["nonce"] != nonce.Value || nonce.Value == "" || claims["aud"] != requestHostname(r.Host) || !validAccountClaims(claims) || !validAppReturn(path) {
		http.Error(w, "Invalid login binding", 400)
		return
	}
	binding, err := p.domains.Route(r.Context(), &domainpb.Domain{Name: requestHostname(r.Host)})
	if err != nil || !strings.HasPrefix(binding.Name, "*.") {
		http.Error(w, "App domain unavailable", 403)
		return
	}
	account, err := p.sessionAccount(r, claims)
	if err != nil {
		http.Error(w, "Account authority unavailable", 503)
		return
	}
	if account == nil || account.OperationalState != "active" {
		http.Error(w, "Access denied", 403)
		return
	}
	claims["account_id"] = account.ID
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
	if err := p.signedSession(w, jwt.MapClaims{"account_id": claims["account_id"], "email": claims["email"], "provider": claims["provider"], "email_verified": true, "google_authoritative": claims["google_authoritative"], "issuer": claims["issuer"], "aud": requestHostname(r.Host)}, appCookie, "", time.Hour); err != nil {
		http.Error(w, "Login unavailable", 503)
		return
	}
	http.Redirect(w, r, path, 302)
}

// Wildcard apps always require a tunn browser account. The namespace and
// reserved name belong to the publisher UUID; guests require an explicit live
// sharing permission even if the publisher selected public mode.
func (p *ProxyServer) authorizeDomainApp(w http.ResponseWriter, r *http.Request, owner *storage.Account, tunnel *TunnelConnection) (jwt.MapClaims, bool) {
	if secret, explicit, malformed := appCredential(r); explicit {
		return p.authorizeAppDevice(w, r, owner, tunnel, secret, malformed)
	}
	session, ok := p.accountSession(r)
	if !ok {
		p.startDomainSSO(w, r)
		return nil, false
	}
	check, stop := appAuthorityContext(r)
	account, status := p.appAccountAccess(r.WithContext(check), session, owner, tunnel)
	stop()
	if status != http.StatusOK {
		http.Error(w, http.StatusText(status), status)
		return nil, false
	}
	session["account_id"] = account.ID
	return session, true
}
func (p *ProxyServer) appAccountAccess(r *http.Request, session jwt.MapClaims, owner *storage.Account, tunnel *TunnelConnection) (*storage.Account, int) {
	account, err := p.sessionAccount(r, session)
	if err != nil {
		return nil, http.StatusServiceUnavailable
	}
	if account == nil || owner == nil || account.OperationalState != "active" || owner.OperationalState != "active" {
		return nil, http.StatusForbidden
	}
	emails := make([]string, 0, len(account.Emails))
	for _, e := range account.Emails {
		emails = append(emails, e.Email)
	}
	// Owners still depend on live resource generation and authority. The same
	// lookup must run for initial admission and every idle-stream poll.
	allowed := account.ID == owner.ID
	if tunnel.ResourceID != "" {
		resource, err := p.webResource(r.Context(), tunnel)
		if err != nil {
			return nil, http.StatusServiceUnavailable
		}
		allowed = allowed || webExplicitIdentityAllowed(resource, emails, nil, "", p.currentTime())
	} else {
		allowed = allowed || isEmailBucketAllowed(emails, tunnel.AllowedEmails)
	}
	if !allowed {
		return nil, http.StatusForbidden
	}
	return account, http.StatusOK
}

// Keep idle streaming and WebSocket requests subject to the same live account
// and explicit sharing checks as new requests. Recheck namespace, reservation
// and publisher authority as well; authority failure closes the transport.
func (p *ProxyServer) watchAppPermission(r *http.Request, tunnel *TunnelConnection) (*http.Request, func()) {
	ctx, cancel := context.WithCancelCause(r.Context())
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				check, stop := context.WithTimeout(ctx, 2*time.Second)
				if auth, _ := r.Context().Value(appDeviceAuthKey{}).(*appDeviceAuth); auth != nil {
					valid := p.recheckAppDevice(check, r, tunnel, auth)
					stop()
					if !valid {
						cancel()
						_ = r.Body.Close()
						return
					}
					continue
				}
				owner, err := p.currentTunnelAccount(check, tunnel)
				session, valid := p.accountSession(r)
				_, status := p.appAccountAccess(r.WithContext(check), session, owner, tunnel)
				binding, domainErr := p.domains.Route(check, &domainpb.Domain{Name: requestHostname(r.Host)})
				expected, _ := r.Context().Value(domainOwnerKey{}).(string)
				liveDomain := domainErr == nil && binding != nil && owner != nil && binding.Owner == expected && binding.Owner == owner.ID && binding.Tunnel == tunnel.TunnelID && strings.HasPrefix(binding.Name, "*.")
				stop()
				if err != nil || !valid || status != http.StatusOK || !liveDomain {
					cancel(&webPermissionError{"app_permission_revoked_or_unavailable"})
					_ = r.Body.Close()
					return
				}
			}
		}
	}()
	return r.WithContext(ctx), func() { cancel(nil) }
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
func (p *ProxyServer) appAssertion(host, accountID, email, provider string) (string, error) {
	if p.config == nil {
		return "", fmt.Errorf("identity unavailable")
	}
	ring, err := identity.Load(p.config.IdentityKeysFile)
	if err != nil {
		return "", err
	}
	return ring.Sign("https://"+p.loginAuthority(), host, accountID, email, provider, time.Now())
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
