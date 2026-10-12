package host

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

const orgCookieName = "__Host-tunn_org_login"
const orgSessionLifetime = 15 * time.Minute

type orgProvider struct {
	provider *oidc.Provider
	oauth    oauth2.Config
}

// This client also supplies deadlines to library-owned discovery/JWKS calls.
// Redirects never carry client secrets or Graph/Directory bearer credentials.
func (p *ProxyServer) orgHTTPClient(org config.OIDCOrg) *http.Client {
	client := &http.Client{}
	if p.orgOIDCHTTPClient != nil {
		*client = *p.orgOIDCHTTPClient
	} else if org.Provider == "google" && p.googleHTTPClient != nil {
		*client = *p.googleHTTPClient
	}
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = orgBoundedTransport{base}
	return client
}

type orgBoundedTransport struct{ base http.RoundTripper }

func (t orgBoundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.User != nil || r.URL.Fragment != "" {
		return nil, fmt.Errorf("organization identity endpoints require HTTPS")
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > 1<<20 {
		response.Body.Close()
		return nil, fmt.Errorf("organization identity response too large")
	}
	response.Body = &orgBoundedBody{ReadCloser: response.Body, remaining: 1 << 20}
	return response, nil
}

type orgBoundedBody struct {
	io.ReadCloser
	remaining int
}

func (b *orgBoundedBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		var extra [1]byte
		n, err := b.ReadCloser.Read(extra[:])
		if n != 0 {
			return 0, fmt.Errorf("organization identity response too large")
		}
		return 0, err
	}
	if len(p) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= n
	return n, err
}

const orgDiscoveryBackoff = 5 * time.Second

type orgProviderInit struct {
	done       chan struct{}
	provider   *orgProvider
	err        error
	retryAfter time.Time
}

func (p *ProxyServer) orgProvider(ctx context.Context, org config.OIDCOrg) (*orgProvider, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := org.PolicyDigest()
	p.orgProvidersMu.Lock()
	if p.orgProviders == nil {
		p.orgProviders = map[string]*orgProvider{}
	}
	if provider := p.orgProviders[key]; provider != nil {
		p.orgProvidersMu.Unlock()
		return provider, nil
	}
	if p.orgProviderInits == nil {
		p.orgProviderInits = map[string]*orgProviderInit{}
	}
	if init := p.orgProviderInits[key]; init != nil {
		select {
		case <-init.done:
			if time.Now().Before(init.retryAfter) {
				p.orgProvidersMu.Unlock()
				return nil, init.err
			}
		default:
			p.orgProvidersMu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-init.done:
				return init.provider, init.err
			}
		}
	}
	init := &orgProviderInit{done: make(chan struct{})}
	p.orgProviderInits[key] = init
	p.orgProvidersMu.Unlock()

	// Only this policy's callers wait. Neither I/O nor waiting holds the cache lock.
	provider, err := p.discoverOrgProvider(ctx, org)
	p.orgProvidersMu.Lock()
	init.provider, init.err = provider, err
	if err == nil {
		p.orgProviders[key] = provider
		delete(p.orgProviderInits, key)
	} else {
		init.retryAfter = time.Now().Add(orgDiscoveryBackoff)
	}
	close(init.done)
	p.orgProvidersMu.Unlock()
	return provider, err
}

func (p *ProxyServer) discoverOrgProvider(ctx context.Context, org config.OIDCOrg) (*orgProvider, error) {
	// Bound discovery even for callers without a deadline.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx = oidc.ClientContext(ctx, p.orgHTTPClient(org))
	provider, err := oidc.NewProvider(ctx, org.Issuer)
	if err != nil {
		return nil, fmt.Errorf("organization discovery unavailable")
	}
	endpoint := provider.Endpoint()
	for _, address := range []string{endpoint.AuthURL, endpoint.TokenURL} {
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("invalid organization discovery endpoint")
		}
	}
	// Avoid probing alternate auth styles with the same one-use code.
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	if org.Provider == "okta" {
		// Okta confidential web apps default to client_secret_basic.
		endpoint.AuthStyle = oauth2.AuthStyleInHeader
	}
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	if org.Provider == "okta" {
		scopes = append(scopes, "groups")
	} else if org.Provider == "entra" {
		scopes = append(scopes, "https://graph.microsoft.com/User.Read")
	}
	out := &orgProvider{provider: provider, oauth: oauth2.Config{ClientID: org.ClientID, ClientSecret: org.ClientSecret, Endpoint: endpoint, RedirectURL: p.orgCallbackURL(org.ID), Scopes: scopes}}
	return out, nil
}

func (p *ProxyServer) orgCallbackURL(id string) string {
	return "https://" + p.loginAuthority() + "/auth/org/" + id + "/callback"
}

func (p *ProxyServer) forwardOrgLogin(w http.ResponseWriter, r *http.Request) bool {
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Platform origin required", 403)
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if p.orgLogins != nil {
		return false
	}
	p.loginNodeMu.RLock()
	addr := p.loginNodeHTTPAddr
	p.loginNodeMu.RUnlock()
	if addr != "" && r.Header.Get("Tunn-Org-Forwarded") == "" {
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		clone.Header.Set("Tunn-Org-Forwarded", "1")
		p.proxyToNode(w, clone, addr, "")
	} else {
		http.Error(w, "Organization login authority unavailable", 503)
	}
	return true
}

func (p *ProxyServer) handleOrgOIDC(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/auth/org/")
	parts := strings.Split(path, "/")
	if len(parts) > 2 || len(parts) == 2 && parts[1] != "callback" {
		http.NotFound(w, r)
		return
	}
	p.handleOrgOIDCFor(w, r, parts[0], len(parts) == 2)
}

func (p *ProxyServer) handleOrgOIDCFor(w http.ResponseWriter, r *http.Request, id string, callback bool) {
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Use GET", 405)
		return
	}
	org, found := p.config.OIDCOrg(id)
	if !found {
		http.NotFound(w, r)
		return
	}
	if p.forwardOrgLogin(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	ctx = oidc.ClientContext(ctx, p.orgHTTPClient(org))
	if callback {
		p.finishOrgOIDC(ctx, w, r, org)
		return
	}
	state, err := generateRandomState()
	if err != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	nonce, err := generateRandomState()
	if err != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	verifier, err := newOIDCPKCEVerifier()
	if err != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	now := p.currentTime()
	login := orgLogin{Org: org.ID, Source: orgLoginSource(r), Nonce: nonce, Verifier: verifier, ReturnTo: p.sanitizeReturnTo(r.URL.Query().Get("return_to")), DeviceCode: r.URL.Query().Get("device_user_code"), Expires: now.Add(10 * time.Minute).Unix()}
	if len(login.ReturnTo) > 2048 || len(login.DeviceCode) > 64 {
		http.Error(w, "Invalid login destination", 400)
		return
	}
	if err = p.orgLogins.begin(ctx, state, login, now); err != nil {
		if errors.Is(err, errOrgLoginAdmission) {
			w.Header().Set("Retry-After", "600")
			http.Error(w, "Too many pending organization logins", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "Organization login authority unavailable", 503)
		return
	}
	provider, err := p.orgProvider(ctx, org)
	if err != nil {
		_, _ = p.orgLogins.consume(ctx, state, org.ID, now)
		http.Error(w, "Organization login provider unavailable", 503)
		return
	}
	setOrgLoginCookie(w, state, 600)
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)}
	if org.Provider == "google" {
		options = append(options, oauth2.SetAuthURLParam("hd", org.AllowedDomains[0]))
	}
	http.Redirect(w, r, provider.oauth.AuthCodeURL(state, options...), 302)
}

func setOrgLoginCookie(w http.ResponseWriter, state string, age int) {
	http.SetCookie(w, &http.Cookie{Name: orgCookieName, Value: state, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: age})
}

func (p *ProxyServer) finishOrgOIDC(ctx context.Context, w http.ResponseWriter, r *http.Request, org config.OIDCOrg) {
	q := r.URL.Query()
	state := q.Get("state")
	cookie, err := r.Cookie(orgCookieName)
	if err != nil || len(q["state"]) != 1 || len(state) > 128 || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "Invalid organization login state", 400)
		return
	}
	setOrgLoginCookie(w, "", -1)
	login, err := p.orgLogins.consume(ctx, state, org.ID, p.currentTime())
	if err != nil {
		http.Error(w, "Invalid, expired or used organization login", 400)
		return
	}
	if q.Get("error") != "" || len(q["code"]) != 1 || q.Get("code") == "" || len(q.Get("code")) > 4096 {
		http.Error(w, "Organization authorization refused", 401)
		return
	}
	provider, err := p.orgProvider(ctx, org)
	if err != nil {
		http.Error(w, "Organization provider unavailable", 503)
		return
	}
	access, err := provider.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(login.Verifier))
	if err != nil {
		http.Error(w, "Organization authorization refused", 401)
		return
	}
	raw, ok := access.Extra("id_token").(string)
	if !ok || len(raw) > 65536 {
		http.Error(w, "Missing organization ID token", 401)
		return
	}
	idToken, err := provider.provider.Verifier(&oidc.Config{ClientID: org.ClientID, SupportedSigningAlgs: []string{"RS256"}, Now: p.currentTime}).Verify(ctx, raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(idTokenNonce(idToken)), []byte(login.Nonce)) != 1 {
		http.Error(w, "Invalid organization identity", 401)
		return
	}
	if idToken.AccessTokenHash != "" && idToken.VerifyAccessToken(access.AccessToken) != nil {
		http.Error(w, "Invalid organization token binding", 401)
		return
	}
	email, claims, err := validateOrgClaims(org, idToken, p.currentTime())
	if err != nil {
		http.Error(w, "Organization identity or domain refused", 403)
		return
	}
	groups, err := p.resolveOrgGroups(ctx, org, idToken, claims, access.AccessToken)
	if err != nil {
		http.Error(w, "Organization group authority unavailable", 503)
		return
	}
	principal := orgPrincipal(org, idToken.Subject)
	if p.storage == nil || !p.storage.Available() {
		http.Error(w, "Account authority unavailable", 503)
		return
	}
	account, err := p.storage.FindOrCreateByEmails(ctx, []string{principal}, "oidc_subject")
	if err != nil || account == nil || account.OperationalState != "active" {
		http.Error(w, "Organization account unavailable", 403)
		return
	}
	if err = p.setOrgAuthCookie(w, org, idToken.Subject, email, groups, idToken.Expiry); err != nil {
		http.Error(w, "Login unavailable", 500)
		return
	}
	if login.DeviceCode != "" {
		http.Redirect(w, r, "/login?code="+url.QueryEscape(login.DeviceCode), 302)
		return
	}
	target := p.sanitizeReturnTo(login.ReturnTo)
	if target == "" || target == "/" {
		target = "/account"
	}
	http.Redirect(w, r, target, 302)
}

func idTokenNonce(token *oidc.IDToken) string {
	if token == nil {
		return ""
	}
	return token.Nonce
}

type orgClaims struct {
	Email             string            `json:"email"`
	EmailVerified     *bool             `json:"email_verified"`
	PreferredUsername string            `json:"preferred_username"`
	HostedDomain      string            `json:"hd"`
	Tenant            string            `json:"tid"`
	ObjectID          string            `json:"oid"`
	AuthorizedParty   string            `json:"azp"`
	Groups            []string          `json:"groups"`
	Roles             []string          `json:"roles"`
	HasGroups         *bool             `json:"hasgroups"`
	ClaimNames        map[string]string `json:"_claim_names"`
	NotBefore         *int64            `json:"nbf"`
}

func validateOrgClaims(org config.OIDCOrg, token *oidc.IDToken, now time.Time) (string, orgClaims, error) {
	var claims orgClaims
	if token.Claims(&claims) != nil || token.Subject == "" || len(token.Subject) > 255 || strings.ContainsAny(token.Subject, "\x00\r\n") || token.IssuedAt.Unix() <= 0 || token.IssuedAt.After(now.Add(time.Minute)) || !token.Expiry.After(token.IssuedAt) || !token.Expiry.After(now) || len(token.Audience) > 1 && claims.AuthorizedParty == "" || claims.AuthorizedParty != "" && claims.AuthorizedParty != org.ClientID {
		return "", claims, fmt.Errorf("invalid organization claims")
	}
	// The verifier checks that our client occurs in aud, not that every audience
	// is trusted. This configuration trusts only its one registered client ID.
	if len(token.Audience) == 0 {
		return "", claims, fmt.Errorf("missing organization audience")
	}
	for _, audience := range token.Audience {
		if audience != org.ClientID {
			return "", claims, fmt.Errorf("untrusted organization audience")
		}
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		return "", claims, fmt.Errorf("unverified email")
	}
	if claims.NotBefore != nil && (*claims.NotBefore <= 0 || *claims.NotBefore > now.Add(time.Minute).Unix()) {
		return "", claims, fmt.Errorf("identity not yet valid")
	}
	email := claims.Email
	switch org.Provider {
	case "google":
		if claims.EmailVerified == nil || !*claims.EmailVerified || !org.AllowsDomain(claims.HostedDomain) || claims.HostedDomain == "gmail.com" || claims.HostedDomain == "googlemail.com" {
			return "", claims, fmt.Errorf("Workspace domain required")
		}
	case "okta":
		if claims.EmailVerified == nil || !*claims.EmailVerified {
			return "", claims, fmt.Errorf("verified Okta email required")
		}
	case "entra":
		u, _ := url.Parse(org.Issuer)
		tenant := strings.Split(strings.Trim(u.Path, "/"), "/")[0]
		if claims.Tenant == "" || claims.Tenant != tenant || claims.ObjectID == "" {
			return "", claims, fmt.Errorf("wrong Entra tenant")
		}
		// Microsoft does not promise that email/username is verified or immutable.
		// Use it only as an admin-configured domain filter; identify by issuer/sub.
		if email == "" {
			email = claims.PreferredUsername
		}
	}
	a, err := mail.ParseAddress(email)
	parts := strings.Split(email, "@")
	if err != nil || a.Address != email || len(parts) != 2 || !org.AllowsDomain(parts[1]) || len(email) > 254 {
		return "", claims, fmt.Errorf("company email domain required")
	}
	if len(claims.Groups) > 4096 || len(claims.Roles) > 4096 {
		return "", claims, fmt.Errorf("too many memberships")
	}
	for _, values := range [][]string{claims.Groups, claims.Roles} {
		for _, value := range values {
			if value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
				return "", claims, fmt.Errorf("invalid membership")
			}
		}
	}
	return email, claims, nil
}

func orgPrincipal(org config.OIDCOrg, subject string) string {
	data, _ := json.Marshal([]string{org.ID, org.Issuer, subject})
	digest := sha256.Sum256(data)
	return "oidc-" + hex.EncodeToString(digest[:]) + "@identity.tunn.invalid"
}

type orgSession struct {
	Org, Subject, Email, Policy string
	Groups                      []string
	Expires                     int64
}

func (p *ProxyServer) setOrgAuthCookie(w http.ResponseWriter, org config.OIDCOrg, subject, email string, groups []string, upstreamExpiry time.Time) error {
	now := p.currentTime()
	expires := now.Add(orgSessionLifetime)
	if upstreamExpiry.Before(expires) {
		expires = upstreamExpiry
	}
	if !expires.After(now) {
		return fmt.Errorf("expired identity")
	}
	claims := jwt.MapClaims{"type": "org_session", "email": orgPrincipal(org, subject), "org": org.ID, "upstream_sub": subject, "display_email": email, "policy": org.PolicyDigest(), "groups": groups, "iat": now.Unix(), "exp": expires.Unix()}
	value, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil || len(value) > 3800 {
		return fmt.Errorf("organization session unavailable")
	}
	http.SetCookie(w, &http.Cookie{Name: authCookieName, Value: value, Path: "/", Domain: "." + p.config.Domain, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(expires.Sub(now).Seconds())})
	return nil
}

func (p *ProxyServer) orgSessionClaims(claims jwt.MapClaims) (*orgSession, bool) {
	if claims["type"] != "org_session" {
		return nil, false
	}
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, false
	}
	var values struct {
		Org     string   `json:"org"`
		Subject string   `json:"upstream_sub"`
		Email   string   `json:"display_email"`
		Policy  string   `json:"policy"`
		Groups  []string `json:"groups"`
		Expiry  int64    `json:"exp"`
		Issued  int64    `json:"iat"`
	}
	if json.Unmarshal(data, &values) != nil || values.Expiry <= p.currentTime().Unix() || values.Issued > p.currentTime().Add(time.Minute).Unix() || values.Issued <= 0 || values.Expiry <= values.Issued || values.Expiry-values.Issued > int64(orgSessionLifetime.Seconds()) || len(values.Groups) > config.MaxOIDCGroups {
		return nil, false
	}
	org, found := p.config.OIDCOrg(values.Org)
	if !found || values.Policy != org.PolicyDigest() || values.Subject == "" || claims["email"] != orgPrincipal(org, values.Subject) {
		return nil, false
	}
	for _, group := range values.Groups {
		if !strings.HasPrefix(group, "group:"+org.ID+":") || !p.config.OIDCGroupExists(group) {
			return nil, false
		}
	}
	return &orgSession{Org: org.ID, Subject: values.Subject, Email: values.Email, Policy: values.Policy, Groups: values.Groups, Expires: values.Expiry}, true
}

func (p *ProxyServer) getOrgSession(r *http.Request) (*orgSession, bool) {
	if !p.visitorJWTConfigured() {
		return nil, false
	}
	cookie, err := r.Cookie(authCookieName)
	if err != nil {
		return nil, false
	}
	token, err := jwt.NewParser(jwt.WithoutClaimsValidation(), jwt.WithValidMethods([]string{"HS256"})).Parse(cookie.Value, func(*jwt.Token) (any, error) { return p.getJWTSigningKey(), nil })
	if err != nil || !token.Valid {
		return nil, false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false
	}
	return p.orgSessionClaims(claims)
}

func (p *ProxyServer) writeOrgLoginButtons(w io.Writer, params string) {
	for _, org := range p.config.OIDCOrgs {
		path := "/auth/org/" + org.ID
		if org.Provider == "google" {
			path = "/auth/google"
		}
		q := params
		if org.Provider == "google" {
			q += "&org=" + url.QueryEscape(org.ID)
		}
		_, _ = fmt.Fprintf(w, `<a href="%s?%s" class="btn btn-secondary">Continue with %s</a>`, template.HTMLEscapeString(path), template.HTMLEscapeString(q), template.HTMLEscapeString(org.Name))
	}
}
