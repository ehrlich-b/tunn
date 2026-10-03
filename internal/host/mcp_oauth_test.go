package host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/golang-jwt/jwt/v4"
)

func enableTestMCPOAuth(t *testing.T, p *ProxyServer) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "oauth-clients.json")
	data := `{"clients":[{"client_id":"chatgpt-fixture","name":"ChatGPT synthetic client","redirect_uris":["https://chatgpt.example.test/callback"]},{"client_id":"claude-fixture","name":"Claude synthetic client","redirect_uris":["https://claude.example.test/callback"]}]}`
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	p.config.MCPOAuthClientsFile = file
	oauth, err := loadMCPOAuthConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	p.mcpOAuth = oauth
	for _, id := range []string{"tools"} {
		if tunnel, exists := p.tunnelServer.GetTunnel(id); exists {
			tunnel.EndpointProtocol = "mcp"
		}
	}
}

func oauthFixtureRequest(p *ProxyServer, method, path, host string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body string
	if form != nil {
		body = form.Encode()
	}
	r := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}

func oauthConsentFixture(t *testing.T, p *ProxyServer, endpoint, clientID string) (string, *http.Cookie, string, url.Values) {
	t.Helper()
	client := p.mcpOAuth.clients[clientID]
	ownerEmail := "owner@example.test"
	if tunnel, ok := p.tunnelServer.GetTunnel(endpoint); ok {
		ownerEmail = tunnel.CreatorEmail
	}
	owner := &http.Cookie{Name: authCookieName, Value: ingressJWT(t, p, ownerEmail)}
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{"client_id": {clientID}, "redirect_uri": {client.RedirectURIs[0]}, "resource": {p.mcpResource(endpoint)}, "scope": {mcpOAuthScope}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "state": {"fixture-state"}}
	w := oauthFixtureRequest(p, "GET", "/oauth/authorize?"+query.Encode(), p.Domain, nil, owner)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "100 HTTP requests") || !strings.Contains(w.Body.String(), "tunn grant list "+endpoint) || !strings.Contains(w.Body.String(), "tunn grant revoke") {
		t.Fatalf("consent=%d %s", w.Code, w.Body.String())
	}
	match := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("missing signed consent")
	}
	var csrf *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == mcpOAuthCSRFCookie {
			csrf = cookie
		}
	}
	if csrf == nil || !csrf.Secure || !csrf.HttpOnly || csrf.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe CSRF cookie")
	}
	return match[1], csrf, verifier, query
}

func oauthApprovedCodeFixture(t *testing.T, p *ProxyServer, endpoint, clientID string) (string, url.Values) {
	t.Helper()
	ticket, csrf, verifier, query := oauthConsentFixture(t, p, endpoint, clientID)
	ownerEmail := "owner@example.test"
	if tunnel, ok := p.tunnelServer.GetTunnel(endpoint); ok {
		ownerEmail = tunnel.CreatorEmail
	}
	owner := &http.Cookie{Name: authCookieName, Value: ingressJWT(t, p, ownerEmail)}
	w := oauthFixtureRequest(p, "POST", "/oauth/authorize", p.Domain, url.Values{"ticket": {ticket}, "decision": {"allow"}}, owner, csrf)
	callback, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != 302 || callback.Query().Get("iss") != p.mcpOAuth.issuer || callback.Query().Get("state") != "fixture-state" || callback.Query().Get("code") == "" {
		t.Fatalf("authorization=%d %s", w.Code, w.Header().Get("Location"))
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {query.Get("redirect_uri")}, "resource": {query.Get("resource")}, "code_verifier": {verifier}, "code": {callback.Query().Get("code")}}
	return ticket, form
}

func TestMCPOAuthConsentPKCEResourceAndRevocation(t *testing.T) {
	p, local, tunnel, _ := newIngressProxy(t, false)
	enableTestMCPOAuth(t, p)
	if reg, err := local.RegisterEndpoint(context.Background(), tunnel.TunnelID, tunnel.AccountID, "test-node", "mcp"); err != nil || !reg.Allowed {
		t.Fatal(reg, err)
	}
	for _, clientID := range []string{"chatgpt-fixture", "claude-fixture"} {
		_, form := oauthApprovedCodeFixture(t, p, tunnel.TunnelID, clientID)
		before, err := local.ListGrants(context.Background(), tunnel.AccountID, tunnel.TunnelID)
		if err != nil {
			t.Fatal(err)
		}
		correctVerifier := form.Get("code_verifier")
		form.Set("code_verifier", strings.Repeat("x", 43))
		if wrong := oauthFixtureRequest(p, "POST", "/oauth/token", p.Domain, form); wrong.Code != 400 {
			t.Fatal("wrong PKCE admitted")
		}
		form.Set("code_verifier", correctVerifier)
		w := oauthFixtureRequest(p, "POST", "/oauth/token", p.Domain, form)
		var response struct {
			Token   string `json:"access_token"`
			Type    string `json:"token_type"`
			Expires int64  `json:"expires_in"`
			Scope   string `json:"scope"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || response.Type != "Bearer" || response.Expires < 1 || response.Expires > 1800 || response.Scope != mcpOAuthScope || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("token=%d %s", w.Code, w.Body.String())
		}
		if replay := oauthFixtureRequest(p, "POST", "/oauth/token", p.Domain, form); replay.Code != 400 {
			t.Fatal("code replay admitted")
		}
		after, err := local.ListGrants(context.Background(), tunnel.AccountID, tunnel.TunnelID)
		if err != nil || len(after) != len(before)+1 {
			t.Fatal(after, err)
		}
		var grantID string
		for _, grant := range after {
			if grant.Label == "OAuth: "+p.mcpOAuth.clients[clientID].Name {
				grantID = grant.ID
			}
		}
		if grantID == "" {
			t.Fatal("missing independently visible client grant")
		}
		r := httptest.NewRequest("POST", "https://tools.tunn.to/mcp", strings.NewReader("test"))
		r.Header.Set("Authorization", "Bearer "+response.Token)
		out := httptest.NewRecorder()
		p.createHandler().ServeHTTP(out, r)
		if out.Code != 200 {
			t.Fatal(out.Code)
		}
		if _, err := local.RevokeGrant(context.Background(), tunnel.AccountID, grantID); err != nil {
			t.Fatal(err)
		}
		r = httptest.NewRequest("POST", "https://tools.tunn.to/mcp", strings.NewReader("test"))
		r.Header.Set("Authorization", "Bearer "+response.Token)
		r.AddCookie(&http.Cookie{Name: authCookieName, Value: ingressJWT(t, p, "owner@example.test")})
		out = httptest.NewRecorder()
		p.createHandler().ServeHTTP(out, r)
		if out.Code != 401 || out.Header().Get("X-Tunn-Grant-Reason") != "grant_revoked" || !strings.Contains(out.Header().Get("WWW-Authenticate"), "resource_metadata=") {
			t.Fatal("revocation failed OAuth challenge", out.Code)
		}
	}
}

func TestMCPOAuthCSRFConsentAndRedirectBoundaries(t *testing.T) {
	p, local, tunnel, _ := newIngressProxy(t, false)
	enableTestMCPOAuth(t, p)
	if reg, err := local.RegisterEndpoint(context.Background(), tunnel.TunnelID, tunnel.AccountID, "test-node", "mcp"); err != nil || !reg.Allowed {
		t.Fatal(reg, err)
	}
	ticket, csrf, _, query := oauthConsentFixture(t, p, tunnel.TunnelID, "chatgpt-fixture")
	owner := &http.Cookie{Name: authCookieName, Value: ingressJWT(t, p, "owner@example.test")}
	form := url.Values{"ticket": {ticket}, "decision": {"allow"}}
	if w := oauthFixtureRequest(p, "POST", "/oauth/authorize", p.Domain, form, owner); w.Code != 400 {
		t.Fatal("missing CSRF accepted")
	}
	if w := oauthFixtureRequest(p, "POST", "/oauth/authorize", p.Domain, form, csrf, &http.Cookie{Name: authCookieName, Value: ingressJWT(t, p, "alice@example.test")}); w.Code != 403 {
		t.Fatal("owner changed during consent accepted")
	}
	form.Set("decision", "deny")
	w := oauthFixtureRequest(p, "POST", "/oauth/authorize", p.Domain, form, owner, csrf)
	u, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || u.Query().Get("error") != "access_denied" || u.Query().Get("iss") != p.mcpOAuth.issuer {
		t.Fatal("cancel issuer missing")
	}
	query.Set("redirect_uri", "https://unregistered.example.test/callback")
	w = oauthFixtureRequest(p, "GET", "/oauth/authorize?"+query.Encode(), p.Domain, nil, owner)
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatal("open redirect")
	}
	if grants, err := local.ListGrants(context.Background(), tunnel.AccountID, tunnel.TunnelID); err != nil || len(grants) != 0 {
		t.Fatal("denial minted grant", grants, err)
	}
}

func TestMCPOAuthDiscoveryIsCanonicalAndDoesNotForward(t *testing.T) {
	p, local, tunnel, _ := newIngressProxy(t, true)
	enableTestMCPOAuth(t, p)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		w := oauthFixtureRequest(p, "GET", path, "tools.tunn.to", nil)
		var out struct {
			Resource string   `json:"resource"`
			Issuers  []string `json:"authorization_servers"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || out.Resource != "https://tools.tunn.to/mcp" || len(out.Issuers) != 1 || out.Issuers[0] != "https://tunn.to" {
			t.Fatal(out, w.Code)
		}
	}
	w := oauthFixtureRequest(p, "POST", "/mcp", "tools.tunn.to", url.Values{})
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `resource_metadata="https://tools.tunn.to/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatal(w.Code, w.Header())
	}
	events := exportIngress(t, local, tunnel.AccountID, false).Events
	if len(events) != 1 || events[0].Forwarded {
		t.Fatal("discovery forwarded or metered", events)
	}
	w = oauthFixtureRequest(p, "GET", "/.well-known/oauth-authorization-server", p.Domain, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"S256"`) || strings.Contains(w.Body.String(), "registration_endpoint") {
		t.Fatal("false discovery claim", w.Body.String())
	}
}

type unavailableOAuthCodeStorage struct{ *storage.LocalStorage }

func (s *unavailableOAuthCodeStorage) ExchangeOAuthCode(context.Context, store.OAuthCodeExchange) (*store.Grant, string, error) {
	return nil, "", errors.New("synthetic lost storage acknowledgement")
}

func TestMCPOAuthHTTPBindingParserReplayAndStorageErrors(t *testing.T) {
	p, local, tunnel, _ := newIngressProxy(t, false)
	enableTestMCPOAuth(t, p)
	if reg, err := local.RegisterEndpoint(context.Background(), tunnel.TunnelID, tunnel.AccountID, "test-node", "mcp"); err != nil || !reg.Allowed {
		t.Fatal(reg, err)
	}
	_, form := oauthApprovedCodeFixture(t, p, tunnel.TunnelID, "chatgpt-fixture")
	for _, kind := range []string{"client", "redirect", "resource", "duplicate-code", "duplicate-verifier", "grant-type"} {
		mutated := make(url.Values)
		for key, values := range form {
			mutated[key] = append([]string(nil), values...)
		}
		switch kind {
		case "client":
			mutated.Set("client_id", "claude-fixture")
			mutated.Set("redirect_uri", p.mcpOAuth.clients["claude-fixture"].RedirectURIs[0])
		case "redirect":
			mutated.Set("redirect_uri", "https://chatgpt.example.test/other")
		case "resource":
			mutated.Set("resource", p.mcpResource("other"))
		case "duplicate-code":
			mutated.Add("code", "extra")
		case "duplicate-verifier":
			mutated.Add("code_verifier", strings.Repeat("x", 43))
		case "grant-type":
			mutated.Set("grant_type", "refresh_token")
		}
		if w := oauthFixtureRequest(p, "POST", "/oauth/token", p.Domain, mutated); w.Code != 400 {
			t.Fatal("bad token binding admitted", kind, w.Code)
		}
	}
	for _, kind := range []string{"authorization-values", "content-type-prefix", "wrong-method"} {
		r := httptest.NewRequest("POST", "https://tunn.to/oauth/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		switch kind {
		case "authorization-values":
			r.Header.Add("Authorization", "")
			r.Header.Add("Authorization", "Bearer unexpected")
		case "content-type-prefix":
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded-invalid")
		case "wrong-method":
			r.Method = "GET"
		}
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 405 {
			t.Fatal("bad token parser admitted", kind, w.Code)
		}
	}
	p.storage = &unavailableOAuthCodeStorage{local}
	if w := oauthFixtureRequest(p, "POST", "/oauth/token", p.Domain, form); w.Code != 503 || !strings.Contains(w.Body.String(), "temporarily_unavailable") {
		t.Fatal("storage failure reported invalid grant", w.Code)
	}
	p.storage = local
	if w := oauthFixtureRequest(p, "POST", "/oauth/token", p.Domain, form); w.Code != 200 {
		t.Fatal("failed binding consumed code", w.Code)
	}
	if w := oauthFixtureRequest(p, "POST", "/oauth/token", p.Domain, form); w.Code != 400 {
		t.Fatal("successful exchange replayed")
	}
}

func TestMCPOAuthConsentTicketExpiryMutationAndReplay(t *testing.T) {
	p, local, tunnel, _ := newIngressProxy(t, false)
	enableTestMCPOAuth(t, p)
	if reg, err := local.RegisterEndpoint(context.Background(), tunnel.TunnelID, tunnel.AccountID, "test-node", "mcp"); err != nil || !reg.Allowed {
		t.Fatal(reg, err)
	}
	signed, csrf, _, _ := oauthConsentFixture(t, p, tunnel.TunnelID, "chatgpt-fixture")
	owner := &http.Cookie{Name: authCookieName, Value: ingressJWT(t, p, "owner@example.test")}
	ticket := &mcpConsentTicket{}
	if _, err := jwt.ParseWithClaims(signed, ticket, func(*jwt.Token) (interface{}, error) { return p.getJWTSigningKey(), nil }); err != nil {
		t.Fatal(err)
	}
	ticket.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Second))
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, ticket).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{expired, signed + "tamper"} {
		if w := oauthFixtureRequest(p, "POST", "/oauth/authorize", p.Domain, url.Values{"ticket": {value}, "decision": {"allow"}}, owner, csrf); w.Code != 400 {
			t.Fatal("invalid ticket accepted")
		}
	}
	form := url.Values{"ticket": {signed}, "decision": {"allow"}}
	first := oauthFixtureRequest(p, "POST", "/oauth/authorize", p.Domain, form, owner, csrf)
	callback, _ := url.Parse(first.Header().Get("Location"))
	if first.Code != 302 || callback.Query().Get("code") == "" {
		t.Fatal("consent failed")
	}
	second := oauthFixtureRequest(p, "POST", "/oauth/authorize", p.Domain, form, owner, csrf)
	callback, _ = url.Parse(second.Header().Get("Location"))
	if second.Code != 302 || callback.Query().Get("code") != "" || callback.Query().Get("iss") != p.mcpOAuth.issuer {
		t.Fatal("consent minted second code")
	}
}

func TestMCPOAuthSharedEndpointRoutingAndUnknownProtocol(t *testing.T) {
	for _, proto := range []int{2, 3} {
		p, _, _, _ := newIngressProxy(t, false)
		enableTestMCPOAuth(t, p)
		var handler http.Handler = p.createHandler()
		if proto == 2 {
			handler = p.createHTTP2Router(handler)
		}
		r := httptest.NewRequest("GET", "https://tools.tunn.to/oauth/authorize", nil)
		r.ProtoMajor = proto
		r.AddCookie(&http.Cookie{Name: authCookieName, Value: ingressJWT(t, p, "owner@example.test")})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.String() != "response" {
			t.Fatal("endpoint route reached platform OAuth", proto, w.Code)
		}
	}
	p, _, tunnel, _ := newIngressProxy(t, false)
	enableTestMCPOAuth(t, p)
	tunnel.EndpointProtocol = ""
	if w := oauthFixtureRequest(p, "GET", "/.well-known/oauth-protected-resource/mcp", "tools.tunn.to", nil); w.Code != 404 {
		t.Fatal("unknown protocol advertises OAuth")
	}
}

func TestMCPOAuthDisabledAndCanonicalConfig(t *testing.T) {
	p, _, _, _ := newIngressProxy(t, false)
	if out, err := loadMCPOAuthConfig(p.config); err != nil || out != nil {
		t.Fatal("OAuth enabled without explicit clients")
	}
	enableTestMCPOAuth(t, p)
	for _, issuer := range []string{"https://tunn.to?", "https://tunn.to#", "https://tunn.to/", "https://other.test", "https://tunn.to\\x"} {
		cfg := *p.config
		cfg.MCPOAuthIssuer = issuer
		if _, err := loadMCPOAuthConfig(&cfg); err == nil {
			t.Fatal("unsafe issuer accepted", issuer)
		}
	}
}
