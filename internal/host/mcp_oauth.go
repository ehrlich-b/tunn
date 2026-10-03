package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/golang-jwt/jwt/v4"
)

const mcpOAuthScope = "mcp:access"
const mcpOAuthCSRFCookie = "__Host-tunn_oauth_csrf"

type mcpOAuthClient struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
}
type mcpOAuthConfig struct {
	issuer  string
	clients map[string]mcpOAuthClient
}

func validOAuthText(s string, n int) bool {
	return s != "" && len(s) <= n && !strings.ContainsFunc(s, unicode.IsControl)
}
func httpsOAuthURL(value string, origin bool) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || !validOAuthText(value, 2048) || strings.ContainsAny(value, "\\ \t\r\n#") || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || (origin && (u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || strings.Contains(value, "?") || u.String() != value)) {
		return nil, fmt.Errorf("canonical HTTPS URL required")
	}
	return u, nil
}

func loadMCPOAuthConfig(cfg *config.Config) (*mcpOAuthConfig, error) {
	if cfg.MCPOAuthClientsFile == "" {
		return nil, nil
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("MCP OAuth requires configured owner signing key")
	}
	issuer := cfg.MCPOAuthIssuer
	if issuer == "" {
		issuer = "https://" + cfg.Domain
	}
	u, err := httpsOAuthURL(issuer, true)
	if err != nil || u.Hostname() != cfg.Domain {
		return nil, fmt.Errorf("MCP OAuth issuer must be the configured HTTPS apex origin")
	}
	file, err := os.Open(cfg.MCPOAuthClientsFile)
	if err != nil {
		return nil, fmt.Errorf("read MCP OAuth clients: %w", err)
	}
	defer file.Close()
	var input struct {
		Clients []mcpOAuthClient `json:"clients"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("invalid MCP OAuth clients file")
	}
	if err := decoder.Decode(new(any)); err != io.EOF || len(input.Clients) == 0 || len(input.Clients) > 16 {
		return nil, fmt.Errorf("invalid MCP OAuth clients file")
	}
	out := &mcpOAuthConfig{issuer: issuer, clients: make(map[string]mcpOAuthClient)}
	for _, client := range input.Clients {
		if !validOAuthText(client.ID, 256) || !validOAuthText(client.Name, 113) || len(client.RedirectURIs) == 0 || len(client.RedirectURIs) > 4 {
			return nil, fmt.Errorf("invalid MCP OAuth client")
		}
		if _, exists := out.clients[client.ID]; exists {
			return nil, fmt.Errorf("duplicate MCP OAuth client")
		}
		for _, redirect := range client.RedirectURIs {
			u, err := httpsOAuthURL(redirect, false)
			if err != nil || u.Query().Has("code") || u.Query().Has("state") || u.Query().Has("iss") {
				return nil, fmt.Errorf("invalid MCP OAuth redirect URI")
			}
		}
		out.clients[client.ID] = client
	}
	return out, nil
}

func (p *ProxyServer) mcpResource(endpoint string) string {
	u, _ := url.Parse(p.mcpOAuth.issuer)
	u.Host = endpoint + "." + u.Host
	u.Path = "/mcp"
	return u.String()
}
func oauthResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
func oauthJSONError(w http.ResponseWriter, status int, code string) {
	oauthResponseHeaders(w)
	writeGrantJSON(w, status, map[string]string{"error": code})
}
func (p *ProxyServer) handleMCPOAuthMetadata(w http.ResponseWriter, r *http.Request) {
	oauthResponseHeaders(w)
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		oauthJSONError(w, 405, "invalid_request")
		return
	}
	issuer := p.mcpOAuth.issuer
	writeGrantJSON(w, 200, map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/oauth/authorize", "token_endpoint": issuer + "/oauth/token", "authorization_response_iss_parameter_supported": true, "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"}, "token_endpoint_auth_methods_supported": []string{"none"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{mcpOAuthScope}})
}
func (p *ProxyServer) handleMCPResourceMetadata(w http.ResponseWriter, r *http.Request) {
	oauthResponseHeaders(w)
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		oauthJSONError(w, 405, "invalid_request")
		return
	}
	id := extractTunnelID(r.Host, p.Domain)
	tunnel, exists := p.tunnelServer.GetTunnel(id)
	if !exists || tunnel.AccountID == "" || (tunnel.EndpointProtocol != "http" && tunnel.EndpointProtocol != "mcp") {
		http.NotFound(w, r)
		return
	}
	writeGrantJSON(w, 200, map[string]any{"resource": p.mcpResource(id), "authorization_servers": []string{p.mcpOAuth.issuer}, "scopes_supported": []string{mcpOAuthScope}, "bearer_methods_supported": []string{"header"}})
}
func (p *ProxyServer) mcpOAuthChallenge(w http.ResponseWriter, endpoint string) {
	if p.mcpOAuth == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tunn"`)
		return
	}
	u, _ := url.Parse(p.mcpResource(endpoint))
	u.Path = "/.well-known/oauth-protected-resource/mcp"
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="tunn", resource_metadata="%s", scope="%s"`, u.String(), mcpOAuthScope))
}

type mcpConsentTicket struct {
	jwt.RegisteredClaims
	Kind           string `json:"type"`
	AccountID      string `json:"account_id"`
	EndpointID     string `json:"endpoint_id"`
	ClientID       string `json:"client_id"`
	RedirectURI    string `json:"redirect_uri"`
	Resource       string `json:"resource"`
	Scope          string `json:"scope"`
	Challenge      string `json:"challenge"`
	State          string `json:"state"`
	CSRF           string `json:"csrf"`
	GrantExpiresAt int64  `json:"grant_expires_at"`
}

func oauthRandom() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}
func oauthDigestShape(s string) bool {
	b, e := base64.RawURLEncoding.DecodeString(s)
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func oauthSingle(v url.Values, k string) string {
	if len(v[k]) != 1 {
		return ""
	}
	return v.Get(k)
}
func (p *ProxyServer) validOAuthClient(id, redirect string) (mcpOAuthClient, bool) {
	client, exists := p.mcpOAuth.clients[id]
	if !exists {
		return client, false
	}
	for _, uri := range client.RedirectURIs {
		if uri == redirect {
			return client, true
		}
	}
	return client, false
}
func (p *ProxyServer) oauthEndpoint(resource string) (string, bool) {
	u, err := httpsOAuthURL(resource, false)
	if err != nil || u.Path != "/mcp" || u.EscapedPath() != "/mcp" || u.RawQuery != "" {
		return "", false
	}
	issuer, _ := url.Parse(p.mcpOAuth.issuer)
	id := extractTunnelID(u.Host, p.Domain)
	return id, id != "" && isValidDNSLabel(id) && u.Scheme == issuer.Scheme && resource == p.mcpResource(id)
}
func (p *ProxyServer) oauthRedirect(w http.ResponseWriter, r *http.Request, redirect, state, code, errCode string) {
	u, _ := url.Parse(redirect)
	q := u.Query()
	q.Set("iss", p.mcpOAuth.issuer)
	q.Set("state", state)
	if errCode != "" {
		q.Set("error", errCode)
	} else {
		q.Set("code", code)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

var mcpConsentPage = template.Must(template.New("mcp-consent").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Connect private tools</title></head><body><h1>Connect private tools</h1><p>Client: <strong>{{.Client.Name}}</strong> ({{.Client.ID}})</p><p>Endpoint: <strong>{{.Ticket.Resource}}</strong></p><p>This grants /mcp route access for 100 HTTP requests, including initialization and discovery. The upstream service controls its available tools. Access expires {{.Expiry}}. Find the grant ID with <code>tunn grant list {{.Ticket.EndpointID}}</code> or the account's grant list, then revoke it with <code>tunn grant revoke &lt;grant-id&gt;</code> using your saved owner login.</p><form method="post" action="/oauth/authorize"><input type="hidden" name="ticket" value="{{.Signed}}"><button name="decision" value="allow">Allow this client</button><button name="decision" value="deny">Cancel</button></form></body></html>`))

func (p *ProxyServer) handleMCPOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), ingressStorageTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	oauthResponseHeaders(w)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if r.Method != "GET" && r.Method != "POST" {
		w.Header().Set("Allow", "GET, POST")
		oauthJSONError(w, 405, "invalid_request")
		return
	}
	if r.Method == "GET" {
		p.mcpOAuthConsent(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if err := r.ParseForm(); err != nil {
		oauthJSONError(w, 400, "invalid_request")
		return
	}
	ticket := &mcpConsentTicket{}
	token, err := jwt.ParseWithClaims(oauthSingle(r.PostForm, "ticket"), ticket, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("invalid consent signing method")
		}
		return p.getJWTSigningKey(), nil
	})
	if err != nil || !token.Valid || ticket.Kind != "mcp_oauth_consent" || ticket.Issuer != p.mcpOAuth.issuer || ticket.ExpiresAt == nil || ticket.ID == "" {
		oauthJSONError(w, 400, "invalid_request")
		return
	}
	client, valid := p.validOAuthClient(ticket.ClientID, ticket.RedirectURI)
	id, validResource := p.oauthEndpoint(ticket.Resource)
	csrf, err := r.Cookie(mcpOAuthCSRFCookie)
	if !valid || !validResource || id != ticket.EndpointID || ticket.Scope != mcpOAuthScope || !oauthDigestShape(ticket.Challenge) || err != nil || subtle.ConstantTimeCompare([]byte(csrf.Value), []byte(ticket.CSRF)) != 1 {
		oauthJSONError(w, 400, "invalid_request")
		return
	}
	email, authenticated := p.getAuthFromCookie(r)
	if !authenticated || p.storage == nil || !p.storage.Available() {
		oauthJSONError(w, 401, "access_denied")
		return
	}
	account, err := p.storage.GetAccountByEmail(r.Context(), email)
	if err != nil {
		oauthJSONError(w, 503, "temporarily_unavailable")
		return
	}
	if account == nil || account.ID != ticket.AccountID {
		oauthJSONError(w, 403, "access_denied")
		return
	}
	decision := oauthSingle(r.PostForm, "decision")
	if decision == "deny" {
		p.oauthRedirect(w, r, ticket.RedirectURI, ticket.State, "", "access_denied")
		return
	}
	if decision != "allow" {
		oauthJSONError(w, 400, "invalid_request")
		return
	}
	code, err := oauthRandom()
	if err != nil {
		oauthJSONError(w, 503, "temporarily_unavailable")
		return
	}
	codes, supported := p.storage.(storage.OAuthCodeStorage)
	if !supported {
		oauthJSONError(w, 503, "temporarily_unavailable")
		return
	}
	err = codes.CreateOAuthCode(r.Context(), store.OAuthCodeCreate{Code: code, ConsentID: ticket.ID, AccountID: account.ID, EndpointID: id, ClientID: client.ID, RedirectURI: ticket.RedirectURI, Resource: ticket.Resource, Scope: ticket.Scope, CodeChallenge: ticket.Challenge, ExpiresAt: ticket.ExpiresAt.Time, GrantExpiresAt: time.Unix(ticket.GrantExpiresAt, 0).UTC(), RequestLimit: 100, Label: "OAuth: " + client.Name})
	if err != nil {
		code := "temporarily_unavailable"
		if errors.Is(err, store.ErrOAuthInvalidGrant) || errors.Is(err, store.ErrOAuthInvalidRequest) {
			code = "access_denied"
		}
		p.oauthRedirect(w, r, ticket.RedirectURI, ticket.State, "", code)
		return
	}
	p.oauthRedirect(w, r, ticket.RedirectURI, ticket.State, code, "")
}

func (p *ProxyServer) mcpOAuthConsent(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, valid := p.validOAuthClient(oauthSingle(q, "client_id"), oauthSingle(q, "redirect_uri"))
	if !valid {
		oauthJSONError(w, 400, "invalid_request")
		return
	}
	redirect, state := q.Get("redirect_uri"), q.Get("state")
	id, resourceOK := p.oauthEndpoint(oauthSingle(q, "resource"))
	scope := oauthSingle(q, "scope")
	if scope == "" && len(q["scope"]) == 0 {
		scope = mcpOAuthScope
	}
	if !resourceOK || scope != mcpOAuthScope || oauthSingle(q, "response_type") != "code" || oauthSingle(q, "code_challenge_method") != "S256" || !oauthDigestShape(oauthSingle(q, "code_challenge")) || len(state) > 1024 || strings.ContainsFunc(state, unicode.IsControl) || len(q["state"]) > 1 {
		p.oauthRedirect(w, r, redirect, state, "", "invalid_request")
		return
	}
	email, authenticated := p.getAuthFromCookie(r)
	if !authenticated {
		http.Redirect(w, r, p.mcpOAuth.issuer+"/auth/login?return_to="+url.QueryEscape(r.URL.RequestURI()), 302)
		return
	}
	if p.storage == nil || !p.storage.Available() {
		oauthJSONError(w, 503, "temporarily_unavailable")
		return
	}
	account, err := p.storage.GetAccountByEmail(r.Context(), email)
	if err != nil {
		p.oauthRedirect(w, r, redirect, state, "", "temporarily_unavailable")
		return
	}
	if account == nil {
		p.oauthRedirect(w, r, redirect, state, "", "access_denied")
		return
	}
	nonce, err := oauthRandom()
	if err != nil {
		oauthJSONError(w, 503, "temporarily_unavailable")
		return
	}
	csrf, err := oauthRandom()
	if err != nil {
		oauthJSONError(w, 503, "temporarily_unavailable")
		return
	}
	now := time.Now().UTC()
	ticket := &mcpConsentTicket{RegisteredClaims: jwt.RegisteredClaims{Issuer: p.mcpOAuth.issuer, ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), ID: nonce}, Kind: "mcp_oauth_consent", AccountID: account.ID, EndpointID: id, ClientID: client.ID, RedirectURI: redirect, Resource: q.Get("resource"), Scope: scope, Challenge: q.Get("code_challenge"), State: state, CSRF: csrf, GrantExpiresAt: now.Add(30 * time.Minute).Unix()}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, ticket).SignedString(p.getJWTSigningKey())
	if err != nil {
		oauthJSONError(w, 503, "temporarily_unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: mcpOAuthCSRFCookie, Value: csrf, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 300})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = mcpConsentPage.Execute(w, struct {
		Client         mcpOAuthClient
		Ticket         *mcpConsentTicket
		Signed, Expiry string
	}{client, ticket, signed, time.Unix(ticket.GrantExpiresAt, 0).UTC().Format(time.RFC3339)})
}

func (p *ProxyServer) handleMCPOAuthToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), ingressStorageTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	oauthResponseHeaders(w)
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		oauthJSONError(w, 405, "invalid_request")
		return
	}
	mediaType, _, parseErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if parseErr != nil || mediaType != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Authorization")) != 0 {
		oauthJSONError(w, 400, "invalid_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		oauthJSONError(w, 400, "invalid_request")
		return
	}
	q := r.PostForm
	clientID, redirect := oauthSingle(q, "client_id"), oauthSingle(q, "redirect_uri")
	if _, valid := p.validOAuthClient(clientID, redirect); !valid {
		oauthJSONError(w, 400, "invalid_client")
		return
	}
	if oauthSingle(q, "grant_type") != "authorization_code" || len(q["client_secret"]) != 0 {
		oauthJSONError(w, 400, "unsupported_grant_type")
		return
	}
	verifier := oauthSingle(q, "code_verifier")
	if len(verifier) < 43 || len(verifier) > 128 || strings.ContainsFunc(verifier, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("-._~", r))
	}) {
		oauthJSONError(w, 400, "invalid_grant")
		return
	}
	resource := oauthSingle(q, "resource")
	if _, valid := p.oauthEndpoint(resource); !valid {
		oauthJSONError(w, 400, "invalid_target")
		return
	}
	digest := sha256.Sum256([]byte(verifier))
	codes, supported := p.storage.(storage.OAuthCodeStorage)
	if !supported || !p.storage.Available() {
		oauthJSONError(w, 503, "temporarily_unavailable")
		return
	}
	grant, token, err := codes.ExchangeOAuthCode(r.Context(), store.OAuthCodeExchange{Code: oauthSingle(q, "code"), ClientID: clientID, RedirectURI: redirect, Resource: resource, CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:])})
	if err != nil {
		if errors.Is(err, store.ErrOAuthInvalidGrant) || errors.Is(err, store.ErrOAuthInvalidRequest) {
			oauthJSONError(w, 400, "invalid_grant")
		} else {
			oauthJSONError(w, 503, "temporarily_unavailable")
		}
		return
	}
	remaining := int64(time.Until(grant.ExpiresAt) / time.Second)
	if remaining < 1 {
		remaining = 1
	}
	writeGrantJSON(w, 200, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": remaining, "scope": mcpOAuthScope})
}
