package host

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"github.com/golang-jwt/jwt/v4"
)

const mcpAccessTokenLifetime = time.Hour

func (p *ProxyServer) mcpIssuer() string {
	u, _ := url.Parse("https://" + p.config.PublicAddr)
	authority := p.Domain
	if u != nil && u.Port() != "" && u.Port() != "443" {
		authority = net.JoinHostPort(p.Domain, u.Port())
	}
	return "https://" + authority
}

func (p *ProxyServer) mcpResource(endpoint string) string {
	return strings.Replace(p.mcpIssuer(), "https://", "https://"+endpoint+".", 1) + "/mcp"
}

func (p *ProxyServer) mcpResourceEndpoint(resource string) string {
	u, err := url.Parse(resource)
	if err != nil {
		return ""
	}
	endpoint := extractTunnelID(u.Host, p.Domain)
	if !isValidDNSLabel(endpoint) || isReservedSubdomain(endpoint) || resource != p.mcpResource(endpoint) {
		return ""
	}
	return endpoint
}

func (p *ProxyServer) mcpChallenge(w http.ResponseWriter, endpoint, problem string) {
	value := fmt.Sprintf(`Bearer realm="tunn", resource_metadata="%s", scope="mcp"`, strings.TrimSuffix(p.mcpResource(endpoint), "/mcp")+"/.well-known/oauth-protected-resource/mcp")
	if problem != "" {
		value += `, error="` + problem + `"`
	}
	w.Header().Set("WWW-Authenticate", value)
}

// Only metadata is served on publisher origins. Login, consent and management
// stay on the configured platform origin, outside publisher script control.
func (p *ProxyServer) handleMCPResourceMetadata(w http.ResponseWriter, r *http.Request, endpoint string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", 405)
		return
	}
	writeOAuthJSON(w, 200, map[string]any{
		"resource": p.mcpResource(endpoint), "authorization_servers": []string{p.mcpIssuer()},
		"scopes_supported": []string{"mcp"}, "bearer_methods_supported": []string{"header"},
		"resource_name": endpoint + " MCP tools",
	})
}

func writeOAuthJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func oauthProblem(w http.ResponseWriter, status int, code, description string) {
	writeOAuthJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func randomOAuthValue(prefix string) (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(data[:]), nil
}

func validMCPRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && ip != nil && ip.IsLoopback()
}

// All OAuth state is authoritative on the login node. HTTP forwarding uses
// existing relay routing and preserves the public platform Host header.
func (p *ProxyServer) handleMCPOAuth(w http.ResponseWriter, r *http.Request) {
	if !p.isPlatformHost(r.Host) {
		http.Error(w, "Invalid authentication host", 403)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if p.mcpOAuth == nil {
		p.loginNodeMu.RLock()
		addr := p.loginNodeHTTPAddr
		p.loginNodeMu.RUnlock()
		if addr != "" && r.Header.Get("Tunn-MCP-OAuth-Forwarded") == "" {
			clone := r.Clone(r.Context())
			clone.Header = r.Header.Clone()
			clone.Header.Set("Tunn-MCP-OAuth-Forwarded", "1")
			p.proxyToNode(w, clone, addr, "")
			return
		}
		oauthProblem(w, 503, "temporarily_unavailable", "MCP authorization service unavailable")
		return
	}
	if !p.visitorJWTConfigured() || p.meter == nil {
		oauthProblem(w, 503, "temporarily_unavailable", "MCP authorization is not configured")
		return
	}
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", 405)
			return
		}
		issuer := p.mcpIssuer()
		writeOAuthJSON(w, 200, map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/oauth/authorize", "token_endpoint": issuer + "/oauth/token",
			"registration_endpoint": issuer + "/oauth/register", "response_types_supported": []string{"code"},
			"grant_types_supported": []string{"authorization_code"}, "token_endpoint_auth_methods_supported": []string{"none"},
			"authorization_response_iss_parameter_supported": true, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"mcp"},
		})
	case "/oauth/register":
		p.handleMCPRegistration(w, r)
	case "/oauth/authorize":
		p.handleMCPAuthorize(w, r)
	case "/oauth/token":
		p.handleMCPToken(w, r)
	case "/account/mcp", "/api/mcp/clients":
		p.handleMCPClients(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *ProxyServer) handleMCPRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		oauthProblem(w, 400, "invalid_client_metadata", "Expected JSON client metadata")
		return
	}
	var client mcpOAuthClient
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	if err := decoder.Decode(&client); err != nil {
		oauthProblem(w, 400, "invalid_client_metadata", "Invalid client metadata")
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		oauthProblem(w, 400, "invalid_client_metadata", "Expected one client metadata object")
		return
	}
	if len(client.RedirectURIs) == 0 || len(client.RedirectURIs) > 10 {
		oauthProblem(w, 400, "invalid_redirect_uri", "Register 1 to 10 exact redirect URIs")
		return
	}
	for _, uri := range client.RedirectURIs {
		if !validMCPRedirect(uri) {
			oauthProblem(w, 400, "invalid_redirect_uri", "Redirects require HTTPS or loopback HTTP without credentials or fragments")
			return
		}
	}
	if len(client.Name) > 128 || client.AuthMethod != "" && client.AuthMethod != "none" || len(client.GrantTypes) > 0 && !slices.Equal(client.GrantTypes, []string{"authorization_code"}) || len(client.ResponseTypes) > 0 && !slices.Equal(client.ResponseTypes, []string{"code"}) {
		oauthProblem(w, 400, "invalid_client_metadata", "Only public authorization-code clients are supported")
		return
	}
	if client.Name == "" {
		client.Name = "MCP connector"
	}
	var err error
	client.ID, err = randomOAuthValue("mcp_")
	if err != nil {
		oauthProblem(w, 500, "server_error", "Could not register client")
		return
	}
	client.AuthMethod, client.GrantTypes, client.ResponseTypes, client.IssuedAt = "none", []string{"authorization_code"}, []string{"code"}, time.Now().Unix()
	if err := p.mcpOAuth.register(r.Context(), &client); err != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Client registry unavailable or full")
		return
	}
	writeOAuthJSON(w, 201, &client)
}

// Auth service accepts only exact canonical resource identifiers. Tunnel owner
// UUIDs come from a live publisher or its authenticated internal FindTunnel RPC.
func (p *ProxyServer) mcpTunnel(ctx context.Context, endpoint string) (*TunnelConnection, *storage.Account, error) {
	tunnel, exists := p.tunnelServer.GetTunnel(endpoint)
	if !exists {
		for _, client := range p.nodeClients {
			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			found, err := client.FindTunnel(probeCtx, &internalpb.FindTunnelRequest{TunnelId: endpoint})
			cancel()
			if err == nil && found.Found {
				tunnel = &TunnelConnection{TunnelID: endpoint, AccountID: found.AccountId, CreatorEmail: found.CreatorEmail, TargetURL: found.EndpointKind, AllowedEmails: found.AllowedEmails}
				break
			}
		}
	}
	if tunnel == nil || tunnel.TargetURL != "mcp" {
		return nil, nil, fmt.Errorf("MCP endpoint offline")
	}
	account, err := p.currentTunnelAccount(ctx, tunnel)
	if err != nil || account == nil {
		return nil, nil, fmt.Errorf("MCP owner unavailable")
	}
	return tunnel, account, nil
}

func (p *ProxyServer) mcpUserAllowed(ctx context.Context, email string, tunnel *TunnelConnection, owner *storage.Account) bool {
	account, err := p.storage.GetAccountByEmail(ctx, common.NormalizeEmail(email))
	if err != nil || account == nil {
		return false
	}
	if account.ID == owner.ID {
		return true
	}
	bucket, err := p.storage.GetEmailBucket(ctx, email)
	return err == nil && isEmailBucketAllowed(bucket, tunnel.AllowedEmails)
}

func (p *ProxyServer) handleMCPAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		p.handleMCPConsent(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	query := r.URL.Query()
	for _, values := range query {
		if len(values) != 1 {
			oauthProblem(w, 400, "invalid_request", "Duplicate authorization parameter")
			return
		}
	}
	client, err := p.mcpOAuth.client(r.Context(), query.Get("client_id"))
	if err != nil || !slices.Contains(client.RedirectURIs, query.Get("redirect_uri")) {
		oauthProblem(w, 400, "invalid_request", "Unknown client or unregistered redirect URI")
		return
	}
	// Once redirect ownership is known, OAuth errors go to the registered client.
	auth := &mcpAuthorization{ClientID: client.ID, RedirectURI: query.Get("redirect_uri"), Resource: query.Get("resource"), Challenge: query.Get("code_challenge"), State: query.Get("state"), Scope: query.Get("scope")}
	if len(auth.State) > 1024 {
		oauthProblem(w, 400, "invalid_request", "State is too long")
		return
	}
	if query.Get("response_type") != "code" {
		p.redirectMCPResult(w, r, auth, "error", "unsupported_response_type")
		return
	}
	decoded, err := base64.RawURLEncoding.DecodeString(auth.Challenge)
	if query.Get("code_challenge_method") != "S256" || err != nil || len(decoded) != 32 || len(auth.Challenge) != 43 {
		p.redirectMCPResult(w, r, auth, "error", "invalid_request")
		return
	}
	auth.Endpoint = p.mcpResourceEndpoint(auth.Resource)
	if auth.Endpoint == "" {
		p.redirectMCPResult(w, r, auth, "error", "invalid_target")
		return
	}
	if auth.Scope == "" {
		auth.Scope = "mcp"
	}
	if auth.Scope != "mcp" {
		p.redirectMCPResult(w, r, auth, "error", "invalid_scope")
		return
	}
	email, ok := p.getAuthFromCookie(r)
	if !ok {
		http.Redirect(w, r, "/auth/login?"+url.Values{"return_to": {r.URL.RequestURI()}}.Encode(), 302)
		return
	}
	tunnel, owner, err := p.mcpTunnel(r.Context(), auth.Endpoint)
	if err != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "MCP endpoint or owner unavailable")
		return
	}
	if !p.mcpUserAllowed(r.Context(), email, tunnel, owner) {
		p.redirectMCPResult(w, r, auth, "error", "access_denied")
		return
	}
	auth.Owner, auth.Email = owner.ID, email
	consentID, err := randomOAuthValue("")
	if err != nil || p.mcpOAuth.saveConsent(r.Context(), consentID, auth) != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Could not prepare consent")
		return
	}
	data, _ := json.Marshal(auth)
	claims := jwt.MapClaims{"type": "mcp_consent", "jti": consentID, "authorization": string(data), "exp": time.Now().Add(10 * time.Minute).Unix()}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil {
		oauthProblem(w, 500, "server_error", "Could not prepare consent")
		return
	}
	csrf, err := p.createCSRFToken(r, "mcp-consent")
	if err != nil {
		oauthProblem(w, 500, "server_error", "Could not prepare consent")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	writePageStart(w, "tunn - Connect MCP tools")
	_, _ = fmt.Fprintf(w, `<h1>Allow %s to use %s tools?</h1><p>Signed in as %s. This allows access to the MCP capabilities exposed by this tunnel for one hour. The owner can revoke access at any time.</p><p>Client redirect: <code>%s</code></p><form method="post" action="/oauth/authorize"><input type="hidden" name="authorization" value="%s"><input type="hidden" name="csrf_token" value="%s"><button name="decision" value="allow">Allow</button><button name="decision" value="deny">Deny</button></form>`, html.EscapeString(client.Name), html.EscapeString(auth.Endpoint), html.EscapeString(email), html.EscapeString(auth.RedirectURI), html.EscapeString(signed), html.EscapeString(csrf))
	writePageEnd(w)
}

func (p *ProxyServer) redirectMCPResult(w http.ResponseWriter, r *http.Request, auth *mcpAuthorization, key, value string) {
	u, _ := url.Parse(auth.RedirectURI)
	query := u.Query()
	query.Set(key, value)
	if auth.State != "" {
		query.Set("state", auth.State)
	}
	query.Set("iss", p.mcpIssuer())
	u.RawQuery = query.Encode()
	http.Redirect(w, r, u.String(), 302)
}

func (p *ProxyServer) handleMCPConsent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		oauthProblem(w, 400, "invalid_request", "Invalid consent form")
		return
	}
	email, ok := p.getAuthFromCookie(r)
	if !ok {
		http.Error(w, "Authentication required", 401)
		return
	}
	if !p.requireCSRFToken(w, r, "mcp-consent") {
		return
	}
	token, err := jwt.Parse(r.PostForm.Get("authorization"), func(*jwt.Token) (any, error) { return p.getJWTSigningKey(), nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !token.Valid {
		oauthProblem(w, 400, "invalid_request", "Expired or invalid consent")
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["type"] != "mcp_consent" || !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		oauthProblem(w, 400, "invalid_request", "Invalid consent purpose")
		return
	}
	encoded, _ := claims["authorization"].(string)
	consentID, _ := claims["jti"].(string)
	var auth mcpAuthorization
	if json.Unmarshal([]byte(encoded), &auth) != nil || auth.Email != email {
		oauthProblem(w, 400, "invalid_request", "Consent belongs to another session")
		return
	}
	client, err := p.mcpOAuth.client(r.Context(), auth.ClientID)
	if err != nil || !slices.Contains(client.RedirectURIs, auth.RedirectURI) {
		oauthProblem(w, 400, "invalid_request", "Invalid consent client")
		return
	}
	if r.PostForm.Get("decision") != "allow" {
		if _, err := p.mcpOAuth.db.ExecContext(r.Context(), `DELETE FROM mcp_oauth_consents WHERE id=?`, consentID); err != nil {
			oauthProblem(w, 503, "temporarily_unavailable", "Consent service unavailable")
			return
		}
		p.redirectMCPResult(w, r, &auth, "error", "access_denied")
		return
	}
	tunnel, owner, err := p.mcpTunnel(r.Context(), auth.Endpoint)
	if err != nil || owner.ID != auth.Owner || !p.mcpUserAllowed(r.Context(), email, tunnel, owner) {
		p.redirectMCPResult(w, r, &auth, "error", "access_denied")
		return
	}
	code, err := randomOAuthValue("")
	if err != nil || p.mcpOAuth.saveCode(r.Context(), code, &auth, consentID) != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Could not issue authorization code")
		return
	}
	p.redirectMCPResult(w, r, &auth, "code", code)
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, ch := range verifier {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("-._~", ch)) {
			return false
		}
	}
	return true
}

func (p *ProxyServer) handleMCPToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", 405)
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		oauthProblem(w, 400, "invalid_request", "Expected form-encoded token request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := r.ParseForm(); err != nil {
		oauthProblem(w, 400, "invalid_request", "Invalid token request")
		return
	}
	form := r.PostForm
	if r.Header.Get("Authorization") != "" || form.Has("client_secret") {
		oauthProblem(w, 400, "invalid_client", "This endpoint accepts public clients without client authentication")
		return
	}
	for _, values := range form {
		if len(values) != 1 {
			oauthProblem(w, 400, "invalid_request", "Duplicate token parameter")
			return
		}
	}
	if form.Get("grant_type") != "authorization_code" {
		oauthProblem(w, 400, "unsupported_grant_type", "Use authorization_code")
		return
	}
	if _, err := p.mcpOAuth.client(r.Context(), form.Get("client_id")); err != nil {
		oauthProblem(w, 400, "invalid_client", "Unknown client")
		return
	}
	verifier := form.Get("code_verifier")
	if !validPKCEVerifier(verifier) {
		oauthProblem(w, 400, "invalid_grant", "PKCE verifier required")
		return
	}
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	p.mcpOAuth.mu.Lock()
	defer p.mcpOAuth.mu.Unlock()
	auth, err := p.mcpOAuth.takeCode(r.Context(), form.Get("code"), func(auth *mcpAuthorization) bool {
		return auth.ClientID == form.Get("client_id") && auth.RedirectURI == form.Get("redirect_uri") && auth.Resource == form.Get("resource") && subtle.ConstantTimeCompare([]byte(auth.Challenge), []byte(challenge)) == 1
	})
	if err != nil {
		oauthProblem(w, 400, "invalid_grant", "Invalid, expired, consumed or mismatched authorization code")
		return
	}
	tunnel, owner, err := p.mcpTunnel(r.Context(), auth.Endpoint)
	if err != nil || owner.ID != auth.Owner || !p.mcpUserAllowed(r.Context(), auth.Email, tunnel, owner) {
		oauthProblem(w, 400, "invalid_grant", "Tunnel ownership changed or endpoint unavailable")
		return
	}
	accessToken, err := randomOAuthValue("tunn_mcp_")
	if err != nil {
		oauthProblem(w, 500, "server_error", "Could not issue access token")
		return
	}
	tokenDigest := sha256.Sum256([]byte(accessToken))
	_, err = p.meter.CreateGrant(r.Context(), &meterpb.Grant{Owner: auth.Owner, Endpoint: auth.Endpoint, Consumer: "oauth:" + auth.ClientID, TokenSha256: tokenDigest[:], ExpiresAt: time.Now().Add(mcpAccessTokenLifetime).UnixMilli()})
	if err != nil {
		oauthProblem(w, 503, "temporarily_unavailable", "Grant ledger unavailable")
		return
	}
	writeOAuthJSON(w, 200, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": int(mcpAccessTokenLifetime.Seconds()), "scope": auth.Scope})
}

// Owner management accepts a session on the HTML page (CSRF for disconnects),
// or an owner bearer on the JSON API. MCP/grant tokens cannot manage clients.
func (p *ProxyServer) handleMCPClients(w http.ResponseWriter, r *http.Request) {
	page := r.URL.Path == "/account/mcp"
	email, _, capability, ok := p.getAuthFromTunnelBearer(r, &TunnelConnection{})
	if page {
		email, ok = p.getAuthFromCookie(r)
	}
	if !ok || capability {
		if page {
			http.Redirect(w, r, "/auth/login?return_to=%2Faccount%2Fmcp", 302)
		} else {
			http.Error(w, "Owner authentication required", 401)
		}
		return
	}
	owner, err := p.storage.GetAccountByEmail(r.Context(), common.NormalizeEmail(email))
	if err != nil || owner == nil {
		http.Error(w, "Owner account unavailable", 503)
		return
	}
	endpoint := r.URL.Query().Get("tunnel")
	if endpoint != "" && !isValidDNSLabel(endpoint) {
		http.Error(w, "Invalid tunnel", 400)
		return
	}
	mutate := r.Method == http.MethodDelete && !page || r.Method == http.MethodPost && page
	if mutate {
		if endpoint == "" {
			http.Error(w, "Tunnel required for disconnect", 400)
			return
		}
		if page {
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if !p.requireCSRFToken(w, r, "mcp-revoke") {
				return
			}
		}
		clientID := r.URL.Query().Get("client_id")
		if page {
			clientID = r.PostFormValue("client_id")
		}
		if _, err := p.mcpOAuth.client(r.Context(), clientID); err != nil {
			http.Error(w, "Unknown client", 404)
			return
		}
		p.mcpOAuth.mu.Lock()
		defer p.mcpOAuth.mu.Unlock()
		if _, err := p.mcpOAuth.db.ExecContext(r.Context(), `DELETE FROM mcp_oauth_consents WHERE owner=? AND endpoint=? AND client=?`, owner.ID, endpoint, clientID); err != nil {
			http.Error(w, "Authorization service unavailable", 503)
			return
		}
		if _, err := p.mcpOAuth.db.ExecContext(r.Context(), `DELETE FROM mcp_oauth_codes WHERE owner=? AND endpoint=? AND client=?`, owner.ID, endpoint, clientID); err != nil {
			http.Error(w, "Authorization service unavailable", 503)
			return
		}
		grants, err := p.meter.ListGrants(r.Context(), &meterpb.ListGrantsRequest{Owner: owner.ID, Endpoint: endpoint})
		if err != nil {
			http.Error(w, "Grant ledger unavailable", 503)
			return
		}
		for _, grant := range grants.Grants {
			if grant.Consumer == "oauth:"+clientID && !grant.Revoked {
				if _, err := p.meter.RevokeGrant(r.Context(), &meterpb.Grant{Owner: owner.ID, Endpoint: endpoint, Id: grant.Id}); err != nil {
					http.Error(w, "Could not revoke connected client", 503)
					return
				}
			}
		}
		if page {
			http.Redirect(w, r, "/account/mcp?"+url.Values{"tunnel": {endpoint}}.Encode(), 303)
		} else {
			w.WriteHeader(204)
		}
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	grants, err := p.meter.ListGrants(r.Context(), &meterpb.ListGrantsRequest{Owner: owner.ID, Endpoint: endpoint})
	if err != nil {
		http.Error(w, "Grant ledger unavailable", 503)
		return
	}
	type connection struct {
		ClientID  string `json:"client_id"`
		Name      string `json:"client_name"`
		Tunnel    string `json:"tunnel"`
		GrantID   string `json:"grant_id"`
		ExpiresAt int64  `json:"expires_at"`
		Revoked   bool   `json:"revoked"`
	}
	connections := []connection{}
	for _, grant := range grants.Grants {
		if !strings.HasPrefix(grant.Consumer, "oauth:") {
			continue
		}
		clientID := strings.TrimPrefix(grant.Consumer, "oauth:")
		client, err := p.mcpOAuth.client(r.Context(), clientID)
		if err != nil {
			http.Error(w, "Client registry unavailable", 503)
			return
		}
		connections = append(connections, connection{clientID, client.Name, grant.Endpoint, grant.Id, grant.ExpiresAt, grant.Revoked})
	}
	if !page {
		writeOAuthJSON(w, 200, map[string]any{"clients": connections})
		return
	}
	csrf, err := p.createCSRFToken(r, "mcp-revoke")
	if err != nil {
		http.Error(w, "Could not prepare management page", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	writePageStart(w, "tunn - Connected MCP clients")
	_, _ = fmt.Fprint(w, `<h1>Connected MCP clients</h1><p>Disconnect revokes all current tokens and pending codes for this client on this tunnel. Reconnecting requires consent again.</p>`)
	for _, c := range connections {
		_, _ = fmt.Fprintf(w, `<p>%s — %s — expires %s`, html.EscapeString(c.Name), html.EscapeString(c.Tunnel), time.UnixMilli(c.ExpiresAt).UTC().Format(time.RFC3339))
		if c.Revoked {
			_, _ = fmt.Fprint(w, ` — revoked</p>`)
			continue
		}
		_, _ = fmt.Fprintf(w, `</p><form method="post" action="/account/mcp?tunnel=%s"><input type="hidden" name="csrf_token" value="%s"><input type="hidden" name="client_id" value="%s"><button>Disconnect</button></form>`, url.QueryEscape(c.Tunnel), html.EscapeString(csrf), html.EscapeString(c.ClientID))
	}
	if len(connections) == 0 {
		_, _ = fmt.Fprint(w, `<p>No connected clients.</p>`)
	}
	writePageEnd(w)
}
