package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/mcpbridge"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

// A real newline-delimited stdio MCP server, launched as a child by the bridge.
func TestMCPOAuthStdioHelper(t *testing.T) {
	if os.Getenv("TUNN_MCP_OAUTH_HELPER") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string `json:"name"`
				Arguments struct {
					Text string `json:"text"`
				} `json:"arguments"`
			} `json:"params"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			os.Exit(2)
		}
		if len(request.ID) == 0 {
			continue
		}
		var result any
		switch request.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "stdio-echo", "version": "1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "echo", "inputSchema": map[string]any{"type": "object"}}}}
		case "tools/call":
			if request.Params.Name != "echo" {
				os.Exit(3)
			}
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": request.Params.Arguments.Text}}}
		case "ping":
			result = map[string]any{}
		default:
			os.Exit(4)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}); err != nil {
			os.Exit(5)
		}
	}
	os.Exit(0)
}

type mcpOAuthFixture struct {
	p         *ProxyServer
	tunnel    *TunnelConnection
	forwarded int
}

func newMCPOAuthFixture(t *testing.T) *mcpOAuthFixture {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ledger, err := metering.New(db)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := newMCPOAuthStore(db)
	if err != nil {
		t.Fatal(err)
	}
	local := storage.NewLocalStorage(db)
	owner, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	p := securityProxy(local)
	p.meter, p.mcpOAuth, p.isLoginNode = ledger, registry, true
	p.devices, err = newDeviceCredentialStore(db)
	if err != nil {
		t.Fatal(err)
	}
	p.emailSender = &EmailSender{Host: "unused-in-process-email-fixture"}
	stream := &meteringFixtureStream{}
	tunnel := &TunnelConnection{TunnelID: "tools", TargetURL: "mcp", AccountID: owner.ID, CreatorEmail: "owner@example.com", AllowedEmails: []string{"owner@example.com"}, Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse)}
	p.tunnelServer.tunnels[tunnel.TunnelID] = tunnel
	fixture := &mcpOAuthFixture{p: p, tunnel: tunnel}
	stream.hook = func(message *pb.TunnelMessage) error {
		if request := message.GetHttpRequest(); request != nil {
			fixture.forwarded++
			tunnel.pendingMu.RLock()
			ch := tunnel.pendingRequests[request.ConnectionId]
			tunnel.pendingMu.RUnlock()
			ch <- &pb.HttpResponse{ConnectionId: request.ConnectionId, StatusCode: 200, Body: []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)}
		}
		return nil
	}
	return fixture
}

func (f *mcpOAuthFixture) request(method, target, body, contentType, bearer string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != nil {
		r.AddCookie(cookie)
		if method == "POST" {
			r.Header.Set("Origin", "https://tunn.test")
		}
	}
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	return w
}

type specMCPClient struct {
	f                                                        *mcpOAuthFixture
	clientID, resource, authorize, token, redirect, verifier string
	cookie                                                   *http.Cookie
	query                                                    url.Values
}

func discoverMCPClient(t *testing.T, f *mcpOAuthFixture) *specMCPClient {
	t.Helper()
	challenge := f.request("POST", "https://tools.tunn.test/mcp", `{}`, "application/json", "", nil)
	if challenge.Code != 401 {
		t.Fatalf("challenge: %d %s", challenge.Code, challenge.Body)
	}
	match := regexp.MustCompile(`resource_metadata="([^"]+)"`).FindStringSubmatch(challenge.Header().Get("WWW-Authenticate"))
	if len(match) != 2 {
		t.Fatalf("discovery challenge missing metadata: %s", challenge.Header())
	}
	metadata := f.request("GET", match[1], "", "", "", nil)
	var resource struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(metadata.Body.Bytes(), &resource); err != nil || metadata.Code != 200 || len(resource.AuthorizationServers) != 1 {
		t.Fatalf("resource metadata: %s", metadata.Body)
	}
	issuer := resource.AuthorizationServers[0]
	server := f.request("GET", issuer+"/.well-known/oauth-authorization-server", "", "", "", nil)
	var endpoints struct {
		Issuer    string   `json:"issuer"`
		Authorize string   `json:"authorization_endpoint"`
		Token     string   `json:"token_endpoint"`
		Register  string   `json:"registration_endpoint"`
		PKCE      []string `json:"code_challenge_methods_supported"`
	}
	if err := json.Unmarshal(server.Body.Bytes(), &endpoints); err != nil || endpoints.Issuer != issuer || len(endpoints.PKCE) != 1 || endpoints.PKCE[0] != "S256" {
		t.Fatalf("AS discovery: %s", server.Body)
	}
	redirect := "https://connector.example/callback"
	registration := f.request("POST", endpoints.Register, `{"client_name":"Spec client","redirect_uris":["`+redirect+`"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}`, "application/json", "", nil)
	var client mcpOAuthClient
	if err := json.Unmarshal(registration.Body.Bytes(), &client); err != nil || registration.Code != 201 || client.ID == "" || client.AuthMethod != "none" {
		t.Fatalf("DCR: %d %s", registration.Code, registration.Body)
	}
	verifier := strings.Repeat("a", 43)
	hash := sha256.Sum256([]byte(verifier))
	query := url.Values{"response_type": {"code"}, "client_id": {client.ID}, "redirect_uri": {redirect}, "resource": {resource.Resource}, "state": {"unpredictable-client-state"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"}, "scope": {"mcp"}}
	return &specMCPClient{f: f, clientID: client.ID, resource: resource.Resource, authorize: endpoints.Authorize, token: endpoints.Token, redirect: redirect, verifier: verifier, query: query}
}

func (c *specMCPClient) login(t *testing.T) {
	t.Helper()
	start := c.f.request("GET", c.authorize+"?"+c.query.Encode(), "", "", "", nil)
	if start.Code != 302 || !strings.HasPrefix(start.Header().Get("Location"), "/auth/login?") {
		t.Fatalf("browser login redirect: %d %s", start.Code, start.Body)
	}
	loginURL, _ := url.Parse(start.Header().Get("Location"))
	page := c.f.request("GET", "https://tunn.test"+start.Header().Get("Location"), "", "", "", nil)
	if !strings.Contains(page.Body.String(), "/auth/magic?return_to=") {
		t.Fatalf("email login lost return path: %s", page.Body)
	}
	// Simulate delivery of the existing email login's signed one-use link.
	magic, err := c.f.p.generateMagicLinkTokenForReturnTo("owner@example.com", loginURL.Query().Get("return_to"))
	if err != nil {
		t.Fatal(err)
	}
	verified := c.f.request("GET", "https://tunn.test/auth/verify?"+url.Values{"token": {magic}, "return_to": {"https://attacker.example/"}}.Encode(), "", "", "", nil)
	if verified.Code != 302 || verified.Header().Get("Location") != loginURL.Query().Get("return_to") {
		t.Fatalf("email verification return path: %d %s", verified.Code, verified.Header())
	}
	for _, cookie := range verified.Result().Cookies() {
		if cookie.Name == authCookieName {
			c.cookie = cookie
		}
	}
	if c.cookie == nil {
		t.Fatal("email verification did not establish browser session")
	}
}

func hiddenMCPField(t *testing.T, page, name string) string {
	t.Helper()
	match := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`).FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatalf("consent field %s missing: %s", name, page)
	}
	return html.UnescapeString(match[1])
}

func (c *specMCPClient) consentForm(t *testing.T) url.Values {
	t.Helper()
	if c.cookie == nil {
		c.login(t)
	}
	page := c.f.request("GET", c.authorize+"?"+c.query.Encode(), "", "", "", c.cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "Allow Spec client to use tools tools?") {
		t.Fatalf("consent page: %d %s", page.Code, page.Body)
	}
	return url.Values{"authorization": {hiddenMCPField(t, page.Body.String(), "authorization")}, "csrf_token": {hiddenMCPField(t, page.Body.String(), "csrf_token")}, "decision": {"allow"}}
}

func (c *specMCPClient) code(t *testing.T) string {
	t.Helper()
	approved := c.f.request("POST", c.authorize, c.consentForm(t).Encode(), "application/x-www-form-urlencoded", "", c.cookie)
	location, err := url.Parse(approved.Header().Get("Location"))
	if approved.Code != 302 || err != nil || location.Query().Get("state") != c.query.Get("state") || location.Query().Get("iss") != "https://tunn.test" || location.Query().Get("code") == "" {
		t.Fatalf("authorization response: %d %s %s", approved.Code, approved.Header(), approved.Body)
	}
	return location.Query().Get("code")
}

func (c *specMCPClient) tokenForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {c.clientID}, "code": {code}, "redirect_uri": {c.redirect}, "resource": {c.resource}, "code_verifier": {c.verifier}}
}

func (c *specMCPClient) accessToken(t *testing.T) string {
	t.Helper()
	response := c.f.request("POST", c.token, c.tokenForm(c.code(t)).Encode(), "application/x-www-form-urlencoded", "", nil)
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil || response.Code != 200 || token.AccessToken == "" || token.TokenType != "Bearer" || token.ExpiresIn != 3600 || token.Scope != "mcp" {
		t.Fatalf("token response: %d %s", response.Code, response.Body)
	}
	return token.AccessToken
}

func TestMCPOAuthConnectorEndToEnd(t *testing.T) {
	f := newMCPOAuthFixture(t)
	t.Setenv("TUNN_MCP_OAUTH_HELPER", "1")
	bridge, err := mcpbridge.StartStdioHandler(context.Background(), []string{os.Args[0], "-test.run=^TestMCPOAuthStdioHelper$"}, io.Discard, mcpbridge.Options{AllowedTools: []string{"echo"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := bridge.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	stream := f.tunnel.Stream.(*meteringFixtureStream)
	stream.hook = func(message *pb.TunnelMessage) error {
		if request := message.GetHttpRequest(); request != nil {
			f.forwarded++
			local := httptest.NewRequest(request.Method, request.Path, bytes.NewReader(request.Body))
			for key, value := range request.Headers {
				local.Header.Set(key, value)
			}
			if local.Header.Get("Authorization") != "" || local.Header.Get("Cookie") != "" {
				t.Error("platform credentials reached stdio adapter")
			}
			response := httptest.NewRecorder()
			bridge.ServeHTTP(response, local)
			headers := map[string]string{}
			for key := range response.Header() {
				headers[key] = response.Header().Get(key)
			}
			f.tunnel.pendingMu.RLock()
			ch := f.tunnel.pendingRequests[request.ConnectionId]
			f.tunnel.pendingMu.RUnlock()
			ch <- &pb.HttpResponse{ConnectionId: request.ConnectionId, StatusCode: int32(response.Code), Headers: headers, Body: response.Body.Bytes()}
		}
		return nil
	}
	c := discoverMCPClient(t, f)
	accessToken := c.accessToken(t)
	session := ""
	for _, step := range []struct {
		body, want string
		status     int
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"Spec client","version":"1"}}}`, `"stdio-echo"`, 200},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, "", 202},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, `"echo"`, 200},
		{`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"through the tunnel"}}}`, `"through the tunnel"`, 200},
	} {
		r := httptest.NewRequest("POST", c.resource, strings.NewReader(step.body))
		r.Header.Set("Authorization", "Bearer "+accessToken)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if session != "" {
			r.Header.Set("Mcp-Session-Id", session)
			r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
		}
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != step.status || !strings.Contains(w.Body.String(), step.want) {
			t.Fatalf("MCP response: %d %s", w.Code, w.Body)
		}
		if session == "" {
			session = w.Header().Get("Mcp-Session-Id")
			if session == "" {
				t.Fatal("initialize missing session ID")
			}
		}
	}
	export, err := f.p.meter.Export(context.Background(), &meterpb.ExportRequest{Owner: f.tunnel.AccountID, Endpoint: "tools", Month: time.Now().UTC().Format("2006-01")})
	if err != nil {
		t.Fatal(err)
	}
	admitted := 0
	for _, event := range export.Events {
		if event.AuthMethod == "mcp_oauth" {
			if !event.Allowed || !event.Forwarded || event.GrantId == "" || !event.Finished || event.ResponseBytes < 0 {
				t.Fatalf("missing OAuth audit: %#v", event)
			}
			admitted++
		}
	}
	if admitted != 4 || f.forwarded != 4 {
		t.Fatalf("metered calls = %d, forwarded = %d", admitted, f.forwarded)
	}
	var bytesMetered bool
	for _, usage := range export.Usage {
		if usage.AdmittedRequests == 4 && usage.RequestBytes > 0 && usage.ResponseBytes > 0 {
			bytesMetered = true
		}
	}
	if !bytesMetered {
		t.Fatalf("missing ingress byte usage: %#v", export.Usage)
	}
}

func TestMCPOAuthTokenBindingsAndPKCE(t *testing.T) {
	f := newMCPOAuthFixture(t)
	c := discoverMCPClient(t, f)
	code := c.code(t)
	for _, field := range []string{"resource", "client_id", "redirect_uri", "code_verifier"} {
		form := c.tokenForm(code)
		switch field {
		case "resource":
			form.Set(field, "https://other.tunn.test/mcp")
		case "client_id":
			form.Set(field, "unknown")
		case "redirect_uri":
			form.Set(field, "https://attacker.example/")
		case "code_verifier":
			form.Set(field, strings.Repeat("b", 43))
		}
		w := f.request("POST", c.token, form.Encode(), "application/x-www-form-urlencoded", "", nil)
		if w.Code != 400 {
			t.Fatalf("accepted wrong %s: %d %s", field, w.Code, w.Body)
		}
	}
	form := c.tokenForm(code)
	form.Del("code_verifier")
	if w := f.request("POST", c.token, form.Encode(), "application/x-www-form-urlencoded", "", nil); w.Code != 400 {
		t.Fatal("accepted missing verifier")
	}
	w := f.request("POST", c.token, c.tokenForm(code).Encode(), "application/x-www-form-urlencoded", "", nil)
	if w.Code != 200 {
		t.Fatalf("correct exchange failed: %d %s", w.Code, w.Body)
	}
	if w := f.request("POST", c.token, c.tokenForm(code).Encode(), "application/x-www-form-urlencoded", "", nil); w.Code != 400 {
		t.Fatal("authorization code reused")
	}
	c.query.Del("code_challenge")
	w = f.request("GET", c.authorize+"?"+c.query.Encode(), "", "", "", c.cookie)
	u, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || u.Query().Get("error") != "invalid_request" {
		t.Fatalf("missing PKCE: %d %s", w.Code, w.Header())
	}
}

func TestMCPOAuthAudienceExpiryAndRevokedClient(t *testing.T) {
	f := newMCPOAuthFixture(t)
	c := discoverMCPClient(t, f)
	accessToken := c.accessToken(t)
	f.p.tunnelServer.tunnels["other"] = &TunnelConnection{TunnelID: "other", TargetURL: "mcp", AccountID: f.tunnel.AccountID, CreatorEmail: f.tunnel.CreatorEmail, AllowedEmails: f.tunnel.AllowedEmails, Stream: f.tunnel.Stream}
	for _, resource := range []string{"https://other.tunn.test/mcp", "https://tools.tunn.test/other"} {
		w := f.request("POST", resource, `{}`, "application/json", accessToken, nil)
		if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatalf("wrong audience accepted: %d %s", w.Code, w.Body)
		}
	}
	if f.forwarded != 0 {
		t.Fatal("wrong audience reached publisher")
	}
	pendingCode := c.code(t)
	staleConsent := c.consentForm(t)
	ownerToken := relayJWT(t, f.p, "owner@example.com")
	listURL := "https://tunn.test/api/mcp/clients?tunnel=tools"
	listed := f.request("GET", listURL, "", "", ownerToken, nil)
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), c.clientID) || strings.Contains(listed.Body.String(), accessToken) {
		t.Fatalf("owner list: %d %s", listed.Code, listed.Body)
	}
	for _, token := range []string{accessToken, relayJWT(t, f.p, "stranger@example.com")} {
		w := f.request("DELETE", listURL+"&client_id="+c.clientID, "", "", token, nil)
		if w.Code == 204 {
			t.Fatal("non-owner disconnected client")
		}
	}
	revoked := f.request("DELETE", listURL+"&client_id="+c.clientID, "", "", ownerToken, nil)
	if revoked.Code != 204 {
		t.Fatalf("disconnect: %d %s", revoked.Code, revoked.Body)
	}
	if w := f.request("POST", c.resource, `{}`, "application/json", accessToken, c.cookie); w.Code != 401 {
		t.Fatalf("revoked token fell back to cookie: %d", w.Code)
	}
	if w := f.request("POST", c.token, c.tokenForm(pendingCode).Encode(), "application/x-www-form-urlencoded", "", nil); w.Code != 400 {
		t.Fatal("revoked pending code issued token")
	}
	if w := f.request("POST", c.authorize, staleConsent.Encode(), "application/x-www-form-urlencoded", "", c.cookie); w.Code == 302 {
		t.Fatal("stale consent survived disconnect")
	}
	accessToken = c.accessToken(t) // fresh human approval reconnects
	digest := sha256.Sum256([]byte(accessToken))
	grant, err := f.p.meter.Resolve(context.Background(), &meterpb.ResolveRequest{Owner: f.tunnel.AccountID, Endpoint: "tools", TokenSha256: digest[:]})
	if err != nil {
		t.Fatal(err)
	}
	grant.ExpiresAt = time.Now().Add(-time.Second).UnixMilli()
	data, _ := json.Marshal(grant)
	if _, err := f.p.mcpOAuth.db.Exec(`UPDATE meter_grants SET expires=?, data=? WHERE id=?`, grant.ExpiresAt, data, grant.Id); err != nil {
		t.Fatal(err)
	}
	if w := f.request("POST", c.resource, `{}`, "application/json", accessToken, nil); w.Code != 401 {
		t.Fatalf("expired token: %d %s", w.Code, w.Body)
	}
	if f.forwarded != 0 {
		t.Fatal("invalid credentials reached publisher")
	}
}

func TestMCPOAuthConsentSecurity(t *testing.T) {
	f := newMCPOAuthFixture(t)
	c := discoverMCPClient(t, f)
	form := c.consentForm(t)
	noCSRF := url.Values{"authorization": form["authorization"], "decision": {"allow"}}
	if w := f.request("POST", c.authorize, noCSRF.Encode(), "application/x-www-form-urlencoded", "", c.cookie); w.Code != 403 {
		t.Fatal("consent bypassed CSRF")
	}
	form.Set("decision", "deny")
	w := f.request("POST", c.authorize, form.Encode(), "application/x-www-form-urlencoded", "", c.cookie)
	location, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || location.Query().Get("error") != "access_denied" {
		t.Fatalf("deny: %d %s", w.Code, w.Body)
	}
	form.Set("decision", "allow")
	if w := f.request("POST", c.authorize, form.Encode(), "application/x-www-form-urlencoded", "", c.cookie); w.Code == 302 {
		t.Fatal("denied consent was replayed")
	}
	if _, err := f.p.storage.FindOrCreateByEmails(context.Background(), []string{"stranger@example.com"}, "test"); err != nil {
		t.Fatal(err)
	}
	c.cookie = &http.Cookie{Name: authCookieName, Value: relayJWT(t, f.p, "stranger@example.com")}
	w = f.request("GET", c.authorize+"?"+c.query.Encode(), "", "", "", c.cookie)
	location, _ = url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || location.Query().Get("error") != "access_denied" {
		t.Fatal("unapproved email got consent")
	}
	c.query.Set("redirect_uri", "https://attacker.example/callback")
	w = f.request("GET", c.authorize+"?"+c.query.Encode(), "", "", "", c.cookie)
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatal("authorization redirected to an unregistered URI")
	}
}

func TestMCPOAuthRegistrationAndMetadataSecurity(t *testing.T) {
	f := newMCPOAuthFixture(t)
	for _, uri := range []string{"http://connector.example/cb", "https://user:pass@connector.example/cb", "https://connector.example/cb#fragment", "javascript:alert(1)"} {
		body, _ := json.Marshal(map[string]any{"redirect_uris": []string{uri}})
		w := f.request("POST", "https://tunn.test/oauth/register", string(body), "application/json", "", nil)
		if w.Code != 400 {
			t.Fatalf("registered unsafe redirect %s", uri)
		}
	}
	w := f.request("POST", "https://tunn.test/oauth/register", `{"redirect_uris":["http://127.0.0.1:1234/cb"]}`, "application/json", "", nil)
	if w.Code != 201 {
		t.Fatalf("loopback public client: %d %s", w.Code, w.Body)
	}
	for _, host := range []string{"attacker.example", "tools.tunn.test"} {
		w := f.request("GET", "https://"+host+"/oauth/authorize", "", "", "", nil)
		if strings.Contains(w.Body.String(), "csrf_token") || w.Code == 200 {
			t.Fatal("platform consent served on untrusted origin")
		}
	}
	if w := f.request("GET", "https://tools.tunn.test/.well-known/oauth-protected-resource", "", "", "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"resource":"https://tools.tunn.test/mcp"`) {
		t.Fatalf("root resource discovery: %d %s", w.Code, w.Body)
	}
}

type mcpOAuthPeerClient struct {
	internalpb.InternalServiceClient
	server *InternalServer
}

func (c mcpOAuthPeerClient) FindTunnel(ctx context.Context, request *internalpb.FindTunnelRequest, _ ...grpc.CallOption) (*internalpb.FindTunnelResponse, error) {
	return c.server.FindTunnel(ctx, request)
}
func (c mcpOAuthPeerClient) GetNodeInfo(ctx context.Context, request *internalpb.NodeInfoRequest, _ ...grpc.CallOption) (*internalpb.NodeInfoResponse, error) {
	return c.server.GetNodeInfo(ctx, request)
}

func TestMCPOAuthCrossNodeOwnership(t *testing.T) {
	f := newMCPOAuthFixture(t)
	c := discoverMCPClient(t, f)
	edge := securityProxy(f.p.storage)
	edge.meter = f.p.meter
	edge.tunnelServer.tunnels["tools"] = f.tunnel
	delete(f.p.tunnelServer.tunnels, "tools")
	f.p.nodeClients = map[string]internalpb.InternalServiceClient{"edge": mcpOAuthPeerClient{server: NewInternalServer(edge.tunnelServer, "edge.tunn.test", false)}}
	token := c.accessToken(t)
	r := httptest.NewRequest("POST", c.resource, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	edge.createHandler().ServeHTTP(w, r)
	if w.Code != 200 || f.forwarded != 1 {
		t.Fatalf("remote-issued grant: %d %s", w.Code, w.Body)
	}
	// Old peers cannot prove publisher ownership and must fail consent closed.
	f.tunnel.AccountID = ""
	if _, _, err := f.p.mcpTunnel(context.Background(), "tools"); err == nil {
		t.Fatal("accepted remote publisher without an owner UUID")
	}
}

func TestMCPOAuthDurableSingleUseCodes(t *testing.T) {
	f := newMCPOAuthFixture(t)
	c := discoverMCPClient(t, f)
	code := c.code(t)
	second, err := newMCPOAuthStore(f.p.mcpOAuth.db)
	if err != nil {
		t.Fatal(err)
	}
	if client, err := second.client(context.Background(), c.clientID); err != nil || client.ID != c.clientID {
		t.Fatal("registration did not survive registry recreation")
	}
	selected := make(chan struct{}, 2)
	release := make(chan struct{})
	results := make(chan error, 2)
	for _, registry := range []*mcpOAuthStore{f.p.mcpOAuth, second} {
		go func(registry *mcpOAuthStore) {
			registry.mu.Lock()
			defer registry.mu.Unlock()
			_, err := registry.takeCode(context.Background(), code, func(*mcpAuthorization) bool { selected <- struct{}{}; <-release; return true })
			results <- err
		}(registry)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-selected:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("persisted code not available to concurrent exchange fixtures")
		}
	}
	close(release)
	successes := 0
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err == nil {
				successes++
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent exchange did not complete")
		}
	}
	if successes != 1 {
		t.Fatalf("single code consumed %d times", successes)
	}
}

func TestMCPOAuthRegistrationRateLimitRejectsSpoofedForwarding(t *testing.T) {
	f := newMCPOAuthFixture(t)
	for i := 0; i < 6; i++ {
		r := httptest.NewRequest("POST", "https://tunn.test/oauth/register", strings.NewReader(`{"redirect_uris":["https://connector.example/cb"]}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i+1))
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		want := 201
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("registration %d status = %d: %s", i+1, w.Code, w.Body)
		}
	}
}
