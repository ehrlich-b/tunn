//go:build candidatefixture

package host

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	tunn "github.com/ehrlich-b/tunn/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

const candidateCall = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"inventory","arguments":{"items":["alpha","beta"]}}}`
const candidateResult = `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"alpha,beta"}],"isError":false}}` + "\n"

type candidateApp struct {
	calls   atomic.Int64
	release <-chan struct{}
	seen    chan http.Header
}

func (a *candidateApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.calls.Add(1)
	a.seen <- r.Header.Clone()
	body, err := io.ReadAll(r.Body)
	if err != nil || string(body) != candidateCall || r.URL.Path != "/mcp" {
		http.Error(w, "invalid tool request", 400)
		return
	}
	// Assert an actual typed task rather than status-only echo behavior.
	var request struct {
		Method string
		Params struct {
			Name      string
			Arguments struct{ Items []string }
		}
	}
	if json.Unmarshal(body, &request) != nil || request.Method != "tools/call" || request.Params.Name != "inventory" || !reflect.DeepEqual(request.Params.Arguments.Items, []string{"alpha", "beta"}) {
		http.Error(w, "wrong tool arguments", 400)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "app_first", Value: "one,fragment=two", Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "app_second", Value: "three", Path: "/"})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Add("Trailer", "X-Task-End")
	w.Header().Set("Tunn-Request-ID", "publisher-spoof")
	_, _ = io.WriteString(w, candidateResult[:32])
	if http.NewResponseController(w).Flush() != nil {
		return
	}
	if a.release != nil {
		select {
		case <-a.release:
		case <-r.Context().Done():
			return
		}
	}
	_, _ = io.WriteString(w, candidateResult[32:])
	w.Header().Add("X-Task-End", "inventory-complete")
}

type candidateStack struct {
	f         *mcpOAuthFixture
	publisher *tunn.Tunnel
	client    *http.Client
	origin    string
	app       *candidateApp
}

func newCandidateStack(t *testing.T, release <-chan struct{}) *candidateStack {
	t.Helper()
	f := newMCPOAuthFixture(t)
	// Hosted publisher authentication uses the existing account/JWT path.
	server := NewTunnelServer(f.p.config, nil, nil, f.p.storage)
	f.p.tunnelServer = server
	certFile, keyFile, pool := edgeTLSFiles(t)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	listener := prodAuthRPCListener{bufconn.Listen(1 << 20)}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})))
	pb.RegisterTunnelServiceServer(gs, server)
	served := make(chan struct{})
	go func() { defer close(served); _ = gs.Serve(listener) }()
	t.Cleanup(func() { gs.Stop(); _ = listener.Close(); <-served })
	app := &candidateApp{release: release, seen: make(chan http.Header, 8)}
	options := tunn.Options{Name: "tools", ServerAddr: "tunn.test:443", Credentials: tunn.Credentials{AuthToken: relayJWT(t, f.p, "owner@example.com"), TunnelKey: f.p.config.WellKnownKey}, AllowedEmails: []string{"owner@example.com"}, TLSConfig: &tls.Config{RootCAs: pool, ServerName: "tunn.test", MinVersion: tls.VersionTLS12}, Reconnect: &tunn.ReconnectPolicy{MaxAttempts: 0}, ConnectTimeout: 3 * time.Second}
	publisher, err := tunn.CandidateFixturePublishHandler(context.Background(), app, options, func(ctx context.Context, _, _ string) (net.Conn, error) { return listener.DialContext(ctx) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := publisher.Close(); err != nil {
			t.Error(err)
		}
	})
	ready, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	public, err := publisher.WaitReady(ready)
	if err != nil {
		t.Fatal(err)
	}
	if public != "https://tools.tunn.test" {
		t.Fatalf("registration audience: %q", public)
	}
	server.mu.Lock()
	endpoint := server.tunnels["tools"]
	// SDK currently advertises HTTP; the MCP classification is an explicit
	// fixture prerequisite, not a claim that the HTTP SDK publishes MCP endpoints.
	endpoint.TargetURL = "mcp"
	server.mu.Unlock()
	f.tunnel = endpoint
	if endpoint.AccountID == "" || endpoint.CreatorEmail != "owner@example.com" || !endpoint.Supports(common.CapabilityHTTPResponseTrailersV1) {
		t.Fatalf("registration contract: %+v", endpoint)
	}
	client, origin := sshHTTPS(t, f.p.createHandler())
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &candidateStack{f: f, publisher: publisher, client: client, origin: origin, app: app}
}
func (s *candidateStack) call(t *testing.T, method, host, path, body, contentType, token string, cookie *http.Cookie) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, s.origin+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = host
	r.Header.Set("Content-Type", contentType)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "https://tunn.test")
	}
	if host == "tools.tunn.test" {
		r.AddCookie(&http.Cookie{Name: "app_request", Value: "ordinary"})
		if cookie == nil {
			r.AddCookie(securityCookie(t, s.f.p, "owner@example.com"))
		}
	}
	response, err := s.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func candidateRead(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func (s *candidateStack) authorize(t *testing.T) (string, string) {
	t.Helper()
	metadata := s.call(t, "GET", "tools.tunn.test", "/.well-known/oauth-protected-resource/mcp", "", "", "", nil)
	var resource struct {
		Resource             string
		AuthorizationServers []string `json:"authorization_servers"`
	}
	data := candidateRead(t, metadata)
	if metadata.StatusCode != 200 || json.Unmarshal([]byte(data), &resource) != nil || resource.Resource != "https://tools.tunn.test/mcp" || !reflect.DeepEqual(resource.AuthorizationServers, []string{"https://tunn.test"}) {
		t.Fatalf("resource metadata: %d %s", metadata.StatusCode, data)
	}
	issuer := s.call(t, "GET", "tunn.test", "/.well-known/oauth-authorization-server", "", "", "", nil)
	if data := candidateRead(t, issuer); issuer.StatusCode != 200 || !strings.Contains(data, `"code_challenge_methods_supported":["S256"]`) {
		t.Fatalf("issuer metadata: %d %s", issuer.StatusCode, data)
	}
	reg := s.call(t, "POST", "tunn.test", "/oauth/register", `{"client_name":"Candidate useful task","redirect_uris":["https://consumer.invalid/cb"]}`, "application/json", "", nil)
	var client mcpOAuthClient
	data = candidateRead(t, reg)
	if reg.StatusCode != 201 || json.Unmarshal([]byte(data), &client) != nil || client.ID == "" {
		t.Fatalf("registration: %d %s", reg.StatusCode, data)
	}
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{"response_type": {"code"}, "client_id": {client.ID}, "redirect_uri": {client.RedirectURIs[0]}, "resource": {resource.Resource}, "state": {"candidate-state"}, "scope": {"mcp"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}}
	cookie := securityCookie(t, s.f.p, "owner@example.com")
	page := s.call(t, "GET", "tunn.test", "/oauth/authorize?"+query.Encode(), "", "", "", cookie)
	data = candidateRead(t, page)
	if page.StatusCode != 200 {
		t.Fatalf("consent: %d %s", page.StatusCode, data)
	}
	form := url.Values{"authorization": {hiddenMCPField(t, data, "authorization")}, "csrf_token": {hiddenMCPField(t, data, "csrf_token")}, "decision": {"allow"}}
	consent := s.call(t, "POST", "tunn.test", "/oauth/authorize", form.Encode(), "application/x-www-form-urlencoded", "", cookie)
	_ = candidateRead(t, consent)
	location, e := url.Parse(consent.Header.Get("Location"))
	if e != nil || consent.StatusCode != 302 || location.Query().Get("state") != "candidate-state" || location.Query().Get("iss") != "https://tunn.test" || location.Query().Get("code") == "" {
		t.Fatalf("consent result: %d %s", consent.StatusCode, consent.Header)
	}
	form = url.Values{"grant_type": {"authorization_code"}, "client_id": {client.ID}, "code": {location.Query().Get("code")}, "redirect_uri": {client.RedirectURIs[0]}, "resource": {resource.Resource}, "code_verifier": {verifier}}
	exchange := s.call(t, "POST", "tunn.test", "/oauth/token", form.Encode(), "application/x-www-form-urlencoded", "", nil)
	data = candidateRead(t, exchange)
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if exchange.StatusCode != 200 || exchange.Header.Get("Cache-Control") != "no-store" || json.Unmarshal([]byte(data), &token) != nil || token.AccessToken == "" || token.TokenType != "Bearer" || token.ExpiresIn != 3600 {
		t.Fatalf("exchange: %d %s", exchange.StatusCode, data)
	}
	return token.AccessToken, client.ID
}
func TestCandidateUsefulTask(t *testing.T) {
	release := make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	defer finish()
	s := newCandidateStack(t, release)
	// Discovery has no tool request and must not block the streaming fixture.
	token, _ := s.authorize(t)
	response := s.call(t, "POST", "tools.tunn.test", "/mcp", candidateCall, "application/json", token, nil)
	defer response.Body.Close()
	prefix := make([]byte, 32)
	if _, e := io.ReadFull(response.Body, prefix); e != nil {
		t.Fatal(e)
	}
	if string(prefix) != candidateResult[:32] || len(response.Trailer.Values("X-Task-End")) != 0 {
		t.Fatal("prefix was not independently streamed")
	}
	finish()
	rest, e := io.ReadAll(response.Body)
	if e != nil {
		t.Fatal(e)
	}
	got := string(prefix) + string(rest)
	direct := httptest.NewRecorder()
	oracle := &candidateApp{seen: make(chan http.Header, 1)}
	oracle.ServeHTTP(direct, httptest.NewRequest("POST", "https://app.invalid/mcp", strings.NewReader(candidateCall)))
	if got != candidateResult || got != direct.Body.String() || response.StatusCode != 200 || !reflect.DeepEqual(response.Header.Values("Set-Cookie"), direct.Header().Values("Set-Cookie")) || !reflect.DeepEqual(response.Trailer.Values("X-Task-End"), []string{"inventory-complete"}) || response.Header.Get("Tunn-Request-ID") == "" || response.Header.Get("Tunn-Request-ID") == "publisher-spoof" {
		t.Fatalf("consumer/oracle mismatch: %d %s %v %s", response.StatusCode, response.Header, response.Trailer, got)
	}
	select {
	case seen := <-s.app.seen:
		if seen.Get("Authorization") != "" || seen.Get("Tunn-Authorization") != "" || seen.Get("Cookie") != "app_request=ordinary" {
			t.Fatalf("platform credential reached application: %s", seen)
		}
	default:
		t.Fatal("no SDK handler delivery")
	}
	t.Logf("serialized tools/call: %d bytes; 2 distinct cookies; streamed prefix; complete JSON-RPC result; matching direct oracle; audience=https://tools.tunn.test/mcp", len(got))
}
func TestCandidateAccountLifecycleRefusals(t *testing.T) {
	for _, state := range []string{"two-owners", "moved-owner", "expired-grant", "revoked-client", "quota-exhausted", "wrong-audience"} {
		t.Run(state, func(t *testing.T) {
			s := newCandidateStack(t, nil)
			token, clientID := s.authorize(t)
			want := 401
			problem := "invalid_token"
			path := "/mcp"
			owner := s.f.tunnel.AccountID
			switch state {
			case "two-owners":
				other, e := s.f.p.storage.FindOrCreateByEmails(context.Background(), []string{"other@example.com"}, "test")
				if e != nil {
					t.Fatal(e)
				}
				_ = other
				token = relayJWT(t, s.f.p, "other@example.com")
				want = 403
				problem = ""
			case "moved-owner":
				other, e := s.f.p.storage.FindOrCreateByEmails(context.Background(), []string{"other@example.com"}, "test")
				if e != nil {
					t.Fatal(e)
				}
				s.f.p.tunnelServer.mu.Lock()
				s.f.p.tunnelServer.tunnels["tools"] = &TunnelConnection{TunnelID: "tools", TargetURL: "mcp", AccountID: other.ID, CreatorEmail: "other@example.com", AllowedEmails: []string{"other@example.com"}, Stream: s.f.tunnel.Stream}
				s.f.p.tunnelServer.mu.Unlock()
			case "expired-grant":
				digest := sha256.Sum256([]byte(token))
				grant, e := s.f.p.meter.Resolve(context.Background(), &meterpb.ResolveRequest{Owner: owner, Endpoint: "tools", TokenSha256: digest[:]})
				if e != nil {
					t.Fatal(e)
				}
				grant.ExpiresAt = time.Now().Add(-time.Hour).UnixMilli()
				data, e := json.Marshal(grant)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = s.f.p.mcpOAuth.db.Exec(`UPDATE meter_grants SET expires=?, data=? WHERE id=?`, grant.ExpiresAt, data, grant.Id); e != nil {
					t.Fatal(e)
				}
			case "revoked-client":
				revoked := s.call(t, "DELETE", "tunn.test", "/api/mcp/clients?tunnel=tools&client_id="+clientID, "", "", relayJWT(t, s.f.p, "owner@example.com"), nil)
				data := candidateRead(t, revoked)
				if revoked.StatusCode != 204 {
					t.Fatalf("revoke: %d %s", revoked.StatusCode, data)
				}
			case "quota-exhausted":
				token = "tunn_gr_candidate-one-request"
				digest := sha256.Sum256([]byte(token))
				grant, e := s.f.p.meter.CreateGrant(context.Background(), &meterpb.Grant{Owner: owner, Endpoint: "tools", TokenSha256: digest[:], MonthlyRequests: 1, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
				if e != nil {
					t.Fatal(e)
				}
				_ = grant
				first := s.call(t, "POST", "tools.tunn.test", "/mcp", candidateCall, "application/json", token, nil)
				firstBody := candidateRead(t, first)
				if first.StatusCode != 200 || firstBody != candidateResult {
					t.Fatalf("quota first useful request: %d %s", first.StatusCode, firstBody)
				}

				want = 429
				problem = ""
			case "wrong-audience":
				path = "/other"
			}
			before := s.app.calls.Load()
			response := s.call(t, "POST", "tools.tunn.test", path, candidateCall, "application/json", token, nil)
			data := candidateRead(t, response)
			if response.StatusCode != want || s.app.calls.Load() != before {
				t.Fatalf("public refusal: %d want %d delivered=%d %s", response.StatusCode, want, s.app.calls.Load()-before, data)
			}
			if problem != "" && !strings.Contains(response.Header.Get("WWW-Authenticate"), `error="`+problem+`"`) {
				t.Fatalf("wrong OAuth refusal header: %s", response.Header)
			}
			if state == "quota-exhausted" && (response.Header.Get("Tunn-Limit-Reason") != "request_budget" || response.Header.Get("Retry-After") == "") {
				t.Fatalf("quota error: %s", response.Header)
			}
			if strings.Contains(data, token) || len(response.Cookies()) != 0 {
				t.Fatal("refusal leaked platform credentials")
			}
			t.Log(fmt.Sprintf("%s: public status=%d, no publisher delivery", state, response.StatusCode))
		})
	}
}
