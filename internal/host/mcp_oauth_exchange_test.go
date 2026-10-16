package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/mcpbridge"
	"github.com/ehrlich-b/tunn/internal/store"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	tp "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// This helper is a separate login/resource server process with a disk database,
// local HTTP transport, synthetic login provider and a real stdio MCP child.
func TestMCPExchangeProcessHelper(t *testing.T) {
	if os.Getenv("TUNN_MCP_EXCHANGE_PROCESS") != "1" {
		return
	}
	db, err := store.InitDB(os.Getenv("TUNN_MCP_EXCHANGE_DB"))
	if err != nil {
		t.Fatal(err)
	}
	f := newMCPOAuthFixtureWithDB(t, db)
	var seconds atomic.Int64
	initial, _ := strconv.ParseInt(os.Getenv("TUNN_MCP_EXCHANGE_TIME"), 10, 64)
	seconds.Store(initial)
	f.p.now = func() time.Time { return time.Unix(seconds.Load(), 0) }
	ledger := f.p.meter
	guest, err := f.p.storage.FindOrCreateByEmails(t.Context(), []string{"guest@example.com", "alias@example.com"}, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	_ = guest
	other, err := f.p.storage.FindOrCreateByEmails(t.Context(), []string{"other@example.com"}, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.p.sharingBackend().Sharing(t.Context(), &mp.SharingRequest{Operation: "share", Owner: f.tunnel.AccountID, Endpoint: "tools", Email: "guest@example.com", ExpiresAt: time.Now().Add(90 * 24 * time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TUNN_MCP_OAUTH_HELPER", "1")
	bridge, err := mcpbridge.StartStdioHandler(t.Context(), []string{os.Args[0], "-test.run=^TestMCPOAuthStdioHelper$"}, io.Discard, mcpbridge.Options{AllowedTools: []string{"echo"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = bridge.Close(ctx)
	}()
	f.tunnel.Stream.(*meteringFixtureStream).hook = func(message *tp.TunnelMessage) error {
		if request := message.GetHttpRequest(); request != nil {
			local := httptest.NewRequest(request.Method, request.Path, bytes.NewReader(request.Body))
			for k, v := range request.Headers {
				local.Header.Set(k, v)
			}
			if local.Header.Get("Authorization") != "" || local.Header.Get("Cookie") != "" {
				t.Error("credential forwarded to MCP child")
			}
			w := httptest.NewRecorder()
			bridge.ServeHTTP(w, local)
			headers := map[string]string{}
			for k := range w.Header() {
				headers[k] = w.Header().Get(k)
			}
			f.tunnel.pendingMu.RLock()
			ch := f.tunnel.pendingRequests[request.ConnectionId]
			f.tunnel.pendingMu.RUnlock()
			ch <- &tp.HttpResponse{ConnectionId: request.ConnectionId, StatusCode: int32(w.Code), Headers: headers, Body: w.Body.Bytes()}
		}
		return nil
	}
	var authority sync.RWMutex
	stop := make(chan struct{})
	var stopOnce sync.Once
	routes := f.p.createHandler()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/fixture/") {
			authority.Lock()
			defer authority.Unlock()
			switch r.URL.Path {
			case "/fixture/login":
				http.SetCookie(w, securityCookie(t, f.p, r.URL.Query().Get("email")))
			case "/fixture/advance":
				n, _ := strconv.ParseInt(r.URL.Query().Get("seconds"), 10, 64)
				seconds.Add(n)
			case "/fixture/outage":
				if r.URL.Query().Get("enabled") == "1" {
					f.p.meter = nil
				} else {
					f.p.meter = ledger
				}
			case "/fixture/generation":
				generation := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				if _, err := db.Exec(`UPDATE web_resources SET id=? WHERE endpoint='tools'`, generation); err != nil {
					t.Error(err)
				}
				f.tunnel.PolicyResourceID = generation
			case "/fixture/takeover":
				_, err := f.p.sharingBackend().Sharing(r.Context(), &mp.SharingRequest{Operation: "register", Owner: other.ID, Endpoint: "tools", Mode: "policy-only"})
				if err != nil {
					t.Error(err)
				}
			case "/fixture/stop":
				stopOnce.Do(func() { close(stop) })
			default:
				w.WriteHeader(404)
			}
			return
		}
		authority.RLock()
		defer authority.RUnlock()
		routes.ServeHTTP(w, r)
	}))
	fmt.Println(server.URL)
	<-stop
	server.Close()
}

type exchangeTokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Expires int    `json:"expires_in"`
}
type exchangeProcess struct {
	t       *testing.T
	cmd     *exec.Cmd
	url     string
	http    *http.Client
	logs    *refreshLogCapture
	secrets []string
	session string
}

func startExchangeProcess(t *testing.T, db string, now int64) *exchangeProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMCPExchangeProcessHelper$")
	cmd.Env = append(os.Environ(), "TUNN_MCP_EXCHANGE_PROCESS=1", "TUNN_MCP_EXCHANGE_DB="+db, "TUNN_MCP_EXCHANGE_TIME="+strconv.FormatInt(now, 10))
	logs := &refreshLogCapture{}
	cmd.Stderr = logs
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		if scanner.Scan() {
			line <- scanner.Text()
		}
		for scanner.Scan() {
			logs.Write(append(scanner.Bytes(), '\n'))
		}
	}()
	var origin string
	select {
	case origin = <-line:
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("process did not start")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // fixture loopback certificate only
	p := &exchangeProcess{t: t, cmd: cmd, url: origin, http: &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, logs: logs}
	t.Cleanup(func() { p.stop(); tr.CloseIdleConnections() })
	return p
}
func (p *exchangeProcess) request(method, host, path, body, token string, cookie *http.Cookie) (int, http.Header, []byte) {
	p.t.Helper()
	r, err := http.NewRequest(method, p.url+path, strings.NewReader(body))
	if err != nil {
		p.t.Fatal(err)
	}
	r.Host = host
	if strings.HasPrefix(path, "/oauth/register") {
		r.Header.Set("Content-Type", "application/json")
	} else {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if host == "tools.tunn.test" {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if p.session != "" {
			r.Header.Set("Mcp-Session-Id", p.session)
			r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
		}
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "https://tunn.test")
	}
	response, err := p.http.Do(r)
	if err != nil {
		p.t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		p.t.Fatal(err)
	}
	return response.StatusCode, response.Header, data
}
func (p *exchangeProcess) control(path string) {
	p.t.Helper()
	status, _, _ := p.request("POST", "tunn.test", "/fixture/"+path, "", "", nil)
	if status != 200 {
		p.t.Fatalf("fixture control status %d", status)
	}
}
func (p *exchangeProcess) stop() {
	if p.cmd == nil {
		return
	}
	p.control("stop")
	if err := p.cmd.Wait(); err != nil {
		p.t.Errorf("server process failed: %v", err)
	}
	p.cmd = nil
	for _, secret := range p.secrets {
		if bytes.Contains(p.logs.Bytes(), []byte(secret)) {
			p.t.Error("raw synthetic credential in server logs")
		}
	}
}
func (p *exchangeProcess) cookie(email string) *http.Cookie {
	_, headers, _ := p.request("POST", "tunn.test", "/fixture/login?email="+url.QueryEscape(email), "", "", nil)
	response := http.Response{Header: headers}
	for _, cookie := range response.Cookies() {
		return cookie
	}
	p.t.Fatal("no mock login cookie")
	return nil
}
func (p *exchangeProcess) register(grants string) string {
	p.t.Helper()
	body := `{"client_name":"Process client","redirect_uris":["https://connector.example/cb"]` + grants + `}`
	status, _, data := p.request("POST", "tunn.test", "/oauth/register", body, "", nil)
	var c mcpOAuthClient
	if status != 201 || json.Unmarshal(data, &c) != nil {
		p.t.Fatalf("register status %d", status)
	}
	return c.ID
}
func (p *exchangeProcess) code(client string, cookie *http.Cookie) string {
	p.t.Helper()
	status, headers, data := p.consent(client, cookie)
	if status != 200 {
		p.t.Fatalf("consent status %d", status)
	}
	form := url.Values{"authorization": {hiddenMCPField(p.t, string(data), "authorization")}, "csrf_token": {hiddenMCPField(p.t, string(data), "csrf_token")}, "decision": {"allow"}}
	_ = headers
	status, headers, _ = p.request("POST", "tunn.test", "/oauth/authorize", form.Encode(), "", cookie)
	location, _ := url.Parse(headers.Get("Location"))
	if status != 302 || location.Query().Get("code") == "" {
		p.t.Fatalf("approval status %d", status)
	}
	code := location.Query().Get("code")
	p.secrets = append(p.secrets, code)
	return code
}
func (p *exchangeProcess) consent(client string, cookie *http.Cookie) (int, http.Header, []byte) {
	hash := sha256.Sum256([]byte(strings.Repeat("v", 64)))
	query := url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {"https://connector.example/cb"}, "resource": {"https://tools.tunn.test/mcp"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"}, "scope": {"mcp"}}
	return p.request("GET", "tunn.test", "/oauth/authorize?"+query.Encode(), "", "", cookie)
}
func codeExchangeForm(client, code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "code": {code}, "redirect_uri": {"https://connector.example/cb"}, "resource": {"https://tools.tunn.test/mcp"}, "code_verifier": {strings.Repeat("v", 64)}}
}
func refreshExchangeForm(client, refresh string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {refresh}, "resource": {"https://tools.tunn.test/mcp"}}
}
func (p *exchangeProcess) exchange(form url.Values, want int) exchangeTokens {
	p.t.Helper()
	status, _, data := p.request("POST", "tunn.test", "/oauth/token", form.Encode(), "", nil)
	var tokens exchangeTokens
	if json.Unmarshal(data, &tokens) != nil || status != want {
		p.t.Fatalf("exchange status %d, want %d", status, want)
	}
	if want == 200 {
		if tokens.Access == "" || tokens.Expires != 3600 {
			p.t.Fatal("missing access credential")
		}
		p.secrets = append(p.secrets, tokens.Access)
		if tokens.Refresh != "" {
			p.secrets = append(p.secrets, tokens.Refresh)
			_, secret, _ := strings.Cut(tokens.Refresh, ".")
			p.secrets = append(p.secrets, secret)
		}
	} else if tokens.Access != "" || tokens.Refresh != "" {
		p.t.Fatal("failed exchange issued credentials")
	}
	return tokens
}
func (p *exchangeProcess) call(token string, want int) {
	p.t.Helper()
	if want == 200 {
		p.session = ""
		status, headers, data := p.request("POST", "tools.tunn.test", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"process","version":"1"}}}`, token, nil)
		if status != 200 || bytes.Contains(data, []byte(`"error"`)) {
			p.t.Fatalf("initialize status %d", status)
		}
		p.session = headers.Get("Mcp-Session-Id")
		if p.session == "" {
			p.t.Fatal("missing MCP session")
		}
		status, _, _ = p.request("POST", "tools.tunn.test", "/mcp", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, token, nil)
		if status != 202 {
			p.t.Fatalf("notification status %d", status)
		}
	}
	status, _, data := p.request("POST", "tools.tunn.test", "/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"process round trip"}}}`, token, nil)
	if status != want {
		p.t.Fatalf("tool status %d, want %d", status, want)
	}
	if want == 200 && (!bytes.Contains(data, []byte(`"process round trip"`)) || bytes.Contains(data, []byte(`"error"`)) || bytes.Contains(data, []byte(`"isError":true`))) {
		p.t.Fatal("tool call did not return the expected JSON-RPC result")
	}
}

func TestMCPExchangeProcessJourney(t *testing.T) {
	db := filepath.Join(t.TempDir(), "oauth.db")
	now := time.Now().Unix()
	p := startExchangeProcess(t, db, now)
	status, _, data := p.request("GET", "tunn.test", "/.well-known/oauth-authorization-server", "", "", nil)
	if status != 200 || !bytes.Contains(data, []byte(`"refresh_token"`)) {
		t.Fatal("refresh not advertised")
	}
	client := p.register("")
	guest := p.cookie("guest@example.com")
	first := p.exchange(codeExchangeForm(client, p.code(client, guest)), 200)
	if first.Refresh == "" {
		t.Fatal("no refresh token")
	}
	p.call(first.Access, 200)
	p.control("advance?seconds=3601")
	p.call(first.Access, 401)
	second := p.exchange(refreshExchangeForm(client, first.Refresh), 200)
	if second.Refresh == first.Refresh || second.Access == first.Access {
		t.Fatal("credentials did not rotate")
	}
	secrets := append([]string{}, p.secrets...)
	p.stop()
	p = startExchangeProcess(t, db, now+3601)
	p.secrets = append(p.secrets, secrets...)
	p.call(second.Access, 200)
	third := p.exchange(refreshExchangeForm(client, second.Refresh), 200)
	p.call(third.Access, 200)
	// Pending forms and codes for this person are revoked with all descendants.
	pendingStatus, _, pending := p.consent(client, p.cookie("alias@example.com"))
	if pendingStatus != 200 {
		t.Fatal("alias consent unavailable")
	}
	pendingCode := p.code(client, p.cookie("guest@example.com"))
	owner := relayJWT(t, securityProxy(nil), "owner@example.com")
	status, _, _ = p.request("DELETE", "tunn.test", "/api/sharing/tools", `{"email":"guest@example.com"}`, owner, nil)
	if status != 200 {
		t.Fatalf("person revoke status %d", status)
	}
	p.call(second.Access, 401)
	p.call(third.Access, 401)
	p.exchange(refreshExchangeForm(client, third.Refresh), 400)
	p.exchange(codeExchangeForm(client, pendingCode), 400)
	form := url.Values{"authorization": {hiddenMCPField(t, string(pending), "authorization")}, "csrf_token": {hiddenMCPField(t, string(pending), "csrf_token")}, "decision": {"allow"}}
	status, headers, _ := p.request("POST", "tunn.test", "/oauth/authorize", form.Encode(), "", p.cookie("alias@example.com"))
	location, _ := url.Parse(headers.Get("Location"))
	if status == 302 && location.Query().Get("code") != "" {
		t.Fatal("revoked person consent issued a code")
	}
	t.Log("first consent and stdio tool result; virtual expiry; refresh; process restart; second result; person/alias revoke denied forms, codes, access and refresh")
	// Owner consent exercises client disconnect and explicit consent revocation.
	ownerCookie := p.cookie("owner@example.com")
	ownerTokens := p.exchange(codeExchangeForm(client, p.code(client, ownerCookie)), 200)
	newCode := p.code(client, ownerCookie)
	pendingStatus, _, pending = p.consent(client, ownerCookie)
	if pendingStatus != 200 {
		t.Fatal("owner consent unavailable")
	}
	status, _, _ = p.request("DELETE", "tunn.test", "/api/mcp/clients?tunnel=tools&client_id="+client, "", owner, nil)
	if status != 204 {
		t.Fatalf("client revoke status %d", status)
	}
	p.call(ownerTokens.Access, 401)
	p.exchange(refreshExchangeForm(client, ownerTokens.Refresh), 400)
	p.exchange(codeExchangeForm(client, newCode), 400)
	form = url.Values{"authorization": {hiddenMCPField(t, string(pending), "authorization")}, "csrf_token": {hiddenMCPField(t, string(pending), "csrf_token")}, "decision": {"allow"}}
	status, headers, _ = p.request("POST", "tunn.test", "/oauth/authorize", form.Encode(), "", ownerCookie)
	location, _ = url.Parse(headers.Get("Location"))
	if status == 302 && location.Query().Get("code") != "" {
		t.Fatal("revoked client consent issued a code")
	}
	fresh := p.exchange(codeExchangeForm(client, p.code(client, ownerCookie)), 200)
	status, _, grantsJSON := p.request("GET", "tunn.test", "/api/endpoints/tools/grants", "", owner, nil)
	var grants mp.ListGrantsResponse
	if status != 200 || json.Unmarshal(grantsJSON, &grants) != nil {
		t.Fatal("could not list consent grant")
	}
	var grantID string
	for _, g := range grants.Grants {
		if !g.Revoked {
			grantID = g.Id
		}
	}
	if grantID == "" {
		t.Fatal("missing consent grant")
	}
	status, _, _ = p.request("DELETE", "tunn.test", "/api/endpoints/tools/grants/"+grantID, "", owner, nil)
	if status != 204 {
		t.Fatalf("consent revoke status %d", status)
	}
	p.call(fresh.Access, 401)
	p.exchange(refreshExchangeForm(client, fresh.Refresh), 400)
	t.Log("client and consent revocation denied every credential descendant")
	// Authorization-code-only registrations remain supported without refresh.
	legacy := p.register(`,"grant_types":["authorization_code"]`)
	legacyTokens := p.exchange(codeExchangeForm(legacy, p.code(legacy, ownerCookie)), 200)
	if legacyTokens.Refresh != "" {
		t.Fatal("code-only client unexpectedly received refresh")
	}
	p.call(legacyTokens.Access, 200)
	p.stop()
	for _, path := range []string{db, db + "-wal", db + "-shm"} {
		contents, err := os.ReadFile(path)
		if err != nil && os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range p.secrets {
			if bytes.Contains(contents, []byte(secret)) {
				t.Error("raw credential persisted")
			}
		}
	}
	t.Log("authorization-code-only client works; raw synthetic tokens absent from database and process logs")
}

func TestMCPExchangeProcessFailures(t *testing.T) {
	for _, scenario := range []string{"wrong-client-resource", "cross-owner", "replay", "concurrent", "generation", "takeover", "outage", "expiry", "lifetime"} {
		t.Run(scenario, func(t *testing.T) {
			p := startExchangeProcess(t, filepath.Join(t.TempDir(), "oauth.db"), time.Now().Unix())
			client := p.register("")
			cookie := p.cookie("owner@example.com")
			tokens := p.exchange(codeExchangeForm(client, p.code(client, cookie)), 200)
			switch scenario {
			case "wrong-client-resource":
				other := p.register(`,"grant_types":["refresh_token","authorization_code"]`)
				form := refreshExchangeForm(other, tokens.Refresh)
				p.exchange(form, 400)
				form = refreshExchangeForm(client, tokens.Refresh)
				form.Set("resource", "https://other.tunn.test/mcp")
				p.exchange(form, 400)
				for _, invalid := range []string{"tunn_mcp_refresh_0.bad", tokens.Refresh + "x", "garbage"} {
					p.exchange(refreshExchangeForm(client, invalid), 400)
				}
				rotated := p.exchange(refreshExchangeForm(client, tokens.Refresh), 200)
				p.call(rotated.Access, 200)
			case "cross-owner":
				otherOwner := relayJWT(t, securityProxy(nil), "other@example.com")
				status, _, _ := p.request("DELETE", "tunn.test", "/api/mcp/clients?tunnel=tools&client_id="+client, "", otherOwner, nil)
				if status != 204 {
					t.Fatalf("scoped disconnect status %d", status)
				}
				rotated := p.exchange(refreshExchangeForm(client, tokens.Refresh), 200)
				p.call(rotated.Access, 200)
				status, _, data := p.request("POST", "tunn.test", "/oauth/token", refreshExchangeForm(client, rotated.Refresh).Encode(), otherOwner, nil)
				if status == 200 || bytes.Contains(data, []byte(`"access_token"`)) {
					t.Fatal("platform bearer accepted on public-client refresh endpoint")
				}
			case "replay":
				next := p.exchange(refreshExchangeForm(client, tokens.Refresh), 200)
				p.exchange(refreshExchangeForm(client, tokens.Refresh), 400)
				p.exchange(refreshExchangeForm(client, next.Refresh), 400)
				p.call(tokens.Access, 401)
				p.call(next.Access, 401)
			case "concurrent":
				type result struct {
					status int
					data   []byte
				}
				results := make(chan result, 8)
				start := make(chan struct{})
				for i := 0; i < 8; i++ {
					go func() {
						<-start
						status, _, data := p.request("POST", "tunn.test", "/oauth/token", refreshExchangeForm(client, tokens.Refresh).Encode(), "", nil)
						results <- result{status, data}
					}()
				}
				close(start)
				winners := 0
				var winner exchangeTokens
				for i := 0; i < 8; i++ {
					r := <-results
					var got exchangeTokens
					_ = json.Unmarshal(r.data, &got)
					if r.status == 200 {
						winners++
						winner = got
						p.secrets = append(p.secrets, got.Access, got.Refresh)
					} else if got.Access != "" || got.Refresh != "" {
						t.Fatal("losing rotation issued credentials")
					}
				}
				if winners != 1 {
					t.Fatalf("rotation winners %d", winners)
				}
				p.exchange(refreshExchangeForm(client, winner.Refresh), 400)
				p.call(winner.Access, 401)
			case "generation", "takeover":
				pendingCode := p.code(client, cookie)
				p.control(scenario)
				p.exchange(codeExchangeForm(client, pendingCode), 400)
				p.exchange(refreshExchangeForm(client, tokens.Refresh), 400)
				p.call(tokens.Access, 401)
			case "lifetime":
				for hour := 1; hour < 30*24; hour++ {
					p.control("advance?seconds=3600")
					tokens = p.exchange(refreshExchangeForm(client, tokens.Refresh), 200)
				}
				p.call(tokens.Access, 200)
				p.control("advance?seconds=3601")
				p.exchange(refreshExchangeForm(client, tokens.Refresh), 400)
				p.call(tokens.Access, 401)
				t.Log("719 hourly rotations succeeded across the full 30-day consent lifetime")
			case "expiry":
				p.control("advance?seconds=2592001")
				p.exchange(refreshExchangeForm(client, tokens.Refresh), 400)
				p.call(tokens.Access, 401)
			case "outage":
				p.control("outage?enabled=1")
				p.exchange(refreshExchangeForm(client, tokens.Refresh), 503)
				p.call(tokens.Access, 503)
				p.control("outage?enabled=0")
				next := p.exchange(refreshExchangeForm(client, tokens.Refresh), 200)
				p.call(next.Access, 200)
			}
			p.stop()
			t.Log("fail-closed scenario passed with no credentials returned on rejection")
		})
	}
}

// Person revocation uses a separate authority transaction, without the OAuth
// handler mutex. Issuance must recheck it after the grant backend returns.
func TestMCPExchangePersonRevocationDuringIssuance(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		t.Run(fmt.Sprintf("refresh=%t", refresh), func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			_, err := f.p.storage.FindOrCreateByEmails(t.Context(), []string{"guest@example.com"}, "synthetic")
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.p.sharingBackend().Sharing(t.Context(), &mp.SharingRequest{Operation: "share", Owner: f.tunnel.AccountID, Endpoint: "tools", Email: "guest@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
			if err != nil {
				t.Fatal(err)
			}
			c := discoverMCPClient(t, f)
			if refresh {
				registered := f.request("POST", "https://tunn.test/oauth/register", `{"client_name":"Spec client","redirect_uris":["https://connector.example/callback"],"grant_types":["authorization_code","refresh_token"]}`, "application/json", "", nil)
				var client mcpOAuthClient
				if registered.Code != 201 || json.Unmarshal(registered.Body.Bytes(), &client) != nil {
					t.Fatal("refresh client registration failed")
				}
				c.clientID = client.ID
				c.query.Set("client_id", client.ID)
			}
			c.cookie = securityCookie(t, f.p, "guest@example.com")
			form := c.tokenForm(c.code(t))
			if refresh {
				response := f.request("POST", c.token, form.Encode(), "application/x-www-form-urlencoded", "", nil)
				var tokens exchangeTokens
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &tokens) != nil || tokens.Refresh == "" {
					t.Fatal("initial issuance failed")
				}
				form = refreshExchangeForm(c.clientID, tokens.Refresh)
			}
			barrier := &prodAuthIssuanceBarrier{Backend: f.p.meter, SharingBackend: f.p.sharingBackend(), entered: make(chan struct{}), release: make(chan struct{})}
			f.p.meter = barrier
			var once sync.Once
			release := func() { once.Do(func() { close(barrier.release) }) }
			t.Cleanup(release)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- f.request("POST", c.token, form.Encode(), "application/x-www-form-urlencoded", "", nil)
			}()
			select {
			case <-barrier.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("issuance barrier not reached")
			}
			owner := relayJWT(t, f.p, "owner@example.com")
			revoked := f.request("DELETE", "https://tunn.test/api/sharing/tools", `{"email":"guest@example.com"}`, "application/json", owner, nil)
			if revoked.Code != 200 {
				t.Fatalf("person revoke status %d", revoked.Code)
			}
			release()
			response := prodAuthAwait(t, result)
			if response.Code == 200 || bytes.Contains(response.Body.Bytes(), []byte(`"access_token"`)) || bytes.Contains(response.Body.Bytes(), []byte(`"refresh_token"`)) {
				t.Fatal("revoked consent issued credentials")
			}
			grants, err := f.p.meter.ListGrants(t.Context(), &mp.ListGrantsRequest{Owner: f.tunnel.AccountID, Endpoint: "tools"})
			if err != nil {
				t.Fatal(err)
			}
			for _, g := range grants.Grants {
				if !g.Revoked {
					t.Fatal("issuance left an active descendant")
				}
			}
		})
	}
}
