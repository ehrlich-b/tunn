package host

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Exercise OAuth and account boundaries over an actual TLS listener. Redirects
// are inspected without following them, so the client never leaves loopback.
func TestProdAuthLoopbackHTTPSOAuthLifecycle(t *testing.T) {
	prodAuthHTTPSOAuthLifecycle(t, false)
}

// Also verify the serialized HTTP/TLS lifecycle in the established memory
// transport. The native listener above remains a separate required gate.
func TestProdAuthMCPOAuthMemoryHTTPSLifecycle(t *testing.T) {
	prodAuthHTTPSOAuthLifecycle(t, true)
}

func prodAuthHTTPSOAuthLifecycle(t *testing.T, memory bool) {
	t.Helper()
	f := newMCPOAuthFixture(t)
	prepareMCPAuthorityFixture(t, f)
	var forwarded atomic.Int64
	stream := f.tunnel.Stream.(*meteringFixtureStream)
	originalHook := stream.hook
	stream.hook = func(message *pb.TunnelMessage) error {
		if message.GetHttpRequest() != nil {
			forwarded.Add(1)
		}
		return originalHook(message)
	}
	var client *http.Client
	var serverURL string
	if memory {
		client, serverURL = sshHTTPS(t, f.p.createHandler())
	} else {
		server := httptest.NewTLSServer(f.p.createHandler())
		t.Cleanup(server.Close)
		client, serverURL = server.Client(), server.URL
	}
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	call := func(method, host, path, body, contentType, bearer string, cookie *http.Cookie) (int, http.Header, string) {
		t.Helper()
		r, err := http.NewRequest(method, serverURL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = host
		r.Header.Set("Content-Type", contentType)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if cookie != nil {
			r.AddCookie(cookie)
			r.Header.Set("Origin", "https://tunn.test")
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, response.Header.Clone(), string(data)
	}
	status, headers, _ := call("POST", "tools.tunn.test", "/mcp", `{}`, "application/json", "", nil)
	if status != 401 || !strings.Contains(headers.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("MCP discovery challenge = %d %s", status, headers)
	}
	status, _, body := call("GET", "tools.tunn.test", "/.well-known/oauth-protected-resource/mcp", "", "", "", nil)
	if status != 200 || !strings.Contains(body, `"resource":"https://tools.tunn.test/mcp"`) {
		t.Fatalf("resource discovery = %d %s", status, body)
	}
	status, _, body = call("POST", "tunn.test", "/oauth/register", `{"client_name":"TLS connector","redirect_uris":["https://connector.example/cb"]}`, "application/json", "", nil)
	var registered mcpOAuthClient
	if status != 201 || json.Unmarshal([]byte(body), &registered) != nil || registered.ID == "" {
		t.Fatalf("DCR = %d %s", status, body)
	}
	verifier := strings.Repeat("a", 43)
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type": {"code"}, "client_id": {registered.ID}, "redirect_uri": {registered.RedirectURIs[0]},
		"resource": {"https://tools.tunn.test/mcp"}, "state": {"tls-state"}, "scope": {"mcp"},
		"code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])},
	}
	cookie := securityCookie(t, f.p, "owner@example.com")
	status, _, body = call("GET", "tunn.test", "/oauth/authorize?"+query.Encode(), "", "", "", cookie)
	if status != 200 {
		t.Fatalf("consent page = %d %s", status, body)
	}
	form := url.Values{"authorization": {hiddenMCPField(t, body, "authorization")}, "csrf_token": {hiddenMCPField(t, body, "csrf_token")}, "decision": {"allow"}}
	status, headers, body = call("POST", "tunn.test", "/oauth/authorize", form.Encode(), "application/x-www-form-urlencoded", "", cookie)
	location, err := url.Parse(headers.Get("Location"))
	if status != 302 || err != nil || location.Query().Get("code") == "" || location.Query().Get("state") != "tls-state" || location.Query().Get("iss") != "https://tunn.test" {
		t.Fatalf("consent approval = %d %s %s", status, headers, body)
	}
	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {registered.ID}, "code": {location.Query().Get("code")},
		"redirect_uri": {registered.RedirectURIs[0]}, "resource": {query.Get("resource")}, "code_verifier": {verifier},
	}
	status, _, body = call("POST", "tunn.test", "/oauth/token", tokenForm.Encode(), "application/x-www-form-urlencoded", "", nil)
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &token) != nil || token.AccessToken == "" {
		t.Fatalf("code exchange = %d %s", status, body)
	}
	if status, _, body := call("POST", "tools.tunn.test", "/mcp", `{}`, "application/json", token.AccessToken, nil); status != 200 {
		t.Fatalf("MCP admission = %d %s", status, body)
	}
	if status, _, _ := call("GET", "tunn.test", "/api/grants", "", "", token.AccessToken, nil); status != 401 {
		t.Fatal("MCP access token authorized owner management")
	}
	owner := relayJWT(t, f.p, "owner@example.com")
	if status, _, body := call("DELETE", "tunn.test", "/api/mcp/clients?tunnel=tools&client_id="+registered.ID, "", "", owner, nil); status != 204 {
		t.Fatalf("owner disconnect = %d %s", status, body)
	}
	status, headers, _ = call("POST", "tools.tunn.test", "/mcp", `{}`, "application/json", token.AccessToken, cookie)
	if status != 401 || !strings.Contains(headers.Get("WWW-Authenticate"), `error="invalid_token"`) || forwarded.Load() != 1 {
		t.Fatalf("revocation = %d %s; publisher calls = %d", status, headers, forwarded.Load())
	}
}
