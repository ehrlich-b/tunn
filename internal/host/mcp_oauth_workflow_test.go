package host

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/builddemo"
)

func TestMCPOAuthBuildWorkflowAcrossRealRelay(t *testing.T) { runMCPOAuthBuildWorkflow(t, "") }
func TestMCPOAuthTwoSDKBuildWorkflowAcrossRealRelay(t *testing.T) {
	python := os.Getenv("TUNN_PYTHON")
	if python == "" {
		t.Skip("use make test-mcp-oauth-workflow for pinned Python SDK")
	}
	runMCPOAuthBuildWorkflow(t, python)
}

func runMCPOAuthBuildWorkflow(t *testing.T, python string) {
	start := time.Now()
	fixture := newGrantBuildFixture(t)
	enableTestMCPOAuth(t, fixture.owner)
	ownerHTTP := httptest.NewTLSServer(fixture.owner.createHandler())
	t.Cleanup(ownerHTTP.Close)
	routing := &ProxyServer{Domain: fixture.owner.Domain, config: fixture.owner.config, storage: fixture.remote, mcpOAuth: fixture.owner.mcpOAuth, tunnelServer: NewTunnelServer(fixture.owner.config, nil, nil, fixture.remote), tunnelCache: map[string]string{"build-investigation": strings.TrimPrefix(ownerHTTP.URL, "https://")}}
	fixture.ingress = httptest.NewTLSServer(routing.createHandler())
	t.Cleanup(fixture.ingress.Close)
	ownerToken := ingressJWT(t, fixture.owner, "public@tunn.local")
	request := func(method, path, host string, form url.Values, cookies ...*http.Cookie) (int, http.Header, []byte) {
		var body string
		if form != nil {
			body = form.Encode()
		}
		r, err := http.NewRequest(method, fixture.ingress.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = host
		if form != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		c := *fixture.ingress.Client()
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, response.Header, data
	}
	status, headers, _ := request("GET", "/mcp", "build-investigation.tunn.test", nil)
	if status != 401 || !strings.Contains(headers.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatal("missing discovery challenge", status)
	}
	status, _, data := request("GET", "/.well-known/oauth-protected-resource/mcp", "build-investigation.tunn.test", nil)
	var resource struct {
		Resource string   `json:"resource"`
		Issuers  []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(data, &resource); err != nil {
		t.Fatal(err)
	}
	if status != 200 || resource.Resource != "https://build-investigation.tunn.test/mcp" || len(resource.Issuers) != 1 || resource.Issuers[0] != "https://tunn.test" {
		t.Fatal("wrong canonical resource metadata")
	}
	status, _, data = request("GET", "/.well-known/oauth-authorization-server", "tunn.test", nil)
	if status != 200 || !strings.Contains(string(data), `"S256"`) {
		t.Fatal("missing issuer metadata")
	}
	exchange := func(clientID string) string {
		client := fixture.owner.mcpOAuth.clients[clientID]
		verifier := strings.Repeat("v", 43)
		sum := sha256.Sum256([]byte(verifier))
		query := url.Values{"client_id": {clientID}, "redirect_uri": {client.RedirectURIs[0]}, "resource": {resource.Resource}, "scope": {mcpOAuthScope}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "state": {"synthetic-client-state"}}
		ownerCookie := &http.Cookie{Name: authCookieName, Value: ownerToken}
		status, headers, data := request("GET", "/oauth/authorize?"+query.Encode(), "tunn.test", nil, ownerCookie)
		match := regexp.MustCompile(`name="ticket" value="([^"]+)"`).FindSubmatch(data)
		if status != 200 || len(match) != 2 {
			t.Fatal("missing owner consent", status)
		}
		parsed := (&http.Response{Header: headers}).Cookies()
		var csrf *http.Cookie
		for _, cookie := range parsed {
			if cookie.Name == mcpOAuthCSRFCookie {
				csrf = cookie
			}
		}
		if csrf == nil {
			t.Fatal("missing CSRF protection")
		}
		status, headers, _ = request("POST", "/oauth/authorize", "tunn.test", url.Values{"ticket": {string(match[1])}, "decision": {"allow"}}, ownerCookie, csrf)
		callback, err := url.Parse(headers.Get("Location"))
		if err != nil || status != 302 || callback.Query().Get("iss") != "https://tunn.test" || callback.Query().Get("state") != "synthetic-client-state" {
			t.Fatal("bad authorized callback")
		}
		form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "redirect_uri": {client.RedirectURIs[0]}, "resource": {resource.Resource}, "code_verifier": {verifier}, "code": {callback.Query().Get("code")}}
		status, _, data = request("POST", "/oauth/token", "tunn.test", form)
		var token struct {
			Token string `json:"access_token"`
			Type  string `json:"token_type"`
			Scope string `json:"scope"`
		}
		if err := json.Unmarshal(data, &token); err != nil {
			t.Fatal(err)
		}
		if status != 200 || token.Token == "" || token.Type != "Bearer" || token.Scope != mcpOAuthScope {
			t.Fatal("bad token exchange", status)
		}
		return token.Token
	}
	goToken := exchange("chatgpt-fixture")
	secondToken := exchange("claude-fixture")
	// Establish that this owner cookie works before testing explicit-grant denial.
	fixture.initialize(t, "", "", ownerToken, 200, "")
	baseline := fixture.upstreamCalls.Load()
	first := fixture.investigateGo(t, goToken, "Authorization")
	goUsed := fixture.upstreamCalls.Load() - baseline
	baseline = fixture.upstreamCalls.Load()
	var second *builddemo.Report
	if python == "" {
		second = fixture.investigateGo(t, secondToken, "Authorization")
	} else {
		second = fixture.investigatePython(t, python, secondToken)
	}
	secondUsed := fixture.upstreamCalls.Load() - baseline
	if first.ToolCalls != 7 || second.ToolCalls != 7 || len(first.Evidence) != 6 || !reflect.DeepEqual(first.Evidence, second.Evidence) || first.Diagnosis != second.Diagnosis || goUsed < 7 || secondUsed < 7 {
		t.Fatal("OAuth-authorized useful answer failed")
	}
	grants := fixture.listGrants(t, ownerToken)
	if len(grants) != 2 {
		t.Fatal("missing independent OAuth grants")
	}
	var revokedID, goID string
	for _, grant := range grants {
		if grant.Label == "OAuth: Claude synthetic client" {
			revokedID = grant.ID
		}
		if grant.Label == "OAuth: ChatGPT synthetic client" {
			goID = grant.ID
		}
	}
	if revokedID == "" || goID == "" {
		t.Fatal("missing owner client visibility")
	}
	assertWorkflowGrant(t, grants, goID, "OAuth: ChatGPT synthetic client", goUsed, false)
	assertWorkflowGrant(t, grants, revokedID, "OAuth: Claude synthetic client", secondUsed, false)
	fixture.revokeGrant(t, ownerToken, revokedID)
	beforeDenial := fixture.upstreamCalls.Load()
	fixture.initialize(t, secondToken, "Authorization", ownerToken, 401, "grant_revoked")
	if fixture.upstreamCalls.Load() != beforeDenial {
		t.Fatal("revoked OAuth grant reached the upstream")
	}
	fixture.stopPublisher(t)
	fixture.startPublisher(t)
	fixture.initialize(t, secondToken, "Authorization", ownerToken, 401, "grant_revoked")
	baseline = fixture.upstreamCalls.Load()
	fixture.investigateGo(t, goToken, "Authorization")
	goUsed += fixture.upstreamCalls.Load() - baseline
	grants = fixture.listGrants(t, ownerToken)
	assertWorkflowGrant(t, grants, goID, "OAuth: ChatGPT synthetic client", goUsed, false)
	assertWorkflowGrant(t, grants, revokedID, "OAuth: Claude synthetic client", secondUsed, true)
	deadline := time.Now().Add(2 * time.Second)
	for {
		out := exportIngress(t, fixture.remote, fixture.accountID, true)
		var goRequests, secondRequests, denied int64
		for _, counter := range out.Counters {
			switch counter.CallerID {
			case "grant:" + goID:
				goRequests += counter.Requests
			case "grant:" + revokedID:
				secondRequests += counter.Requests
				denied += counter.Denied
			}
		}
		if goRequests == goUsed && secondRequests == secondUsed+2 && denied == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("OAuth grant completion attribution does not match admissions and denials")
		}
		time.Sleep(time.Millisecond)
	}
	t.Logf("OAuth-issued grants retain exact durable HTTP allowances and caller attribution: Go %d admissions; second %d admissions and 2 denied requests", goUsed, secondUsed)
	t.Logf("Synthetic static-client OAuth discovery, owner consent, S256 exchange, two useful SDK answers, revoke/no fallback and reconnect passed in %s; Go %.3f ms, second %.3f ms; clients %s/%s. These are fixtures, not hosted application acceptance.", time.Since(start), first.UsefulAnswerMillis, second.UsefulAnswerMillis, first.Client, second.Client)
}
