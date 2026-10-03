package host

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/builddemo"
	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestGrantBuildWorkflowAcrossRealRelay(t *testing.T) {
	runGrantBuildWorkflow(t, "")
}

func TestGrantTwoSDKBuildWorkflowAcrossRealRelay(t *testing.T) {
	python := os.Getenv("TUNN_PYTHON")
	if python == "" {
		t.Skip("TUNN_PYTHON is unset; use make test-build-workflow for the pinned official Python SDK")
	}
	runGrantBuildWorkflow(t, python)
}

// This is an actual TLS gRPC publisher, an HTTP MCP target, a second HTTP
// routing node, and authenticated login-node storage RPC. No live endpoint or
// external account is touched; all grants and certificates belong to the test.
func runGrantBuildWorkflow(t *testing.T, python string) {
	started := time.Now()
	fixture := newGrantBuildFixture(t)
	ownerToken := ingressJWT(t, fixture.owner, "public@tunn.local")
	goGrant, goToken := fixture.createGrant(t, ownerToken, "go-investigator")
	secondLabel := "second-go-investigator"
	if python != "" {
		secondLabel = "python-investigator"
	}
	secondGrant, secondToken := fixture.createGrant(t, ownerToken, secondLabel)
	// Prove this cookie is valid before testing that a revoked grant cannot use
	// it as a fallback. This request is not charged to either grant.
	fixture.initialize(t, "", "", ownerToken, http.StatusOK, "")
	baseline := fixture.upstreamCalls.Load()
	goReport := fixture.investigateGo(t, goToken, "Tunn-Authorization")
	goUsed := fixture.upstreamCalls.Load() - baseline
	t.Logf("setup-to-useful-answer Go: %s; connect-to-first-tool %.3f ms; connect-to-answer %.3f ms; tool calls %d; protocol %s", time.Since(started), goReport.FirstToolMillis, goReport.UsefulAnswerMillis, goReport.ToolCalls, goReport.Protocol)
	baseline = fixture.upstreamCalls.Load()
	var secondReport *builddemo.Report
	if python == "" {
		secondReport = fixture.investigateGo(t, secondToken, "Authorization")
	} else {
		secondReport = fixture.investigatePython(t, python, secondToken)
		t.Logf("setup-to-useful-answer Python: %s; connect-to-first-tool %.3f ms; connect-to-answer %.3f ms; tool calls %d; protocol %s", time.Since(started), secondReport.FirstToolMillis, secondReport.UsefulAnswerMillis, secondReport.ToolCalls, secondReport.Protocol)
	}
	secondUsed := fixture.upstreamCalls.Load() - baseline
	if goReport.ToolCalls != 7 || secondReport.ToolCalls != 7 || len(goReport.Evidence) != 6 || !reflect.DeepEqual(goReport.Evidence, secondReport.Evidence) || goReport.Diagnosis != secondReport.Diagnosis {
		t.Fatalf("clients did not produce matching useful evidence: go calls=%d, second calls=%d", goReport.ToolCalls, secondReport.ToolCalls)
	}
	if python != "" && (goReport.Client != "official-go-sdk@v1.7.0" || secondReport.Client != "official-python-sdk@1.27.2") {
		t.Fatalf("SDK versions differ from the pinned clients: %q, %q", goReport.Client, secondReport.Client)
	}
	grants := fixture.listGrants(t, ownerToken)
	assertWorkflowGrant(t, grants, goGrant.ID, "go-investigator", goUsed, false)
	assertWorkflowGrant(t, grants, secondGrant.ID, secondLabel, secondUsed, false)
	if goUsed < 7 || secondUsed < 7 {
		t.Fatalf("admissions missing completed tool calls: go=%d, second=%d", goUsed, secondUsed)
	}
	t.Logf("owner sees distinct grants and exact HTTP admissions: Go %d; %s %d (7 tool calls each; protocol/control requests also consume allowance)", goUsed, secondLabel, secondUsed)

	fixture.revokeGrant(t, ownerToken, secondGrant.ID)
	beforeDenial := fixture.upstreamCalls.Load()
	fixture.initialize(t, secondToken, "Authorization", ownerToken, http.StatusForbidden, "grant_revoked")
	if fixture.upstreamCalls.Load() != beforeDenial {
		t.Fatal("revoked grant request reached upstream using a valid owner cookie")
	}
	// The independent Go grant still completes the entire useful investigation.
	baseline = fixture.upstreamCalls.Load()
	fixture.investigateGo(t, goToken, "Tunn-Authorization")
	goUsed += fixture.upstreamCalls.Load() - baseline
	grants = fixture.listGrants(t, ownerToken)
	assertWorkflowGrant(t, grants, goGrant.ID, "go-investigator", goUsed, false)
	assertWorkflowGrant(t, grants, secondGrant.ID, secondLabel, secondUsed, true)

	fixture.stopPublisher(t)
	fixture.startPublisher(t)
	grants = fixture.listGrants(t, ownerToken)
	assertWorkflowGrant(t, grants, goGrant.ID, "go-investigator", goUsed, false)
	assertWorkflowGrant(t, grants, secondGrant.ID, secondLabel, secondUsed, true)
	fixture.initialize(t, secondToken, "Tunn-Authorization", ownerToken, http.StatusForbidden, "grant_revoked")
	baseline = fixture.upstreamCalls.Load()
	fixture.investigateGo(t, goToken, "Authorization")
	goUsed += fixture.upstreamCalls.Load() - baseline
	assertWorkflowGrant(t, fixture.listGrants(t, ownerToken), goGrant.ID, "go-investigator", goUsed, false)

	// Completion records preserve attribution across the routing node, while
	// admission counters were already durable before any request was forwarded.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		out := exportIngress(t, fixture.remote, fixture.accountID, true)
		var goRequests, secondRequests, denied int64
		for _, counter := range out.Counters {
			switch counter.CallerID {
			case "grant:" + goGrant.ID:
				goRequests += counter.Requests
			case "grant:" + secondGrant.ID:
				secondRequests += counter.Requests
				denied += counter.Denied
			}
		}
		if goRequests == goUsed && secondRequests == secondUsed+2 && denied == 2 {
			t.Logf("independent revoke, no cookie fallback, publisher reconnect, caller attribution, and upstream credential stripping passed; setup and verification total %s", time.Since(started))
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("grant caller completion counters do not match admissions and denials")
}

type grantBuildFixture struct {
	owner         *ProxyServer
	remote        *storage.ProxyStorage
	local         *storage.LocalStorage
	accountID     string
	tunnelServer  *TunnelServer
	grpcAddress   string
	target        *httptest.Server
	ingress       *httptest.Server
	upstreamCalls atomic.Int64
	cancel        context.CancelFunc
	publisherDone chan error
}

func newGrantBuildFixture(t *testing.T) *grantBuildFixture {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	local := storage.NewLocalStorage(db)
	account, err := local.FindOrCreateByEmails(context.Background(), []string{"public@tunn.local"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &grantBuildFixture{local: local, remote: ingressProxyStorage(t, local), accountID: account.ID}
	service := builddemo.NewHandler()
	fixture.target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Tunn-Authorization") != "" || strings.Contains(r.Header.Get("Authorization"), store.GrantTokenPrefix) || strings.Contains(r.Header.Get("Cookie"), authCookieName) {
			t.Error("platform credential reached synthetic build service")
		}
		fixture.upstreamCalls.Add(1)
		service.ServeHTTP(w, r)
	}))
	t.Cleanup(fixture.target.Close)
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateSource.TLS.Certificates[0]
	certificateSource.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	cfg := &config.Config{PublicMode: true, Domain: "tunn.test", JWTSecret: "synthetic-grant-workflow-key", Insecure: true}
	fixture.tunnelServer = NewTunnelServer(cfg, nil, nil, fixture.remote)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}})))
	pb.RegisterTunnelServiceServer(grpcServer, fixture.tunnelServer)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	fixture.grpcAddress = listener.Addr().String()
	t.Cleanup(func() { fixture.stopPublisher(t) })
	fixture.startPublisher(t)
	fixture.owner = &ProxyServer{Domain: cfg.Domain, config: cfg, storage: fixture.remote, tunnelServer: fixture.tunnelServer, usageBuffer: NewUsageBuffer(), quotaCache: NewQuotaCache(time.Second)}
	ownerHTTP := httptest.NewTLSServer(fixture.owner.createHandler())
	t.Cleanup(ownerHTTP.Close)
	routing := &ProxyServer{Domain: cfg.Domain, config: cfg, storage: fixture.remote, tunnelServer: NewTunnelServer(cfg, nil, nil, fixture.remote), tunnelCache: map[string]string{"build-investigation": strings.TrimPrefix(ownerHTTP.URL, "https://")}}
	fixture.ingress = httptest.NewTLSServer(routing.createHandler())
	t.Cleanup(fixture.ingress.Close)
	return fixture
}

func (fixture *grantBuildFixture) startPublisher(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	fixture.cancel = cancel
	fixture.publisherDone = make(chan error, 1)
	publisher := &client.ServeClient{TunnelID: "build-investigation", TargetURL: fixture.target.URL, PublicPath: "/mcp", UpstreamPath: "/mcp", ServerAddr: fixture.grpcAddress, Insecure: true, InitialDelay: time.Millisecond, MaxReconnectDelay: 10 * time.Millisecond, AllowedEmails: []string{"public@tunn.local"}}
	go func() { fixture.publisherDone <- publisher.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if tunnel, found := fixture.tunnelServer.GetTunnel("build-investigation"); found {
			if tunnel.AccountID != fixture.accountID || tunnel.TargetURL != "mcp" {
				t.Fatal("publisher identity or target redaction mismatch")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("synthetic MCP publisher did not register")
}

func (fixture *grantBuildFixture) stopPublisher(t *testing.T) {
	t.Helper()
	if fixture.cancel == nil {
		return
	}
	fixture.cancel()
	fixture.cancel = nil
	select {
	case <-fixture.publisherDone:
	case <-time.After(2 * time.Second):
		t.Error("synthetic publisher failed to stop")
		return
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, exists := fixture.tunnelServer.GetTunnel("build-investigation")
		count, err := fixture.local.GetTunnelCount(context.Background(), fixture.accountID)
		if !exists && err == nil && count == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Error("publisher did not unregister from login-node storage")
}

func (fixture *grantBuildFixture) createGrant(t *testing.T, ownerToken, label string) (*store.Grant, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"endpoint": "build-investigation", "label": label, "ttl_seconds": 300, "request_limit": 100})
	response := fixture.api(t, http.MethodPost, "/api/grants", ownerToken, body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create synthetic grant: HTTP %d", response.StatusCode)
	}
	var result struct {
		Grant *store.Grant `json:"grant"`
		Token string       `json:"token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil || result.Grant == nil || !strings.HasPrefix(result.Token, store.GrantTokenPrefix) {
		t.Fatal("create response omitted synthetic grant metadata or credential")
	}
	return result.Grant, result.Token
}

func (fixture *grantBuildFixture) listGrants(t *testing.T, ownerToken string) map[string]store.Grant {
	t.Helper()
	response := fixture.api(t, http.MethodGet, "/api/grants?endpoint=build-investigation", ownerToken, nil)
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || bytes.Contains(data, []byte(store.GrantTokenPrefix)) || bytes.Contains(data, []byte("token_digest")) {
		t.Fatal("owner grant metadata response failed or disclosed credentials")
	}
	var result struct {
		Grants []store.Grant `json:"grants"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	grants := make(map[string]store.Grant)
	for _, grant := range result.Grants {
		grants[grant.ID] = grant
	}
	return grants
}

func (fixture *grantBuildFixture) revokeGrant(t *testing.T, ownerToken, id string) {
	t.Helper()
	response := fixture.api(t, http.MethodDelete, "/api/grants/"+id, ownerToken, nil)
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke synthetic grant: HTTP %d", response.StatusCode)
	}
}

func (fixture *grantBuildFixture) api(t *testing.T, method, path, ownerToken string, body []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, fixture.ingress.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "tunn.test"
	request.Header.Set("Authorization", "Bearer "+ownerToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := fixture.ingress.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func (fixture *grantBuildFixture) initialize(t *testing.T, token, authHeader, cookie string, status int, reason string) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"synthetic-auth-check","version":"1"}}}`
	request, err := http.NewRequest(http.MethodPost, fixture.ingress.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "build-investigation.tunn.test"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		request.Header.Set(authHeader, "Bearer "+token)
	}
	if cookie != "" {
		request.AddCookie(&http.Cookie{Name: authCookieName, Value: cookie})
	}
	response, err := fixture.ingress.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != status || response.Header.Get("X-Tunn-Grant-Reason") != reason {
		t.Fatalf("synthetic authentication check: status=%d, reason=%q", response.StatusCode, response.Header.Get("X-Tunn-Grant-Reason"))
	}
}

func (fixture *grantBuildFixture) investigateGo(t *testing.T, token, header string) *builddemo.Report {
	t.Helper()
	base := fixture.ingress.Client()
	httpClient := &http.Client{Transport: grantWorkflowTransport{base: base.Transport, token: token, header: header}, Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	report, err := builddemo.Investigate(ctx, builddemo.ClientOptions{Endpoint: fixture.ingress.URL + "/mcp", HTTPClient: httpClient})
	if err != nil {
		t.Fatalf("official Go SDK investigation through two-node relay: %v", err)
	}
	return report
}

func (fixture *grantBuildFixture) investigatePython(t *testing.T, python, token string) *builddemo.Report {
	t.Helper()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "synthetic-grant.token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "synthetic-relay-ca.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.ingress.Certificate().Raw})
	if err := os.WriteFile(certificatePath, certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "integration-tests", "build-investigation", "client.py"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, script, "--endpoint", fixture.ingress.URL+"/mcp", "--token-file", tokenPath, "--ca-cert", certificatePath, "--host", "build-investigation.tunn.test")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("official Python SDK investigation failed: %v; %s", err, stderr.String())
	}
	var report builddemo.Report
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("decode official Python SDK investigation report: %v", err)
	}
	return &report
}

func assertWorkflowGrant(t *testing.T, grants map[string]store.Grant, id, label string, used int64, revoked bool) {
	t.Helper()
	grant, found := grants[id]
	if !found || grant.Label != label || grant.EndpointID != "build-investigation" || grant.RequestLimit != 100 || grant.Used != used || grant.Revoked != revoked {
		t.Fatalf("owner grant metadata mismatch for label %q: found=%v, used=%d expected=%d, revoked=%v expected=%v", label, found, grant.Used, used, grant.Revoked, revoked)
	}
}

type grantWorkflowTransport struct {
	base   http.RoundTripper
	token  string
	header string
}

func (transport grantWorkflowTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Host = "build-investigation.tunn.test"
	clone.Header.Set(transport.header, "Bearer "+transport.token)
	return transport.base.RoundTrip(clone)
}
