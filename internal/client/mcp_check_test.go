package client

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mcpCheckFixture struct {
	server      *httptest.Server
	resource    map[string]any
	authorize   map[string]any
	challenge   string
	status      int
	rewrite     func(http.ResponseWriter, *http.Request) bool
	mu          sync.Mutex
	requests    []string
	credentials bool
}

func newMCPCheckFixture(t *testing.T) *mcpCheckFixture {
	t.Helper()
	f := &mcpCheckFixture{status: http.StatusUnauthorized}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.credentials = f.credentials || r.Header.Get("Authorization") != "" || r.Header.Get("Tunn-Authorization") != "" || r.Header.Get("Cookie") != ""
		f.mu.Unlock()
		if f.rewrite != nil && f.rewrite(w, r) {
			return
		}
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", f.challenge)
			w.WriteHeader(f.status)
		case "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.resource)
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.authorize)
		default:
			t.Errorf("unexpected non-discovery request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	f.challenge = fmt.Sprintf(`Basic realm="example, realm", Bearer realm="tunn", resource_metadata="%s/.well-known/oauth-protected-resource", scope="mcp:access"`, f.server.URL)
	f.resource = map[string]any{"resource": f.server.URL + "/mcp", "authorization_servers": []string{f.server.URL}, "scopes_supported": []string{"mcp:access"}}
	f.authorize = validMCPCheckAuthorization(f.server.URL)
	t.Cleanup(f.server.Close)
	return f
}

func validMCPCheckAuthorization(issuer string) map[string]any {
	return map[string]any{
		"issuer": issuer, "authorization_endpoint": issuer + "/oauth/authorize", "token_endpoint": issuer + "/oauth/token",
		"token_endpoint_auth_methods_supported": []string{"none"}, "code_challenge_methods_supported": []string{"S256"},
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code"},
		"scopes_supported": []string{"mcp:access"}, "authorization_response_iss_parameter_supported": true,
	}
}

func (f *mcpCheckFixture) options() MCPCheckOptions {
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	return MCPCheckOptions{Endpoint: f.server.URL + "/mcp", RootCAs: pool}
}

func checkFailure(t *testing.T, options MCPCheckOptions, name string) *MCPCheckReport {
	t.Helper()
	report, err := CheckMCPDiscovery(context.Background(), options)
	if err == nil || report.Ready || len(report.Checks) == 0 || report.Checks[len(report.Checks)-1].Name != name {
		t.Fatalf("wanted failure %q, got report %+v and error %v", name, report, err)
	}
	return report
}

func TestMCPCheckDiscoveryIsReadOnly(t *testing.T) {
	f := newMCPCheckFixture(t)
	report, err := CheckMCPDiscovery(context.Background(), f.options())
	if err != nil || !report.Ready || report.Endpoint != f.server.URL+"/mcp" || report.Issuer != f.server.URL {
		t.Fatalf("report %+v, error %v", report, err)
	}
	expected := []string{"GET /mcp", "GET /.well-known/oauth-protected-resource", "GET /.well-known/oauth-authorization-server"}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !reflect.DeepEqual(f.requests, expected) || f.credentials {
		t.Fatalf("requests %v, credentials sent %v", f.requests, f.credentials)
	}
	if len(report.NextSteps) < 4 || !strings.Contains(report.NextSteps[0], "not an OAuth client ID") {
		t.Fatalf("missing actionable onboarding: %v", report.NextSteps)
	}
}

func TestMCPCheckMissingContract(t *testing.T) {
	cases := []struct {
		name   string
		modify func(*mcpCheckFixture)
		check  string
	}{
		{"public endpoint", func(f *mcpCheckFixture) { f.status = 200 }, "challenge"},
		{"grant only", func(f *mcpCheckFixture) { f.challenge = `Bearer realm="tunn"` }, "challenge"},
		{"wrong challenge scope", func(f *mcpCheckFixture) { f.challenge = strings.ReplaceAll(f.challenge, "mcp:access", "files:read") }, "challenge_scope"},
		{"resource mismatch", func(f *mcpCheckFixture) { f.resource["resource"] = f.server.URL }, "resource"},
		{"multiple issuers", func(f *mcpCheckFixture) { f.resource["authorization_servers"] = []string{f.server.URL, f.server.URL} }, "issuer"},
		{"no PKCE", func(f *mcpCheckFixture) { delete(f.authorize, "code_challenge_methods_supported") }, "pkce"},
		{"plain PKCE", func(f *mcpCheckFixture) { f.authorize["code_challenge_methods_supported"] = []string{"plain"} }, "pkce"},
		{"secret only", func(f *mcpCheckFixture) {
			f.authorize["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"}
		}, "public_client"},
		{"issuer mismatch", func(f *mcpCheckFixture) { f.authorize["issuer"] = f.server.URL + "/" }, "issuer_match"},
		{"no code response", func(f *mcpCheckFixture) { f.authorize["response_types_supported"] = []string{"token"} }, "authorization_code"},
		{"different grant", func(f *mcpCheckFixture) { f.authorize["grant_types_supported"] = []string{"client_credentials"} }, "authorization_code"},
		{"resource scope", func(f *mcpCheckFixture) { f.resource["scopes_supported"] = []string{"files:read"} }, "scope"},
		{"AS scope", func(f *mcpCheckFixture) { f.authorize["scopes_supported"] = []string{"files:read"} }, "scope"},
		{"no issuer identification", func(f *mcpCheckFixture) { delete(f.authorize, "authorization_response_iss_parameter_supported") }, "issuer_response"},
		{"different token origin", func(f *mcpCheckFixture) { f.authorize["token_endpoint"] = "https://unapproved.invalid/token" }, "oauth_endpoints"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMCPCheckFixture(t)
			tc.modify(f)
			checkFailure(t, f.options(), tc.check)
		})
	}
}

func TestMCPCheckFailuresPrioritizeRecoveryBeforeConnectionSetup(t *testing.T) {
	cases := []struct {
		name   string
		modify func(*mcpCheckFixture)
		check  string
		action string
		gets   int
	}{
		{"grant-only relay", func(f *mcpCheckFixture) { f.challenge = `Bearer realm="tunn"` }, "challenge", "TUNN_MCP_OAUTH_CLIENTS_FILE", 1},
		{"public endpoint", func(f *mcpCheckFixture) { f.status = 200 }, "challenge", "private /mcp route", 1},
		{"broken PKCE metadata", func(f *mcpCheckFixture) { delete(f.authorize, "code_challenge_methods_supported") }, "pkce", "relay owner", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newMCPCheckFixture(t)
			tc.modify(f)
			report := checkFailure(t, f.options(), tc.check)
			if len(report.NextSteps) == 0 || !strings.Contains(report.NextSteps[0], tc.action) {
				t.Fatalf("missing immediate recovery action: %+v", report.NextSteps)
			}
			for _, action := range report.NextSteps {
				if strings.Contains(action, "Choose OAuth") || strings.Contains(action, "In Claude choose") {
					t.Fatal("failed discovery prematurely instructed application registration")
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.requests) != tc.gets || f.credentials {
				t.Fatalf("recovery changed bounded requests or authentication: %v, credentials %v", f.requests, f.credentials)
			}
		})
	}
}

func TestMCPCheckSeparateIssuerNeedsExplicitOrigin(t *testing.T) {
	var issuerRequests atomic.Int64
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuerRequests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/.well-known/oauth-authorization-server" {
			t.Errorf("unexpected issuer request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(validMCPCheckAuthorization(issuer.URL))
	}))
	defer issuer.Close()
	f := newMCPCheckFixture(t)
	f.resource["authorization_servers"] = []string{issuer.URL}
	options := f.options()
	options.RootCAs.AddCert(issuer.Certificate())
	report := checkFailure(t, options, "issuer")
	if issuerRequests.Load() != 0 || report.Issuer != issuer.URL {
		t.Fatalf("unapproved issuer fetched: %d, report %+v", issuerRequests.Load(), report)
	}
	if len(report.NextSteps) == 0 || !strings.Contains(report.NextSteps[0], "--issuer") || strings.Contains(report.NextSteps[0], "Choose OAuth") {
		t.Fatalf("issuer approval was buried behind application setup: %v", report.NextSteps)
	}
	options.ExpectedIssuer = f.server.URL
	checkFailure(t, options, "issuer")
	if issuerRequests.Load() != 0 {
		t.Fatal("mismatching explicit issuer was fetched")
	}
	options.ExpectedIssuer = issuer.URL
	report, err := CheckMCPDiscovery(context.Background(), options)
	if err != nil || !report.Ready || issuerRequests.Load() != 1 {
		t.Fatalf("explicit issuer report %+v, error %v, requests %d", report, err, issuerRequests.Load())
	}
}

func TestMCPCheckRejectsUnsafeURLsBeforeFetching(t *testing.T) {
	unsafe := []string{"http://example.invalid", "https://user:secret@example.invalid", "https://example.invalid?token=secret", "https://example.invalid?", "https://example.invalid#fragment", "https://example.invalid/", "https://example.invalid/oauth", "https://example.invalid/%2e%2e", "https://example.invalid\\other"}
	for _, value := range unsafe {
		t.Run(value, func(t *testing.T) {
			f := newMCPCheckFixture(t)
			options := f.options()
			options.ExpectedIssuer = value
			checkFailure(t, options, "expected_issuer")
			if len(f.requests) != 0 {
				t.Fatalf("unsafe expected issuer triggered requests: %v", f.requests)
			}
			options.ExpectedIssuer = ""
			f.resource["authorization_servers"] = []string{value}
			checkFailure(t, options, "issuer")
			if len(f.requests) != 2 {
				t.Fatalf("unsafe metadata issuer fetched: %v", f.requests)
			}
		})
	}
	for _, value := range []string{"http://example.invalid/mcp", "https://user:secret@example.invalid/mcp", "https://example.invalid/mcp?token=secret", "https://example.invalid/mcp#fragment", "https://example.invalid/%6dcp"} {
		report := checkFailure(t, MCPCheckOptions{Endpoint: value}, "endpoint")
		if report.Endpoint != "" {
			t.Fatal("unsafe input copied into report")
		}
	}
}

func TestMCPCheckDoesNotFollowDiscoveryRedirects(t *testing.T) {
	for _, path := range []string{"/mcp", "/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"} {
		t.Run(path, func(t *testing.T) {
			var redirectedRequests atomic.Int64
			destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirectedRequests.Add(1)
				w.WriteHeader(200)
			}))
			defer destination.Close()
			f := newMCPCheckFixture(t)
			f.rewrite = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != path {
					return false
				}
				http.Redirect(w, r, destination.URL+"/credentials", http.StatusFound)
				return true
			}
			options := f.options()
			options.RootCAs.AddCert(destination.Certificate())
			report, err := CheckMCPDiscovery(context.Background(), options)
			if err == nil || report.Ready || redirectedRequests.Load() != 0 {
				t.Fatalf("redirect followed: report %+v, err %v, requests %d", report, err, redirectedRequests.Load())
			}
		})
	}
}

func TestMCPCheckUnapprovedMetadataOriginIsNeverFetched(t *testing.T) {
	var requests atomic.Int64
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer destination.Close()
	f := newMCPCheckFixture(t)
	f.challenge = fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, destination.URL)
	checkFailure(t, f.options(), "metadata_location")
	if requests.Load() != 0 {
		t.Fatal("unapproved metadata origin fetched")
	}
}

func TestMCPCheckMetadataBodyIsBoundedAndUnambiguous(t *testing.T) {
	for _, body := range []string{
		`{"resource":"one","resource":"two"}`,
		`{"resource":"one","Resource":"two"}`,
		`{"resource":"one"} {"resource":"two"}`,
		`{"resource":`,
		`[]`,
		`{"resource":7}`,
		strings.Repeat(" ", mcpMetadataLimit+1),
	} {
		f := newMCPCheckFixture(t)
		f.rewrite = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != "/.well-known/oauth-protected-resource" {
				return false
			}
			_, _ = fmt.Fprint(w, body)
			return true
		}
		checkFailure(t, f.options(), "protected_resource_metadata")
	}
}

func TestMCPCheckTLSVerificationAndContextDeadline(t *testing.T) {
	f := newMCPCheckFixture(t)
	checkFailure(t, MCPCheckOptions{Endpoint: f.server.URL + "/mcp"}, "challenge")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	report, err := CheckMCPDiscovery(ctx, f.options())
	if err == nil || report.Ready || time.Since(start) > time.Second {
		t.Fatalf("cancelled discovery did not stop promptly: %+v, %v", report, err)
	}
}

func TestMCPChallengeMetadataParsing(t *testing.T) {
	for _, header := range []string{
		`Bearer resource_metadata="https://example.invalid/.well-known/oauth-protected-resource"`,
		`Bearer realm="tunn", resource_metadata = "https://example.invalid/.well-known/oauth-protected-resource"`,
		`Basic realm="fake, realm", bEaReR realm="tunn", resource_metadata=https://example.invalid/.well-known/oauth-protected-resource`,
	} {
		metadata, err := mcpChallengeParameters([]string{header})
		if err != nil || metadata["resource_metadata"] != "https://example.invalid/.well-known/oauth-protected-resource" {
			t.Fatalf("header %q => %q, %v", header, metadata, err)
		}
	}
	for _, header := range []string{
		`Basic resource_metadata="https://example.invalid"`,
		`Bearer realm="tunn"`,
		`Bearer resource_metadata="unterminated`,
		`Bearer resource_metadata="one", resource_metadata="two"`,
		`Bearer resource_metadata="one", scope="mcp:access", scope="files:read"`,
		`Bearer resource_metadata=""`,
	} {
		if value, err := mcpChallengeParameters([]string{header}); err == nil {
			t.Fatalf("invalid challenge accepted: %q => %q", header, value)
		}
	}
}
