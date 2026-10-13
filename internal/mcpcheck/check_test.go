package mcpcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

const resourceURL = "https://tools.tunn.test/mcp"

func metadataFixture(t *testing.T, mutate func(string, *http.Response)) (*Checker, *[]string) {
	t.Helper()
	calls := []string{}
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.URL.String())
		if r.Header.Get("Authorization") != "" {
			t.Fatal("credentials sent during discovery")
		}
		var resp *http.Response
		switch r.URL.String() {
		case resourceURL:
			resp = response(401, "")
			resp.Header.Set("WWW-Authenticate", `Bearer realm="tunn", resource_metadata="https://tools.tunn.test/.well-known/oauth-protected-resource/mcp", scope="mcp"`)
		case "https://tools.tunn.test/.well-known/oauth-protected-resource/mcp":
			resp = response(200, `{"resource":"https://tools.tunn.test/mcp","authorization_servers":["https://tunn.test"],"scopes_supported":["mcp"],"bearer_methods_supported":["header"]}`)
		case "https://tunn.test/.well-known/oauth-authorization-server":
			resp = response(200, `{"issuer":"https://tunn.test","authorization_endpoint":"https://tunn.test/oauth/authorize","token_endpoint":"https://tunn.test/oauth/token","registration_endpoint":"https://tunn.test/oauth/register","response_types_supported":["code"],"grant_types_supported":["authorization_code"],"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],"scopes_supported":["mcp"]}`)
		default:
			t.Fatalf("unexpected outbound request %s", r.URL)
			return nil, errors.New("unexpected request")
		}
		if mutate != nil {
			mutate(r.URL.String(), resp)
		}
		return resp, nil
	})
	return New(transport), &calls
}
func requireProblem(t *testing.T, err error, code string) {
	t.Helper()
	var p *Problem
	if !errors.As(err, &p) || p.Code != code || p.Stage == "" || p.Action == "" {
		t.Fatalf("problem = %v; want %s with stage/action", err, code)
	}
	if strings.Contains(p.Error(), "secret-marker") {
		t.Fatal("sensitive server data in diagnostic")
	}
}
func TestConnectorDiscoveryContract(t *testing.T) {
	c, calls := metadataFixture(t, nil)
	d, err := c.Discover(context.Background(), resourceURL)
	if err != nil || d.Resource != resourceURL || d.Issuer != "https://tunn.test" || len(*calls) != 3 {
		t.Fatalf("discovery: %#v, %v, %v", d, err, *calls)
	}
}
func TestConnectorDiscoveryRejectsInvalidURLsWithoutNetwork(t *testing.T) {
	for _, raw := range []string{"http://tools.tunn.test/mcp", "https://tools.tunn.test/", "https://user:secret-marker@tools.tunn.test/mcp", "https://tools.tunn.test/mcp?secret-marker=x", "https://tools.tunn.test/mcp#x", "https://tools.tunn.test/%6dcp", "https://tools.tunn.test/mcp?", "https://localhost/mcp", "https://127.0.0.1/mcp", "https://192.168.0.1/mcp", "https://[::1]/mcp"} {
		t.Run(raw, func(t *testing.T) {
			c, calls := metadataFixture(t, nil)
			_, err := c.Discover(context.Background(), raw)
			if err == nil || len(*calls) != 0 {
				t.Fatalf("unsafe URL used: %v calls=%v", err, *calls)
			}
			if strings.Contains(err.Error(), "secret-marker") {
				t.Fatal("URL secret leaked")
			}
		})
	}
}
func TestConnectorDiscoveryBrokenMetadata(t *testing.T) {
	for _, tt := range []struct {
		name, target, old, new, code string
		count                        int
	}{
		{"challenge", "/mcp", "Bearer", "Basic", "metadata_challenge", 1},
		{"metadata origin", "/mcp", "https://tools.tunn.test/.well-known", "https://attacker.test/.well-known", "origin", 1},
		{"resource", "oauth-protected-resource/mcp", "https://tools.tunn.test/mcp", "https://other.tunn.test/mcp", "resource", 2},
		{"scope", "oauth-protected-resource/mcp", `"mcp"`, `"wrong"`, "resource", 2},
		{"issuer scheme", "oauth-protected-resource/mcp", "https://tunn.test", "http://tunn.test", "issuer", 2},
		{"issuer identity", "oauth-authorization-server", `"issuer":"https://tunn.test"`, `"issuer":"https://other.test"`, "issuer", 3},
		{"PKCE", "oauth-authorization-server", "S256", "plain", "pkce", 3},
		{"public client", "oauth-authorization-server", `"none"`, `"client_secret_post"`, "pkce", 3},
		{"grant", "oauth-authorization-server", "authorization_code", "client_credentials", "pkce", 3},
		{"token endpoint origin", "oauth-authorization-server", "https://tunn.test/oauth/token", "https://attacker.test/oauth/token", "endpoint", 3},
		{"registration scheme", "oauth-authorization-server", "https://tunn.test/oauth/register", "http://tunn.test/oauth/register", "endpoint", 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, calls := metadataFixture(t, func(target string, r *http.Response) {
				if !strings.HasSuffix(target, tt.target) {
					return
				}
				if tt.target == "/mcp" {
					r.Header.Set("WWW-Authenticate", strings.Replace(r.Header.Get("WWW-Authenticate"), tt.old, tt.new, 1))
				} else {
					b, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(strings.NewReader(strings.Replace(string(b), tt.old, tt.new, 1)))
				}
			})
			_, err := c.Discover(context.Background(), resourceURL)
			requireProblem(t, err, tt.code)
			if len(*calls) != tt.count {
				t.Fatalf("requests=%v", *calls)
			}
		})
	}
	for _, tt := range []struct{ name, body, ct, code string }{
		{"html", "<html>secret-marker</html>", "text/html", "json"},
		{"malformed", "{secret-marker", "application/json", "json"},
		{"extra", `{} {"secret-marker":true}`, "application/json", "json"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := metadataFixture(t, func(target string, r *http.Response) {
				if strings.Contains(target, "protected-resource") {
					r.Body = io.NopCloser(strings.NewReader(tt.body))
					r.Header.Set("Content-Type", tt.ct)
				}
			})
			_, err := c.Discover(context.Background(), resourceURL)
			requireProblem(t, err, tt.code)
		})
	}
}
func TestConnectorStatusActionsAndNoRemoteLeak(t *testing.T) {
	for _, tt := range []struct {
		status int
		code   string
	}{{200, "public"}, {202, "public"}, {302, "redirect"}, {400, "bad_request"}, {403, "forbidden"}, {404, "not_found"}, {405, "method"}, {429, "rate_limit"}, {502, "upstream"}, {503, "unavailable"}, {504, "upstream_timeout"}, {500, "http"}} {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			c, calls := metadataFixture(t, func(target string, r *http.Response) {
				if target == resourceURL {
					r.StatusCode = tt.status
					r.Header.Set("Location", "https://attacker.test/secret-marker")
					r.Body = io.NopCloser(strings.NewReader("secret-marker"))
				}
			})
			_, err := c.Discover(context.Background(), resourceURL)
			requireProblem(t, err, tt.code)
			if len(*calls) != 1 {
				t.Fatal("followed redirect")
			}
		})
	}
	requireProblem(t, statusProblem("token", 401), "unauthorized")
}
func TestConnectorTransportActions(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		code string
	}{
		{"DNS", &net.DNSError{Err: "secret-marker", Name: "secret-marker"}, "dns"},
		{"TLS", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, "tls"},
		{"timeout", context.DeadlineExceeded, "timeout"}, {"cancelled", context.Canceled, "cancelled"}, {"network", errors.New("secret-marker"), "network"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := New(roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, tt.err }))
			_, err := c.Discover(context.Background(), resourceURL)
			requireProblem(t, err, tt.code)
		})
	}
}
func TestConnectorOAuthBindings(t *testing.T) {
	c, _ := metadataFixture(t, nil)
	d, err := c.Discover(context.Background(), resourceURL)
	if err != nil {
		t.Fatal(err)
	}
	posts := 0
	c = New(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("bearer sent to issuer")
		}
		posts++
		b, _ := io.ReadAll(r.Body)
		if r.URL.String() == d.Register {
			var registration map[string]json.RawMessage
			if json.Unmarshal(b, &registration) != nil {
				t.Fatal("bad registration")
			}
			return response(201, `{"client_id":"fixture-id","token_endpoint_auth_method":"none","redirect_uris":["http://127.0.0.1:12345/callback"]}`), nil
		}
		if r.URL.String() != d.Token {
			t.Fatal("unexpected endpoint")
		}
		form, _ := url.ParseQuery(string(b))
		if form.Get("resource") != d.Resource || form.Get("client_id") != "fixture-id" || form.Get("redirect_uri") != "http://127.0.0.1:12345/callback" || len(form.Get("code_verifier")) != 43 || form.Get("code") != "fixture-code" {
			t.Fatal("token binding lost")
		}
		return response(200, `{"access_token":"fixture-token","token_type":"Bearer","scope":"mcp","expires_in":3600}`), nil
	}))
	a, err := c.BeginOAuth(context.Background(), d, "http://127.0.0.1:12345/callback")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(a.URL)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("resource") != d.Resource || len(q.Get("state")) != 43 {
		t.Fatal("missing OAuth binding")
	}
	callback := a.redirect + "?" + url.Values{"code": {"fixture-code"}, "state": {a.state}, "iss": {d.Issuer}}.Encode()
	for _, tt := range []struct {
		name   string
		modify func(*url.URL)
		code   string
	}{
		{"wrong callback", func(u *url.URL) { u.Host = "attacker.test" }, "callback"},
		{"state", func(u *url.URL) { q := u.Query(); q.Set("state", "wrong"); u.RawQuery = q.Encode() }, "state"},
		{"issuer", func(u *url.URL) { q := u.Query(); q.Set("iss", "https://attacker.test"); u.RawQuery = q.Encode() }, "state"},
		{"duplicate state", func(u *url.URL) { q := u.Query(); q.Add("state", a.state); u.RawQuery = q.Encode() }, "state"},
		{"missing code", func(u *url.URL) { q := u.Query(); q.Del("code"); u.RawQuery = q.Encode() }, "code"},
		{"denied", func(u *url.URL) {
			q := u.Query()
			q.Del("code")
			q.Set("error", "access_denied")
			u.RawQuery = q.Encode()
		}, "denied"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(callback)
			tt.modify(u)
			_, err := c.Exchange(context.Background(), a, u.String())
			requireProblem(t, err, tt.code)
			if posts != 1 {
				t.Fatal("token request issued for invalid callback")
			}
		})
	}
	token, err := c.Exchange(context.Background(), a, callback)
	if err != nil || token != "fixture-token" || posts != 2 {
		t.Fatalf("exchange: %v", err)
	}
	for _, bad := range []string{"https://127.0.0.1:12345/callback", "http://attacker.test:12345/callback", "http://127.0.0.1/callback", "http://user@127.0.0.1:12345/callback"} {
		if _, err := c.BeginOAuth(context.Background(), d, bad); err == nil {
			t.Fatal("accepted unsafe callback")
		}
	}
}
func TestConnectorRPCJSONAndFiniteSSE(t *testing.T) {
	for _, tt := range []struct {
		name, ct, body string
		ok             bool
	}{
		{"JSON", "application/json", `{"jsonrpc":"2.0","id":1,"result":{}}`, true},
		{"SSE", "text/event-stream", "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n", true},
		{"SSE notification", "text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"method\":\"progress\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n", true},
		{"wrong ID", "application/json", `{"jsonrpc":"2.0","id":2,"result":{}}`, false},
		{"ambiguous envelope", "application/json", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1}}`, false},
		{"HTML", "text/html", "secret-marker", false},
		{"SSE wrong ID", "text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := response(200, tt.body)
			r.Header.Set("Content-Type", tt.ct)
			var out rpcResponse
			err := rpcJSON([]byte(tt.body), r, 1, &out)
			if (err == nil) != tt.ok {
				t.Fatalf("parse: %v", err)
			}
		})
	}
}
