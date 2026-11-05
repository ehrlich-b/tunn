package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/mcpcheck"
)

func TestConnectorFlags(t *testing.T) {
	for _, args := range [][]string{{}, {"--oauth"}, {"--expect-tools", "echo", "https://tools.test/mcp"}, {"--call-tool", "echo", "https://tools.test/mcp"}, {"--oauth", "--arguments", "{}", "https://tools.test/mcp"}, {"--oauth", "--expect-tools", "echo,echo", "https://tools.test/mcp"}, {"--oauth", "--arguments", "[]", "--call-tool", "echo", "https://tools.test/mcp"}, {"--timeout", "0s", "https://tools.test/mcp"}, {"--timeout", "11m", "https://tools.test/mcp"}, {"--oauth", "--call-tool", "echo", "--deny-tool", "echo", "https://tools.test/mcp"}, {"--unknown", "https://tools.test/mcp"}} {
		if _, err := parseConnectorCheckFlags(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, args := range [][]string{{"https://tools.test/mcp"}, {"--oauth", "--expect-tools", "echo", "https://tools.test/mcp"}, {"--oauth", "--expect-tools=", "https://tools.test/mcp"}, {"--oauth", "--call-tool", "echo", "--arguments", `{"message":"hello"}`, "--json", "https://tools.test/mcp"}} {
		if _, err := parseConnectorCheckFlags(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if _, err := parseConnectorCheckFlags([]string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal("help must succeed")
	}
}

type connectorTransport func(*http.Request) (*http.Response, error)

func (f connectorTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestConnectorFailureReports(t *testing.T) {
	c := mcpcheck.New(connectorTransport(func(*http.Request) (*http.Response, error) { t.Fatal("invalid URL reached transport"); return nil, nil }))
	for _, structured := range []bool{false, true} {
		opts := &connectorCheckOptions{url: "http://localhost/mcp", json: structured}
		var out, diagnostic bytes.Buffer
		if executeConnectorCheck(context.Background(), c, opts, &out, &diagnostic) == nil {
			t.Fatal("failure exited successfully")
		}
		if !strings.Contains(out.String(), "REQUIRED-UNRUN") || !strings.Contains(out.String(), "url") || diagnostic.Len() != 0 {
			t.Fatalf("incomplete failure report: %s", out.String())
		}
	}
}

func TestConnectorInvalidFlagsHelper(t *testing.T) {
	if os.Getenv("TUNN_CHECK_FLAGS_HELPER") != "1" {
		return
	}
	runConnectorCheck([]string{os.Getenv("TUNN_CHECK_BAD_FLAG"), "https://tools.test/mcp"})
	os.Exit(0)
}
func TestConnectorInvalidFlagsDoNotLeak(t *testing.T) {
	for _, arg := range []string{"--timeout=secret-marker", "--json=secret-marker", "--secret-marker=value"} {
		_, err := parseConnectorCheckFlags([]string{arg, "https://tools.test/mcp"})
		if err == nil || strings.Contains(err.Error(), "secret-marker") {
			t.Fatalf("parser echoed supplied value: %v", err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestConnectorInvalidFlagsHelper$")
		cmd.Env = append(os.Environ(), "TUNN_CHECK_FLAGS_HELPER=1", "TUNN_CHECK_BAD_FLAG="+arg)
		output, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Fatal("invalid flags did not exit 1")
		}
		if strings.Contains(string(output), "secret-marker") || !strings.Contains(string(output), "invalid connector-check options") {
			t.Fatal("CLI parser output leaked input or omitted action")
		}
	}
}

// TestConnectorCheckFailureContract runs the reporting path in a subprocess so
// its exit status and both output streams are checked as an automation client sees them.
func TestConnectorCheckFailureContract(t *testing.T) {
	if scenario := os.Getenv("TUNN_CONNECTOR_SCENARIO"); scenario != "" {
		fixtureConnectorFailure(scenario)
		return
	}
	for _, scenario := range []string{"discovery_404", "malformed_discovery", "missing_tool", "consent_refusal", "request_cancellation"} {
		t.Run(scenario, func(t *testing.T) {
			if scenario == "request_cancellation" && !connectorInterruptSupported {
				t.Skip("process interrupt unavailable")
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestConnectorCheckFailureContract$")
			cmd.Env = append(os.Environ(), "TUNN_CONNECTOR_SCENARIO="+scenario)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = io.MultiWriter(&stderr, &connectorCallbackWriter{scenario: scenario})
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() == 0 {
				t.Fatalf("expected nonzero exit, got %v", err)
			}
			var report connectorCheckReport
			raw := stdout.String()
			dec := json.NewDecoder(strings.NewReader(raw))
			if err := dec.Decode(&report); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			var extra any
			if err := dec.Decode(&extra); err != io.EOF {
				t.Fatalf("extra stdout: %v", err)
			}
			if report.Status != "FAIL" || report.Error == "" {
				t.Fatalf("unexpected report: %+v", report)
			}
			for _, stream := range []string{raw, stderr.String()} {
				if connectorUnsafeOutput(stream) {
					t.Fatalf("unsafe output: %q", stream)
				}
			}
			// OAuth needs a browser instruction; no other diagnostic or progress output is allowed.
			lines := strings.Split(strings.TrimSuffix(stderr.String(), "\n"), "\n")
			if scenario == "missing_tool" || scenario == "consent_refusal" {
				if len(lines) != 2 || lines[0] != "Open this URL in your browser and approve this tunnel:" || !strings.HasPrefix(lines[1], "https://tunn.test/oauth/authorize?") {
					t.Fatalf("unexpected stderr: %q", stderr.String())
				}
			} else if stderr.Len() != 0 {
				t.Fatalf("unexpected stderr: %q", stderr.String())
			}
			expected := map[string]string{"discovery_404": "challenge [not_found]", "malformed_discovery": "resource_metadata [json]", "missing_tool": "allow_list [tools_mismatch]", "consent_refusal": "consent [denied]", "request_cancellation": "challenge [cancelled]"}[scenario]
			if !strings.HasPrefix(report.Error, expected) {
				t.Fatalf("expected error stage %s, got %s", expected, report.Error)
			}
			wantDiscovery := scenario == "missing_tool" || scenario == "consent_refusal"
			if report.Discovery != wantDiscovery {
				t.Fatalf("discovery = %v, want %v", report.Discovery, wantDiscovery)
			}
			t.Logf("exit=%d stdout=%q stderr=%q", exit.ExitCode(), raw, stderr.String())
		})
	}
}

// connectorUnsafeOutput examines the raw stream, including a final partial line.
func connectorUnsafeOutput(s string) bool {
	return strings.ContainsAny(s, "\x1b\r") || strings.Contains(s, "token-sentinel") || strings.Contains(s, "code-sentinel")
}

func TestConnectorCheckRawStderrSentinels(t *testing.T) {
	for _, s := range []string{"token-sentinel", "token-sentinel\n", "code-sentinel", "code-sentinel\n"} {
		if !connectorUnsafeOutput(s) {
			t.Errorf("missed stderr leak %q", s)
		}
	}
}

type connectorCallbackWriter struct {
	scenario string
	pending  string
}

func (w *connectorCallbackWriter) Write(p []byte) (int, error) {
	w.pending += string(p)
	for {
		i := strings.IndexByte(w.pending, '\n')
		if i < 0 {
			break
		}
		s := strings.TrimSpace(w.pending[:i])
		w.pending = w.pending[i+1:]
		if !strings.HasPrefix(s, "https://tunn.test/oauth/authorize?") {
			continue
		}
		u, _ := url.Parse(s)
		q := u.Query()
		callback, _ := url.Parse(q.Get("redirect_uri"))
		values := callback.Query()
		values.Set("state", q.Get("state"))
		values.Set("iss", "https://tunn.test")
		if w.scenario == "consent_refusal" {
			values.Set("error", "access_denied")
		} else {
			values.Set("code", "code-sentinel")
		}
		callback.RawQuery = values.Encode()
		go func() {
			resp, err := (&http.Client{Transport: &http.Transport{}}).Get(callback.String())
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	return len(p), nil
}

func fixtureConnectorFailure(scenario string) {
	response := func(status int, body string) *http.Response {
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
	}
	transport := connectorTransport(func(r *http.Request) (*http.Response, error) {
		if scenario == "request_cancellation" {
			// Interrupt only after the request is in flight, then observe its context.
			if err := interruptConnectorFixture(); err != nil {
				return nil, err
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		switch r.URL.String() {
		case "https://tools.tunn.test/mcp":
			if r.Header.Get("Authorization") == "" {
				if scenario == "discovery_404" {
					return response(404, "token-sentinel code-sentinel"), nil
				}
				x := response(401, "")
				x.Header.Set("WWW-Authenticate", `Bearer realm="tunn", resource_metadata="https://tools.tunn.test/.well-known/oauth-protected-resource/mcp", scope="mcp"`)
				return x, nil
			}
			body, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(string(body), `"initialize"`):
				return response(200, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`), nil
			case strings.Contains(string(body), `"notifications/initialized"`):
				return response(202, ""), nil
			default:
				return response(200, `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`), nil
			}
		case "https://tools.tunn.test/.well-known/oauth-protected-resource/mcp":
			if scenario == "malformed_discovery" {
				return response(200, `{"token-sentinel":`), nil
			}
			return response(200, `{"resource":"https://tools.tunn.test/mcp","authorization_servers":["https://tunn.test"],"scopes_supported":["mcp"],"bearer_methods_supported":["header"]}`), nil
		case "https://tunn.test/.well-known/oauth-authorization-server":
			return response(200, `{"issuer":"https://tunn.test","authorization_endpoint":"https://tunn.test/oauth/authorize","token_endpoint":"https://tunn.test/oauth/token","registration_endpoint":"https://tunn.test/oauth/register","response_types_supported":["code"],"grant_types_supported":["authorization_code"],"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],"scopes_supported":["mcp"]}`), nil
		case "https://tunn.test/oauth/register":
			var body struct {
				RedirectURIs []string `json:"redirect_uris"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			b, _ := json.Marshal(map[string]any{"client_id": "fixture-id", "token_endpoint_auth_method": "none", "redirect_uris": body.RedirectURIs})
			return response(201, string(b)), nil
		case "https://tunn.test/oauth/token":
			return response(200, `{"access_token":"token-sentinel","token_type":"Bearer","scope":"mcp","expires_in":3600}`), nil
		}
		return nil, errors.New("unexpected fixture request")
	})
	http.DefaultTransport = transport
	args := []string{"tunn", "connector-check", "--json", "--timeout", "5s"}
	if scenario == "missing_tool" || scenario == "consent_refusal" {
		args = append(args, "--oauth", "--expect-tools", "echo")
	}
	os.Args = append(args, "https://tools.tunn.test/mcp")
	main()
}
