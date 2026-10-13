package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net/http"
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
