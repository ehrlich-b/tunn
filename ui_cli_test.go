package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/terminal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCLIFailureCommands(t *testing.T) {
	for _, test := range []struct {
		err            error
		title, command string
	}{
		{status.Error(codes.Unauthenticated, "private token"), "Sign in again", "tunn login"},
		{status.Error(codes.ResourceExhausted, "private quota detail"), "Limit reached", "https://tunn.to/account"},
		{errors.New("private network error"), "Cannot reach tunn", "tunn hosts --json"},
	} {
		var out, errout bytes.Buffer
		o := terminal.New(&out, &errout, false)
		showTunnelError(o, test.err, "tunn.to:443")
		if !strings.Contains(errout.String(), test.title) || !strings.Contains(errout.String(), test.command) || strings.Contains(errout.String(), "private") {
			t.Fatal(errout.String())
		}
		if out.Len() != 0 {
			t.Fatal("diagnostic on stdout")
		}
	}
}
func TestCLIHealthOverridesRelayAndRecovers(t *testing.T) {
	var out, errout bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &client.ServeClient{TargetURL: "http://127.0.0.1:1", Public: true}
	attachCLI(ctx, s, terminal.New(&out, &errout, false))
	s.OnLifecycle(client.LifecycleEvent{State: client.StateReady, PublicURL: "https://app.example"})
	if strings.Contains(out.String(), "[ok]") || !strings.Contains(errout.String(), "Local app unreachable") || !strings.Contains(errout.String(), "curl -I http://127.0.0.1:1") {
		t.Fatal(out.String(), errout.String())
	}
	s.Inspector.OnEvent(client.InspectionEvent{At: time.Now(), Method: "GET", Path: "/health", Status: 200, TerminalReason: "complete"}, client.InspectionMetrics{})
	if !strings.Contains(out.String(), "[ok] Online") || !strings.Contains(out.String(), "Public · Anyone with the link") {
		t.Fatal(out.String())
	}
	s.OnLifecycle(client.LifecycleEvent{State: client.StateReconnecting, RetryDelay: time.Second})
	s.OnLifecycle(client.LifecycleEvent{State: client.StateReconnecting, RetryDelay: 2 * time.Second})
	if !strings.Contains(out.String(), "Retrying in 2s") {
		t.Fatal("stale retry delay", out.String())
	}
}
func TestCLIReadinessUsesHEADAndVerifiedTLS(t *testing.T) {
	var method string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { method = r.Method; w.WriteHeader(200) }))
	defer origin.Close()
	s := &client.ServeClient{TargetURL: origin.URL}
	if err := probeLocalApp(context.Background(), s); err == nil {
		t.Fatal("untrusted local TLS accepted")
	}
	s.SkipLocalTLSVerify = true
	if err := probeLocalApp(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if method != "HEAD" {
		t.Fatal(method)
	}
}
func TestCLIHelpAndFlags(t *testing.T) {
	var out bytes.Buffer
	firstRun(&out)
	if strings.Count(out.String(), "tunn development build") != 1 || !strings.Contains(out.String(), "tunn login") || strings.Contains(out.String(), "tunn list") {
		t.Fatal(out.String())
	}
	opts, err := parseServeFlags([]string{"3000", "--json"})
	if err != nil || !opts.jsonOutput || opts.public {
		t.Fatal(opts, err)
	}
	opts, err = parseServeFlags([]string{"--public", "3000"})
	if err != nil || !opts.public {
		t.Fatal(opts, err)
	}
}

func TestCLIRejectsInvalidPortsBeforeLogin(t *testing.T) {
	for _, input := range []string{"0", "99999", "http://localhost:bad", "http://", "foo"} {
		if _, err := normalizeTargetURL(input); err == nil {
			t.Fatal(input)
		}
	}
	if got, err := normalizeTargetURL("3000"); err != nil || got != "http://localhost:3000" {
		t.Fatal(got, err)
	}
}
