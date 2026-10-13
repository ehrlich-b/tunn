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
	o := terminal.New(&out, &errout, false)
	o.TTY = true
	session := attachCLI(ctx, s, o)
	s.OnLifecycle(client.LifecycleEvent{State: client.StateReady, PublicURL: "https://app.example"})
	if strings.Contains(out.String(), "[ok]") || !strings.Contains(errout.String(), "Local app unreachable") || !strings.Contains(errout.String(), "curl -I http://127.0.0.1:1") {
		t.Fatal(out.String(), errout.String())
	}
	session.mu.Lock()
	session.probeLocked(ctx)
	session.mu.Unlock()
	if strings.Count(errout.String(), "browser [o]") != 1 {
		t.Fatal("repeated failure route", errout.String())
	}
	s.Inspector.OnEvent(client.InspectionEvent{At: time.Now(), Method: "GET", Path: "/health", Status: 200, TerminalReason: "complete"}, client.InspectionMetrics{})
	if !strings.Contains(out.String(), "[ok] Online") || !strings.Contains(out.String(), "Public · Anyone with the link") {
		t.Fatal(out.String())
	}
	s.OnLifecycle(client.LifecycleEvent{State: client.StateReconnecting, RetryDelay: time.Second})
	s.OnLifecycle(client.LifecycleEvent{State: client.StateReconnecting, RetryDelay: 2 * time.Second})
	if !strings.Contains(out.String(), "Retrying in 2.0 s") {
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
	if strings.Contains(out.String(), "development build") || !strings.Contains(out.String(), "--allow=alex@example.com") || !strings.Contains(out.String(), "tunn login") || strings.Contains(out.String(), "tunn list") {
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

func TestCLIUsesTheRequestedTargetAndPrivateInvitation(t *testing.T) {
	var out, errout bytes.Buffer
	o := terminal.New(&out, &errout, false)
	o.TTY = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &client.ServeClient{TargetURL: "http://localhost:3000", HTTPTransport: cliProbeTransport{}}
	attachCLI(ctx, s, o)
	s.OnLifecycle(client.LifecycleEvent{State: client.StateReady, PublicURL: "https://app.example"})
	for _, text := range []string{"to   localhost:3000", "--allow=alex@example.com"} {
		if !strings.Contains(out.String(), text) {
			t.Fatal(out.String())
		}
	}
	s.Inspector.OnEvent(client.InspectionEvent{At: time.Now(), Method: "GET", Path: "/", Status: 200, TerminalReason: "complete"}, client.InspectionMetrics{})
	if strings.Contains(out.String()+errout.String(), "No requests yet") {
		t.Fatal("persistent empty state")
	}
}

type cliProbeTransport struct{}

func (cliProbeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header), Request: r}, nil
}

func TestCLIInvitationDoesNotEchoLocalCredentials(t *testing.T) {
	for _, target := range []string{"http://guest:local-secret@localhost:3000/private", "https://localhost:8443/private?token=query-secret"} {
		var out, errout bytes.Buffer
		o := terminal.New(&out, &errout, false)
		o.TTY = true
		ctx, cancel := context.WithCancel(context.Background())
		s := &client.ServeClient{TunnelID: "my-app", TargetURL: target, HTTPTransport: cliProbeTransport{}}
		attachCLI(ctx, s, o)
		s.OnLifecycle(client.LifecycleEvent{State: client.StateReady, PublicURL: "https://app.example"})
		cancel()
		text := out.String() + errout.String()
		if strings.Contains(text, "local-secret") || strings.Contains(text, "query-secret") || strings.Contains(text, "guest:") {
			t.Fatal("local credentials printed")
		}
		if !strings.Contains(text, "tunn share my-app alex@example.com") {
			t.Fatal(text)
		}
	}
}
