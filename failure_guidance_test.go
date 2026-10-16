package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/terminal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func decodeFailure(t *testing.T, data string) terminal.Event {
	t.Helper()
	var event terminal.Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &event); err != nil {
		t.Fatalf("invalid failure JSON: %v: %s", err, data)
	}
	if event.Cause == "" || event.NextAction == "" || event.NextAction != event.Command {
		t.Fatalf("missing recovery fields: %+v", event)
	}
	if strings.Contains(data, "synthetic-token") || strings.Contains(data, "\x1b") {
		t.Fatalf("unsafe failure: %s", data)
	}
	return event
}

func TestTunnelFailuresNameCauseAndOneAction(t *testing.T) {
	t.Setenv("TUNN_CONFIG_DIR", "")
	for _, tc := range []struct {
		name          string
		err           error
		cause, action string
	}{
		{"expired", status.Error(codes.Unauthenticated, "synthetic-token"), "Login expired or rejected", "tunn login"},
		{"denied", status.Error(codes.PermissionDenied, "synthetic-token"), "Relay denied this account access", "https://relay.example/account"},
		{"tunnels", status.Error(codes.ResourceExhausted, "tunnel limit reached (3/3) synthetic-token"), "3 / 3 tunnels in use. Stop a running tunnel.", "https://relay.example/account"},
		{"usage", status.Error(codes.ResourceExhausted, "quota synthetic-token"), "Relay usage limit reached. Check the reset time.", "https://relay.example/account"},
		{"dns", &net.DNSError{Err: "synthetic-token", Name: "relay.example"}, "Relay DNS lookup failed", "curl --connect-timeout 5 -I https://relay.example"},
		{"refused", fmt.Errorf("synthetic-token: %w", syscall.ECONNREFUSED), "Relay connection refused. Relay is down or the address is wrong", "curl --connect-timeout 5 -I https://relay.example"},
		{"grpc-refused", status.Error(codes.Unavailable, "transport dial: connection refused synthetic-token"), "Relay connection refused. Relay is down or the address is wrong", "curl --connect-timeout 5 -I https://relay.example"},
		{"timeout", context.DeadlineExceeded, "Relay connection timed out", "curl --connect-timeout 5 -I https://relay.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, machine := range []bool{false, true} {
				var out, errout bytes.Buffer
				showTunnelError(terminal.New(&out, &errout, machine), tc.err, "relay.example:443")
				if out.Len() != 0 {
					t.Fatal("failure on stdout")
				}
				if machine {
					e := decodeFailure(t, errout.String())
					if !strings.Contains(e.Cause, tc.cause) || e.NextAction != tc.action {
						t.Fatalf("wrong recovery: %+v", e)
					}
				} else if !strings.Contains(errout.String(), tc.cause) || strings.Count(errout.String(), tc.action) != 1 || strings.Contains(errout.String(), "synthetic-token") {
					t.Fatal(errout.String())
				}
			}
		})
	}
}

func TestLocalFailureAtStartAndDuringRequests(t *testing.T) {
	for _, first := range []bool{true, false} {
		for _, machine := range []bool{true, false} {
			var out, errout bytes.Buffer
			ctx, cancel := context.WithCancel(context.Background())
			s := &client.ServeClient{ServerAddr: "relay.example:443", TargetURL: "http://guest:synthetic-token@localhost:3000/?token=synthetic-token", Public: true, HTTPTransport: guidanceTransport{failed: first}}
			attachCLI(ctx, s, terminal.New(&out, &errout, machine))
			s.OnLifecycle(client.LifecycleEvent{State: client.StateReady, PublicURL: "https://app.example"})
			if !first {
				s.Inspector.OnEvent(client.InspectionEvent{At: time.Now(), Method: "GET", Path: "/", Status: 502, TerminalReason: "target_error"}, client.InspectionMetrics{})
			}
			cancel()
			if machine {
				e := decodeFailure(t, errout.String())
				if e.State != "unreachable" || e.NextAction != "curl -I http://localhost:3000" || !strings.Contains(e.Cause, "start your app here") {
					t.Fatalf("wrong local recovery: %+v", e)
				}
				if !first && !strings.Contains(out.String(), `"status":502`) {
					t.Fatal("request status changed", out.String())
				}
			} else if strings.Count(errout.String(), "curl -I http://localhost:3000") != 1 || !strings.Contains(errout.String(), "start your app here") {
				t.Fatal(errout.String())
			}
			if strings.Contains(out.String()+errout.String(), "synthetic-token") {
				t.Fatal("target credential leaked")
			}
		}
	}
}

type guidanceTransport struct{ failed bool }

func (g guidanceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if g.failed {
		return nil, fmt.Errorf("synthetic-token: %w", syscall.ECONNREFUSED)
	}
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header), Request: r}, nil
}

func TestRunningOfflineNamesRelayAndKeepsRetryDelay(t *testing.T) {
	var out, errout bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &client.ServeClient{ServerAddr: "relay.example:443", TargetURL: "http://localhost:3000", HTTPTransport: guidanceTransport{}}
	attachCLI(ctx, s, terminal.New(&out, &errout, true))
	s.OnLifecycle(client.LifecycleEvent{State: client.StateReady, PublicURL: "https://app.example"})
	s.OnLifecycle(client.LifecycleEvent{State: client.StateReconnecting, Err: fmt.Errorf("synthetic-token: %w", syscall.ECONNREFUSED), RetryDelay: 2 * time.Second})
	s.OnLifecycle(client.LifecycleEvent{State: client.StateReconnecting, RetryDelay: 3 * time.Second})
	e := decodeFailure(t, errout.String())
	if !strings.Contains(e.Cause, "Relay is down or the address is wrong") || strings.Contains(e.Cause, "Restore your connection") || e.NextAction != "curl --connect-timeout 5 -I https://relay.example" {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), `"retry_delay_ms":3000`) {
		t.Fatal("backoff lost", out.String())
	}
}

func TestRefusedGRPCRelayNamesRelayOrAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := &client.ServeClient{ServerAddr: address, TargetURL: "http://localhost:3000", AuthToken: "synthetic-token", Insecure: true}
	attachCLI(ctx, s, terminal.New(&out, &errout, true))
	lifecycle := s.OnLifecycle
	s.OnLifecycle = func(e client.LifecycleEvent) {
		lifecycle(e)
		if e.State == client.StateReconnecting {
			cancel()
		}
	}
	_ = s.Run(ctx)
	e := decodeFailure(t, errout.String())
	if e.State != "offline" || !strings.Contains(e.Cause, "Relay is down or the address is wrong") || strings.Contains(e.Cause, "Restore your connection") || e.NextAction != relayCheck(address) {
		t.Fatal(e)
	}
}

func TestInventoryFailureThroughTLSForStatusAndList(t *testing.T) {
	t.Setenv("TUNN_ENV", "dev")
	t.Setenv("TUNN_CONFIG_DIR", "")
	t.Setenv("HOME", t.TempDir())
	for _, command := range []string{"status", "list", "hosts"} {
		for _, code := range []int{401, 403, 404, 429, 501, 503} {
			t.Run(fmt.Sprintf("%s/%d", command, code), func(t *testing.T) {
				relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/api/hosts" || r.Header.Get("Authorization") != "Bearer synthetic-token" {
						t.Error("wrong inventory request")
					}
					w.WriteHeader(code)
					fmt.Fprint(w, "synthetic-token")
				}))
				defer relay.Close()
				manifest := guidanceManifest(t, strings.TrimPrefix(relay.URL, "https://"))
				var out, errout bytes.Buffer
				args := []string{"--config", manifest, "--json"}
				var err error
				if command == "status" {
					err = executeStatus(context.Background(), args, &out, &errout)
				} else {
					err = hostCommand(context.Background(), command, args, &out, &errout)
				}
				if err == nil {
					t.Fatal("denial accepted")
				}
				writeHostError(&out, &errout, err, args)
				e := decodeFailure(t, errout.String())
				if e.HTTPStatus != code || !strings.Contains(e.Cause, fmt.Sprintf("HTTP %d", code)) {
					t.Fatalf("status changed: %+v", e)
				}
				want := "tunn " + command + " --config " + shellURL(manifest) + " --json"
				switch code {
				case 401:
					want = "tunn login"
				case 403, 429:
					want = relay.URL + "/account"
				case 404, 501:
					want = "tunn service --help"
				}
				if (code == 401 || code == 403) && e.State != "auth_expired" {
					t.Fatalf("auth state changed: %+v", e)
				}
				if e.NextAction != want || out.Len() != 0 {
					t.Fatalf("wrong action: %+v stdout=%s", e, out.String())
				}
				errout.Reset()
				writeHostError(&out, &errout, err, nil)
				if strings.Count(errout.String(), want) != 1 || !strings.Contains(errout.String(), fmt.Sprintf("HTTP %d", code)) || strings.Contains(errout.String(), "synthetic-token") {
					t.Fatal(errout.String())
				}
			})
		}
	}
}
func guidanceManifest(t *testing.T, server string) string {
	t.Helper()
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	manifest := filepath.Join(dir, "host.yaml")
	if err := os.WriteFile(token, []byte("synthetic-token"), 0600); err != nil {
		t.Fatal(err)
	}
	data := fmt.Sprintf("version: 1\nmachine: laptop\nserver: %s\ninsecure: true\ntoken_file: %s\ntunnels:\n  - name: app\n    kind: http\n    target: http://localhost:3000\n    allow: [alex@example.com]\n", server, token)
	if err := os.WriteFile(manifest, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestOfflineInventoryPreservesArrayAndUnknownAppHealth(t *testing.T) {
	machines := []common.Machine{{Name: "laptop", Tunnels: []common.HostEndpoint{
		{Name: "app", Kind: "http", Online: false, LastSeen: time.Now(), Access: "private", EndpointToken: true},
		{Name: "unknown", Kind: "http"},
		{Name: "connected", Kind: "http", Online: true},
	}}}
	data, err := json.Marshal(inventoryReadings(machines))
	if err != nil {
		t.Fatal(err)
	}
	var got []struct {
		Tunnels []map[string]any `json:"tunnels"`
	}
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	e := got[0].Tunnels[0]
	if e["cause"] != "No relay heartbeat from laptop. Run on that machine." || e["next_action"] != "tunn service restart" || e["endpoint_token"] != true || e["access"] != "private" {
		t.Fatal(string(data))
	}
	for _, e := range got[0].Tunnels[1:] {
		if _, exists := e["cause"]; exists {
			t.Fatal("invented failure", e)
		}
	}
	var out, errout bytes.Buffer
	if err = printHosts(&out, &errout, machines); err != nil {
		t.Fatal(err)
	}
	if strings.Count(errout.String(), "tunn service restart") != 1 || !strings.Contains(out.String(), "App not checked") {
		t.Fatal(out.String(), errout.String())
	}
}

func TestHTTPMissingLoginJSONKeepsServiceExit(t *testing.T) {
	if os.Getenv("TUNN_GUIDANCE_LOGIN_CHILD") == "1" {
		runServe([]string{"3000", "--json"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHTTPMissingLoginJSONKeepsServiceExit$")
	dir := t.TempDir()
	cmd.Env = append(os.Environ(), "TUNN_GUIDANCE_LOGIN_CHILD=1", "TUNN_ENV=dev", "TUNN_PUBLIC_MODE=false", "TUNN_CONFIG_DIR="+dir, "HOME="+t.TempDir(), "TUNN_SERVER_ADDR=127.0.0.1:1")
	var out, errout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errout
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != client.ExitLoginRequired {
		t.Fatalf("wrong service exit: %v %s", err, errout.String())
	}
	e := decodeFailure(t, errout.String())
	if e.State != "auth_missing" || e.Cause != "No saved login on this machine" || e.NextAction != "TUNN_CONFIG_DIR="+dir+" tunn login" || out.Len() != 0 {
		t.Fatalf("wrong login recovery: %+v", e)
	}
}

func TestHTTPLoginRequiredHumanAndJSON(t *testing.T) {
	t.Setenv("TUNN_CONFIG_DIR", "/tmp/synthetic login")
	for _, machine := range []bool{true, false} {
		var out, errout bytes.Buffer
		if !showHTTPLoginRequired(terminal.New(&out, &errout, machine), client.ErrNotLoggedIn) {
			t.Fatal("login ignored")
		}
		want := "TUNN_CONFIG_DIR='/tmp/synthetic login' tunn login"
		if machine {
			e := decodeFailure(t, errout.String())
			if e.NextAction != want {
				t.Fatal(e)
			}
		} else if errout.String() != client.LoginRequiredMessage()+"\n" || !strings.Contains(errout.String(), "then restart this service") {
			t.Fatal(errout.String())
		}
	}
}

func TestFailureHelpTargetsExplainRecovery(t *testing.T) {
	var out, errout bytes.Buffer
	if err := hostCommand(context.Background(), "list", []string{"--help"}, &out, &errout); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"tunn list [--json]", "Local app health is not checked", "Run its command there"} {
		if !strings.Contains(out.String(), text) {
			t.Fatal(out.String())
		}
	}
	out.Reset()
	if err := executeStatus(context.Background(), []string{"--help"}, &out, &errout); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"tunn status [--json]", "tunn status serve", "tunn status incident", "tunn status resolve"} {
		if !strings.Contains(out.String(), text) {
			t.Fatal(out.String())
		}
	}
}

func TestRelayActionsStripCredentials(t *testing.T) {
	for _, server := range []string{"https://user:synthetic-token@relay.example:443/path?token=synthetic-token", "relay.example:443"} {
		if got := relayCheck(server); got != "curl --connect-timeout 5 -I https://relay.example" {
			t.Fatal(got)
		}
		if got := accountURL(server); got != "https://relay.example/account" {
			t.Fatal(got)
		}
	}
}

func TestMissingInventoryLoginNamesCause(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TUNN_CONFIG_DIR", t.TempDir())
	t.Setenv("TUNN_ENV", "dev")
	for _, command := range []string{"status", "list"} {
		var out, errout bytes.Buffer
		args := []string{"--json"}
		var err error
		if command == "status" {
			err = executeStatus(context.Background(), args, &out, &errout)
		} else {
			err = hostCommand(context.Background(), command, args, &out, &errout)
		}
		if err == nil {
			t.Fatal("missing login accepted")
		}
		writeHostError(&out, &errout, err, args)
		e := decodeFailure(t, errout.String())
		if e.State != "auth_expired" || e.Cause != "No saved login on this machine" || !strings.HasSuffix(e.NextAction, " tunn login") {
			t.Fatalf("wrong missing-login cause: %+v", e)
		}
	}
}

func TestStartupRenewalOfflineStaysJSON(t *testing.T) {
	var calls atomic.Int64
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			fmt.Fprint(w, "synthetic-token")
			return
		}
		fmt.Fprint(w, `{"access_token":"renewed","refresh_token":"tunn_rt_next","device_id":"dev_test","expires_in":300}`)
	}))
	defer relay.Close()
	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	data, _ := json.Marshal(map[string]any{"server": relay.URL, "access_token": "expired", "refresh_token": "tunn_rt_synthetic-token", "device_id": "dev_test", "expires_at": time.Now().Add(-time.Hour)})
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	o := terminal.New(&out, &errout, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	token, _, err := loadPublisherTokenWithRetry(ctx, strings.TrimPrefix(relay.URL, "https://"), true, func(err error, delay time.Duration) {
		o.State("offline", "Cannot renew login", relayCause(err), relayCheck(strings.TrimPrefix(relay.URL, "https://")), delay)
	})
	if err != nil || token != "renewed" || calls.Load() != 2 {
		t.Fatal("renewal did not recover", err, calls.Load())
	}
	e := decodeFailure(t, errout.String())
	if e.Cause != "Login server unavailable" || e.NextAction != "curl --connect-timeout 5 -I "+relay.URL || e.RetryDelayMS == 0 || out.Len() != 0 {
		t.Fatal(e, out.String())
	}
}

func TestInventoryInvalidFlagsStayJSONAndDoNotEchoValues(t *testing.T) {
	for _, command := range []string{"list", "hosts", "status"} {
		for _, tc := range []struct {
			args  []string
			cause string
		}{
			{[]string{"--json", "--bogus"}, "Invalid option -bogus"},
			{[]string{"--json", "--unknown=synthetic-token"}, "Invalid option -unknown"},
			{[]string{"--json", "--unknown", "synthetic-token"}, "Invalid option -unknown"},
			{[]string{"--json=synthetic-token", "--json"}, "Invalid option -json"},
			{[]string{"--json=value for -synthetic-token: parse error", "--json"}, "Invalid option -json"},
			{[]string{"--json", "--config"}, "Invalid option -config"},
			{[]string{"--json", "synthetic-token"}, "Unexpected argument"},
		} {
			var out, errout bytes.Buffer
			var err error
			if command == "status" {
				err = executeStatus(context.Background(), tc.args, &out, &errout)
			} else {
				err = hostCommand(context.Background(), command, tc.args, &out, &errout)
			}
			if err == nil {
				t.Fatal("bad arguments accepted")
			}
			writeHostError(&out, &errout, err, tc.args)
			e := decodeFailure(t, errout.String())
			if e.NextAction != "tunn "+command+" --help" || e.Cause != tc.cause || out.Len() != 0 {
				t.Fatal(e, out.String())
			}
			errout.Reset()
			writeHostError(&out, &errout, err, nil)
			if !strings.Contains(errout.String(), tc.cause) || !strings.Contains(errout.String(), e.NextAction) || strings.Contains(errout.String(), "synthetic-token") {
				t.Fatal(errout.String())
			}
		}
	}
}

func TestServicePublishersWithoutConfigEnvUseResolvedLoginDirectory(t *testing.T) {
	if command := os.Getenv("TUNN_GUIDANCE_PUBLISHER_CHILD"); command != "" {
		switch command {
		case "http":
			runServe([]string{"3000"})
		case "ssh":
			runTCP([]string{"--account-only", "127.0.0.1:22"})
		case "tcp":
			runTCP([]string{"127.0.0.1:5432"})
		case "unix":
			runUnix([]string{filepath.Join(os.Getenv("HOME"), "app.sock")})
		}
		return
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TUNN_CONFIG_DIR", "")
	if err := os.Unsetenv("TUNN_CONFIG_DIR"); err != nil {
		t.Fatal(err)
	}
	want := client.LoginRequiredMessage() + "\n"
	if !strings.Contains(want, "TUNN_CONFIG_DIR="+filepath.Join(home, ".tunn")+" tunn login") || !strings.Contains(want, "then restart this service") {
		t.Fatal(want)
	}
	for _, command := range []string{"http", "ssh", "tcp", "unix"} {
		t.Run(command, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServicePublishersWithoutConfigEnvUseResolvedLoginDirectory$")
			cmd.Env = append(os.Environ(), "TUNN_GUIDANCE_PUBLISHER_CHILD="+command, "TUNN_ENV=dev", "TUNN_PUBLIC_MODE=false", "TUNN_SECRET=", "TUNN_SERVER_ADDR=127.0.0.1:1")
			var out, errout bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errout
			err := cmd.Run() // A nil Stdin supplies /dev/null, as a service does.
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != client.ExitLoginRequired || out.Len() != 0 || errout.String() != want {
				t.Fatalf("exit %v, stdout %q, stderr %q; want exit 78 and %q", err, out.String(), errout.String(), want)
			}
		})
	}
}

func TestRefusedInventoryKeepsInvocationAndConfig(t *testing.T) {
	t.Setenv("TUNN_ENV", "dev")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	manifest := guidanceManifest(t, address)
	// A space in the path must remain one shell argument in the retry command.
	spaced := filepath.Join(filepath.Dir(manifest), "host config.yaml")
	if err := os.Rename(manifest, spaced); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"hosts", "list", "status"} {
		for _, configArgs := range [][]string{{"--config", spaced}, {"--config=" + spaced}} {
			for _, machine := range []bool{false, true} {
				args := append([]string{}, configArgs...)
				want := "tunn " + command + " --config " + shellURL(spaced)
				if machine {
					args = append(args, "--json")
					want += " --json"
				}
				var out, errout bytes.Buffer
				var err error
				if command == "status" {
					err = executeStatus(context.Background(), args, &out, &errout)
				} else {
					err = hostCommand(context.Background(), command, args, &out, &errout)
				}
				writeHostError(&out, &errout, err, args)
				if machine {
					e := decodeFailure(t, errout.String())
					if e.State != "offline" || e.NextAction != want {
						t.Fatal(e)
					}
				}
				if !strings.Contains(errout.String(), "Relay is down or the address is wrong") || strings.Contains(errout.String(), "Restore your connection") || !strings.Contains(errout.String(), want) || out.Len() != 0 {
					t.Fatal(errout.String(), out.String())
				}
			}
		}
	}
}

func TestHTTPFirstRunLoginFailures(t *testing.T) {
	if os.Getenv("TUNN_GUIDANCE_ENROLL_CHILD") == "1" {
		if !stdinIsTerminal() {
			t.Fatal("first-run enrollment needs terminal stdin")
		}
		os.Args = []string{"tunn", "--verbosity", "none", "--insecure", "http", "3000"}
		main()
		return
	}
	script, err := exec.LookPath("script")
	if err != nil {
		t.Skip("script is required for terminal stdin")
	}
	for _, code := range []int{0, 500, 502, 503, 504, 400, 401} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/device/code" {
					t.Error("wrong enrollment request", r.Method, r.URL.Path)
				}
				w.WriteHeader(code)
				fmt.Fprint(w, "synthetic-token")
			}))
			defer relay.Close()
			address := strings.TrimPrefix(relay.URL, "https://")
			if code == 0 {
				relay.Close() // No saved login, and a real refused loopback connection.
			}
			home := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, script, "-qefc", shellURL(os.Args[0])+" -test.run=^TestHTTPFirstRunLoginFailures$", "/dev/null")
			cmd.Env = append(os.Environ(), "HOME="+home, "TUNN_CONFIG_DIR="+filepath.Join(home, ".tunn"), "TUNN_GUIDANCE_ENROLL_CHILD=1", "TUNN_ENV=dev", "TUNN_PUBLIC_MODE=false", "TUNN_SECRET=", "TUNN_SERVER_ADDR="+address, "NO_COLOR=1")
			data, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("exit %v, output %s", err, data)
			}
			text := string(data)
			want := "curl --connect-timeout 5 -I https://" + address
			cause := "Relay connection failed. Restore your connection."
			if code == 0 {
				cause = "Relay connection refused. Relay is down or the address is wrong."
			} else if code < 500 {
				cause = "Sign-in failed"
				want = "TUNN_CONFIG_DIR=" + filepath.Join(home, ".tunn") + " tunn login"
			}
			if !strings.Contains(text, cause) || strings.Count(text, want) != 1 || strings.Contains(text, "expired or revoked") || strings.Contains(text, "synthetic-token") {
				t.Fatalf("wrong first-run recovery: %s", text)
			}
		})
	}
}

func TestEnrollmentNetworkClassification(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("device code: %w", &net.DNSError{Err: "synthetic-token", Name: "relay.example"}),
		fmt.Errorf("device code: %w", context.DeadlineExceeded),
		fmt.Errorf("device code: %w", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}),
	} {
		if !loginRelayFailure(err) || loginCause(err) != "Sign-in failed" {
			t.Fatalf("network enrollment error treated as rejected login: %v", err)
		}
	}
	if loginRelayFailure(errors.New("invalid device code response")) || loginCause(client.ErrNotLoggedIn) != "No saved login on this machine" || loginCause(status.Error(codes.Unauthenticated, "synthetic-token")) != "Login expired or revoked" {
		t.Fatal("login failure causes changed")
	}
}

func TestInventoryRetryQuotesShellCharactersAndKeepsInsecure(t *testing.T) {
	t.Setenv("TUNN_ENV", "dev")
	previous := *insecure
	t.Cleanup(func() { *insecure = previous })
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer relay.Close()
	manifest := guidanceManifest(t, strings.TrimPrefix(relay.URL, "https://"))
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	// Only the global flag permits TLS to this synthetic relay.
	data = bytes.ReplaceAll(data, []byte("insecure: true"), []byte("insecure: false"))
	for _, name := range []string{"host[1].yaml", "host].yaml", "host*.yaml", "host?.yaml", "host{a,b}.yaml", "~host.yaml", "#host.yaml", "host's.yaml"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(filepath.Dir(manifest), name)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, command := range []string{"hosts", "list", "status"} {
				for _, machine := range []bool{false, true} {
					*insecure = true
					args := []string{"--config", path}
					want := "tunn --insecure " + command + " --config '" + strings.ReplaceAll(path, "'", "'\\''") + "'"
					if machine {
						args = append(args, "--json")
						want += " --json"
					}
					var out, errout bytes.Buffer
					err := hostCommand(context.Background(), command, args, &out, &errout)
					writeHostError(&out, &errout, err, args)
					if machine {
						e := decodeFailure(t, errout.String())
						if e.NextAction != want || e.HTTPStatus != 503 {
							t.Fatal(e)
						}
					} else if strings.Count(errout.String(), want) != 1 {
						t.Fatal(errout.String())
					}
				}
			}
		})
	}
}
