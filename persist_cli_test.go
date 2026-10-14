package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
)

func TestPublisherLoginRequiredExitHelper(t *testing.T) {
	if os.Getenv("TUNN_LOGIN_REQUIRED_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	exitIfLoginRequired(fmt.Errorf("publisher authentication renewal: %w", client.ErrNotLoggedIn))
	os.Exit(0)
}

// A rejected login stops the service once with a status its unit does not
// restart and a single line that names the command to run.
func TestPublisherLoginRequiredExitsWithoutRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "forge-ssh")
	cmd := exec.Command(os.Args[0], "-test.run=^TestPublisherLoginRequiredExitHelper$")
	cmd.Env = append(os.Environ(), "TUNN_LOGIN_REQUIRED_CHILD=1", "TUNN_CONFIG_DIR="+dir)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != client.ExitLoginRequired {
		t.Fatalf("exit = %v, want status %d", err, client.ExitLoginRequired)
	}
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "TUNN_CONFIG_DIR="+dir+" tunn login") {
		t.Fatalf("stderr = %q, want one line naming the fix", stderr.String())
	}
	exitIfLoginRequired(errors.New("relay unreachable")) // returns: not a login problem
}

func TestWebPublisherServiceDoesNotWaitForBrowserLogin(t *testing.T) {
	enrolled := false
	load := func(context.Context, string, bool) (string, *client.CredentialManager, error) {
		return "", nil, client.ErrNotLoggedIn
	}
	_, _, err := loadOrEnrollWebPublisher(context.Background(), "relay.example:443", false, false, load, func(context.Context) error { enrolled = true; return nil })
	if enrolled || !client.LoginRequired(err) {
		t.Fatal("service without a terminal started a device login", enrolled, err)
	}
}

// A service that starts before its network keeps waiting for the login
// server instead of exiting.
func TestPublisherStartupWaitsForLoginServer(t *testing.T) {
	var calls atomic.Int64
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/device/refresh" {
			http.NotFound(w, r)
			return
		}
		if calls.Add(1) == 1 {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"renewed","refresh_token":"tunn_rt_next","device_id":"dev_boot","expires_in":300}`)
	}))
	defer relay.Close()
	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	data, _ := json.Marshal(map[string]any{"server": relay.URL, "access_token": "expired", "refresh_token": "tunn_rt_boot", "device_id": "dev_boot", "expires_at": time.Now().Add(-time.Hour)})
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	token, manager, err := loadPublisherToken(ctx, strings.TrimPrefix(relay.URL, "https://"), true)
	if err != nil || token != "renewed" || manager == nil || calls.Load() != 2 {
		t.Fatal("startup did not retry the login server", token, err, calls.Load())
	}
}

func TestServeServiceStdinHelper(t *testing.T) {
	if os.Getenv("TUNN_SERVE_SERVICE_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	runServe([]string{"8080"})
	os.Exit(0)
}

// A service unit gives tunn /dev/null as stdin. A missing or rejected login
// must exit once with the single line, never start a browser login.
func TestServeServiceWithoutTerminalExitsForLogin(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	for _, tc := range []struct {
		name        string
		credentials bool
	}{{"missing", false}, {"rejected", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var other atomic.Int64
			relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/device/refresh" {
					http.Error(w, `{"error":"invalid_grant"}`, http.StatusUnauthorized)
					return
				}
				other.Add(1)
				http.NotFound(w, r)
			}))
			defer relay.Close()
			dir := t.TempDir()
			if tc.credentials {
				data, _ := json.Marshal(map[string]any{"server": relay.URL, "access_token": "expired", "refresh_token": "tunn_rt_revoked", "device_id": "dev_svc", "expires_at": time.Now().Add(-time.Hour)})
				if err := os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServeServiceStdinHelper$")
			cmd.Env = append(os.Environ(), "TUNN_SERVE_SERVICE_CHILD=1", "TUNN_ENV=dev", "TUNN_PUBLIC_MODE=false",
				"TUNN_SERVER_ADDR="+strings.TrimPrefix(relay.URL, "https://"), "TUNN_CONFIG_DIR="+dir, "HOME="+t.TempDir())
			cmd.Stdin = devNull
			var stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stderr, &stderr
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != client.ExitLoginRequired {
				t.Fatalf("exit = %v, want status %d; output %q", err, client.ExitLoginRequired, stderr.String())
			}
			lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
			if len(lines) != 1 || !strings.Contains(lines[0], "TUNN_CONFIG_DIR="+dir+" tunn login") || other.Load() != 0 {
				t.Fatalf("output %q, other relay requests %d; want one line naming the fix and no device login", stderr.String(), other.Load())
			}
		})
	}
}
