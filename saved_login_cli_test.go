package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSavedLoginFailuresMatchBaseState(t *testing.T) {
	if os.Getenv("TUNN_SAVED_LOGIN_CHILD") == "1" {
		os.Args = []string{"tunn", "--verbosity", "none", "http", "3000"}
		if os.Getenv("TUNN_SAVED_LOGIN_JSON") == "1" {
			os.Args = append(os.Args, "--json")
		}
		main()
		return
	}
	var requests atomic.Int64
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer relay.Close()
	address := strings.TrimPrefix(relay.URL, "https://")
	for _, fixture := range []struct{ name, data, cause string }{
		{"corrupt", "{synthetic-token", "Saved login file is unreadable"},
		{"incomplete", `{"server":"https://other.invalid","access_token":"synthetic-token"}`, "Saved login file is unreadable"},
		{"unreadable", "", "Saved login file is unreadable"},
		{"different-server", `{"server":"https://other.invalid","access_token":"synthetic-token","refresh_token":"synthetic-token","device_id":"fixture","expires_at":"2099-01-01T00:00:00Z"}`, "Saved login is for a different server"},
	} {
		for _, mode := range []string{"json", "json-terminal", "human"} {
			t.Run(fixture.name+"/"+mode, func(t *testing.T) {
				home := t.TempDir()
				dir := filepath.Join(home, "login with spaces")
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "credentials.json")
				if fixture.name == "unreadable" {
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, []byte(fixture.data), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHTTPSavedLoginFailuresMatchBaseState$")
				if mode == "json-terminal" {
					script, err := exec.LookPath("script")
					if err != nil {
						t.Skip("script is required for terminal stdin")
					}
					cmd = exec.CommandContext(ctx, script, "-qefc", shellURL(os.Args[0])+" -test.run=^TestHTTPSavedLoginFailuresMatchBaseState$", "/dev/null")
				}
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TUNN_CONFIG_DIR=" + dir, "TUNN_SAVED_LOGIN_CHILD=1", "TUNN_ENV=dev", "TUNN_PUBLIC_MODE=false", "TUNN_SECRET=", "TUNN_SERVER_ADDR=" + address, "NO_COLOR=1"}
				if mode != "human" {
					cmd.Env = append(cmd.Env, "TUNN_SAVED_LOGIN_JSON=1")
				}
				var out, errout bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &errout
				err := cmd.Run()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 {
					t.Fatalf("exit %v, stdout %q, stderr %q", err, out.String(), errout.String())
				}
				data := errout.String()
				if mode == "json-terminal" {
					data = out.String()
				} else if out.Len() != 0 {
					t.Fatalf("failure on stdout: %s", out.String())
				}
				wantCommand := "TUNN_CONFIG_DIR=" + shellURL(dir) + " tunn login"
				if mode != "human" {
					e := decodeFailure(t, data)
					// 5909b9c used auth_expired for both corrupt and wrong-server saved logins.
					if e.State != "auth_expired" || e.Cause != fixture.cause || e.NextAction != wantCommand {
						t.Fatalf("saved-login JSON changed from base state: %+v", e)
					}
				} else if !strings.Contains(data, fixture.cause) || strings.Count(data, wantCommand) != 1 {
					t.Fatal(data)
				}
				if strings.Contains(data, "synthetic-token") || strings.Contains(data, "Sign-in failed") {
					t.Fatalf("unsafe or vague saved-login failure: %s", data)
				}
				t.Logf("%s: %s", fixture.name, strings.TrimSpace(data))
			})
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("saved-login failures attempted enrollment: %d requests", got)
	}
}
