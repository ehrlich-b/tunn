package host

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Exercise real CLI processes and the production relay admission path. All
// accounts, origins, credentials and listeners are synthetic and local.
func TestPlanLimitCLI(t *testing.T) {
	testPlanLimitCLI(t, "", false)
}

func TestPlanLimitInstalledCLI(t *testing.T) {
	binary := os.Getenv("TUNN_INSTALLED_CLI")
	if binary == "" {
		t.Skip("set TUNN_INSTALLED_CLI to the installed v0.1.6 binary")
	}
	if out, err := exec.Command(binary, "version").CombinedOutput(); err != nil || string(out) != "tunn v0.1.6\n" {
		t.Fatalf("installed version: %v: %s", err, out)
	}
	testPlanLimitCLI(t, binary, false)
}

func TestPlanLimitReleasedCLI(t *testing.T) {
	binary := os.Getenv("TUNN_RELEASE_CLI")
	if binary == "" {
		t.Skip("set TUNN_RELEASE_CLI to the SHA256SUMS-verified v0.1.5 binary")
	}
	testPlanLimitCLI(t, binary, true)
}

func testPlanLimitCLI(t *testing.T, binary string, released bool) {
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "tunn")
		build := exec.Command("go", "build", "-p", "2", "-o", binary, "../..")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("local fixture")) }))
	defer origin.Close()
	for _, replica := range []bool{false, true} {
		label := "local"
		if replica {
			label = "replica"
		}
		t.Run(label, func(t *testing.T) {
			db, err := store.InitForTest()
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			t.Cleanup(func() { _ = db.Close() })
			local := storage.NewLocalStorage(db)
			sharing, err := metering.New(db, metering.WithAccountPlans())
			if err != nil {
				t.Fatal(err)
			}
			account, err := local.FindOrCreateByEmails(context.Background(), []string{"buyer@example.com"}, "github")
			if err != nil {
				t.Fatal(err)
			}
			if err := local.AccountStore().ReserveSubdomain(account.ID, "first-project"); err != nil {
				t.Fatal(err)
			}
			var authority storage.Storage = local
			if replica {
				authority = securityReplicaStorage(t, local)
			}
			cfg := testConfig()
			relay := NewTunnelServer(cfg, nil, nil, authority)
			relay.SetSharingBackend(sharing)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
			certificate := certificateSource.TLS.Certificates[0]
			certificateSource.Close()
			server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}})))
			pb.RegisterTunnelServiceServer(server, relay)
			go func() { _ = server.Serve(listener) }()
			defer server.Stop()
			run := func(name string, jsonOutput bool) (string, error) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				args := []string{"--insecure", "http", origin.URL, "--name", name, "--public", "--expire", "500ms", "--secret", createTestJWT("buyer@example.com", cfg.JWTSecret), "--tunnel-key", "test-key"}
				if jsonOutput {
					args = append(args, "--json")
				}
				cmd := exec.CommandContext(ctx, binary, args...)
				cmd.Env = append(os.Environ(), "TUNN_CONFIG_DIR="+t.TempDir(), "TUNN_SERVER_ADDR="+listener.Addr().String(), "TUNN_CLIENT_SECRET="+createTestJWT("buyer@example.com", cfg.JWTSecret), "WELL_KNOWN_KEY=test-key", "NO_COLOR=1")
				var forwarding chan error
				if name != "sixth-project" {
					forwarding = make(chan error, 1)
					go func() {
						deadline := time.Now().Add(2 * time.Second)
						for time.Now().Before(deadline) {
							if tunnel, ok := relay.GetTunnel(name); ok {
								request := httptest.NewRequest("GET", "/still-running", nil).WithContext(ctx)
								response := httptest.NewRecorder()
								err := (&ProxyServer{storage: authority, usageBuffer: NewUsageBuffer()}).proxyHTTPOverGRPC(response, request, tunnel)
								if err == nil && (response.Code != 200 || response.Body.String() != "local fixture") {
									err = fmt.Errorf("forwarded response: %d %q", response.Code, response.Body.String())
								}
								forwarding <- err
								return
							}
							time.Sleep(time.Millisecond)
						}
						forwarding <- fmt.Errorf("publisher never registered")
					}()
				}
				out, err := cmd.CombinedOutput()
				if forwarding != nil {
					if forwardErr := <-forwarding; forwardErr != nil {
						t.Errorf("tunnel did not forward: %v", forwardErr)
					}
				}
				if ctx.Err() != nil {
					t.Fatalf("CLI timed out: %s", out)
				}
				return string(out), err
			}
			save := func(name, out string) {
				t.Helper()
				if dir := os.Getenv("TUNN_TEST_EVIDENCE"); dir != "" {
					if err := os.WriteFile(filepath.Join(dir, label+"-"+name), []byte(out), 0600); err != nil {
						t.Fatal(err)
					}
				}
				t.Log(out)
			}
			t.Run("second-name", func(t *testing.T) {
				out, err := run("second-project", false)
				save("second-name.txt", out)
				if err != nil {
					t.Errorf("second tunnel refused: %v", err)
				}
				if released {
					for _, notice := range []string{"This name won't be kept", "Pro keeps 10", "$5", "https://tunn.to/upgrade?period=monthly", "https://tunn.to/pricing"} {
						if strings.Contains(out, notice) {
							t.Errorf("v0.1.5 unexpectedly displays %q; revisit compatibility claim", notice)
						}
					}
					for _, want := range []string{"second-project.tunn.to", "Online"} {
						if !strings.Contains(out, want) {
							t.Errorf("released tunnel not running: missing %q", want)
						}
					}
					return
				}
				for _, want := range []string{"This name won't be kept while you're offline", "Free keeps 1", "Pro keeps 10", "$5 a month or $48 a year", "https://tunn.to/upgrade?period=monthly", "https://tunn.to/pricing", "second-project.tunn.to", "Online"} {
					if !strings.Contains(out, want) {
						t.Errorf("CLI missing %q", want)
					}
				}
			})
			if !released {
				t.Run("second-name-json", func(t *testing.T) {
					out, err := run("second-project", true)
					save("second-name.json", out)
					if err != nil || !strings.Contains(out, `"code":"name_not_kept"`) || !strings.Contains(out, `"type":"notice"`) || !strings.Contains(out, `"type":"route"`) {
						t.Errorf("JSON notice: %v\n%s", err, out)
					}
				})
			}

			for i, name := range []string{"one", "two", "three", "four", "five"} {
				reg, err := local.RegisterTunnel(context.Background(), name, account.ID, "local")
				if err != nil || !reg.Allowed {
					t.Fatalf("seed tunnel %d: %v %v", i, reg, err)
				}
			}
			for _, jsonOutput := range []bool{false, true} {
				name := "tunnel-limit.txt"
				if jsonOutput {
					name = "tunnel-limit.json"
				}
				t.Run(name, func(t *testing.T) {
					out, err := run("sixth-project", jsonOutput)
					save(name, out)
					if err == nil {
						t.Error("sixth tunnel succeeded")
					}
					if released {
						if strings.Contains(out, "https://tunn.to/pricing") {
							t.Error("v0.1.5 unexpectedly displays upgrade guidance; revisit compatibility claim")
						}
						if !strings.Contains(out, "Limit reached") {
							t.Error("released client did not display a refusal")
						}
						return
					}
					for _, want := range []string{"Free", "5/5", "https://tunn.to/pricing"} {
						if !strings.Contains(out, want) {
							t.Errorf("CLI missing %q", want)
						}
					}
					if jsonOutput {
						found := false
						for _, line := range strings.Split(out, "\n") {
							var event map[string]any
							if json.Unmarshal([]byte(line), &event) == nil && event["code"] == "tunnel_limit" {
								found = true
							}
						}
						if !found {
							t.Error("no stable tunnel_limit JSON code")
						}
					}
				})
			}
		})
	}
}
