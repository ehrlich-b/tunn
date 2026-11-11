package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Run the actual CLI against a local relay, including runMCP's two upstream
// branches. No login, checkout, or other production service is contacted.
func TestMCPSecondNameOffer(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "tunn")
	if out, err := exec.Command("go", "build", "-p", "2", "-o", binary, "../..").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	t.Setenv("TUNN_MCP_OAUTH_HELPER", "1")
	// Read the shipped price defaults through config, rather than duplicating $5.
	t.Setenv("TUNN_PRO_MONTHLY_USD", "")
	t.Setenv("TUNN_PRO_YEARLY_USD", "")
	prices, err := config.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"http-fixture","version":"1"}}}`))
	}))
	defer origin.Close()

	for _, scenario := range []struct {
		name, plan string
		keepsName  bool
		wantOffer  bool
	}{
		{"free-second", "free", true, true},
		{"free-first", "free", false, false},
		{"pro-second", "pro", true, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var previewNotice string
			for _, transport := range []string{"preview", "http", "stdio"} {
				t.Run(transport, func(t *testing.T) {
					// Isolate reservation state so a previous publisher cannot turn
					// the first-name control into a second-name case.
					db, err := store.InitForTest()
					if err != nil {
						t.Fatal(err)
					}
					defer db.Close()
					db.SetMaxOpenConns(1)
					local := storage.NewLocalStorage(db)
					account, err := local.FindOrCreateByEmails(t.Context(), []string{"buyer@example.com"}, "test")
					if err != nil {
						t.Fatal(err)
					}
					if err := local.UpdatePlan(t.Context(), account.ID, scenario.plan); err != nil {
						t.Fatal(err)
					}
					if scenario.keepsName {
						if err := local.AccountStore().ReserveSubdomain(account.ID, "first-project"); err != nil {
							t.Fatal(err)
						}
					}
					sharing, err := metering.New(db, metering.WithAccountPlans())
					if err != nil {
						t.Fatal(err)
					}
					cfg := testConfig()
					relay := NewTunnelServer(cfg, nil, nil, local)
					relay.SetSharingBackend(sharing)
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					certSource := httptest.NewTLSServer(http.NotFoundHandler())
					cert := certSource.TLS.Certificates[0]
					certSource.Close()
					server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})))
					pb.RegisterTunnelServiceServer(server, relay)
					go func() { _ = server.Serve(listener) }()
					defer server.GracefulStop()

					token := createTestJWT("buyer@example.com", cfg.JWTSecret)
					args := []string{"--insecure", "mcp", "--name", "new-project", "--secret", token, "--tunnel-key", "test-key"}
					switch transport {
					case "preview":
						args = []string{"--insecure", "http", origin.URL, "--name", "new-project", "--public", "--expire", "150ms", "--secret", token, "--tunnel-key", "test-key"}
					case "http":
						args = append(args, origin.URL+"/mcp")
					case "stdio":
						args = append(args, "--", os.Args[0], "-test.run=^TestMCPOAuthStdioHelper$")
					}
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, binary, args...)
					cmd.Env = append(os.Environ(), "TUNN_CONFIG_DIR="+t.TempDir(), "TUNN_SERVER_ADDR="+listener.Addr().String(), "NO_COLOR=1")
					var out []byte
					if transport == "preview" {
						out, err = cmd.CombinedOutput()
					} else {
						var stdout, stderr bytes.Buffer
						cmd.Stderr = &stderr
						pipe, pipeErr := cmd.StdoutPipe()
						if pipeErr != nil {
							t.Fatal(pipeErr)
						}
						if err := cmd.Start(); err != nil {
							t.Fatal(err)
						}
						connected := false
						// Capture raw bytes; Scanner is only used to detect readiness.
						scanner := bufio.NewScanner(io.TeeReader(pipe, &stdout))
						for scanner.Scan() {
							line := scanner.Text()
							if strings.HasPrefix(line, "Connector URL: ") {
								connected = line == "Connector URL: https://new-project.tunn.to/mcp"
								_ = cmd.Process.Signal(os.Interrupt)
							}
						}
						err = cmd.Wait()
						out = append(stdout.Bytes(), stderr.Bytes()...)
						if scanErr := scanner.Err(); scanErr != nil {
							t.Error(scanErr)
						}
						if !connected {
							t.Errorf("MCP connector did not publish: %s", out)
						}
					}
					if err != nil || ctx.Err() != nil {
						t.Fatalf("publisher: %v (context: %v)\n%s", err, ctx.Err(), out)
					}
					if dir := os.Getenv("TUNN_TEST_EVIDENCE"); dir != "" {
						if err := os.WriteFile(filepath.Join(dir, scenario.name+"-"+transport+".txt"), out, 0600); err != nil {
							t.Fatal(err)
						}
					}
					var notice string
					for _, line := range strings.SplitAfter(string(out), "\n") {
						if strings.HasPrefix(line, "This name won't be kept") {
							notice += line
						}
					}
					if scenario.wantOffer {
						for _, want := range []string{fmt.Sprintf("Pro keeps %d for $%d a month", store.MaxReservedSubdomains, prices.ProMonthlyUSD), "/upgrade?period=monthly"} {
							if !strings.Contains(notice, want) {
								t.Errorf("offer missing %q: %q", want, notice)
							}
						}
						t.Logf("printed offer: %q", notice)
					} else if notice != "" || strings.Contains(string(out), "/upgrade?period=monthly") || strings.Contains(string(out), "Pro keeps") {
						t.Errorf("unexpected offer: %s", out)
					}
					if transport == "preview" {
						previewNotice = notice
					} else if notice != previewNotice {
						t.Errorf("MCP notice differs byte-for-byte from preview:\nMCP: %q\npreview: %q", notice, previewNotice)
					}
				})
			}
		})
	}
}
