package host

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

func TestAccountTunnelsBrowserJourney(t *testing.T) {
	module := os.Getenv("TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE")
	if module == "" {
		t.Skip("set TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE to run browser acceptance")
	}
	f := newWebInspectorFixture(t, 0, 0)
	p := f.p
	delete(p.tunnelServer.tunnels, "api")
	p.tunnelServer.SetSharingBackend(p.sharingBackend())
	p.config.GoogleClientID, p.config.GoogleClientSecret, p.config.GitHubClientID = "fixture-id", "fixture-secret", ""
	p.googleHTTPClient = googleFixtureTransport(t, p, true)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "healthy") }))
	defer origin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	publisherCtx, disconnect := context.WithCancel(ctx)
	defer disconnect()
	started := make(chan struct{})
	var startOnce sync.Once
	routes := p.createHandler()
	fixture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/_fixture/") {
			if r.Method != http.MethodPost || p.revenueAccount(w, r) == nil {
				return
			}
			switch r.URL.Path {
			case "/_fixture/connect":
				startOnce.Do(func() { close(started) })
			case "/_fixture/disconnect":
				disconnect()
			default:
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		routes.ServeHTTP(w, r)
	})
	grpcServer := grpc.NewServer()
	pb.RegisterTunnelServiceServer(grpcServer, p.tunnelServer)
	p.grpcServer = grpcServer
	relay := httptest.NewUnstartedServer(p.createHTTP2Router(fixture))
	relay.EnableHTTP2 = true
	_, port, _ := net.SplitHostPort(relay.Listener.Addr().String())
	p.config.PublicAddr = "tunn.test:" + port
	relay.StartTLS()
	defer relay.Close()
	defer grpcServer.Stop()
	done := make(chan error, 1)
	publisher := &client.ServeClient{TunnelID: "webhooks", TargetURL: origin.URL, AuthToken: createTestJWT("owner@example.com", p.config.JWTSecret), TunnelKey: p.config.WellKnownKey, ServerAddr: relay.Listener.Addr().String(), RelayTLSConfig: &tls.Config{InsecureSkipVerify: true}, Public: true, RequireSharing: true, Quiet: true, ClientVersion: "1.2.3", InitialDelay: 5 * time.Millisecond, MaxReconnectDelay: 20 * time.Millisecond}
	go func() {
		select {
		case <-started:
			done <- publisher.Run(publisherCtx)
		case <-ctx.Done():
			done <- ctx.Err()
		}
	}()
	defer func() {
		cancel()
		disconnect()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("publisher did not stop")
		}
	}()
	script, err := filepath.Abs("../../scripts/integration-tests/account-tunnels-browser.cjs")
	if err != nil {
		t.Fatal(err)
	}
	evidence := os.Getenv("TUNN_ACCOUNT_TUNNELS_EVIDENCE")
	if evidence == "" {
		evidence = t.TempDir()
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", script, port, evidence)
	command.Env = append(os.Environ(), "NO_PROXY=*")
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil || !strings.Contains(string(output), `"result":"PASS"`) {
		t.Fatalf("browser acceptance: %v", err)
	}
}
