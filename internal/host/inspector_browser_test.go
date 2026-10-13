package host

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

// Real TLS relay, publisher stream, origin and browser. Only the external
// Google consent/token service is replaced. No hosted account is touched.
func TestWebInspectorBrowserJourney(t *testing.T) {
	module := os.Getenv("TUNN_INSPECT_PLAYWRIGHT_MODULE")
	if module == "" {
		t.Skip("browser acceptance requires installed Playwright; use make test-web-inspector-browser")
	}
	f := newWebInspectorFixture(t, 0, 0)
	p := f.p
	delete(p.tunnelServer.tunnels, "api")
	p.tunnelServer.SetSharingBackend(p.sharingBackend())
	p.config.GoogleClientID = "fixture-id"
	p.config.GoogleClientSecret = "fixture-secret"
	p.config.GitHubClientID = ""
	p.googleHTTPClient = googleFixtureTransport(t, p, true)
	var received, redirectVisits, redirected atomic.Int64
	alternate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(200) }))
	defer alternate.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil {
			t.Error(err)
		}
		if strings.Contains(r.Header.Get("Cookie"), authCookieName) || r.Header.Get("Tunn-Authorization") != "" {
			t.Error("platform credential reached real origin")
		}
		received.Add(1)
		if r.URL.Path == "/redirect-on-replay" && redirectVisits.Add(1) > 1 {
			w.Header().Set("Location", alternate.URL)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status := 202
		if r.URL.Path == "/health" {
			status = 200
		}
		if r.URL.Path == "/missing" {
			status = 404
		}
		if r.URL.Path == "/failing" {
			status = 500
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": status < 400, "request_bytes": len(data), "response_secret": "RESPONSE_PAYLOAD_SENTINEL"})
	}))
	defer origin.Close()
	grpcServer := grpc.NewServer()
	pb.RegisterTunnelServiceServer(grpcServer, p.tunnelServer)
	p.grpcServer = grpcServer
	relay := httptest.NewUnstartedServer(p.createHTTP2Router(p.createHandler()))
	relay.EnableHTTP2 = true
	_, port, _ := net.SplitHostPort(relay.Listener.Addr().String())
	p.config.PublicAddr = "tunn.test:" + port
	relay.StartTLS()
	defer relay.Close()
	defer grpcServer.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	publisher := &client.ServeClient{TunnelID: "webhooks", TargetURL: origin.URL, AuthToken: createTestJWT("owner@example.com", p.config.JWTSecret), TunnelKey: p.config.WellKnownKey, ServerAddr: relay.Listener.Addr().String(), RelayTLSConfig: &tls.Config{InsecureSkipVerify: true}, RequireSharing: true, Quiet: true, InitialDelay: 5 * time.Millisecond, MaxReconnectDelay: 20 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- publisher.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("publisher did not stop")
		}
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	ready := false
	for !ready {
		if _, exists := p.tunnelServer.GetTunnel("webhooks"); exists {
			ready = true
			break
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("publisher registration: %v", err)
		case <-deadline.C:
			t.Fatal("publisher did not register")
		case <-ticker.C:
		}
	}
	script, err := filepath.Abs("../../scripts/integration-tests/web-inspector-browser.cjs")
	if err != nil {
		t.Fatal(err)
	}
	evidence := os.Getenv("TUNN_INSPECT_EVIDENCE")
	if evidence == "" {
		evidence = filepath.Join(filepath.Dir(script), "../../.scratch/web-inspector")
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", script, port, evidence)
	command.Env = append(os.Environ(), "NO_PROXY=*")
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("real browser journey: %v", err)
	}
	if !strings.Contains(string(output), `"result":"PASS"`) {
		t.Fatal("browser did not report acceptance")
	}
	if received.Load() != 8 {
		t.Fatalf("expected 6 original requests and 2 confirmed replays, received %d", received.Load())
	}
	if redirected.Load() != 0 {
		t.Fatalf("replay followed origin redirect %d times", redirected.Load())
	}
	t.Log(fmt.Sprintf("real origin received %d deliveries", received.Load()))
}
