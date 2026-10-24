package host

import (
	"context"
	"crypto/sha256"
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
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

func TestAccountTunnelsBrowserCache(t *testing.T) {
	module := os.Getenv("TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE")
	if module == "" {
		t.Skip("set TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE to run browser acceptance")
	}
	f := newWebInspectorFixture(t, 0, 0)
	for i := 0; i < 7; i++ {
		name := fmt.Sprintf("worker-%d", i)
		f.p.tunnelServer.tunnels[name] = &TunnelConnection{TunnelID: name, AccountID: f.tunnel.AccountID, TargetURL: "http", Connected: time.Now().Add(-2 * time.Hour)}
	}
	page := f.call("GET", "/account", nil, f.cookie, nil)
	if page.Code != http.StatusOK {
		t.Fatal(page.Code)
	}
	assetURL, err := webAssetURL("account-tunnels.js")
	if err != nil {
		t.Fatal(err)
	}
	asset := httptest.NewRecorder()
	serveWebAsset(asset, httptest.NewRequest("GET", assetURL, nil))
	wantURL := fmt.Sprintf("/assets/account-tunnels.js?v=%x", sha256.Sum256(asset.Body.Bytes()))
	if asset.Code != http.StatusOK || assetURL != wantURL || !strings.Contains(page.Body.String(), `src="`+wantURL+`"`) {
		t.Fatalf("account script must use its served content digest: status %d, URL %q", asset.Code, assetURL)
	}
	// Preserve the e83f158 script's exact DOM contract to exercise both directions.
	legacy, err := os.ReadFile("testdata/account-tunnels-legacy/account-tunnels.js")
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "cache.json")
	listing := f.call("GET", "/api/account/tunnels", nil, f.cookie, nil)
	if listing.Code != http.StatusOK {
		t.Fatal(listing.Code)
	}
	data, err := json.Marshal(map[string]any{
		"html": page.Body.String(), "script": asset.Body.String(), "url": assetURL,
		"cacheControl": asset.Header().Get("Cache-Control"), "legacyScript": string(legacy),
		"listing": json.RawMessage(listing.Body.Bytes()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	evidence := os.Getenv("TUNN_ACCOUNT_TUNNELS_EVIDENCE")
	if evidence == "" {
		evidence = t.TempDir()
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "../../scripts/integration-tests/account-tunnels-cache.cjs", input, evidence)
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil || !strings.Contains(string(output), `"result":"PASS"`) {
		t.Fatalf("browser cache acceptance: %v", err)
	}
}

func TestAccountTunnelsBrowserJourney(t *testing.T) {
	module := os.Getenv("TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE")
	if module == "" {
		t.Skip("set TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE to run browser acceptance")
	}
	schedule := os.Getenv("TUNN_ACCOUNT_TUNNELS_POLL_SCHEDULE")
	if schedule == "" {
		schedule = "normal"
	}
	if schedule != "normal" && schedule != "delayed" {
		t.Fatalf("unknown account tunnels poll schedule %q", schedule)
	}
	f := newWebInspectorFixture(t, 0, 0)
	p := f.p
	delete(p.tunnelServer.tunnels, "api")
	p.tunnelServer.SetSharingBackend(p.sharingBackend())
	p.config.GoogleClientID, p.config.GoogleClientSecret, p.config.GitHubClientID = "fixture-id", "fixture-secret", ""
	p.googleHTTPClient = googleFixtureTransport(t, p, true)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "healthy") }))
	defer origin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
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
	command.Env = append(os.Environ(), "NO_PROXY=*", "TUNN_ACCOUNT_TUNNELS_POLL_SCHEDULE="+schedule)
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil || !strings.Contains(string(output), `"result":"PASS"`) {
		t.Fatalf("browser acceptance: %v", err)
	}
}
