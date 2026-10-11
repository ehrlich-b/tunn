package host

import (
	"context"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

// Chromium starts empty browser contexts and acquires cookies through the actual
// Google callback. Only the external identity provider is replaced by a fixture.
func TestWebSharingBrowserJourney(t *testing.T) {
	python := os.Getenv("TUNN_SHARE_BROWSER_PYTHON")
	if python == "" {
		t.Skip("set TUNN_SHARE_BROWSER_PYTHON to Python with Playwright for the browser acceptance gate")
	}
	f := newMCPOAuthFixture(t)
	p, tunnel := f.p, f.tunnel
	delete(p.tunnelServer.tunnels, "tools")
	tunnel.TunnelID = "api"
	tunnel.TargetURL = "http"
	tunnel.AllowedEmails = nil
	tunnel.EndpointProtocol = "http"
	p.tunnelServer.tunnels["api"] = tunnel
	ledger := p.meter.(*metering.Store)
	out, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: "api", Mode: "private"})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.ResourceID = out.Resources[0].Id
	p.config.GoogleClientID = "fixture-id"
	p.config.GoogleClientSecret = "fixture-secret"
	p.config.GitHubClientID = ""
	p.googleHTTPClient = googleFixtureTransport(t, p, true)
	server := httptest.NewUnstartedServer(p.createHandler())
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	p.config.PublicAddr = "tunn.test:" + port
	server.StartTLS()
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	script, err := filepath.Abs("../../scripts/integration-tests/web-sharing-browser.py")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, script, parsed.Port())
	cmd.Env = append(os.Environ(), "NO_PROXY=*")
	result, err := cmd.CombinedOutput()
	t.Log(string(result))
	if err != nil {
		t.Fatalf("browser sharing acceptance failed: %v", err)
	}
}
