package host

import (
	"context"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAppDeviceBrowserJourney(t *testing.T) {
	module := os.Getenv("TUNN_PLAYWRIGHT_MODULE")
	if module == "" {
		t.Skip("set TUNN_PLAYWRIGHT_MODULE to run the clean-browser enrollment acceptance")
	}
	f := newAppDeviceFixture(t)
	f.p.config.GoogleClientID = "fixture-id"
	f.p.config.GoogleClientSecret = "fixture-secret"
	f.p.googleHTTPClient = googleFixtureTransport(t, f.p, true)
	server := appDeviceTLSServer(t, f.p.createHandler())
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	f.p.config.PublicAddr = "tunn.test:" + port
	// Only the public disposable certificate is supplied to the browser harness.
	// Its Node transport verifies TLS with this trust anchor and the exact host.
	ca := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../scripts/integration-tests/app-devices-browser.cjs")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", script, port, ca)
	cmd.Env = append(os.Environ(), "NO_PROXY=*")
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("app-device browser journey failed: %v", err)
	}
}
