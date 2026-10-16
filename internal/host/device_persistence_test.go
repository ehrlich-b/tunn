package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Complete a browser login against a synthetic GitHub, then make all provider
// and other external HTTP requests fail. No production provider is contacted.
func durableProviderLogin(t *testing.T, p *ProxyServer) durableTokenFixture {
	t.Helper()
	p.config.GitHubClientID, p.config.GitHubClientSecret = "fixture-client", "fixture-secret"
	var unavailable atomic.Bool
	var calls atomic.Int64
	installAccountsHTTPFake(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if unavailable.Load() {
			return nil, fmt.Errorf("synthetic identity provider unavailable")
		}
		switch r.URL.String() {
		case githubTokenURL:
			return accountsProviderResponse(r, 200, `{"access_token":"fixture-provider-token"}`), nil
		case githubEmailsURL:
			return accountsProviderResponse(r, 200, `[{"email":"owner@example.com","primary":true,"verified":true}]`), nil
		default:
			return nil, fmt.Errorf("unexpected external request: %s", r.URL)
		}
	})
	state, cookie := accountsGitHubBrowserStart(t, p, url.Values{})
	if response := accountsGitHubCallback(p, state, "fixture-code", cookie); response.Code != 302 || calls.Load() != 2 {
		t.Fatal("synthetic provider login failed", response.Code, calls.Load())
	}
	token := durableLogin(t, p)
	unavailable.Store(true)
	if _, err := p.exchangeGitHubCode("provider-now-offline"); err == nil {
		t.Fatal("provider outage fixture did not reject a new login")
	}
	calls.Store(0)
	t.Cleanup(func() {
		if n := calls.Load(); n != 0 {
			t.Errorf("durable authentication attempted %d external requests after login", n)
		}
	})
	return token
}

func TestDurableClientRecoversAfterLoginAndRelayRestart(t *testing.T) {
	clientTransport := http.DefaultTransport
	p := durableFixture(t)
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	clock := func() time.Time { return time.Unix(seconds.Load(), 0) }
	p.now = clock
	p.tunnelServer.now = p.now
	token := durableProviderLogin(t, p)
	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	// Seed only synthetic state in the format written by LoginClient.
	data, err := json.Marshal(map[string]any{"server": "https://tunn.test", "access_token": token.Access, "refresh_token": token.Refresh, "device_id": token.Device, "expires_at": clock().Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	// Client transport construction clones the standard *http.Transport. Keep
	// the provider fake around it, then inject the in-process refresh transport
	// before any client network request can occur (the access token is current).
	providerTransport := http.DefaultTransport
	http.DefaultTransport = clientTransport
	_, manager, err := client.LoadTunnelToken(context.Background(), "tunn.test", false)
	http.DefaultTransport = providerTransport
	if err != nil || manager == nil {
		t.Fatal("load synthetic device state", err)
	}
	manager.Now = clock
	var offline, loseResponse bool
	manager.HTTPClient = &http.Client{Transport: accountsHTTPFake(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://tunn.test/api/device/refresh" {
			return nil, fmt.Errorf("unexpected credential URL: %s", r.URL)
		}
		if offline {
			return nil, fmt.Errorf("synthetic login node restarting")
		}
		response := httptest.NewRecorder()
		p.handleDeviceRefresh(response, r)
		if loseResponse {
			loseResponse = false
			return nil, fmt.Errorf("synthetic lost committed refresh response")
		}
		return response.Result(), nil
	})}

	// Register through the real resource relay, then disconnect its stream.
	register := func(access string) (context.CancelFunc, <-chan error) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 1), outgoing: make(chan *pb.TunnelMessage, 1)}
		stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "restart-ssh", TargetUrl: "tcp", EndpointProtocol: "tcp", AuthToken: access, TunnelKey: p.config.WellKnownKey, AllowedEmails: []string{"owner@example.com"}, Capabilities: []string{deviceReauthCapability, "connection-stream-v1"}}}}
		done := make(chan error, 1)
		go func() { done <- p.tunnelServer.EstablishTunnel(stream) }()
		select {
		case response := <-stream.outgoing:
			if !response.GetRegisterResponse().Success {
				t.Fatal("registration rejected", response.GetRegisterResponse().ErrorMessage)
			}
		case err := <-done:
			t.Fatal("registration ended", err)
		case <-time.After(3 * time.Second):
			t.Fatal("registration stalled")
		}
		return cancel, done
	}
	cancel, done := register(token.Access)
	seconds.Add(240)
	loseResponse = true
	if _, err := manager.Token(context.Background(), false); err == nil || client.LoginRequired(err) {
		t.Fatal("lost response must remain recoverable", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("resource relay did not disconnect")
	}
	offline = true
	seconds.Add(int64((72 * time.Hour) / time.Second))
	if _, err := manager.Token(context.Background(), false); err == nil || client.LoginRequired(err) {
		t.Fatal("login node outage must remain recoverable", err)
	}

	// Reopen the persisted database as a new login-node process would. The
	// fixture retains its original handle solely to own temporary-file cleanup.
	var seq int
	var name, path string
	if err := p.devices.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	p = newMCPOAuthFixtureWithDB(t, db).p
	p.now = clock
	p.tunnelServer.now = p.now
	offline = false
	access, err := manager.Token(context.Background(), false)
	if err != nil {
		t.Fatal("recover pending rotation after node restarts", err)
	}
	cancel, done = register(access)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("reconnected resource relay did not stop")
	}
	if _, err := db.Exec(`UPDATE durable_devices SET revoked=? WHERE id=?`, clock().Unix(), token.Device); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Token(context.Background(), true); err == nil || !client.LoginRequired(err) {
		t.Fatal("revocation did not terminate client renewal", err)
	}
	t.Log("client recovered a lost committed rotation after a 72-hour outage, reopened login database and replacement resource relay; revocation requires login")
}

// The fast client lifetime test exercises every renewal. Check the production
// issuer's age decisions separately with real SQLite and a real provider login.
func TestDurableDeviceRenewsAfterTwoYearsWithoutIdentityProvider(t *testing.T) {
	p := durableFixture(t)
	now := time.Now().Truncate(time.Second)
	p.now = func() time.Time { return now }
	token := durableProviderLogin(t, p)
	for year := 1; year <= 2; year++ {
		now = now.Add(365 * 24 * time.Hour)
		response, next := durableRefresh(p, token.Refresh, fmt.Sprintf("%043d", year))
		if response.Code != 200 || next.Device != token.Device || next.Refresh == token.Refresh {
			t.Fatal("device stopped renewing with age", year, response.Code)
		}
		if _, _, _, err := parseDeviceToken(next.Access, p.getJWTSigningKey(), now); err != nil {
			t.Fatal("issuer returned an invalid access token", err)
		}
		token = next
	}
	if _, err := p.devices.db.Exec(`UPDATE durable_devices SET revoked=? WHERE id=?`, now.Unix(), token.Device); err != nil {
		t.Fatal(err)
	}
	if response, _ := durableRefresh(p, token.Refresh, "revoked-device-request-identifier"); response.Code != 401 {
		t.Fatal("two-year-old revoked device still refreshed", response.Code)
	}
}
