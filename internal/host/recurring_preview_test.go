package host

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

// Compose the sales reservation/replacement contract with durable client refresh.
// All provider data is synthetic; the clock advances one day without a soak.
func TestRecurringBuyerPreviewContinuity(t *testing.T) {
	p := durableFixture(t)
	local := p.storage.(*storage.LocalStorage)
	accounts := local.AccountStore()
	ctx := context.Background()
	var seconds atomic.Int64
	seconds.Store(time.Date(2035, 1, 2, 12, 0, 0, 0, time.UTC).Unix())
	clock := func() time.Time { return time.Unix(seconds.Load(), 0).UTC() }
	p.now, p.tunnelServer.now = clock, clock
	owner, err := accounts.GetByEmail("owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	competitor, err := accounts.FindOrCreateByEmails([]string{"competitor@example.invalid"}, "test")
	if err != nil {
		t.Fatal(err)
	}

	// Exercise the local paid checkout/review path rather than changing limits.
	ops := store.NewOperationsStore(p.devices.db, clock)
	adminSecret := "synthetic-preview-operator-secret-0123456789"
	digest := sha256.Sum256([]byte(adminSecret))
	admin, err := store.AuthenticateAdmin([]store.AdminCredential{{Actor: "fixture", TokenSHA256: hex.EncodeToString(digest[:]), Accounts: []string{owner.ID}}}, adminSecret)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := ops.BeginBillingCheckout(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	event := store.BillingEvent{Provider: "stripe", ID: "evt_preview", Type: "checkout.session.completed", CustomerID: "cus_preview", SubscriptionID: "sub_preview", SessionID: "cs_preview", CheckoutReference: ref, Supported: true}
	if result, err := ops.ProcessBillingEvent(ctx, event); err != nil || result.AccountID != owner.ID {
		t.Fatal("local payment receipt", result, err)
	}
	if err := ops.BindBilling(ctx, admin, store.BillingMapping{Provider: "stripe", CustomerID: event.CustomerID, SubscriptionID: event.SubscriptionID, AccountID: owner.ID}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.BillingSnapshot{Provider: "stripe", CustomerID: event.CustomerID, SubscriptionID: event.SubscriptionID, AccountID: owner.ID, Plan: "pro", ProviderStatus: "active", PaymentConfirmed: true, ProviderReadAt: clock(), PriceID: "price_fixture_recurring", EvidenceSHA256: strings.Repeat("e", 64), EventIDs: []string{event.ID}}
	if _, err := ops.ApplyReviewedBilling(ctx, admin, []store.BillingSnapshot{snapshot}); err != nil {
		t.Fatal(err)
	}
	const name = "q7m2n9"
	if err := accounts.ReserveSubdomain(owner.ID, name); err != nil {
		t.Fatal(err)
	}
	checkReservation := func(stage string) {
		t.Helper()
		got, err := accounts.GetSubdomainOwner(name)
		if err != nil || got != owner.ID {
			t.Fatalf("reservation continuity at %s: name=%s owner=%s want=%s err=%v", stage, name, got, owner.ID, err)
		}
		account, err := accounts.GetByID(owner.ID)
		if err != nil || account.Plan != "pro" {
			t.Fatal("paid entitlement lost", err)
		}
		t.Logf("%s time=%s name=%s owner=%s plan=%s", stage, clock().Format(time.RFC3339), name, got, account.Plan)
	}
	denyCompetitor := func() {
		t.Helper()
		if err := accounts.ReserveSubdomain(competitor.ID, name); err == nil {
			t.Fatal("competitor claimed retained reservation")
		}
		registration, err := local.RegisterTunnel(ctx, name, competitor.ID, "local")
		if err != nil || registration.Allowed || registration.Reason != "subdomain is reserved by another user" {
			t.Fatal("competitor publisher was not denied by reservation", registration, err)
		}
		t.Logf("competitor=%s denied reservation and publication of name=%s", competitor.ID, name)
	}
	checkReservation("paid-before")
	denyCompetitor()

	// Device-code creation uses wall time; pin this synthetic code's deadline to
	// the scenario clock before the real durable issuer consumes it.
	code, err := p.storage.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := p.storage.AuthorizeDeviceCode(ctx, code.Code, owner.PrimaryEmail); err != nil || !ok {
		t.Fatal("authorize fixture device", err)
	}
	if _, err := p.devices.db.Exec(`UPDATE device_codes SET expires_at=? WHERE code=?`, clock().Add(10*time.Minute).Unix(), code.Code); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	p.handleDeviceToken(recorder, httptest.NewRequest("GET", "https://tunn.test/api/device/token?durable=1&code="+code.Code, nil))
	var token durableTokenFixture
	if err := json.Unmarshal(recorder.Body.Bytes(), &token); err != nil || recorder.Code != 200 || token.Device == "" {
		t.Fatal("issue fixture device", recorder.Code, err)
	}
	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	data, err := json.Marshal(map[string]any{"server": "https://tunn.test", "access_token": token.Access, "refresh_token": token.Refresh, "device_id": token.Device, "expires_at": clock().Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	var refreshes atomic.Int64
	loadManager := func() *client.CredentialManager {
		t.Helper()
		_, manager, err := client.LoadTunnelToken(ctx, "tunn.test", false)
		if err != nil || manager == nil {
			t.Fatal("load durable state", err)
		}
		manager.Now = clock
		manager.HTTPClient = &http.Client{Transport: accountsHTTPFake(func(r *http.Request) (*http.Response, error) {
			if r.Method != "POST" || r.URL.String() != "https://tunn.test/api/device/refresh" {
				return nil, fmt.Errorf("unexpected credential request")
			}
			response := httptest.NewRecorder()
			p.handleDeviceRefresh(response, r)
			if response.Code == 200 {
				refreshes.Add(1)
			}
			return response.Result(), nil
		})}
		return manager
	}
	manager := loadManager()

	// The actual publisher and relay exchange gRPC over an in-memory TLS socket.
	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateSource.TLS.Certificates[0]
	certificateSource.Close()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}})))
	pb.RegisterTunnelServiceServer(server, p.tunnelServer)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	startPublisher := func(manager *client.CredentialManager) func() {
		t.Helper()
		runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ready := make(chan string, 1)
		done := make(chan error, 1)
		publisher := &client.ServeClient{TunnelID: name, TargetURL: "http://preview.invalid", Credentials: manager,
			ServerAddr: "tunn.test", Insecure: true, Quiet: true, TunnelKey: p.config.WellKnownKey,
			DialContext: func(context.Context, string, string) (net.Conn, error) { return listener.Dial() },
			HTTPTransport: accountsHTTPFake(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("recurring preview")), ContentLength: 17, Request: r}, nil
			}),
			RenewInterval: 5 * time.Millisecond, OnRegistered: func(url string) { ready <- url },
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		go func() { done <- publisher.Run(runCtx) }()
		stop := func() {
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Error("publisher stop", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("publisher did not stop")
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				if _, exists := p.tunnelServer.GetTunnel(name); !exists {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("publisher route survived stop")
				}
				time.Sleep(time.Millisecond)
			}
		}
		// Always stop on early test failure as well as the explicit restart.
		var stopped atomic.Bool
		stopOnce := func() {
			if stopped.CompareAndSwap(false, true) {
				stop()
			}
		}
		t.Cleanup(stopOnce)
		select {
		case url := <-ready:
			if url != "https://"+name+"."+p.Domain {
				t.Fatal("publisher allocated a different name", url)
			}
		case err := <-done:
			stopped.Store(true)
			cancel()
			t.Fatal("publisher failed to register", err)
		case <-runCtx.Done():
			t.Fatal("publisher registration timed out")
		}
		return stopOnce
	}
	checkPreview := func(stage string) *TunnelConnection {
		t.Helper()
		tunnel, ok := p.tunnelServer.GetTunnel(name)
		if !ok || tunnel.AccountID != owner.ID || tunnel.Plan != "pro" {
			t.Fatal("publisher identity changed", stage)
		}
		request := httptest.NewRequest("GET", "https://"+name+"."+p.Domain+"/", nil)
		response := httptest.NewRecorder()
		if err := p.proxyHTTPOverGRPC(response, request, tunnel); err != nil || response.Code != 200 || response.Body.String() != "recurring preview" {
			t.Fatal("preview unusable", stage, response.Code, response.Body.String(), err)
		}
		t.Logf("%s url=https://%s.%s HTTP=%d", stage, name, p.Domain, response.Code)
		checkReservation(stage)
		return tunnel
	}
	stop := startPublisher(manager)
	before := checkPreview("publisher-before")
	seconds.Add(240)
	deadline := time.Now().Add(3 * time.Second)
	for refreshes.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("running publisher did not refresh")
		}
		time.Sleep(time.Millisecond)
	}
	access, err := manager.Token(ctx, false) // Join the durable write under its lock.
	if err != nil || access == token.Access || signedAccountID(access) != owner.ID {
		t.Fatal("refreshed access lost opaque owner", err)
	}
	if after := checkPreview("publisher-after-refresh"); after != before {
		t.Fatal("refresh replaced the publisher route")
	}
	stop()
	seconds.Add(int64((24 * time.Hour) / time.Second))
	checkReservation("offline-next-day")
	denyCompetitor()
	manager = loadManager() // Fresh client instance, same on-disk device and name.
	stop = startPublisher(manager)
	checkPreview("publisher-after-restart")
	access, err = manager.Token(ctx, false)
	_, device, _, parseErr := parseDeviceToken(access, p.getJWTSigningKey(), clock())
	if err != nil || parseErr != nil || device != token.Device || signedAccountID(access) != owner.ID || refreshes.Load() != 2 {
		t.Fatal("restart changed device or account", err, parseErr, refreshes.Load())
	}
	stop()
	denyCompetitor()

	// Released names are reusable; failed replacements must retain the old one.
	if err := accounts.ReleaseSubdomain(owner.ID, name); err != nil {
		t.Fatal(err)
	}
	if err := accounts.ReserveSubdomain(competitor.ID, name); err != nil {
		t.Fatal("released name not reusable", err)
	}
	if err := accounts.ReplaceSubdomain(ctx, owner.ID, name, "z8p4r6"); err == nil {
		t.Fatal("former owner replaced competitor reservation")
	}
	if err := accounts.ReplaceSubdomain(ctx, competitor.ID, name, name); err == nil {
		t.Fatal("same-name replacement accepted")
	}
	if got, err := accounts.GetSubdomainOwner(name); err != nil || got != competitor.ID {
		t.Fatal("failed replacement lost reservation", got, err)
	}
	if err := accounts.ReplaceSubdomain(ctx, competitor.ID, name, "z8p4r6"); err != nil {
		t.Fatal(err)
	}
	if got, err := accounts.GetSubdomainOwner("z8p4r6"); err != nil || got != competitor.ID {
		t.Fatal("replacement owner", got, err)
	}
	if got, err := accounts.GetSubdomainOwner(name); err != nil || got != "" {
		t.Fatal("replaced name was not released", got, err)
	}
	t.Logf("released name=%s reclaimed-by=%s replaced-with=z8p4r6; refreshes=%d same-device=true", name, competitor.ID, refreshes.Load())
}
