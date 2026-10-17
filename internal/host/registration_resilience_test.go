package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestServeClientRecoversFromSecondAccountLookupOutage(t *testing.T) {
	f := newDurablePublisherFixture(t)
	f.secondLookupError.Store(true)
	recoverRegistration(t, f, "Account service temporarily unavailable.", func() {
		if got := f.lookups.Load(); got != 6 {
			t.Fatalf("three retries must each pass token validation and fail the second lookup, got %d lookups", got)
		}
		f.secondLookupError.Store(false)
	})
}

type recoveringRegistrationSharing struct {
	metering.SharingBackend
	unavailable atomic.Bool
	calls       atomic.Int64
}

func (s *recoveringRegistrationSharing) Sharing(ctx context.Context, req *meterpb.SharingRequest) (*meterpb.SharingResponse, error) {
	s.calls.Add(1)
	if s.unavailable.Load() {
		return nil, errors.New("synthetic policy outage")
	}
	return s.SharingBackend.Sharing(ctx, req)
}

func TestServeClientRecoversFromPolicyAuthorityOutage(t *testing.T) {
	for _, target := range []string{"web", "mcp"} {
		t.Run(target, func(t *testing.T) {
			f := newDurablePublisherFixture(t)
			sharing := &recoveringRegistrationSharing{SharingBackend: f.login.meter.(metering.SharingBackend)}
			sharing.unavailable.Store(true)
			f.relay.tunnelServer.SetSharingBackend(sharing)
			f.publisher.EndpointProtocol = "http"
			f.publisher.RequireSharing = true
			want := "Web permission authority unavailable."
			if target == "mcp" {
				f.publisher.PublicPath = "/mcp"
				want = "Endpoint policy authority unavailable."
			}
			recoverRegistration(t, f, want, func() { sharing.unavailable.Store(false) })
			if got := sharing.calls.Load(); got != 4 {
				t.Fatalf("expected three failed policy registrations and one success, got %d", got)
			}
		})
	}
}

// Exercise Run, the relay registration handler and login-node storage together.
// The same publisher must survive repeated failures and register after recovery.
func recoverRegistration(t *testing.T, f *durablePublisherFixture, want string, recoverAuthority func()) {
	t.Helper()
	done := f.run(t)
	retries := 0
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("publisher exited during outage (exit 78=%v): %v", client.LoginRequired(err), err)
		case event := <-f.events:
			switch event.State {
			case client.StateReconnecting:
				if event.Err == nil || !strings.Contains(event.Err.Error(), want) || client.LoginRequired(event.Err) || client.ClassifyFailure(event.Err) != client.FailureRegistration {
					t.Fatalf("outage was not a transient registration rejection: %v", event.Err)
				}
				cap := f.publisher.InitialDelay * time.Duration(1<<retries)
				if cap > f.publisher.MaxReconnectDelay {
					cap = f.publisher.MaxReconnectDelay
				}
				if event.RetryDelay < cap/2 || event.RetryDelay > cap {
					t.Fatalf("retry %d delay=%v, expected backoff in [%v, %v]", retries, event.RetryDelay, cap/2, cap)
				}
				retries++
				if retries > 3 {
					t.Fatal("publisher did not recover after authority returned")
				}
				if _, exists := f.relay.tunnelServer.GetTunnel(f.publisher.TunnelID); exists {
					t.Fatal("failed registration exposed a tunnel")
				}
				count, err := f.remote.GetTunnelCount(context.Background(), signedAccountID(f.token.Access))
				if err != nil || count != 0 {
					t.Fatalf("failed registration retained a storage reservation: count=%d err=%v", count, err)
				}
				if retries == 3 {
					recoverAuthority()
				}
			case client.StateReady:
				if retries != 3 || f.refreshes.Load() != 0 {
					t.Fatalf("retries=%d credential refreshes=%d, expected three retries without rotating credentials", retries, f.refreshes.Load())
				}
				if _, exists := f.relay.tunnelServer.GetTunnel(f.publisher.TunnelID); !exists {
					t.Fatal("recovered publisher has no tunnel")
				}
				t.Logf("recovered in process after %d registration retries; no login-required exit or credential refresh", retries)
				return
			}
		case <-deadline:
			t.Fatal("publisher failed to recover")
		}
	}
}

type rejectedRegistrationAccount struct {
	storage.Storage
	lookup int64
	calls  atomic.Int64
	state  string
}

func (s *rejectedRegistrationAccount) GetAccount(ctx context.Context, id string) (*storage.Account, error) {
	if s.calls.Add(1) < s.lookup {
		return s.Storage.GetAccount(ctx, id)
	}
	if s.state == "missing" {
		return nil, nil
	}
	return &storage.Account{ID: id, PrimaryEmail: "owner@example.com", OperationalState: s.state}, nil
}

func TestServeClientMissingOrRevokedAccountStops(t *testing.T) {
	for _, lookup := range []int64{1, 2} {
		for _, state := range []string{"missing", "suspended"} {
			t.Run(fmt.Sprintf("%s/lookup-%d", state, lookup), func(t *testing.T) {
				f := newDurablePublisherFixture(t)
				accounts := &rejectedRegistrationAccount{Storage: f.remote, lookup: lookup, state: state}
				f.relay.tunnelServer.storage = accounts
				done := f.run(t)
				select {
				case err := <-done:
					if err == nil || errors.Is(err, context.DeadlineExceeded) || client.ClassifyFailure(err) != client.FailureRegistration {
						t.Fatalf("account rejection did not stop publisher: %v", err)
					}
					// The first lookup rejects authentication, allowing one forced
					// renewal; neither lookup may enter outage reconnect backoff.
					for len(f.events) > 0 {
						if event := <-f.events; event.State == client.StateReconnecting || event.State == client.StateReady {
							t.Fatalf("missing or revoked account entered %s", event.State)
						}
					}
					if _, exists := f.relay.tunnelServer.GetTunnel(f.publisher.TunnelID); exists {
						t.Fatal("rejected account retained a tunnel")
					}
					t.Logf("account rejected terminally at lookup %d: %v", lookup, err)
				case <-time.After(3 * time.Second):
					t.Fatal("missing or revoked account kept retrying")
				}
			})
		}
	}
}

// Use the real ledger over both in-process and production-style RPC backends.
func registrationLedger(t *testing.T, f *durablePublisherFixture, remote bool) metering.SharingBackend {
	t.Helper()
	ledger := f.login.meter.(metering.SharingBackend)
	if !remote {
		return ledger
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	meterpb.RegisterMeteringServer(server, f.login.meter.(meterpb.MeteringServer))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	conn, err := grpc.NewClient("passthrough:///registration-policy", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &metering.Remote{Connection: func() *grpc.ClientConn { return conn }}
}

func TestServeClientPermanentPolicyDenialStops(t *testing.T) {
	for _, remote := range []bool{false, true} {
		for _, mode := range []string{"capacity", "legacy-downgrade", "invalid-email", "web-rate", "mcp-rate"} {
			t.Run(fmt.Sprintf("remote-%v/%s", remote, mode), func(t *testing.T) {
				f := newDurablePublisherFixture(t)
				ledger := registrationLedger(t, f, remote)
				recorder := &recoveringRegistrationSharing{SharingBackend: ledger}
				f.relay.tunnelServer.SetSharingBackend(recorder)
				f.publisher.EndpointProtocol = "http"
				f.publisher.RequireSharing = true
				owner := signedAccountID(f.token.Access)
				switch mode {
				case "capacity":
					f.publisher.AllowedEmails = nil
					for i := 0; i <= metering.MaxResourcePeople; i++ {
						f.publisher.AllowedEmails = append(f.publisher.AllowedEmails, fmt.Sprintf("person%d@example.com", i))
					}
				case "legacy-downgrade":
					if _, err := ledger.Sharing(context.Background(), &meterpb.SharingRequest{Operation: "register", Owner: owner, Endpoint: f.publisher.TunnelID, Mode: "private"}); err != nil {
						t.Fatal(err)
					}
					f.publisher.RequireSharing = false
					f.publisher.AllowedEmails = nil
				case "invalid-email":
					f.publisher.AllowedEmails = []string{"invalid"}
				case "web-rate", "mcp-rate":
					if mode == "mcp-rate" {
						f.publisher.PublicPath = "/mcp"
					}
					for i := 0; i < metering.MaxSharingMutationsPerMinute; i++ {
						if _, err := ledger.Sharing(context.Background(), &meterpb.SharingRequest{Operation: "register", Owner: owner, Endpoint: f.publisher.TunnelID, Mode: "policy-only"}); err != nil {
							t.Fatal(err)
						}
					}
				}
				done := f.run(t)
				select {
				case err := <-done:
					if err == nil || client.ClassifyFailure(err) != client.FailureRegistration || client.LoginRequired(err) {
						t.Fatalf("expected terminal policy rejection: %v", err)
					}
					if calls := recorder.calls.Load(); calls != 1 {
						t.Fatalf("permanent denial retried: %d policy calls", calls)
					}
					if f.refreshes.Load() != 0 {
						t.Fatal("policy denial forced credential renewal")
					}
					if mode == "legacy-downgrade" {
						result, err := ledger.Sharing(context.Background(), &meterpb.SharingRequest{Operation: "get", Owner: owner, Endpoint: f.publisher.TunnelID})
						if err != nil || result == nil || len(result.Resources) != 1 || result.Resources[0].Mode != "private" {
							t.Fatalf("denied legacy publisher changed managed exposure: result=%v err=%v", result, err)
						}
					}
					for len(f.events) > 0 {
						if event := <-f.events; event.State == client.StateReconnecting || event.State == client.StateReady {
							t.Fatalf("denied publisher entered %s", event.State)
						}
					}
					if _, exists := f.relay.tunnelServer.GetTunnel(f.publisher.TunnelID); exists {
						t.Fatal("denied publisher exposed a tunnel")
					}
					count, countErr := f.remote.GetTunnelCount(context.Background(), owner)
					if countErr != nil || count != 0 {
						t.Fatalf("denied publisher retained reservation: count=%d err=%v", count, countErr)
					}
					t.Logf("healthy ledger denial stopped after one registration: %v", err)
				case <-time.After(time.Second):
					t.Fatalf("permanent denial kept retrying: %d policy calls", recorder.calls.Load())
				}
			})
		}
	}
}

func TestServeClientRecoversFromHostAccountLookupOutage(t *testing.T) {
	f := newDurablePublisherFixture(t)
	server := f.relay.tunnelServer
	server.cfg.HostModeEnabled = true
	registry, err := store.NewHostStore(f.login.mcpOAuth.db)
	if err != nil {
		t.Fatal(err)
	}
	owner := signedAccountID(f.token.Access)
	if err := registry.Register(owner, common.HostManifest{Machine: "publisher", Tunnels: []common.HostEndpointSpec{{Name: f.publisher.TunnelID, Kind: "tcp"}}}); err != nil {
		t.Fatal(err)
	}
	server.hosts = registry
	f.publisher.HostID = "publisher"
	f.publisher.Credentials = nil
	f.publisher.AuthToken = "configured-host-publisher"
	server.userTokens = map[string]string{"owner@example.com": f.publisher.AuthToken}
	failedDB, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := failedDB.Close(); err != nil {
		t.Fatal(err)
	}
	server.accounts = store.NewAccountStore(failedDB)
	// Restore from Run's lifecycle callback before it starts the next RPC.
	// Changing the fixture from the event consumer would race the retry loop.
	onLifecycle := f.publisher.OnLifecycle
	retries := 0
	f.publisher.OnLifecycle = func(event client.LifecycleEvent) {
		if event.State == client.StateReconnecting {
			retries++
			if retries == 3 {
				server.accounts = store.NewAccountStore(f.login.mcpOAuth.db)
			}
		}
		onLifecycle(event)
	}
	recoverRegistration(t, f, "Account service temporarily unavailable.", func() {})
}
