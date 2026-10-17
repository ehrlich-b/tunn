package host

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type durablePublisherFixture struct {
	login             *ProxyServer
	relay             *ProxyServer
	remote            *storage.ProxyStorage
	connection        *grpc.ClientConn
	publisher         *client.ServeClient
	token             durableTokenFixture
	seconds           atomic.Int64
	lookupError       atomic.Bool
	secondLookupError atomic.Bool
	lookups           atomic.Int64
	refreshes         atomic.Int64
	events            chan client.LifecycleEvent
}

func newDurablePublisherFixture(t *testing.T) *durablePublisherFixture {
	t.Helper()
	f := &durablePublisherFixture{login: durableFixture(t), events: make(chan client.LifecycleEvent, 64)}
	f.seconds.Store(time.Now().Unix())
	clock := func() time.Time { return time.Unix(f.seconds.Load(), 0) }
	f.login.now = clock
	f.token = durableLogin(t, f.login)

	// The resource relay has no local database or device store. All account
	// operations cross the real proxy-storage gRPC connection to the login node.
	loginListener := bufconn.Listen(1 << 20)
	loginServer := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info.FullMethod == internalpb.LoginNodeDB_GetAccount_FullMethodName {
			lookup := f.lookups.Add(1)
			if f.lookupError.Load() || f.secondLookupError.Load() && lookup%2 == 0 {
				return nil, status.Error(codes.Unavailable, "synthetic account lookup failure")
			}
		}
		return handler(ctx, req)
	}))
	internalpb.RegisterLoginNodeDBServer(loginServer, NewLoginNodeDBServer(f.login.storage.(*storage.LocalStorage)))
	go func() { _ = loginServer.Serve(loginListener) }()
	t.Cleanup(func() { loginServer.Stop(); _ = loginListener.Close() })
	var err error
	f.connection, err = grpc.NewClient("passthrough:///durable-login-node",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return loginListener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.connection.Close() })
	f.remote = storage.NewProxyStorage()
	f.remote.SetConnection(f.connection)
	f.relay = securityProxy(f.remote)
	f.relay.tunnelServer.now = clock
	if f.relay.isLoginNode || f.relay.devices != nil {
		t.Fatal("publisher fixture must use a resource relay")
	}

	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	data, err := json.Marshal(map[string]any{"server": "https://tunn.test", "access_token": f.token.Access, "refresh_token": f.token.Refresh, "device_id": f.token.Device, "expires_at": clock().Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	_, manager, err := client.LoadTunnelToken(context.Background(), "tunn.test", false)
	if err != nil || manager == nil {
		t.Fatal("load synthetic device state", err)
	}
	manager.Now = clock
	manager.HTTPClient = &http.Client{Transport: accountsHTTPFake(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://tunn.test/api/device/refresh" {
			return nil, errors.New("unexpected credential URL")
		}
		response := httptest.NewRecorder()
		f.login.handleDeviceRefresh(response, r)
		if response.Code == http.StatusOK {
			f.refreshes.Add(1)
		}
		return response.Result(), nil
	})}

	certificateSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateSource.TLS.Certificates[0]
	certificateSource.Close()
	relayListener := bufconn.Listen(1 << 20)
	relayServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}})))
	pb.RegisterTunnelServiceServer(relayServer, f.relay.tunnelServer)
	go func() { _ = relayServer.Serve(relayListener) }()
	t.Cleanup(func() { relayServer.Stop(); _ = relayListener.Close() })
	f.publisher = &client.ServeClient{
		TunnelID: "durable-reconnect", TargetURL: "127.0.0.1:1", EndpointProtocol: "tcp",
		ServerAddr: "resource.tunn.test", Credentials: manager, TunnelKey: f.relay.config.WellKnownKey,
		AllowedEmails: []string{"owner@example.com"}, Insecure: true, Quiet: true,
		DialContext:  func(context.Context, string, string) (net.Conn, error) { return relayListener.Dial() },
		InitialDelay: 20 * time.Millisecond, MaxReconnectDelay: 80 * time.Millisecond,
		RenewInterval: 10 * time.Millisecond, ConnectTimeout: 3 * time.Second,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnLifecycle: func(event client.LifecycleEvent) { f.events <- event },
	}
	return f
}

func (f *durablePublisherFixture) run(t *testing.T) <-chan error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done, stopped := make(chan error, 1), make(chan struct{})
	go func() { defer close(stopped); done <- f.publisher.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Error("publisher did not stop")
		}
	})
	return done
}

func TestDurableServeClientRecoversFromProxyStorageOutage(t *testing.T) {
	for _, mode := range []string{"unavailable", "lookup-error"} {
		t.Run(mode, func(t *testing.T) {
			f := newDurablePublisherFixture(t)
			if mode == "unavailable" {
				f.remote.SetConnection(nil)
			} else {
				f.lookupError.Store(true)
			}
			// Refresh HTTP has recovered after an outage longer than the lease,
			// while the relay's account-storage connection is still unavailable.
			f.seconds.Add(6 * 60)
			done := f.run(t)
			retries := 0
			deadline := time.After(5 * time.Second)
			for {
				select {
				case err := <-done:
					t.Fatalf("publisher stopped during transient storage outage (login required=%v): %v", client.LoginRequired(err), err)
				case event := <-f.events:
					if event.State == client.StateReconnecting {
						if event.Err == nil || !strings.Contains(event.Err.Error(), "Account service temporarily unavailable.") || client.LoginRequired(event.Err) {
							t.Fatalf("account outage was not transient: %v", event.Err)
						}
						cap := f.publisher.InitialDelay * time.Duration(1<<retries)
						if event.RetryDelay < cap/2 || event.RetryDelay > cap {
							t.Fatalf("retry %d has no exponential backoff: %v", retries, event.RetryDelay)
						}
						retries++
						if retries == 3 {
							if f.refreshes.Load() != 1 {
								t.Fatalf("storage outage forced unnecessary refreshes: %d", f.refreshes.Load())
							}
							f.lookupError.Store(false)
							f.remote.SetConnection(f.connection)
						}
					}
					if event.State == client.StateReady {
						if retries != 3 {
							t.Fatalf("publisher registered before storage recovered: retries=%d", retries)
						}
						return
					}
				case <-deadline:
					t.Fatal("publisher failed to recover when proxy storage returned")
				}
			}
		})
	}
}

func TestDurableServeClientStopsAfterDeviceRevocation(t *testing.T) {
	f := newDurablePublisherFixture(t)
	done := f.run(t)
	for ready := false; !ready; {
		select {
		case event := <-f.events:
			ready = event.State == client.StateReady
		case err := <-done:
			t.Fatal("publisher stopped before revocation", err)
		case <-time.After(5 * time.Second):
			t.Fatal("publisher never registered")
		}
	}
	if _, err := f.login.devices.db.Exec(`UPDATE durable_devices SET revoked=? WHERE id=?`, f.seconds.Load(), f.token.Device); err != nil {
		t.Fatal(err)
	}
	f.seconds.Add(240) // Trigger renewal on the next publisher lease check.
	select {
	case err := <-done:
		if !client.LoginRequired(err) {
			t.Fatal("revoked device did not stop with login required", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked device kept running")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, exists := f.relay.tunnelServer.GetTunnel(f.publisher.TunnelID); !exists {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("revoked publisher left a registered tunnel")
}

type deviceAccountStorage struct {
	storage.Storage
	account *storage.Account
}

func (s deviceAccountStorage) GetAccount(context.Context, string) (*storage.Account, error) {
	return s.account, nil
}

func TestDurablePublisherMissingOrInactiveAccountRemainsTerminal(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	for _, account := range []*storage.Account{nil, {OperationalState: "suspended"}} {
		relay := securityProxy(deviceAccountStorage{Storage: p.storage, account: account})
		if _, err := relay.tunnelServer.validatePublisherToken(context.Background(), token.Access); err == nil || errors.Is(err, storage.ErrNotAvailable) {
			t.Fatalf("missing or inactive account was not terminal: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 1), outgoing: make(chan *pb.TunnelMessage, 1)}
		stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{
			TunnelId: "terminal-account", TargetUrl: "tcp", EndpointProtocol: "tcp", AuthToken: token.Access, TunnelKey: relay.config.WellKnownKey,
			Capabilities: []string{deviceReauthCapability, "connection-stream-v1"},
		}}}
		err := relay.tunnelServer.EstablishTunnel(stream)
		cancel()
		if err == nil {
			t.Fatal("missing or inactive account registered")
		}
		select {
		case response := <-stream.outgoing:
			if response.GetRegisterResponse().ErrorMessage != "Invalid or expired token. Run 'tunn login' to refresh." {
				t.Fatal("missing or inactive account became retryable", response)
			}
		default:
			t.Fatal("missing terminal registration response")
		}
	}
}
