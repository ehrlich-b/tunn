package host

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

type renewalObservedStorage struct {
	storage.Storage
	up chan struct{}
}

func (s renewalObservedStorage) TunnelAlert(ctx context.Context, r *internalpb.TunnelAlertRequest) (*internalpb.TunnelAlertResponse, error) {
	response, err := s.Storage.(storage.TunnelAlerts).TunnelAlert(ctx, r)
	if r.Operation == "up" && err == nil {
		s.up <- struct{}{}
	}
	return response, err
}

type refreshRejectTransport struct{}

func (refreshRejectTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"invalid_grant"}`))}, nil
}

// A terminal refresh failure stops the real CLI while the owner context is live.
// It must retain outage tracking rather than count as an intentional owner stop.
func TestTunnelAlertsCredentialFailure(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprintf("remote=%v", remote), func(t *testing.T) {
			f := &tunnelAlertFixture{t: t, mailer: &tunnelAlertMailer{}}
			f.clock.Store(time.Now().Unix())
			db, err := store.InitForTest()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Close() })
			f.local = storage.NewLocalStorageWithClock(db, func() time.Time { return time.Unix(f.clock.Load(), 0) })
			f.backend = f.local
			if remote {
				f.backend = securityReplicaStorage(t, f.local)
			}
			f.owner, err = f.local.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			f.p = securityProxy(f.local)
			f.p.emailSender = f.mailer
			f.p.devices, err = newDeviceCredentialStore(db)
			if err != nil {
				t.Fatal(err)
			}
			token := durableLogin(t, f.p)
			observed := renewalObservedStorage{Storage: f.backend, up: make(chan struct{}, 8)}
			server := NewTunnelServer(f.p.config, nil, nil, observed)
			g := grpc.NewServer()
			pb.RegisterTunnelServiceServer(g, server)
			defer g.Stop()
			cert := httptest.NewTLSServer(http.NotFoundHandler())
			f.p.tlsConfig = cert.TLS.Clone()
			cert.Close()
			f.p.grpcServer = g
			f.p.HTTP2Addr = opsFreeTCP(t)
			relayCtx, relayCancel := context.WithCancel(context.Background())
			relayDone := make(chan error, 1)
			go func() { relayDone <- f.p.startHTTP2Server(relayCtx, http.NotFoundHandler()) }()
			t.Cleanup(func() {
				relayCancel()
				select {
				case err := <-relayDone:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("production listener shutdown timed out")
				}
			})
			addr := f.p.HTTP2Addr
			origin := "https://" + addr
			dir := t.TempDir()
			t.Setenv("TUNN_CONFIG_DIR", dir)
			now := time.Now()
			var clock atomic.Int64
			clock.Store(now.Unix())
			data, err := json.Marshal(map[string]any{"server": origin, "access_token": token.Access, "refresh_token": token.Refresh, "device_id": token.Device, "expires_at": now.Add(5 * time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			_, manager, err := client.LoadTunnelToken(context.Background(), addr, true)
			if err != nil {
				t.Fatal(err)
			}
			manager.Now = func() time.Time { return time.Unix(clock.Load(), 0) }
			manager.HTTPClient = &http.Client{Transport: refreshRejectTransport{}}
			ownerCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ready := make(chan struct{})
			c := &client.ServeClient{TunnelID: "renewal-failure", ServerAddr: addr, TargetURL: "http://127.0.0.1:1", Insecure: true, Quiet: true, TunnelKey: server.cfg.WellKnownKey, Credentials: manager, RenewInterval: 20 * time.Millisecond, OnRegistered: func(string) { close(ready) }}
			done := make(chan error, 1)
			go func() { done <- c.Run(ownerCtx) }()
			select {
			case <-ready:
			case err := <-done:
				t.Fatalf("not registered: %v", err)
			case <-ownerCtx.Done():
				t.Fatal("registration timed out")
			}
			select {
			case <-observed.up:
			case <-time.After(5 * time.Second):
				t.Fatal("availability not persisted")
			}
			conn, ok := server.GetTunnel("renewal-failure")
			if !ok || !conn.Supports(common.CapabilityGracefulStopV1) || !conn.Supports(common.CapabilityFailureStopV1) {
				t.Fatal("publisher did not negotiate stop messages")
			}
			clock.Add(300)
			select {
			case err := <-done:
				if !client.LoginRequired(err) {
					t.Fatalf("expected terminal renewal rejection: %v", err)
				}
			case <-ownerCtx.Done():
				t.Fatal("publisher failed to stop")
			}
			if ownerCtx.Err() != nil {
				t.Fatal("owner canceled")
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				count, err := f.local.GetTunnelCount(context.Background(), f.owner.ID)
				if err != nil {
					t.Fatal(err)
				}
				if count == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("cleanup timed out")
				}
				time.Sleep(time.Millisecond)
			}
			t.Log("terminal renewal rejected; publisher exited LoginRequired while owner context remained live")
			f.clock.Add(599)
			f.sweep(0)
			f.clock.Add(1)
			f.sweep(1)
			if !strings.Contains(f.mailer.messages[0].body, "Invalid or expired token") {
				t.Fatal("credential failure diagnosis missing from alert")
			}
			f.sweep(1)
			f.clock.Add(7200)
			f.sweep(1)
		})
	}
}
