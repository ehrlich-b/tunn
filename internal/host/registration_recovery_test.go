package host

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type interruptedPublisherStream struct {
	grpc.ServerStream
	interrupt <-chan struct{}
}

func (s *interruptedPublisherStream) RecvMsg(m any) error {
	result := make(chan error, 1)
	go func() { result <- s.ServerStream.RecvMsg(m) }()
	select {
	case err := <-result:
		return err
	case <-s.interrupt:
		return status.Error(codes.DeadlineExceeded, "synthetic publisher transport loss")
	}
}

type recoveryAvailability struct {
	*storage.ProxyStorage
	unavailable *atomic.Bool
}

func (s *recoveryAvailability) Available() bool {
	return !s.unavailable.Load() && s.ProxyStorage.Available()
}

// Real ServeClient -> relay -> proxy storage -> login-node storage. Only the
// transport loss and final report error are injected; registration and cleanup
// execute the production code. A name conflict remains terminal to the client.
func TestRegistrationRecoveryRealClient(t *testing.T) {
	for _, mode := range []string{"delivered", "lost-down", "unimplemented", "lost-up-and-release", "lost-up-and-release-maintenance", "lost-up-and-release-other-relay"} {
		t.Run(mode, func(t *testing.T) {
			db, err := store.InitForTest()
			if err != nil {
				t.Fatal(err)
			}
			f := newMCPOAuthFixtureWithDB(t, db)
			local := f.p.storage.(*storage.LocalStorage)
			owner, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			up := make(chan struct{}, 4)
			released := make(chan struct{}, 4)
			var failed atomic.Int64
			var unavailable atomic.Bool
			var failedUp, failedRelease atomic.Int64
			loginListener := bufconn.Listen(1 << 20)
			login := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
				if info.FullMethod == internalpb.LoginNodeDB_UnregisterTunnelSession_FullMethodName && unavailable.Load() {
					failedRelease.Add(1)
					return nil, status.Error(codes.DeadlineExceeded, "synthetic conditional release outage")
				}
				if r, ok := req.(*internalpb.TunnelAlertRequest); ok {
					if r.Operation == "up" && strings.HasPrefix(mode, "lost-up-and-release") && failedUp.CompareAndSwap(0, 1) {
						unavailable.Store(true)
						up <- struct{}{}
						return nil, status.Error(codes.DeadlineExceeded, "synthetic lost initial up report")
					}
					if mode == "unimplemented" {
						return nil, status.Error(codes.Unimplemented, "legacy availability backend")
					}
					if r.Operation == "down" && (mode == "lost-down" || unavailable.Load()) {
						failed.Add(1)
						return nil, status.Error(codes.DeadlineExceeded, "synthetic lost final down report")
					}
					out, err := next(ctx, req)
					if r.Operation == "up" && err == nil {
						up <- struct{}{}
					}
					return out, err
				}
				out, err := next(ctx, req)
				if info.FullMethod == internalpb.LoginNodeDB_UnregisterTunnelSession_FullMethodName && err == nil {
					released <- struct{}{}
				}
				return out, err
			}))
			internalpb.RegisterLoginNodeDBServer(login, NewLoginNodeDBServer(local))
			go func() { _ = login.Serve(loginListener) }()
			defer login.Stop()
			connection, err := grpc.NewClient("passthrough:///recovery-login", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return loginListener.Dial() }))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			remote := storage.NewProxyStorage()
			remote.SetConnection(connection)
			server := NewTunnelServer(f.p.config, nil, nil, &recoveryAvailability{remote, &unavailable})
			server.SetSharingBackend(f.p.sharingBackend())
			f.p.tunnelServer = server
			var hits atomic.Int64
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte("private owner body"))
			}))
			defer origin.Close()
			privacy := func() {
				t.Helper()
				before := hits.Load()
				for _, test := range []struct {
					token  string
					cookie *http.Cookie
					code   int
				}{{"", nil, 302}, {"invalid-token", nil, 401}} {
					r := f.request("GET", "https://recovery.tunn.test/", "", "", test.token, test.cookie)
					if r.Code != test.code {
						t.Fatalf("privacy response=%d want=%d body=%s", r.Code, test.code, r.Body)
					}
				}
				if hits.Load() != before {
					t.Fatal("denied request reached origin")
				}
				r := f.request("GET", "https://recovery.tunn.test/", "", "", "", securityCookie(t, f.p, owner.PrimaryEmail))
				if r.Code != 200 || r.Body.String() != "private owner body" {
					t.Fatalf("owner response=%d %s", r.Code, r.Body)
				}
			}
			cert := httptest.NewTLSServer(http.NotFoundHandler())
			certificate := cert.TLS.Certificates[0]
			cert.Close()
			drop := make(chan struct{})
			ended := make(chan struct{})
			resume := make(chan struct{})
			defer func() {
				select {
				case <-resume:
				default:
					close(resume)
				}
			}()
			var streams atomic.Int64
			relay := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}})), grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, next grpc.StreamHandler) error {
				if streams.Add(1) == 1 {
					defer close(ended)
					return next(srv, &interruptedPublisherStream{ServerStream: ss, interrupt: drop})
				}
				select {
				case <-resume:
				case <-ss.Context().Done():
					return ss.Context().Err()
				}
				return next(srv, ss)
			}))
			pb.RegisterTunnelServiceServer(relay, server)
			listener := bufconn.Listen(1 << 20)
			go func() { _ = relay.Serve(listener) }()
			defer relay.Stop()
			var otherListener *bufconn.Listener
			var otherServer *TunnelServer
			var useOther atomic.Bool
			if mode == "lost-up-and-release-other-relay" {
				otherServer = NewTunnelServer(f.p.config, nil, nil, &recoveryAvailability{remote, &unavailable})
				otherServer.SetSharingBackend(f.p.sharingBackend())
				otherRelay := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}})), grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, next grpc.StreamHandler) error {
					select {
					case <-resume:
					case <-ss.Context().Done():
						return ss.Context().Err()
					}
					return next(srv, ss)
				}))
				pb.RegisterTunnelServiceServer(otherRelay, otherServer)
				otherListener = bufconn.Listen(1 << 20)
				go func() { _ = otherRelay.Serve(otherListener) }()
				defer otherRelay.Stop()
			}
			ready := make(chan struct{}, 4)
			pending := make(chan struct{}, 4)
			publisher := &client.ServeClient{OnLifecycle: func(e client.LifecycleEvent) {
				if e.State == client.StateReconnecting && e.Err != nil && strings.Contains(e.Err.Error(), "Previous publisher session is still active") {
					select {
					case pending <- struct{}{}:
					default:
					}
				}
			}, TunnelID: "recovery", TargetURL: origin.URL, RequireSharing: true, ServerAddr: "relay.test:443", AuthToken: createTestJWT(owner.PrimaryEmail, server.cfg.JWTSecret), TunnelKey: server.cfg.WellKnownKey, Insecure: true, Quiet: true,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if addr == "relay.test:443" {
						if useOther.Load() {
							return otherListener.DialContext(ctx)
						}
						return listener.DialContext(ctx)
					}
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				}, InitialDelay: 20 * time.Millisecond, MaxReconnectDelay: 40 * time.Millisecond, OnRegistered: func(string) { ready <- struct{}{} }}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			exited := make(chan struct{})
			go func() { defer close(exited); done <- publisher.Run(ctx) }()
			defer func() {
				cancel()
				select {
				case <-exited:
				case <-time.After(3 * time.Second):
					t.Error("publisher did not stop")
				}
			}()
			wait := func(ch <-chan struct{}, label string) {
				t.Helper()
				select {
				case <-ch:
				case err := <-done:
					t.Fatalf("%s: publisher exited: %v", label, err)
				case <-time.After(3 * time.Second):
					t.Fatalf("%s stalled", label)
				}
			}
			wait(ready, "initial registration")
			if mode != "unimplemented" {
				wait(up, "initial availability")
			}
			// The reporting-only outage leaves the ordinary data plane usable.
			privacy()
			original, exists := server.GetTunnel("recovery")
			if !exists {
				t.Fatal("initial route absent")
			}
			oldSession := original.alertSession
			useOther.Store(otherServer != nil)
			close(drop)
			wait(ended, "old teardown")
			if _, exists := server.GetTunnel("recovery"); exists {
				t.Fatal("old route retained")
			}
			if strings.HasPrefix(mode, "lost-up-and-release") {
				count, err := local.GetTunnelCount(context.Background(), owner.ID)
				var rows int
				if err != nil || count != 1 {
					t.Fatal("outage fabricated cleanup", count, err)
				}
				if err := db.QueryRow("SELECT count(*) FROM tunnel_availability WHERE tunnel='recovery'").Scan(&rows); err != nil || rows != 0 {
					t.Fatal("expected no row for expiry to sweep", rows, err)
				}
				t.Logf("storage_unavailable=true local_route=false active_count=%d availability_rows=%d failed_up=%d failed_release=%d failed_down=%d", count, rows, failedUp.Load(), failedRelease.Load(), failed.Load())
				if failedRelease.Load() != 1 || failed.Load() != 1 {
					t.Fatal("conditional release and final reporting were skipped during outage")
				}
				unavailable.Store(false)
				if mode == "lost-up-and-release-maintenance" {
					maintenanceCtx, stopMaintenance := context.WithCancel(context.Background())
					maintenanceDone := make(chan struct{})
					go func() { defer close(maintenanceDone); server.registrationReleaseLoop(maintenanceCtx) }()
					defer func() { stopMaintenance(); <-maintenanceDone }()
					wait(released, "maintenance conditional release without a new publisher")
					count, err := local.GetTunnelCount(context.Background(), owner.ID)
					if err != nil || count != 0 {
						t.Fatal("maintenance did not release stale claim", count, err)
					}
					t.Log("maintenance confirmed release after storage recovery without an availability row or a new admission")
				}
			}
			before := hits.Load()
			for _, cookie := range []*http.Cookie{nil, securityCookie(t, f.p, owner.PrimaryEmail)} {
				r := f.request("GET", "https://recovery.tunn.test/", "", "", "", cookie)
				if r.Code != 503 || !strings.Contains(strings.ToLower(r.Body.String()), "offline") {
					t.Fatalf("offline=%d %s", r.Code, r.Body)
				}
			}
			if hits.Load() != before {
				t.Fatal("offline request reached origin")
			}
			if otherServer != nil {
				f.p.tunnelServer = otherServer
			}
			close(resume)
			if otherServer != nil {
				// The second relay must refuse admission and the real client must
				// back off before the first relay is allowed to retry cleanup.
				wait(pending, "cross-relay exact-generation backoff")
				if count, err := local.GetTunnelCount(context.Background(), owner.ID); err != nil || count != 1 {
					t.Fatal("pending reconnect changed active claim", count, err)
				}
				if _, exists := otherServer.GetTunnel("recovery"); exists {
					t.Fatal("pending reconnect installed a second route")
				}
				t.Log("second relay denied exact previous generation; real client backed off; original cleanup has not run")
				maintenanceCtx, stopMaintenance := context.WithCancel(context.Background())
				maintenanceDone := make(chan struct{})
				go func() { defer close(maintenanceDone); server.registrationReleaseLoop(maintenanceCtx) }()
				defer func() { stopMaintenance(); <-maintenanceDone }()
			}
			wait(ready, "same authenticated owner/name recovery")
			if mode != "unimplemented" {
				wait(up, "replacement availability")
			}
			count, err := local.GetTunnelCount(context.Background(), owner.ID)
			recoveredServer := server
			if otherServer != nil {
				recoveredServer = otherServer
			}
			replacement, exists := recoveredServer.GetTunnel("recovery")
			if err != nil || count != 1 || !exists || replacement.AccountID != owner.ID {
				t.Fatalf("replacement: count=%d route=%v err=%v", count, exists, err)
			}
			if (mode == "lost-down" || strings.HasPrefix(mode, "lost-up-and-release")) && failed.Load() != 1 {
				t.Fatal("final down fault not exercised")
			}
			if otherServer != nil {
				if replacement.alertSession == oldSession {
					t.Fatal("replacement reused old session")
				}
				if err := remote.UnregisterTunnelSession(context.Background(), "recovery", oldSession); err != nil {
					t.Fatal(err)
				}
				for _, op := range []string{"down", "up", "heartbeat"} {
					if _, err := remote.TunnelAlert(context.Background(), &internalpb.TunnelAlertRequest{AccountId: owner.ID, Tunnel: "recovery", Session: oldSession, Operation: op}); err != nil {
						t.Fatal(err)
					}
				}
				if count, err := local.GetTunnelCount(context.Background(), owner.ID); err != nil || count != 1 {
					t.Fatal("late old cleanup erased replacement", count, err)
				}
				var session string
				var online int
				if err := db.QueryRow("SELECT session,online FROM tunnel_availability WHERE tunnel='recovery'").Scan(&session, &online); err != nil || session != replacement.alertSession || online != 1 {
					t.Fatal("late reports changed replacement availability", session, online, err)
				}
				t.Log("delayed old relay cleanup/reports preserve second relay replacement and online generation")
			}
			privacy()
			t.Logf("mode=%s failed_down=%d replacement_route=%v active_count=%d owner_preserved=true private_body=200 anonymous=302 invalid_token=401 offline=503 denied_origin_hits=0", mode, failed.Load(), exists, count)
		})
	}
}

func TestRegistrationRecoveryRemoteGenerationFence(t *testing.T) {
	f := newTunnelAlertFixture(t, true)
	sessions := f.backend.(storage.TunnelSessions)
	ctx := context.Background()
	admit := func(session string) {
		t.Helper()
		r, err := sessions.RegisterTunnelSession(ctx, "remote-fence", f.owner.ID, "replica", session)
		if err != nil || !r.Allowed {
			t.Fatal(r, err)
		}
	}
	admit("old")
	for _, previous := range []string{"", "wrong", "old"} {
		r, err := f.backend.(storage.TunnelSessionRecovery).RegisterTunnelSessionAfter(ctx, "remote-fence", f.owner.ID, "other-replica", "candidate", previous)
		if err != nil || r.Allowed || (r.Reason == common.PublisherSessionPending) != (previous == "old") {
			t.Fatalf("previous=%q reply=%+v err=%v", previous, r, err)
		}
	}
	f.report("remote-fence", "old", "up", "")
	if err := sessions.UnregisterTunnelSession(ctx, "remote-fence", "old"); err != nil {
		t.Fatal(err)
	}
	admit("new")
	for _, phase := range []string{"before-up", "after-up"} {
		if phase == "after-up" {
			f.report("remote-fence", "new", "up", "")
		}
		for _, op := range []string{"down", "graceful", "up", "heartbeat"} {
			f.report("remote-fence", "old", op, "")
		}
		if err := sessions.UnregisterTunnelSession(ctx, "remote-fence", "old"); err != nil {
			t.Fatal(err)
		}
		count, err := f.backend.GetTunnelCount(ctx, f.owner.ID)
		if err != nil || count != 1 {
			t.Fatalf("%s active count=%d err=%v", phase, count, err)
		}
	}
	other, err := f.local.FindOrCreateByEmails(ctx, []string{"other@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if r, err := f.backend.(storage.TunnelSessionRecovery).RegisterTunnelSessionAfter(ctx, "remote-fence", other.ID, "replica", "different-owner", "new"); err != nil || r.Allowed || r.Reason == common.PublisherSessionPending {
		t.Fatal(r, err)
	}
	if r, err := f.backend.(storage.TunnelSessionRecovery).RegisterTunnelSessionAfter(ctx, "remote-fence", f.owner.ID, "replica", "stale-continuation", "old"); err != nil || r.Allowed || r.Reason == common.PublisherSessionPending {
		t.Fatal("old continuation matched replacement", r, err)
	}
	t.Log("proxy RPC preserves generation across admission, late reports, conditional cleanup and different-owner denial")
}

type unversionedRegistrationBackend struct {
	internalpb.UnimplementedLoginNodeDBServer
}

func (*unversionedRegistrationBackend) RegisterTunnel(context.Context, *internalpb.RegisterTunnelRequest) (*internalpb.RegisterTunnelResponse, error) {
	return &internalpb.RegisterTunnelResponse{Allowed: true}, nil
}
func (*unversionedRegistrationBackend) UnregisterTunnel(context.Context, *internalpb.UnregisterTunnelRequest) (*internalpb.UnregisterTunnelResponse, error) {
	return &internalpb.UnregisterTunnelResponse{}, nil
}

func TestRegistrationRecoveryRequiresGenerationConfirmation(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	defer listener.Close()
	server := grpc.NewServer()
	internalpb.RegisterLoginNodeDBServer(server, &unversionedRegistrationBackend{})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	conn, err := grpc.NewClient("passthrough:///unversioned", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	proxy := storage.NewProxyStorage()
	proxy.SetConnection(conn)
	if _, err := proxy.RegisterTunnelSession(context.Background(), "name", "owner", "node", "generation"); err == nil {
		t.Fatal("unversioned admission reported generation support")
	}
	if err := proxy.UnregisterTunnelSession(context.Background(), "name", "generation"); err == nil {
		t.Fatal("unversioned cleanup reported conditional success")
	}
	t.Log("legacy RPC reply cannot prove versioned admission or conditional cleanup")
}

// Hold an old final report inside actual deferred host teardown while admitting
// a replacement. Storage must already have released the removed local route.
type delayedRegistrationReports struct {
	storage.Storage
	storage.TunnelSessions
	alerts storage.TunnelAlerts
	up     chan string
	down   chan struct{}
	resume <-chan struct{}
}

func (s *delayedRegistrationReports) TunnelAlert(ctx context.Context, r *internalpb.TunnelAlertRequest) (*internalpb.TunnelAlertResponse, error) {
	if r.Operation == "down" {
		close(s.down)
		<-s.resume
	}
	out, err := s.alerts.TunnelAlert(ctx, r)
	if r.Operation == "up" && err == nil {
		s.up <- r.Session
	}
	return out, err
}
func TestRegistrationRecoveryDelayedHostTeardown(t *testing.T) {
	local := securityDB(t)
	owner, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	resume := make(chan struct{})
	defer func() {
		select {
		case <-resume:
		default:
			close(resume)
		}
	}()
	backend := &delayedRegistrationReports{Storage: local, TunnelSessions: local, alerts: local, up: make(chan string, 2), down: make(chan struct{}), resume: resume}
	server := NewTunnelServer(securityConfig(), nil, nil, backend)
	start := func() (context.CancelFunc, <-chan error) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 1), outgoing: make(chan *pb.TunnelMessage, 1)}
		stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "delayed", TargetUrl: "tcp", EndpointProtocol: "tcp", AuthToken: createTestJWT(owner.PrimaryEmail, server.cfg.JWTSecret), TunnelKey: server.cfg.WellKnownKey, Capabilities: []string{"connection-stream-v1", "graceful-stop-v1"}}}}
		done := make(chan error, 1)
		go func() { done <- server.EstablishTunnel(stream) }()
		select {
		case reply := <-stream.outgoing:
			if !reply.GetRegisterResponse().GetSuccess() {
				t.Fatal(reply)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("admission stalled")
		}
		select {
		case <-backend.up:
		case <-time.After(3 * time.Second):
			t.Fatal("up stalled")
		}
		return cancel, done
	}
	cancelOld, oldDone := start()
	defer cancelOld()
	cancelOld()
	select {
	case <-backend.down:
	case <-time.After(3 * time.Second):
		t.Fatal("old final report not reached")
	}
	if _, exists := server.GetTunnel("delayed"); exists {
		t.Fatal("old route retained")
	}
	cancelNew, newDone := start()
	// Mark cancellation as graceful so only the intentionally held old report blocks.
	replacement, _ := server.GetTunnel("delayed")
	defer func() {
		replacement.stop.CompareAndSwap(nil, &publisherStop{reason: publisherClientStop})
		cancelNew()
		select {
		case <-newDone:
		case <-time.After(3 * time.Second):
			t.Error("replacement teardown stalled")
		}
	}()
	close(resume)
	select {
	case <-oldDone:
	case <-time.After(3 * time.Second):
		t.Fatal("old teardown stalled")
	}
	current, exists := server.GetTunnel("delayed")
	count, err := local.GetTunnelCount(context.Background(), owner.ID)
	if !exists || current != replacement || err != nil || count != 1 {
		t.Fatal("old deferred teardown erased live replacement", exists, count, err)
	}
	t.Log("replacement admitted while old final report blocked; delayed old host teardown preserves replacement route and active registration")
}
