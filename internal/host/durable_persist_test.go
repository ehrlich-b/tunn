package host

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
)

// persistRelay is an in-process relay that can restart on the same address
// while keeping its SQLite login state, like a deploy of the login node.
type persistRelay struct {
	t       *testing.T
	db      *sql.DB
	clock   func() time.Time
	mu      sync.Mutex
	p       *ProxyServer
	gs      *grpc.Server
	server  *httptest.Server
	addr    atomic.Value // string
	pending atomic.Value // string: last token received in a RegisterClient
	applied atomic.Value // string: last token the relay finished processing
	refresh atomic.Int64
	// failRefresh makes the next N refresh calls fail without reaching the relay.
	failRefresh atomic.Int64
	// asleep stalls refresh calls until closed, then fails them.
	asleep atomic.Pointer[chan struct{}]
	// loseResponse commits the next refresh, then runs midRequest (the host
	// sleeping) and drops the connection before the client sees the response.
	loseResponse atomic.Int64
	midRequest   func()
	// Optional synchronization/trace for the first-renewal settle diagnostic.
	events      chan persistRenewalEvent
	refreshGate <-chan struct{}
}

func (r *persistRelay) start() {
	r.t.Helper()
	f := newMCPOAuthFixtureWithDB(r.t, r.db)
	p := f.p
	p.now = r.clock
	p.tunnelServer.now = r.clock
	gs := grpc.NewServer(grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &persistWatchedStream{ServerStream: ss, relay: r})
	}))
	pb.RegisterTunnelServiceServer(gs, p.tunnelServer)
	p.grpcServer = gs
	routes := p.createHandler()
	server := httptest.NewUnstartedServer(p.createHTTP2Router(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/device/refresh" {
			if wake := r.asleep.Load(); wake != nil {
				select {
				case <-*wake:
				case <-req.Context().Done():
				}
				http.Error(w, "network unavailable after sleep", http.StatusServiceUnavailable)
				return
			}
			if r.failRefresh.Load() > 0 {
				r.failRefresh.Add(-1)
				http.Error(w, "login node restarting", http.StatusServiceUnavailable)
				return
			}
			r.refresh.Add(1)
			r.event("refresh-start")
			if r.refreshGate != nil {
				select {
				case <-r.refreshGate:
				case <-req.Context().Done():
					return
				}
			}
			if r.loseResponse.Load() > 0 {
				r.loseResponse.Add(-1)
				routes.ServeHTTP(httptest.NewRecorder(), req)
				r.midRequest()
				panic(http.ErrAbortHandler)
			}
		}
		routes.ServeHTTP(w, req)
		if req.URL.Path == "/api/device/refresh" {
			r.event("refresh-return")
		}
	})))
	server.EnableHTTP2 = true
	server.StartTLS()
	r.mu.Lock()
	r.p, r.gs, r.server = p, gs, server
	r.mu.Unlock()
	r.addr.Store(server.Listener.Addr().String())
}

func (r *persistRelay) stop() {
	r.mu.Lock()
	gs, server := r.gs, r.server
	r.mu.Unlock()
	r.addr.Store("")
	gs.Stop()
	server.Close()
}

func (r *persistRelay) proxy() *ProxyServer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.p
}

func (r *persistRelay) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	addr, _ := r.addr.Load().(string)
	if addr == "" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: os.ErrDeadlineExceeded}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

type persistRenewalEvent struct {
	Kind  string
	Clock time.Time
}

func (r *persistRelay) event(kind string) {
	if r.events != nil {
		r.events <- persistRenewalEvent{kind, r.clock()}
	}
}

type persistWatchedStream struct {
	grpc.ServerStream
	relay *persistRelay
}

// The relay applies a RegisterClient before it asks for the next message, so
// the next RecvMsg marks the previous token as applied.
func (s *persistWatchedStream) RecvMsg(m any) error {
	if token, _ := s.relay.pending.Load().(string); token != "" {
		previous, _ := s.relay.applied.Load().(string)
		s.relay.applied.Store(token)
		if previous != token {
			s.relay.event("register-applied")
		}
	}
	err := s.ServerStream.RecvMsg(m)
	if msg, ok := m.(*pb.TunnelMessage); err == nil && ok && msg.GetRegisterClient() != nil {
		s.relay.pending.Store(msg.GetRegisterClient().AuthToken)
		s.relay.event("register-received")
	}
	return err
}

type persistSavedLogin struct {
	Access  string    `json:"access_token"`
	Refresh string    `json:"refresh_token"`
	Expires time.Time `json:"expires_at"`
	Pending string    `json:"pending_request_id"`
}

func readPersistLogin(t *testing.T, dir string) persistSavedLogin {
	t.Helper()
	var saved persistSavedLogin
	data, err := os.ReadFile(filepath.Join(dir, "credentials.json"))
	if err == nil {
		err = json.Unmarshal(data, &saved)
	}
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

// A publisher logged in once stays registered for 7 simulated days through a
// relay restart, the host clock stepping back, a login-node outage during
// reauthentication, a host sleep past expiry and a host sleep that loses a
// committed rotation's response. Only a terminal refresh rejection stops it.
func TestDogfoodPublisherPersistsSevenDays(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	clock := func() time.Time { return time.Unix(seconds.Load(), 0) }
	var skew atomic.Int64 // client clock offset from the relay, in seconds
	clientClock := func() time.Time { return clock().Add(time.Duration(skew.Load()) * time.Second) }
	relay := &persistRelay{t: t, db: db, clock: clock, midRequest: func() { seconds.Add(int64(2 * time.Hour / time.Second)) }}
	relay.start()
	login := durableLogin(t, relay.proxy())
	firstRefresh := login.Refresh

	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	saved := map[string]any{"server": "https://tunn.test", "access_token": login.Access, "refresh_token": login.Refresh, "device_id": login.Device, "expires_at": clock().Add(time.Duration(login.Expires) * time.Second)}
	data, _ := json.Marshal(saved)
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	token, manager, err := client.LoadTunnelToken(context.Background(), "tunn.test", true)
	if err != nil || manager == nil || token != login.Access {
		t.Fatal("saved device login did not load", err)
	}
	manager.Now = clientClock
	manager.HTTPClient = &http.Client{Transport: &http.Transport{DialContext: relay.dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("build-host")) }))
	defer origin.Close()

	var registrations atomic.Int64
	publisher := &client.ServeClient{
		TunnelID: "build-host-ssh", TargetURL: origin.URL, ServerAddr: "tunn.test:443", AuthToken: token, Credentials: manager,
		TunnelKey: relay.proxy().config.WellKnownKey, AllowedEmails: []string{"owner@example.com"}, Insecure: true, Quiet: true,
		DialContext: relay.dial, InitialDelay: 5 * time.Millisecond, MaxReconnectDelay: 50 * time.Millisecond, RenewInterval: time.Millisecond,
		OnRegistered: func(string) { registrations.Add(1) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- publisher.Run(ctx) }()
	defer func() { cancel(); relay.stop() }()

	// settle waits until the relay holds the publisher's current login and the
	// login is not yet due for renewal.
	var current persistSavedLogin
	settle := func(stage string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for first := true; ; first = false {
			select {
			case err := <-done:
				t.Fatalf("%s: publisher stopped: %v", stage, err)
			default:
			}
			if !first || !current.Expires.After(clientClock().Add(time.Minute)) {
				current = readPersistLogin(t, dir)
			}
			applied, _ := relay.applied.Load().(string)
			_, registered := relay.proxy().tunnelServer.GetTunnel("build-host-ssh")
			if registered && current.Pending == "" && applied == current.Access && current.Expires.After(clientClock().Add(time.Minute)) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: publisher not registered with a current login (registered=%t)", stage, registered)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}
	settle("initial registration")

	start := clock()
	const step = 30 * time.Second
	restarted, steppedBack, slept, lost := false, false, false, false
	for clock().Sub(start) < 7*24*time.Hour+time.Hour {
		seconds.Add(int64(step / time.Second))
		elapsed := clock().Sub(start)
		switch {
		case !restarted && elapsed >= 3*24*time.Hour:
			restarted = true
			relay.stop()
			relay.start()
		case !steppedBack && elapsed >= 4*24*time.Hour:
			// The host clock steps back 2 hours, so the client believes its
			// login is valid after the relay has expired it.
			steppedBack = true
			skew.Store(-int64(2 * time.Hour / time.Second))
		case !slept && elapsed >= 5*24*time.Hour:
			// The host sleeps for 3 hours: it cannot renew, so the relay drops
			// the expired lease. On wake its first refreshes fail twice more.
			slept = true
			wake := make(chan struct{})
			relay.asleep.Store(&wake)
			seconds.Add(int64(3 * time.Hour / time.Second))
			deadline := time.Now().Add(10 * time.Second)
			for _, registered := relay.proxy().tunnelServer.GetTunnel("build-host-ssh"); registered; _, registered = relay.proxy().tunnelServer.GetTunnel("build-host-ssh") {
				if time.Now().After(deadline) {
					t.Fatal("relay kept an expired lease")
				}
				time.Sleep(time.Millisecond)
			}
			relay.failRefresh.Store(2)
			relay.asleep.Store(nil)
			close(wake)
		case !lost && elapsed >= 6*24*time.Hour:
			// The relay commits the next rotation, the host sleeps 2 hours
			// before reading the response, and the connection drops. The
			// client retries with the same request ID long after the commit.
			lost = true
			relay.loseResponse.Store(1)
		}
		settle(elapsed.String())
	}
	if !restarted || !steppedBack || !slept || !lost || relay.loseResponse.Load() != 0 || registrations.Load() != 5 {
		t.Fatalf("restart=%t clock=%t sleep=%t lost=%t registrations=%d, want one per disruption", restarted, steppedBack, slept, lost, registrations.Load())
	}
	if relay.refresh.Load() < 7*24*60/5 {
		t.Fatalf("only %d refreshes in 7 days of 5-minute logins", relay.refresh.Load())
	}
	var revoked int64
	if err := db.QueryRow(`SELECT revoked FROM durable_devices WHERE id=?`, login.Device).Scan(&revoked); err != nil || revoked != 0 {
		t.Fatal("device revoked during normal renewal", err, revoked)
	}

	// Replaying the first, long-consumed refresh token revokes the device. The
	// publisher's next renewal is rejected and it stops once with a login error.
	rec, _ := durableRefresh(relay.proxy(), firstRefresh, strings.Repeat("r", 43))
	if rec.Code != http.StatusUnauthorized {
		t.Fatal("consumed refresh token accepted", rec.Code)
	}
	if rec, _ = durableRefresh(relay.proxy(), readPersistLogin(t, dir).Refresh, strings.Repeat("s", 43)); rec.Code != http.StatusUnauthorized {
		t.Fatal("reuse did not revoke the device family", rec.Code)
	}
	before := relay.refresh.Load()
	// Renewal is due but the relay lease is still live, so the publisher's own
	// renewal is the request that meets the rejection.
	seconds.Store(readPersistLogin(t, dir).Expires.Add(-30*time.Second).Unix() - skew.Load())
	select {
	case err := <-done:
		if !client.LoginRequired(err) || !strings.Contains(err.Error(), "tunn login") {
			t.Fatal("terminal rejection did not ask for login", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("publisher kept running after its login was revoked")
	}
	time.Sleep(100 * time.Millisecond)
	if attempts := relay.refresh.Load() - before; attempts != 1 {
		t.Fatalf("publisher sent %d refreshes after revocation, want 1", attempts)
	}
}
