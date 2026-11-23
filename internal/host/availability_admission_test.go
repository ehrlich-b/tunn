package host

import (
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Both relays use independent real proxy-storage RPC callers. Only failed
// releases and publisher messages are controlled; no admission is stubbed.
type expiryBackend struct {
	*storage.ProxyStorage
	up          chan string
	failRelease atomic.Bool
	failed      atomic.Int32
}

func (b *expiryBackend) TunnelAlert(ctx context.Context, r *internalpb.TunnelAlertRequest) (*internalpb.TunnelAlertResponse, error) {
	out, err := b.ProxyStorage.TunnelAlert(ctx, r)
	if r.Operation == "up" && err == nil {
		b.up <- r.Session
	}
	return out, err
}
func (b *expiryBackend) UnregisterTunnelSession(ctx context.Context, name, session string) error {
	if b.failRelease.Load() {
		b.failed.Add(1)
		return fmt.Errorf("controlled conditional-release failure")
	}
	return b.ProxyStorage.UnregisterTunnelSession(ctx, name, session)
}

type expiryStream struct {
	*durableControlStream
	body    string
	fixture *expiryFixture
}

func (s *expiryStream) Send(m *pb.TunnelMessage) error {
	if m.GetRegisterResponse().GetSuccess() {
		// Hold both map locks for one coherent snapshot at every installation.
		s.fixture.relays[0].mu.RLock()
		s.fixture.relays[1].mu.RLock()
		n := len(s.fixture.relays[0].tunnels) + len(s.fixture.relays[1].tunnels)
		s.fixture.relays[1].mu.RUnlock()
		s.fixture.relays[0].mu.RUnlock()
		if n > 1 {
			s.fixture.t.Errorf("simultaneously installed routes=%d", n)
		}
	}
	if r := m.GetHttpRequest(); r != nil {
		select {
		case s.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_HttpResponse{HttpResponse: &pb.HttpResponse{ConnectionId: r.ConnectionId, StatusCode: 200, Body: []byte(s.body)}}}:
			return nil
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
	return s.durableControlStream.Send(m)
}

type expiryPublisher struct {
	conn     *TunnelConnection
	cancel   context.CancelFunc
	done     chan struct{}
	accepted bool
}

func (p *expiryPublisher) stop(t *testing.T) {
	t.Helper()
	p.cancel()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		t.Fatal("publisher teardown stalled")
	}
}

type expiryFixture struct {
	t        *testing.T
	db       *sql.DB
	local    *storage.LocalStorage
	owner    *storage.Account
	clock    atomic.Int64
	relays   [2]*TunnelServer
	backends [2]*expiryBackend
}

const expiryName = "expiry-owner"

func newExpiryFixture(t *testing.T) *expiryFixture {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	// Match the login node's connection limit. Both RPC callers and HTTP
	// usage writes share this database, including during removal races.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	f := &expiryFixture{t: t, db: db}
	f.clock.Store(time.Now().Unix())
	f.local = storage.NewLocalStorageWithClock(db, func() time.Time { return time.Unix(f.clock.Load(), 0) })
	f.owner, err = f.local.FindOrCreateByEmails(context.Background(), []string{"expiry@example.test"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.relays {
		b := &expiryBackend{ProxyStorage: securityReplicaStorage(t, f.local), up: make(chan string, 16)}
		f.backends[i] = b
		f.relays[i] = NewTunnelServer(securityConfig(), nil, nil, b)
	}
	return f
}
func (f *expiryFixture) start(i int, body, previous string) *expiryPublisher {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &expiryStream{durableControlStream: &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 16), outgoing: make(chan *pb.TunnelMessage, 16)}, body: body, fixture: f}
	stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{
		TunnelId: expiryName, TargetUrl: "http://publisher.invalid", AuthToken: createTestJWT(f.owner.PrimaryEmail, f.relays[i].cfg.JWTSecret), TunnelKey: f.relays[i].cfg.WellKnownKey, PreviousSession: previous,
	}}}
	p := &expiryPublisher{cancel: cancel, done: make(chan struct{})}
	go func() { defer close(p.done); _ = f.relays[i].EstablishTunnel(stream) }()
	f.t.Cleanup(func() { p.stop(f.t) })
	select {
	case m := <-stream.outgoing:
		p.accepted = m.GetRegisterResponse().GetSuccess()
	case <-time.After(3 * time.Second):
		f.t.Fatal("registration stalled")
	}
	if p.accepted {
		select {
		case <-f.backends[i].up:
		case <-time.After(3 * time.Second):
			f.t.Fatal("initial up stalled")
		}
		p.conn, _ = f.relays[i].GetTunnel(expiryName)
	} else {
		p.stop(f.t)
	}
	return p
}
func (f *expiryFixture) expire() {
	f.t.Helper()
	if _, err := f.local.ClaimTunnelAlerts(context.Background()); err != nil {
		f.t.Fatal(err)
	}
}
func (f *expiryFixture) report(i int, p *expiryPublisher, op string) {
	f.t.Helper()
	if err := f.relays[i].reportAvailability(p.conn, op, ""); err != nil {
		f.t.Fatal(err)
	}
}

// Assert real route delivery as well as claim and availability identity. A
// retained map entry alone cannot count as a usable publisher.
func (f *expiryFixture) check(route, session string, online, claims int) {
	f.t.Helper()
	routes := 0
	for _, s := range f.relays {
		conn, ok := s.GetTunnel(expiryName)
		if !ok {
			continue
		}
		routes++
		f.probe(conn, route)
	}
	wantRoutes := 1
	if route == "" {
		wantRoutes = 0
	}
	if routes != wantRoutes || routes > 1 {
		f.t.Fatalf("routable owners=%d want=%d", routes, wantRoutes)
	}
	count, err := f.local.GetTunnelCount(context.Background(), f.owner.ID)
	if err != nil || int(count) != claims {
		f.t.Fatalf("claims=%d want=%d err=%v", count, claims, err)
	}
	var got, owner string
	var live int
	err = f.db.QueryRow("SELECT session,owner,online FROM tunnel_availability WHERE tunnel=?", expiryName).Scan(&got, &owner, &live)
	if err != nil || got != session || owner != f.owner.ID || live != online {
		f.t.Fatalf("availability=%s/%s/%d want=%s/%s/%d err=%v", got, owner, live, session, f.owner.ID, online, err)
	}
	f.t.Logf("route=%q availability=%s/%d claims=%d", route, session, online, claims)
}

func (f *expiryFixture) probe(conn *TunnelConnection, route string) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	req := httptest.NewRequest("GET", "https://expiry-owner.test/probe", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	err := (&ProxyServer{storage: f.local}).proxyHTTPOverGRPC(w, req, conn)
	cancel()
	if err != nil || w.Code != 200 || w.Body.String() != route {
		f.t.Fatalf("route body=%q code=%d err=%v want=%q", w.Body.String(), w.Code, err, route)
	}
	f.t.Logf("forwarded HTTP body=%q session=%s", w.Body.String(), conn.alertSession)
}

func TestAvailabilityExpiryRetainsAdmission(t *testing.T) {
	f := newExpiryFixture(t)
	a := f.start(0, "A", "")
	if !a.accepted {
		t.Fatal("A denied")
	}
	f.check("A", a.conn.alertSession, 1, 1)
	f.clock.Add(91)
	f.expire()
	// Run this exact test on aa2d141 too: capture the complete original symptom
	// before asserting, so denial alone cannot mask discarded live heartbeats.
	f.report(0, a, "heartbeat")
	count, err := f.local.GetTunnelCount(context.Background(), f.owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	b := f.start(1, "B", "")
	if count != 1 || b.accepted {
		f.probe(a.conn, "A")
		if b.accepted {
			f.probe(b.conn, "B")
		}
		t.Fatalf("heartbeat returned success; active count=%d; replacement allowed=%v", count, b.accepted)
	}
	f.check("A", a.conn.alertSession, 1, 1)
	// Availability reports cannot stand in for confirmed route removal/release.
	for _, op := range []string{"down", "graceful"} {
		f.report(0, a, op)
		f.check("A", a.conn.alertSession, 0, 1)
		if p := f.start(1, "B", a.conn.alertSession); p.accepted {
			t.Fatal("report released live admission")
		}
		f.report(0, a, "heartbeat")
		f.check("A", a.conn.alertSession, 1, 1)
	}
	a.stop(t)
	f.check("", a.conn.alertSession, 0, 0)
	b = f.start(1, "B", a.conn.alertSession)
	if !b.accepted {
		t.Fatal("B denied after removal/release")
	}
	f.check("B", b.conn.alertSession, 1, 1)
	for _, op := range []string{"heartbeat", "up", "down", "graceful"} {
		f.report(0, a, op)
		f.check("B", b.conn.alertSession, 1, 1)
	}
	if err := f.backends[0].UnregisterTunnelSession(context.Background(), expiryName, a.conn.alertSession); err != nil {
		t.Fatal(err)
	}
	f.check("B", b.conn.alertSession, 1, 1)
}

func TestAvailabilityRemovalAndReleaseFailures(t *testing.T) {
	f := newExpiryFixture(t)
	a := f.start(0, "A", "")
	if !a.accepted {
		t.Fatal("A denied")
	}
	f.clock.Add(91)
	f.expire()
	f.check("A", a.conn.alertSession, 0, 1)
	// A failed/unconfirmed removal leaves the actual route installed. Even an
	// explicit release attempt must fail before creating a retry obligation.
	err := f.relays[0].releaseRegistration(context.Background(), f.backends[0], registrationRelease{expiryName, a.conn.alertSession})
	if err == nil {
		t.Fatal("release succeeded without route removal")
	}
	f.relays[0].mu.RLock()
	pending := len(f.relays[0].pendingReleases)
	f.relays[0].mu.RUnlock()
	if pending != 0 {
		t.Fatal("failed removal queued an unsafe release")
	}
	f.check("A", a.conn.alertSession, 0, 1)
	if p := f.start(1, "B", a.conn.alertSession); p.accepted {
		t.Fatal("B admitted after failed removal")
	}
	f.report(0, a, "heartbeat")
	f.check("A", a.conn.alertSession, 1, 1)
	f.backends[0].failRelease.Store(true)
	a.stop(t)
	if f.backends[0].failed.Load() == 0 {
		t.Fatal("release fault unused")
	}
	f.check("", a.conn.alertSession, 0, 1)
	if p := f.start(1, "B", a.conn.alertSession); p.accepted {
		t.Fatal("B admitted before confirmed release")
	}
	if err := f.relays[0].releasePendingRegistrations(context.Background(), expiryName); err == nil {
		t.Fatal("retry hid release failure")
	}
	f.check("", a.conn.alertSession, 0, 1)
	f.backends[0].failRelease.Store(false)
	if err := f.relays[0].releasePendingRegistrations(context.Background(), expiryName); err != nil {
		t.Fatal(err)
	}
	f.check("", a.conn.alertSession, 0, 0)
	b := f.start(1, "B", a.conn.alertSession)
	if !b.accepted {
		t.Fatal("B denied after retry")
	}
	f.check("B", b.conn.alertSession, 1, 1)
	if err := f.relays[0].releaseRegistration(context.Background(), f.backends[0], registrationRelease{expiryName, a.conn.alertSession}); err != nil {
		t.Fatal(err)
	}
	f.report(0, a, "heartbeat")
	f.check("B", b.conn.alertSession, 1, 1)
}

func TestAvailabilityExpiryRemovalRace(t *testing.T) {
	f := newExpiryFixture(t)
	a := f.start(0, "A", "")
	if !a.accepted {
		t.Fatal("A denied")
	}
	f.clock.Add(91)
	start := make(chan struct{})
	var wg sync.WaitGroup
	// Expiry, heartbeat, exact-generation release and competing registrations
	// contend on production locks. Channels join every transition; no sleeps.
	for _, fn := range []func(){f.expire, func() { f.report(0, a, "heartbeat") }, func() { a.stop(t) }} {
		wg.Add(1)
		go func(fn func()) { defer wg.Done(); <-start; fn() }(fn)
	}
	candidates := make(chan *expiryPublisher, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			candidates <- f.start(i, fmt.Sprintf("B%d", i), a.conn.alertSession)
		}(i)
	}
	close(start)
	wg.Wait()
	close(candidates)
	var winner *expiryPublisher
	for p := range candidates {
		if p.accepted {
			if winner != nil {
				t.Fatal("concurrent replacements both admitted")
			}
			winner = p
		}
	}
	if winner == nil {
		winner = f.start(1, "B1", a.conn.alertSession)
	}
	if !winner.accepted {
		t.Fatal("replacement denied after joined removal/release")
	}
	f.report(0, a, "heartbeat")
	if err := f.backends[0].UnregisterTunnelSession(context.Background(), expiryName, a.conn.alertSession); err != nil {
		t.Fatal(err)
	}
	body := "B1"
	if conn, ok := f.relays[0].GetTunnel(expiryName); ok && conn == winner.conn {
		body = "B0"
	}
	f.check(body, winner.conn.alertSession, 1, 1)
}

func TestAvailabilityExpiryRemovalOrdering(t *testing.T) {
	for _, order := range []string{"expire-first", "remove-first", "replacement-first"} {
		t.Run(order, func(t *testing.T) {
			f := newExpiryFixture(t)
			a := f.start(0, "A", "")
			if !a.accepted {
				t.Fatal("A denied")
			}
			f.clock.Add(91)
			if order == "expire-first" {
				f.expire()
				f.check("A", a.conn.alertSession, 0, 1)
			}
			a.stop(t)
			f.check("", a.conn.alertSession, 0, 0)
			if order == "remove-first" {
				f.expire()
				f.check("", a.conn.alertSession, 0, 0)
			}
			b := f.start(1, "B", a.conn.alertSession)
			if !b.accepted {
				t.Fatal("B denied")
			}
			f.check("B", b.conn.alertSession, 1, 1)
			f.expire()
			f.check("B", b.conn.alertSession, 1, 1)
			f.report(0, a, "heartbeat")
			f.check("B", b.conn.alertSession, 1, 1)
		})
	}
}
