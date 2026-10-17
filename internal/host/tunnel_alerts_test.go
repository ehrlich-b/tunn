package host

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type tunnelAlertMail struct{ to, subject, body string }
type tunnelAlertMailer struct {
	messages []tunnelAlertMail
	fail     bool
}

func TestTunnelAlertsSMTPContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- NewEmailSender(host, port, "", "", "relay@example.invalid").SendContext(ctx, "owner@example.invalid", "fixture", "fixture")
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("fake SMTP connection timeout")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled SMTP attempt succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP cancellation did not stop worker")
	}
}

func TestTunnelAlertsRealClientGracefulStop(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprintf("remote=%v", remote), func(t *testing.T) {
			f := newTunnelAlertFixture(t, remote)
			server := NewTunnelServer(securityConfig(), nil, nil, f.backend)
			g := grpc.NewServer()
			pb.RegisterTunnelServiceServer(g, server)
			relay := httptest.NewUnstartedServer(g)
			relay.EnableHTTP2 = true
			relay.StartTLS()
			defer relay.Close()
			defer g.Stop()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := make(chan struct{})
			c := &client.ServeClient{TunnelID: "real-client", TargetURL: "http://127.0.0.1:1", ServerAddr: strings.TrimPrefix(relay.URL, "https://"), RelayTLSConfig: relay.Client().Transport.(*http.Transport).TLSClientConfig, AuthToken: createTestJWT(f.owner.PrimaryEmail, server.cfg.JWTSecret), TunnelKey: server.cfg.WellKnownKey, Quiet: true, OnRegistered: func(string) { close(ready) }}
			done := make(chan error, 1)
			go func() { done <- c.Run(ctx) }()
			select {
			case <-ready:
			case err := <-done:
				t.Fatalf("publisher exited before ready: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("publisher readiness timeout")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("publisher shutdown timeout")
			}
			// Wait for relay cleanup, then advance only the injected alert clock.
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
					t.Fatal("publisher cleanup timeout")
				}
				time.Sleep(time.Millisecond)
			}
			f.clock.Add(7200)
			f.sweep(0)
		})
	}
}

func (m *tunnelAlertMailer) SendMagicLink(string, string) error {
	return fmt.Errorf("unexpected magic link")
}
func (m *tunnelAlertMailer) Send(to, subject, body string) error {
	if m.fail {
		return fmt.Errorf("fake SMTP unavailable")
	}
	m.messages = append(m.messages, tunnelAlertMail{to, subject, body})
	return nil
}

type tunnelAlertFixture struct {
	t       *testing.T
	clock   atomic.Int64
	local   *storage.LocalStorage
	backend storage.Storage
	owner   *storage.Account
	p       *ProxyServer
	mailer  *tunnelAlertMailer
}

func newTunnelAlertFixture(t *testing.T, remote bool) *tunnelAlertFixture {
	t.Helper()
	f := &tunnelAlertFixture{t: t, mailer: &tunnelAlertMailer{}}
	f.clock.Store(time.Now().Unix())
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
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
	f.p.isLoginNode = true
	return f
}
func (f *tunnelAlertFixture) report(name, session, operation, lastError string) {
	f.t.Helper()
	_, err := f.backend.(storage.TunnelAlerts).TunnelAlert(context.Background(), &internalpb.TunnelAlertRequest{Operation: operation, AccountId: f.owner.ID, Tunnel: name, Session: session, LastError: lastError})
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *tunnelAlertFixture) register(name, session string) {
	f.t.Helper()
	r, err := f.backend.RegisterTunnel(context.Background(), name, f.owner.ID, "replica.test")
	if err != nil || !r.Allowed {
		f.t.Fatalf("register: %v %v", r, err)
	}
	f.report(name, session, "up", "")
}
func (f *tunnelAlertFixture) sweep(want int) {
	f.t.Helper()
	if err := f.p.deliverTunnelAlerts(context.Background()); err != nil {
		f.t.Fatal(err)
	}
	if len(f.mailer.messages) != want {
		f.t.Fatalf("emails=%d want=%d: %+v", len(f.mailer.messages), want, f.mailer.messages)
	}
}
func (f *tunnelAlertFixture) settings(enabled, graceful bool, threshold int64) {
	f.t.Helper()
	_, err := f.backend.(storage.TunnelAlerts).TunnelAlert(context.Background(), &internalpb.TunnelAlertRequest{Operation: "save_settings", AccountId: f.owner.ID, Enabled: enabled, OnGracefulStop: graceful, ThresholdSeconds: threshold})
	if err != nil {
		f.t.Fatal(err)
	}
}

func TestTunnelAlertsLifecycle(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprintf("remote=%v", remote), func(t *testing.T) {
			f := newTunnelAlertFixture(t, remote)
			ctx := context.Background()
			if err := f.local.AccountStore().ReserveSubdomain(f.owner.ID, "never-up"); err != nil {
				t.Fatal(err)
			}
			f.clock.Add(86400)
			f.sweep(0)
			if err := f.local.AccountStore().ReleaseSubdomain(f.owner.ID, "never-up"); err != nil {
				t.Fatal(err)
			}
			f.register("named-demo", "one")
			since := f.clock.Load()
			f.report("named-demo", "one", "down", "Invalid or expired token")
			f.clock.Add(599)
			f.sweep(0)
			f.clock.Add(1)
			f.sweep(1)
			f.sweep(1)
			mail := f.mailer.messages[0]
			for _, text := range []string{"named-demo", time.Unix(since, 0).UTC().Format(time.RFC3339), "Invalid or expired token", "tunn status", "TUNN_SERVER_ADDR=tunn.test:443 tunn login"} {
				if !strings.Contains(mail.body, text) {
					t.Errorf("email missing %q: %s", text, mail.body)
				}
			}
			if mail.to != f.owner.PrimaryEmail {
				t.Fatal(mail.to)
			}
			f.register("named-demo", "two")
			f.sweep(1)
			// Rapid recoveries and disconnects share one durable hourly budget.
			for i := 0; i < 20; i++ {
				f.report("named-demo", "two", "down", "")
				f.report("named-demo", "two", "heartbeat", "")
				f.sweep(1)
			}
			f.clock.Add(3599)
			f.report("named-demo", "two", "heartbeat", "")
			f.sweep(1)
			f.clock.Add(1)
			f.report("named-demo", "two", "heartbeat", "")
			f.sweep(2)
			f.sweep(2)
			if !strings.Contains(f.mailer.messages[1].subject, "recovered") {
				t.Fatal(f.mailer.messages[1])
			}
			// An old node cannot remove or mark down the replacement publisher.
			f.report("named-demo", "one", "down", "stale disconnect")
			count, err := f.backend.GetTunnelCount(ctx, f.owner.ID)
			if err != nil || count != 1 {
				t.Fatal(count, err)
			}
			f.report("named-demo", "two", "graceful", "")
			f.clock.Add(7200)
			f.sweep(2)
			f.register("named-demo", "three")
			f.settings(false, false, 1)
			f.report("named-demo", "three", "down", "")
			f.clock.Add(7200)
			f.sweep(2)
			f.settings(true, true, 42)
			f.register("named-demo", "four")
			f.report("named-demo", "four", "graceful", "")
			f.clock.Add(41)
			f.sweep(2)
			f.clock.Add(1)
			f.sweep(3)
		})
	}
}

func TestTunnelAlertsRelayCrashAndMailerRetry(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprintf("remote=%v", remote), func(t *testing.T) {
			f := newTunnelAlertFixture(t, remote)
			f.register("crash-demo", "crashed-node")
			f.clock.Add(90 + 599)
			f.sweep(0)
			f.clock.Add(1)
			f.mailer.fail = true
			f.sweep(0)
			f.mailer.fail = false
			f.sweep(0)
			f.clock.Add(3600)
			f.sweep(1)
			if !strings.Contains(f.mailer.messages[0].body, "Relay heartbeat lost") {
				t.Fatal(f.mailer.messages[0])
			}
			// A new relay can claim the name after the old node's heartbeat expires.
			f.register("crash-demo", "replacement")
			f.clock.Add(3600)
			f.report("crash-demo", "replacement", "heartbeat", "")
			f.sweep(2)
		})
	}
}

type tunnelAlertRecv struct {
	message *pb.TunnelMessage
	err     error
}
type tunnelAlertStream struct {
	mockTunnelStream
	recv chan tunnelAlertRecv
	sent chan *pb.TunnelMessage
}

func (s *tunnelAlertStream) Recv() (*pb.TunnelMessage, error) { r := <-s.recv; return r.message, r.err }
func (s *tunnelAlertStream) Send(m *pb.TunnelMessage) error   { s.sent <- m; return nil }

func TestTunnelAlertsRegistrationAndStop(t *testing.T) {
	for _, remote := range []bool{false, true} {
		for _, graceful := range []bool{false, true} {
			t.Run(fmt.Sprintf("remote=%v/graceful=%v", remote, graceful), func(t *testing.T) {
				f := newTunnelAlertFixture(t, remote)
				server := NewTunnelServer(securityConfig(), nil, nil, f.backend)
				stream := &tunnelAlertStream{recv: make(chan tunnelAlertRecv, 2), sent: make(chan *pb.TunnelMessage, 4)}
				token := createTestJWT(f.owner.PrimaryEmail, server.cfg.JWTSecret)
				stream.recv <- tunnelAlertRecv{message: &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "stream-demo", AuthToken: token, TunnelKey: server.cfg.WellKnownKey}}}}
				done := make(chan error, 1)
				go func() { done <- server.EstablishTunnel(stream) }()
				select {
				case msg := <-stream.sent:
					if !msg.GetRegisterResponse().Success {
						t.Fatal(msg)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("registration timeout")
				}
				if graceful {
					stream.recv <- tunnelAlertRecv{message: &pb.TunnelMessage{Message: &pb.TunnelMessage_GracefulStop{GracefulStop: &pb.GracefulStop{}}}}
				} else {
					stream.recv <- tunnelAlertRecv{err: status.Error(codes.Unavailable, "connection reset")}
				}
				select {
				case err := <-done:
					if (err == nil) != graceful {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("disconnect timeout")
				}
				f.clock.Add(600)
				want := 1
				if graceful {
					want = 0
				}
				f.sweep(want)
			})
		}
	}
}

func TestTunnelAlertsRejectedReconnectDiagnosis(t *testing.T) {
	for _, remote := range []bool{false, true} {
		for _, kind := range []string{"expired-owner", "expired-foreign", "forged", "wrong-purpose"} {
			t.Run(fmt.Sprintf("remote=%v/%s", remote, kind), func(t *testing.T) {
				f := newTunnelAlertFixture(t, remote)
				f.register("diagnosis-demo", "owner")
				f.report("diagnosis-demo", "owner", "down", "Publisher connection lost")
				server := NewTunnelServer(securityConfig(), nil, nil, f.backend)
				claims := jwt.MapClaims{"email": f.owner.PrimaryEmail, "exp": time.Now().Add(-time.Hour).Unix()}
				secret := server.cfg.JWTSecret
				switch kind {
				case "expired-foreign":
					_, err := f.local.FindOrCreateByEmails(context.Background(), []string{"other@example.com"}, "test")
					if err != nil {
						t.Fatal(err)
					}
					claims["email"] = "other@example.com"
				case "forged":
					secret = "wrong-key"
				case "wrong-purpose":
					claims["type"] = "magic_link"
				}
				token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
				if err != nil {
					t.Fatal(err)
				}
				if r := securityRegister(t, server, "diagnosis-demo", token); r.Success {
					t.Fatal("expired token accepted")
				}
				f.clock.Add(600)
				f.sweep(1)
				wantExpired := kind == "expired-owner"
				if strings.Contains(f.mailer.messages[0].body, "Invalid or expired token") != wantExpired {
					t.Fatal("untrusted diagnosis", f.mailer.messages[0].body)
				}
			})
		}
	}
}

func TestTunnelAlertsSettingsAccountSessionAndCSRF(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprintf("remote=%v", remote), func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			p := f.p
			if remote {
				p.storage = securityReplicaStorage(t, p.storage.(*storage.LocalStorage))
			}
			cookie := emailSession(t, p, "owner@example.com")
			get := f.request("GET", "https://tunn.test/account/tunnel-alerts", "", "", "", cookie)
			if get.Code != 200 || !strings.Contains(get.Body.String(), `value="600"`) {
				t.Fatal(get.Code, get.Body.String())
			}
			r := httptest.NewRequest("GET", "https://tunn.test/account/tunnel-alerts", nil)
			r.AddCookie(cookie)
			csrf, err := p.createCSRFToken(r, tunnelAlertSettingsPath)
			if err != nil {
				t.Fatal(err)
			}
			values := url.Values{"threshold_seconds": {"120"}, "csrf_token": {csrf}}
			w := f.request("POST", "https://tunn.test/account/tunnel-alerts", values.Encode(), "application/x-www-form-urlencoded", "", cookie)
			if w.Code != 303 {
				t.Fatal(w.Code, w.Body.String())
			}
			get = f.request("GET", "https://tunn.test/account/tunnel-alerts", "", "", "", cookie)
			if !strings.Contains(get.Body.String(), `value="120"`) || strings.Contains(get.Body.String(), `name="enabled" checked`) {
				t.Fatal(get.Body.String())
			}
			values.Del("csrf_token")
			w = f.request("POST", "https://tunn.test/account/tunnel-alerts", values.Encode(), "application/x-www-form-urlencoded", "", cookie)
			if w.Code != 403 {
				t.Fatal("missing CSRF accepted", w.Code)
			}
			w = f.request("GET", "https://tunn.test/account/tunnel-alerts", "", "", "", nil)
			if w.Code != 302 {
				t.Fatal("anonymous settings accepted", w.Code)
			}
		})
	}
}
