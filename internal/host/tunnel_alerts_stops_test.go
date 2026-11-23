package host

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type observedTunnelAlertStorage struct {
	storage.Storage
	up chan struct{}
}

func (s observedTunnelAlertStorage) TunnelAlert(ctx context.Context, r *internalpb.TunnelAlertRequest) (*internalpb.TunnelAlertResponse, error) {
	reply, err := s.Storage.(storage.TunnelAlerts).TunnelAlert(ctx, r)
	if r.Operation == "up" && err == nil {
		s.up <- struct{}{}
	}
	return reply, err
}

func awaitTunnelAlertUp(t *testing.T, up <-chan struct{}) {
	t.Helper()
	select {
	case <-up:
	case <-time.After(5 * time.Second):
		t.Fatal("availability persistence timed out")
	}
}

func awaitTunnelAlertCleanup(t *testing.T, local *storage.LocalStorage, owner string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		count, err := local.GetTunnelCount(context.Background(), owner)
		if err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("publisher cleanup timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTunnelAlertsSSHStopReasons(t *testing.T) {
	for _, remote := range []bool{false, true} {
		for _, kind := range []string{"SIGINT", "Ctrl-C", "Ctrl-D", "stdin EOF", "stdio EOF", "requested expiry", "session close", "cancel-forward", "transport loss"} {
			t.Run(fmt.Sprintf("remote=%v/%s", remote, kind), func(t *testing.T) {
				var clock atomic.Int64
				clock.Store(time.Now().Unix())
				p, c, dial := sshRelayWithClock(t, true, func() time.Time { return time.Unix(clock.Load(), 0) })
				local := p.storage.(*storage.LocalStorage)
				if remote {
					p.tunnelServer.storage = securityReplicaStorage(t, local)
				}
				observed := observedTunnelAlertStorage{Storage: p.tunnelServer.storage, up: make(chan struct{}, 8)}
				p.tunnelServer.storage = observed
				owner, err := local.GetAccountByEmail(context.Background(), "owner@example.com")
				if err != nil {
					t.Fatal(err)
				}
				_, err = observed.TunnelAlert(context.Background(), &internalpb.TunnelAlertRequest{Operation: "save_settings", AccountId: owner.ID, Enabled: true, ThresholdSeconds: 600})
				if err != nil {
					t.Fatal(err)
				}
				mailer := &tunnelAlertMailer{}
				p.emailSender = mailer
				sweep := func(want int) {
					t.Helper()
					if err := p.deliverTunnelAlerts(context.Background()); err != nil {
						t.Fatal(err)
					}
					if len(mailer.messages) != want {
						t.Fatalf("emails=%d want=%d: %+v", len(mailer.messages), want, mailer.messages)
					}
				}
				start := func(c *ssh.Client) (*ssh.Session, io.WriteCloser) {
					t.Helper()
					if kind == "stdio EOF" {
						session, err := c.NewSession()
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = session.Close() })
						in, err := session.StdinPipe()
						if err != nil {
							t.Fatal(err)
						}
						out, err := session.StderrPipe()
						if err != nil {
							t.Fatal(err)
						}
						if err := session.Start("mcp --stdio --name ssh-stop"); err != nil {
							t.Fatal(err)
						}
						if line := sshLine(t, bufio.NewReader(out)); line != "https://ssh-stop.tunn.test/mcp\n" {
							t.Fatal(line)
						}
						awaitTunnelAlertUp(t, observed.up)
						return session, in
					}
					spec := struct {
						Address string
						Port    uint32
					}{"ssh-stop", 80}
					ok, _, err := c.SendRequest("tcpip-forward", true, ssh.Marshal(spec))
					if err != nil || !ok {
						t.Fatal(ok, err)
					}
					command := "--public"
					if kind == "requested expiry" {
						command += " --expire 200ms"
					}
					session, in, out := edgeSSHSession(t, c, command)
					if line := sshLine(t, out); line != "https://ssh-stop.tunn.test\n" {
						t.Fatal(line)
					}
					awaitTunnelAlertUp(t, observed.up)
					return session, in
				}
				session, in := start(c)
				publisher, ok := p.tunnelServer.GetTunnel("ssh-stop")
				if !ok {
					t.Fatal("registered publisher missing")
				}
				switch kind {
				case "SIGINT":
					err = session.Signal(ssh.SIGINT)
				case "Ctrl-C":
					_, err = in.Write([]byte{3})
				case "Ctrl-D":
					_, err = in.Write([]byte{4})
				case "stdin EOF":
					err = in.Close()
					if err != nil {
						t.Fatal(err)
					}
					// EOF alone keeps the existing -n publication behavior. Closing the
					// session afterwards is also a client stop, even without GracefulStop.
					sweep(0)
					err = session.Close()
				case "stdio EOF":
					err = in.Close()
				case "requested expiry":
					// The owner's requested lifetime ends without a shutdown message.
				case "session close":
					err = session.Close()
				case "cancel-forward":
					var ok bool
					ok, _, err = c.SendRequest("cancel-tcpip-forward", true, ssh.Marshal(struct {
						Address string
						Port    uint32
					}{"ssh-stop", 80}))
					if !ok {
						t.Fatal("cancel-forward rejected")
					}
				case "transport loss":
					err = c.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
				awaitTunnelAlertCleanup(t, local, owner.ID)
				wantReason := publisherClientStop
				if kind == "transport loss" {
					wantReason = publisherTransportLoss
				}
				if ended := publisher.stop.Load(); ended == nil || ended.reason != wantReason {
					t.Fatalf("stop=%+v want=%s", ended, wantReason)
				}
				clock.Add(599)
				sweep(0)
				clock.Add(1)
				want := 0
				if kind == "transport loss" {
					want = 1
				}
				sweep(want)
				sweep(want)
				if kind == "transport loss" {
					if !strings.Contains(mailer.messages[0].subject, "offline") {
						t.Fatal(mailer.messages)
					}
					recovered, _ := start(dial())
					sweep(1)
					clock.Add(3600)
					conn, ok := p.tunnelServer.GetTunnel("ssh-stop")
					if !ok {
						t.Fatal("recovered publisher missing")
					}
					if err := p.tunnelServer.reportAvailability(conn, "heartbeat", ""); err != nil {
						t.Fatal(err)
					}
					sweep(2)
					sweep(2)
					if !strings.Contains(mailer.messages[1].subject, "recovered") {
						t.Fatal(mailer.messages)
					}
					if err := recovered.Signal(ssh.SIGINT); err != nil {
						t.Fatal(err)
					}
					awaitTunnelAlertCleanup(t, local, owner.ID)
					clock.Add(7200)
					sweep(2)
				} else {
					clock.Add(7200)
					sweep(0)
				}
			})
		}
	}
}

func TestTunnelAlertsGRPCClientStops(t *testing.T) {
	for _, remote := range []bool{false, true} {
		for _, kind := range []string{"cancel", "EOF"} {
			t.Run(fmt.Sprintf("remote=%v/%s", remote, kind), func(t *testing.T) {
				f := newTunnelAlertFixture(t, remote)
				f.settings(true, false, 600)
				observed := observedTunnelAlertStorage{Storage: f.backend, up: make(chan struct{}, 8)}
				server := NewTunnelServer(securityConfig(), nil, nil, observed)
				g := grpc.NewServer()
				pb.RegisterTunnelServiceServer(g, server)
				listener := bufconn.Listen(1 << 20)
				go func() { _ = g.Serve(listener) }()
				defer g.Stop()
				defer listener.Close()
				cc, err := grpc.NewClient("passthrough:///stop-test", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
				if err != nil {
					t.Fatal(err)
				}
				defer cc.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				stream, err := pb.NewTunnelServiceClient(cc).EstablishTunnel(ctx)
				if err != nil {
					t.Fatal(err)
				}
				err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "grpc-stop", AuthToken: createTestJWT(f.owner.PrimaryEmail, server.cfg.JWTSecret), TunnelKey: server.cfg.WellKnownKey}}})
				if err != nil {
					t.Fatal(err)
				}
				reply, err := stream.Recv()
				if err != nil || !reply.GetRegisterResponse().GetSuccess() {
					t.Fatal(reply, err)
				}
				awaitTunnelAlertUp(t, observed.up)
				if kind == "cancel" {
					cancel()
				} else if err := stream.CloseSend(); err != nil {
					t.Fatal(err)
				}
				awaitTunnelAlertCleanup(t, f.local, f.owner.ID)
				f.clock.Add(7200)
				f.sweep(0)
			})
		}
	}
}

func TestTunnelAlertsTerminalFailuresAndRecovery(t *testing.T) {
	for _, remote := range []bool{false, true} {
		for _, failure := range []struct {
			name   string
			err    error
			reason publisherStopReason
		}{
			{"dropped", status.Error(codes.Unavailable, "connection reset"), publisherTransportLoss},
			{"keepalive", status.Error(codes.DeadlineExceeded, "keepalive timeout"), publisherTimeout},
			{"evicted", status.Error(codes.Unauthenticated, "publisher lease expired"), publisherEviction},
		} {
			t.Run(fmt.Sprintf("remote=%v/%s", remote, failure.name), func(t *testing.T) {
				f := newTunnelAlertFixture(t, remote)
				f.settings(true, false, 600)
				server := NewTunnelServer(securityConfig(), nil, nil, f.backend)
				stream := &tunnelAlertStream{recv: make(chan tunnelAlertRecv, 2), sent: make(chan *pb.TunnelMessage, 4)}
				stream.recv <- tunnelAlertRecv{message: &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "failed-stop", AuthToken: createTestJWT(f.owner.PrimaryEmail, server.cfg.JWTSecret), TunnelKey: server.cfg.WellKnownKey}}}}
				done := make(chan error, 1)
				go func() { done <- server.EstablishTunnel(stream) }()
				select {
				case reply := <-stream.sent:
					if !reply.GetRegisterResponse().GetSuccess() {
						t.Fatal(reply)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("registration timed out")
				}
				conn, ok := server.GetTunnel("failed-stop")
				if !ok {
					t.Fatal("missing publisher")
				}
				stream.recv <- tunnelAlertRecv{err: failure.err}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("failure discarded")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("cleanup timed out")
				}
				if ended := conn.stop.Load(); ended == nil || ended.reason != failure.reason {
					t.Fatalf("stop=%+v", ended)
				}
				// Cleanup cancellation cannot replace the terminal failure.
				conn.endRegistration(context.Canceled)
				f.clock.Add(599)
				f.sweep(0)
				f.clock.Add(1)
				f.sweep(1)
				f.sweep(1)
				f.registerSession("failed-stop", "replacement")
				f.sweep(1)
				f.clock.Add(3600)
				f.report("failed-stop", "replacement", "heartbeat", "")
				f.sweep(2)
				f.sweep(2)
				if !strings.Contains(f.mailer.messages[1].subject, "recovered") {
					t.Fatal(f.mailer.messages)
				}
			})
		}
	}
}

func TestTunnelAlertsHTTP2StopReasons(t *testing.T) {
	for _, remote := range []bool{false, true} {
		for _, modern := range []bool{false, true} {
			for _, kind := range []string{"cancel", "cancel then close", "EOF", "graceful", "transport loss"} {
				t.Run(fmt.Sprintf("remote=%v/modern=%v/%s", remote, modern, kind), func(t *testing.T) {
					f := newTunnelAlertFixture(t, remote)
					f.settings(true, false, 600)
					observed := observedTunnelAlertStorage{Storage: f.backend, up: make(chan struct{}, 8)}
					server := NewTunnelServer(securityConfig(), nil, nil, observed)
					g := grpc.NewServer()
					pb.RegisterTunnelServiceServer(g, server)
					bodies := make(chan *publisherRequestBody, 1)
					relay := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						r = publisherRequest(r)
						bodies <- r.Body.(*publisherRequestBody)
						g.ServeHTTP(w, r)
					}))
					relay.Listener = publisherListener{relay.Listener}
					relay.Config.ConnContext = publisherConnContext
					relay.EnableHTTP2 = true
					if err := http2.ConfigureServer(relay.Config, &http2.Server{}); err != nil {
						t.Fatal(err)
					}
					relay.StartTLS()
					defer relay.Close()
					defer g.Stop()
					raw := make(chan net.Conn, 8)
					cc, err := grpc.NewClient("passthrough:///"+relay.Listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(relay.Client().Transport.(*http.Transport).TLSClientConfig)), grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
						c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
						if err == nil {
							raw <- c
						}
						return c, err
					}))
					if err != nil {
						t.Fatal(err)
					}
					defer cc.Close()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					stream, err := pb.NewTunnelServiceClient(cc).EstablishTunnel(ctx)
					if err != nil {
						t.Fatal(err)
					}
					capabilities := []string(nil)
					if modern {
						capabilities = append(capabilities, common.CapabilityGracefulStopV1)
					}
					err = stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{Capabilities: capabilities, TunnelId: "http2-stop", AuthToken: createTestJWT(f.owner.PrimaryEmail, server.cfg.JWTSecret), TunnelKey: server.cfg.WellKnownKey}}})
					if err != nil {
						t.Fatal(err)
					}
					reply, err := stream.Recv()
					if err != nil || !reply.GetRegisterResponse().GetSuccess() {
						t.Fatal(reply, err)
					}
					awaitTunnelAlertUp(t, observed.up)
					body := <-bodies
					switch kind {
					case "cancel":
						cancel()
					case "cancel then close":
						cancel()
						// Wait until the relay has observed cancellation and cleaned up.
						select {
						case <-body.done:
						case <-time.After(5 * time.Second):
							t.Fatal("relay did not observe stream cancellation before socket close")
						}
						awaitTunnelAlertCleanup(t, f.local, f.owner.ID)
						if err := cc.Close(); err != nil {
							t.Fatal(err)
						}
					case "graceful":
						if err := stream.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_GracefulStop{GracefulStop: &pb.GracefulStop{}}}); err != nil {
							t.Fatal(err)
						}
						if _, err := stream.Recv(); err != io.EOF {
							t.Fatalf("graceful acknowledgement: %v", err)
						}
						cancel()
						if err := cc.Close(); err != nil {
							t.Fatal(err)
						}
					case "EOF":
						if err := stream.CloseSend(); err != nil {
							t.Fatal(err)
						}
					case "transport loss":
						if err := (<-raw).Close(); err != nil {
							t.Fatal(err)
						}
					}
					awaitTunnelAlertCleanup(t, f.local, f.owner.ID)
					f.clock.Add(599)
					f.sweep(0)
					f.clock.Add(1)
					if kind == "transport loss" || modern && kind != "graceful" {
						f.sweep(1)
						f.sweep(1)
						f.registerSession("http2-stop", "replacement")
						f.clock.Add(3600)
						f.report("http2-stop", "replacement", "heartbeat", "")
						f.sweep(2)
						f.sweep(2)
					} else {
						f.sweep(0)
						f.clock.Add(7200)
						f.sweep(0)
					}
				})
			}
		}
	}
}

func TestTunnelAlertsLegacyResetPrecedesGRPCConnectionFailure(t *testing.T) {
	for _, modern := range []bool{false, true} {
		for _, tc := range []struct {
			code codes.Code
			want publisherStopReason
		}{
			{codes.Canceled, publisherClientStop},
			{codes.Unavailable, publisherClientStop},
			{codes.Unknown, publisherClientStop},
			{codes.Internal, publisherClientStop},
			{codes.Unauthenticated, publisherEviction},
			{codes.PermissionDenied, publisherEviction},
			{codes.DeadlineExceeded, publisherTimeout},
		} {
			t.Run(fmt.Sprintf("modern=%v/%s", modern, tc.code), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				body := &publisherRequestBody{ctx: ctx, done: make(chan struct{}), err: http2.StreamError{StreamID: 1, Code: http2.ErrCodeCancel}}
				close(body.done)
				ctx = context.WithValue(ctx, publisherRequestKey{}, body)
				conn := &TunnelConnection{Stream: &durableControlStream{ctx: ctx}, Capabilities: map[string]bool{common.CapabilityGracefulStopV1: modern}}
				conn.endRegistration(status.Error(tc.code, "terminal result"))
				want := tc.want
				if modern && want == publisherClientStop {
					want = publisherTransportLoss
				}
				if got := conn.stop.Load(); got == nil || got.reason != want {
					t.Fatalf("stop=%+v want=%s", got, want)
				}
			})
		}
	}
}
