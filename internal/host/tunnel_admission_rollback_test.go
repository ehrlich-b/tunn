package host

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// Exercise ambiguous admission through the real relay, proxy RPC and login
// storage. The first response is lost either after commit or while the login
// node is still working, with cancellation not yet observed at that node.
func TestTunnelRegistrationRollbackLostAdmissionResponse(t *testing.T) {
	for _, mode := range []string{"committed", "release-before-commit", "replacement-before-commit", "release-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			local := securityDB(t)
			owner, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			cfg := securityConfig()
			const name = "lost-admission"
			late := mode == "release-before-commit" || mode == "replacement-before-commit"
			started, resume := make(chan struct{}), make(chan struct{})
			var resumeOnce sync.Once
			unblock := func() { resumeOnce.Do(func() { close(resume) }) }
			t.Cleanup(unblock)
			var admissions atomic.Int32
			var releases atomic.Int32
			var firstSession string // published by the started channel
			login := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
				if info.FullMethod == internalpb.LoginNodeDB_RegisterTunnelSession_FullMethodName && admissions.Add(1) == 1 {
					firstSession = req.(*internalpb.RegisterTunnelRequest).Session
					close(started)
					if late {
						select {
						case <-resume:
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					out, err := next(ctx, req)
					if !late && err == nil && out.(*internalpb.RegisterTunnelResponse).Allowed {
						return nil, status.Error(codes.Unavailable, "synthetic lost committed admission response")
					}
					return out, err
				}
				if info.FullMethod == internalpb.LoginNodeDB_UnregisterTunnelSession_FullMethodName {
					releases.Add(1)
					if mode == "release-unavailable" {
						return nil, status.Error(codes.Unavailable, "synthetic cleanup outage")
					}
				}
				return next(ctx, req)
			}))
			internalpb.RegisterLoginNodeDBServer(login, NewLoginNodeDBServer(local))
			listener := bufconn.Listen(1 << 20)
			go func() { _ = login.Serve(listener) }()
			t.Cleanup(func() { login.Stop(); _ = listener.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type admissionResult struct {
				response *internalpb.RegisterTunnelResponse
				err      error
			}
			finished := make(chan admissionResult, 1)
			var calls atomic.Int32
			conn, err := grpc.NewClient("passthrough:///ambiguous-admission", grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
				grpc.WithUnaryInterceptor(func(rpcCtx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
					if method == internalpb.LoginNodeDB_UnregisterTunnelSession_FullMethodName {
						if rpcCtx.Err() != nil {
							t.Error("rollback inherited publisher cancellation")
						}
						if deadline, ok := rpcCtx.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
							t.Error("rollback needs a live deadline within ten seconds")
						}
					}
					if method == internalpb.LoginNodeDB_RegisterTunnelSession_FullMethodName && calls.Add(1) == 1 {
						if late {
							// Model a transport error reaching the relay before the
							// login node observes cancellation of its in-flight work.
							go func() {
								pendingCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
								defer stop()
								response := new(internalpb.RegisterTunnelResponse)
								err := invoke(pendingCtx, method, req, response, cc, opts...)
								finished <- admissionResult{response, err}
							}()
							select {
							case <-started:
							case <-time.After(3 * time.Second):
								return status.Error(codes.DeadlineExceeded, "admission never reached login node")
							}
							cancel()
							return status.Error(codes.Unavailable, "synthetic transport loss during admission")
						}
						err := invoke(rpcCtx, method, req, reply, cc, opts...)
						cancel()
						return err
					}
					return invoke(rpcCtx, method, req, reply, cc, opts...)
				}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			remote := storage.NewProxyStorage()
			remote.SetConnection(conn)
			server := NewTunnelServer(cfg, nil, nil, remote)
			streamFor := func(streamCtx context.Context, email string) *durableControlStream {
				stream := &durableControlStream{ctx: streamCtx, incoming: make(chan *pb.TunnelMessage, 1), outgoing: make(chan *pb.TunnelMessage, 8)}
				stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{
					TunnelId: name, TargetUrl: "tcp", EndpointProtocol: "tcp",
					AuthToken: createTestJWT(email, cfg.JWTSecret), TunnelKey: cfg.WellKnownKey,
					Capabilities: []string{"connection-stream-v1"},
				}}}
				return stream
			}
			if err := server.EstablishTunnel(streamFor(ctx, owner.PrimaryEmail)); err == nil || !strings.Contains(err.Error(), "ownership could not be verified") {
				t.Fatalf("ambiguous registration returned %v", err)
			}
			if _, ok := server.GetTunnel(name); ok {
				t.Fatal("ambiguous registration installed a local route")
			}
			<-started
			count, err := remote.GetTunnelCount(context.Background(), owner.ID)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: no local route; cleanup attempts=%d active count=%d", mode, releases.Load(), count)
			if releases.Load() != 1 {
				t.Error("ambiguous admission did not attempt conditional release")
			}
			if mode == "release-unavailable" {
				retry, err := remote.RegisterTunnelSession(context.Background(), name, owner.ID, cfg.Domain, "retry")
				if err != nil || count != 1 || retry.Allowed {
					t.Fatalf("cleanup outage must not fabricate release: count=%d retry=%+v err=%v", count, retry, err)
				}
				return
			}
			if count != 0 {
				t.Fatal("ambiguous admission retained its active claim")
			}
			joinAdmission := func() {
				t.Helper()
				unblock()
				select {
				case got := <-finished:
					if got.err != nil || got.response.Allowed || got.response.Reason != "publisher generation retired" {
						t.Fatalf("late retired admission must be denied: response=%+v error=%v", got.response, got.err)
					}
					t.Logf("late admission denied: %s", got.response.Reason)
				case <-time.After(3 * time.Second):
					t.Fatal("late admission did not finish")
				}
			}
			if mode == "release-before-commit" {
				joinAdmission()
			}

			// Retry via the normal authenticated relay registration path.
			retryCtx, stopRetry := context.WithCancel(context.Background())
			retryStream := streamFor(retryCtx, owner.PrimaryEmail)
			retryDone := make(chan error, 1)
			go func() { retryDone <- server.EstablishTunnel(retryStream) }()
			defer func() {
				stopRetry()
				select {
				case <-retryDone:
				case <-time.After(3 * time.Second):
					t.Error("retry teardown stalled")
				}
			}()
			select {
			case response := <-retryStream.outgoing:
				if !response.GetRegisterResponse().GetSuccess() {
					t.Fatal("same authenticated owner retry rejected", response)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("retry registration stalled")
			}
			if mode == "replacement-before-commit" {
				joinAdmission()
			}
			cleanupCtx, stopCleanup := context.WithTimeout(context.Background(), 3*time.Second)
			defer stopCleanup()
			if err := remote.UnregisterTunnelSession(cleanupCtx, name, firstSession); err != nil {
				t.Fatal(err)
			}
			count, err = remote.GetTunnelCount(context.Background(), owner.ID)
			if err != nil || count != 1 {
				t.Fatalf("late cleanup erased replacement: count=%d error=%v", count, err)
			}
			other, err := local.FindOrCreateByEmails(context.Background(), []string{"other@example.com"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if err := server.EstablishTunnel(streamFor(context.Background(), other.PrimaryEmail)); err == nil {
				t.Fatal("different owner replaced live publisher")
			}
			t.Log("same authenticated owner/name recovered; delayed admission/release cannot erase replacement or admit another owner")
		})
	}
}
