package host

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type rollbackSharingFailure struct {
	cancel context.CancelFunc
	mode   string
	t      *testing.T
}

func (f rollbackSharingFailure) Sharing(ctx context.Context, req *meterpb.SharingRequest) (*meterpb.SharingResponse, error) {
	if req.Operation != "register" || req.Mode != f.mode {
		f.t.Fatalf("unexpected sharing request: %v", req)
	}
	// Registration at the login node has completed, but the publisher goes
	// away before the permission authority can finish registering it.
	f.cancel()
	return nil, ctx.Err()
}

func TestTunnelRegistrationRollbackAfterPublisherCancellation(t *testing.T) {
	for _, path := range []string{"web-permission", "mcp-policy", "duplicate-race"} {
		t.Run(path, func(t *testing.T) {
			local := securityDB(t)
			account, err := local.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg := securityConfig()
			server := NewTunnelServer(cfg, nil, nil, nil)
			const name = "rollback-test"
			existing := &TunnelConnection{TunnelID: name}

			// Use the real login-node service and proxy over an in-memory gRPC
			// connection so a canceled RPC cannot mutate storage directly.
			unregisters := make(chan string, 1)
			login := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				if info.FullMethod == internalpb.LoginNodeDB_UnregisterTunnelSession_FullMethodName {
					unregisters <- req.(*internalpb.UnregisterTunnelRequest).TunnelId
				}
				return handler(ctx, req)
			}))
			internalpb.RegisterLoginNodeDBServer(login, NewLoginNodeDBServer(local))
			listener := bufconn.Listen(1 << 20)
			go func() { _ = login.Serve(listener) }()
			t.Cleanup(func() { login.Stop(); _ = listener.Close() })

			accepted, rollbackAttempts := 0, 0
			conn, err := grpc.NewClient("passthrough:///rollback-login-node",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
				grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
					if method == internalpb.LoginNodeDB_UnregisterTunnelSession_FullMethodName {
						rollbackAttempts++
						if ctx.Err() != nil {
							t.Errorf("rollback started with canceled context: %v", ctx.Err())
						}
						if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
							t.Error("rollback must have a live deadline within ten seconds")
						}
					}
					err := invoke(ctx, method, req, reply, cc, opts...)
					if method == internalpb.LoginNodeDB_RegisterTunnelSession_FullMethodName && err == nil && reply.(*internalpb.RegisterTunnelResponse).Allowed {
						accepted++
						if path == "duplicate-race" && accepted == 1 {
							// Another local publisher wins the race after the first
							// duplicate check but before the second one.
							server.mu.Lock()
							server.tunnels[name] = existing
							server.mu.Unlock()
							cancel()
						}
					}
					return err
				}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			remote := storage.NewProxyStorage()
			remote.SetConnection(conn)
			server.storage = remote

			target, wantError := "http", "Web permission authority unavailable."
			if path == "mcp-policy" {
				target, wantError = "mcp", "Endpoint policy authority unavailable."
			}
			if path == "duplicate-race" {
				target, wantError = "tcp", "already registered (race)"
			} else {
				mode := "legacy-public"
				if path == "mcp-policy" {
					mode = "policy-only"
				}
				server.sharing = rollbackSharingFailure{cancel: cancel, mode: mode, t: t}
			}
			protocol := "http"
			if target == "tcp" {
				protocol = "tcp"
			}
			stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 1), outgoing: make(chan *pb.TunnelMessage, 1)}
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{
				TunnelId: name, TargetUrl: target, EndpointProtocol: protocol,
				AuthToken: createTestJWT("owner@example.com", cfg.JWTSecret), TunnelKey: cfg.WellKnownKey,
				Capabilities: []string{"connection-stream-v1"},
			}}}
			if err := server.EstablishTunnel(stream); err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("registration returned %v, want %q", err, wantError)
			}
			if accepted != 1 || rollbackAttempts != 1 || ctx.Err() != context.Canceled {
				t.Fatalf("accepted=%d rollback attempts=%d publisher error=%v", accepted, rollbackAttempts, ctx.Err())
			}
			if tunnel, ok := server.GetTunnel(name); path == "duplicate-race" {
				if !ok || tunnel != existing {
					t.Error("rollback changed the winning local tunnel")
				}
			} else if ok {
				t.Error("failed publisher retained a local tunnel")
			}

			checkCtx, checkCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer checkCancel()
			count, err := remote.GetTunnelCount(checkCtx, account.ID)
			if err != nil {
				t.Fatal(err)
			}
			retry, err := remote.RegisterTunnelSession(checkCtx, name, account.ID, cfg.Domain, "retry")
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("after canceled registration: login-node active count=%d; same-name retry allowed=%v reason=%q; unregister RPCs received=%d", count, retry.Allowed, retry.Reason, len(unregisters))
			if count != 0 || !retry.Allowed {
				t.Errorf("rollback left a stale registration: count=%d retry=%+v", count, retry)
			}
			select {
			case got := <-unregisters:
				if got != name {
					t.Errorf("unregistered %q, want %q", got, name)
				}
			default:
				t.Error("login node never received rollback unregister")
			}
		})
	}
}
