package host

import (
	"context"
	"net"
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

func TestTunnelTeardownWithHungLoginNode(t *testing.T) {
	for _, reason := range []string{"lease-expiry", "disconnect"} {
		t.Run(reason, func(t *testing.T) {
			p := durableFixture(t)
			var seconds atomic.Int64
			seconds.Store(time.Now().Unix())
			clock := func() time.Time { return time.Unix(seconds.Load(), 0) }
			p.now, p.tunnelServer.now = clock, clock
			token := durableLogin(t, p)

			// Serve registration and heartbeats normally, but stall either legacy
			// unregister or generation-aware availability cleanup until its context
			// ends, as a login node stuck on storage would do. Both paths must
			// release local resources first and finish within the same bound.
			entered := make(chan context.Context, 1)
			canceled := make(chan error, 1)
			login := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				alert, _ := req.(*internalpb.TunnelAlertRequest)
				availabilityCleanup := info.FullMethod == internalpb.LoginNodeDB_TunnelAlert_FullMethodName && alert != nil && (alert.Operation == "down" || alert.Operation == "graceful")
				if info.FullMethod == internalpb.LoginNodeDB_UnregisterTunnel_FullMethodName || info.FullMethod == internalpb.LoginNodeDB_UnregisterTunnelSession_FullMethodName || availabilityCleanup {
					entered <- ctx
					<-ctx.Done()
					canceled <- ctx.Err()
					return nil, ctx.Err()
				}
				return handler(ctx, req)
			}))
			internalpb.RegisterLoginNodeDBServer(login, NewLoginNodeDBServer(p.storage.(*storage.LocalStorage)))
			listener := bufconn.Listen(1 << 20)
			go func() { _ = login.Serve(listener) }()
			t.Cleanup(func() { login.Stop(); _ = listener.Close() })
			conn, err := grpc.NewClient("passthrough:///teardown-login-node", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			remote := storage.NewProxyStorage()
			remote.SetConnection(conn)
			p.tunnelServer.storage = remote

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 1), outgoing: make(chan *pb.TunnelMessage, 1)}
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{
				TunnelId: "teardown", TargetUrl: "tcp", EndpointProtocol: "tcp", AuthToken: token.Access, TunnelKey: p.config.WellKnownKey,
				Capabilities: []string{deviceReauthCapability, "connection-stream-v1"},
			}}}
			done := make(chan error, 1)
			go func() { done <- p.tunnelServer.EstablishTunnel(stream) }()
			select {
			case response := <-stream.outgoing:
				if !response.GetRegisterResponse().GetSuccess() {
					t.Fatal(response)
				}
			case err := <-done:
				t.Fatal(err)
			case <-time.After(3 * time.Second):
				t.Fatal("registration stalled")
			}
			tunnel, _ := p.tunnelServer.GetTunnel("teardown")
			pending, err := tunnel.addPendingConnection("pending")
			if err != nil {
				t.Fatal(err)
			}
			if reason == "lease-expiry" {
				seconds.Add(301)
			} else {
				cancel()
			}
			select {
			case cleanup := <-entered:
				// Cleanup must remain possible after publisher cancellation.
				if cleanup.Err() != nil {
					t.Fatalf("cleanup started canceled: %v", cleanup.Err())
				}
				if deadline, ok := cleanup.Deadline(); !ok || time.Until(deadline) > 10*time.Second {
					t.Error("unregister RPC has no deadline within ten seconds")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("teardown did not attempt unregister")
			}
			if _, ok := p.tunnelServer.GetTunnel("teardown"); ok {
				t.Fatal("teardown retained local tunnel")
			}
			select {
			case <-pending.done:
			default:
				t.Fatal("teardown retained pending connection")
			}
			select {
			case err := <-done:
				if reason == "lease-expiry" && status.Code(err) != codes.Unauthenticated {
					t.Fatalf("lease expiry returned %v", err)
				}
				if reason == "disconnect" && err != context.Canceled {
					t.Fatalf("disconnect returned %v", err)
				}
			case <-time.After(12 * time.Second):
				t.Fatal("hung login node prevented tunnel teardown from returning")
			}
			select {
			case err := <-canceled:
				// The client deadline can send cancellation before the server's
				// own deadline timer fires.
				if err != context.DeadlineExceeded && err != context.Canceled {
					t.Fatalf("unregister context ended with %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("unregister RPC was not canceled")
			}
		})
	}
}
