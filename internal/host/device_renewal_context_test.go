package host

import (
	"context"
	"errors"
	"net"
	"strings"
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

func TestDurablePostMergeRenewalHungLoginNode(t *testing.T) {
	for _, reason := range []string{"disconnect", "lease-expiry"} {
		t.Run(reason, func(t *testing.T) {
			p := durableFixture(t)
			original := durableLogin(t, p)
			_, _, expiry, err := parseDeviceToken(original.Access, p.getJWTSigningKey(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			local := p.storage.(*storage.LocalStorage)
			var stall atomic.Bool
			entered := make(chan struct{}, 1)
			canceled := make(chan error, 1)
			release := make(chan struct{})
			login := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				if info.FullMethod == internalpb.LoginNodeDB_GetAccount_FullMethodName && stall.Load() {
					entered <- struct{}{}
					select {
					case <-ctx.Done():
						canceled <- ctx.Err()
						return nil, ctx.Err()
					case <-release:
						return nil, status.Error(codes.Unavailable, "test login node stopped")
					}
				}
				return handler(ctx, req)
			}))
			internalpb.RegisterLoginNodeDBServer(login, NewLoginNodeDBServer(local))
			listener := bufconn.Listen(1 << 20)
			go func() { _ = login.Serve(listener) }()
			t.Cleanup(func() { login.Stop(); _ = listener.Close() })
			conn, err := grpc.NewClient("passthrough:///renewal-login-node", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			remote := storage.NewProxyStorage()
			remote.SetConnection(conn)
			p.tunnelServer.storage = remote
			var now atomic.Int64
			now.Store(time.Now().UnixNano())
			p.tunnelServer.now = func() time.Time { return time.Unix(0, now.Load()) }
			ctx, cancel := context.WithCancel(context.Background())
			stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 2), outgoing: make(chan *pb.TunnelMessage, 1)}
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "renewal-context", TargetUrl: "tcp", EndpointProtocol: "tcp", AuthToken: original.Access, TunnelKey: p.config.WellKnownKey, AllowedEmails: []string{"owner@example.com"}, Capabilities: []string{deviceReauthCapability, "connection-stream-v1"}}}}
			done, stopped := make(chan error, 1), make(chan struct{})
			go func() { defer close(stopped); done <- p.tunnelServer.EstablishTunnel(stream) }()
			t.Cleanup(func() {
				cancel()
				close(release)
				select {
				case <-stopped:
				case <-time.After(3 * time.Second):
					t.Error("publisher did not stop after releasing test login node")
				}
			})
			select {
			case response := <-stream.outgoing:
				if !response.GetRegisterResponse().Success {
					t.Fatal(response)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("registration stalled")
			}
			tunnel, ok := p.tunnelServer.GetTunnel("renewal-context")
			if !ok {
				t.Fatal("publisher missing")
			}
			pending, err := tunnel.addPendingConnection("live-connection")
			if err != nil {
				t.Fatal(err)
			}
			survivor, err := local.FindOrCreateByEmails(ctx, []string{"survivor@example.com"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if err := local.UpdatePlan(ctx, survivor.ID, "pro"); err != nil {
				t.Fatal(err)
			}
			merged, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.com", survivor.PrimaryEmail}, "github")
			if err != nil || merged.ID != survivor.ID || merged.ID == signedAccountID(original.Access) {
				t.Fatal("merge did not retire publisher account ID", merged, err)
			}
			response, renewed := durableRefresh(p, original.Refresh, strings.Repeat("r", 43))
			if response.Code != 200 || signedAccountID(renewed.Access) != merged.ID {
				t.Fatal("refresh did not resolve merged account", response.Code, response.Body)
			}
			if reason == "lease-expiry" {
				now.Store(expiry.Add(-1500 * time.Millisecond).UnixNano())
			}
			stall.Store(true)
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{AuthToken: renewed.Access}}}
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("renewal did not reach stalled login node")
			}
			if reason == "disconnect" {
				// Let the watcher tick while renewal holds the lease lock.
				time.Sleep(1100 * time.Millisecond)
				cancel()
			} else {
				now.Store(expiry.UnixNano())
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Unauthenticated {
					t.Fatalf("publisher shutdown: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("hung post-merge renewal prevented publisher shutdown on " + reason)
			}
			select {
			case err := <-canceled:
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("unexpected login lookup error", err)
				}
			case <-time.After(time.Second):
				t.Fatal("login node lookup outlived publisher")
			}
			select {
			case <-pending.done:
			default:
				t.Fatal("live connection survived publisher shutdown")
			}
			if _, ok := p.tunnelServer.GetTunnel("renewal-context"); ok {
				t.Fatal("publisher remained registered")
			}
		})
	}
}
