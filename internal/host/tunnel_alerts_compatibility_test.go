package host

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/sshfront"
	"github.com/ehrlich-b/tunn/internal/storage"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestTunnelAlertsLegacyLoginCleanup(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(fmt.Sprintf("rollback=%v", rollback), func(t *testing.T) {
			var unavailable atomic.Bool
			unavailable.Store(!rollback)
			up := make(chan struct{}, 1)
			local := securityDB(t)
			a, err := local.FindOrCreateByEmails(context.Background(), []string{"rollback@example.invalid"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			login := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				if info.FullMethod == "/internal.LoginNodeDB/TunnelAlert" && unavailable.Load() {
					return nil, status.Error(codes.Unimplemented, "4336465 has no TunnelAlert RPC")
				}
				response, err := handler(ctx, req)
				if r, ok := req.(*internalpb.TunnelAlertRequest); ok && r.Operation == "up" {
					up <- struct{}{}
				}
				return response, err
			}))
			internalpb.RegisterLoginNodeDBServer(login, NewLoginNodeDBServer(local))
			listener := bufconn.Listen(1 << 20)
			go func() { _ = login.Serve(listener) }()
			defer login.Stop()
			defer listener.Close()
			cc, err := grpc.NewClient("passthrough:///old-login", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()
			remote := storage.NewProxyStorage()
			remote.SetConnection(cc)
			server := NewTunnelServer(securityConfig(), nil, nil, remote)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 1), outgoing: make(chan *pb.TunnelMessage, 4)}
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "rollback-probe", AuthToken: createTestJWT(a.PrimaryEmail, server.cfg.JWTSecret), TunnelKey: server.cfg.WellKnownKey}}}
			done := make(chan error, 1)
			go func() { done <- server.EstablishTunnel(stream) }()
			select {
			case msg := <-stream.outgoing:
				if !msg.GetRegisterResponse().GetSuccess() {
					t.Fatal(msg)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("registration timed out")
			}
			// Wait until initial availability has been persisted before rolling back.
			if rollback {
				select {
				case <-up:
				case <-time.After(5 * time.Second):
					t.Fatal("availability setup timed out")
				}
				unavailable.Store(true)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(12 * time.Second):
				t.Fatal("cleanup timed out")
			}
			count, err := local.GetTunnelCount(context.Background(), a.ID)
			if err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("old login retains %d active publisher(s) after disconnect; reconnect is blocked", count)
			}
		})
	}
}

func TestTunnelAlertsSSHTransportLoss(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprint(remote), func(t *testing.T) {
			f := newTunnelAlertFixture(t, remote)
			server := NewTunnelServer(securityConfig(), nil, nil, f.backend)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream, messages := sshfront.NewStream(ctx)
			err := messages.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "ssh-loss-probe", AuthToken: createTestJWT(f.owner.PrimaryEmail, server.cfg.JWTSecret), TunnelKey: server.cfg.WellKnownKey}}})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- server.EstablishTunnel(sshHostStream{Stream: stream, ctx: context.WithValue(ctx, sshPublisherContextKey{}, sshPublisher{email: f.owner.PrimaryEmail, accountID: f.owner.ID})})
			}()
			msg, err := messages.Recv()
			if err != nil || !msg.GetRegisterResponse().GetSuccess() {
				t.Fatal(msg, err)
			}
			// SSH connection and channel losses cancel this same context in sshfront.Server.
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("cleanup timed out")
			}
			f.clock.Add(600)
			f.sweep(1)
		})
	}
}

// Live publishers keep their original account UUID across verified identity merges.
func TestTunnelAlertsMergedPublisher(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprint(remote), func(t *testing.T) {
			f := newTunnelAlertFixture(t, remote)
			ctx := context.Background()
			other, err := f.local.FindOrCreateByEmails(ctx, []string{"other@example.invalid"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if err := f.local.AccountStore().ReserveSubdomain(f.owner.ID, "merged-publisher"); err != nil {
				t.Fatal(err)
			}
			f.register("merged-publisher", "generation")
			merged, err := f.local.FindOrCreateByEmails(ctx, []string{f.owner.PrimaryEmail, other.PrimaryEmail}, "test")
			if err != nil {
				t.Fatal(err)
			}
			// Exercise both an obsolete persisted owner and an obsolete in-memory owner,
			// regardless of which account survives the store's selection.
			for _, owner := range []string{f.owner.ID, other.ID} {
				f.owner.ID = owner
				f.report("merged-publisher", "generation", "heartbeat", "")
				f.report("merged-publisher", "generation", "up", "")
			}
			f.report("merged-publisher", "generation", "down", "transport lost")
			f.clock.Add(600)
			f.sweep(1)
			if f.mailer.messages[0].to != merged.PrimaryEmail {
				t.Fatal(f.mailer.messages)
			}
			count, err := f.local.GetTunnelCount(ctx, merged.ID)
			if err != nil || count != 0 {
				t.Fatal(count, err)
			}
		})
	}
}
