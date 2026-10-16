package host

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestRelaySessionWithUnreachableLoginNode(t *testing.T) {
	p := durableFixture(t)
	cookie := emailSession(t, p, "owner@example.com")
	conn, err := grpc.NewClient("passthrough:///unreachable-login-node", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	// A closed transport fails every RPC without contacting any external host.
	_ = conn.Close()
	remote := storage.NewProxyStorage()
	remote.SetConnection(conn)
	p.storage, p.tunnelServer.storage = remote, remote
	p.isLoginNode, p.meter = false, nil
	tunnel, _ := securityEndpoint(p, "outage", "owner@example.com", "", []string{"owner@example.com"}, false)
	// Exercise session admission independently of the existing quota policy.
	tunnel.accountQuotaExempt = true
	for _, header := range []string{"", "Authorization", "Tunn-Authorization"} {
		t.Run(header, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://outage.tunn.test/", nil)
			if header == "" {
				r.AddCookie(cookie)
			} else {
				r.Header.Set(header, "Bearer "+cookie.Value)
			}
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, r)
			if w.Code != http.StatusOK || w.Body.String() != "fixture" {
				t.Fatalf("valid session refused during outage: %d %s", w.Code, w.Body)
			}
		})
	}
}

type hungAccountLoginNode struct {
	internalv1.UnimplementedLoginNodeDBServer
	started chan struct{}
}

func (s *hungAccountLoginNode) GetAccount(ctx context.Context, _ *internalv1.GetAccountRequest) (*internalv1.AccountResponse, error) {
	s.started <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestRegistrationLoginLookupRespectsStreamDeadline(t *testing.T) {
	p := durableFixture(t)
	session := emailSession(t, p, "owner@example.com").Value
	device := durableLogin(t, p).Access
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	login := &hungAccountLoginNode{started: make(chan struct{}, 2)}
	internalv1.RegisterLoginNodeDBServer(server, login)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///hung-login-node", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); server.Stop(); _ = listener.Close() })
	remote := storage.NewProxyStorage()
	remote.SetConnection(conn)
	p.tunnelServer.storage = remote
	for _, token := range []struct{ name, raw string }{{"session", session}, {"device", device}} {
		t.Run(token.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 1), outgoing: make(chan *pb.TunnelMessage, 1)}
			stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{
				TunnelId: "deadline", TargetUrl: "http://localhost:8080", AuthToken: token.raw, TunnelKey: p.config.WellKnownKey,
			}}}
			done := make(chan error, 1)
			go func() { done <- p.tunnelServer.EstablishTunnel(stream) }()
			select {
			case <-login.started:
			case <-time.After(2 * time.Second):
				t.Fatal("registration never reached login-node lookup")
			}
			select {
			case err := <-done:
				if err == nil || ctx.Err() != context.DeadlineExceeded {
					t.Fatalf("registration returned before lookup deadline: %v, context: %v", err, ctx.Err())
				}
			case <-time.After(time.Second):
				t.Fatal("hung login node stalled registration beyond stream deadline")
			}
			if p.tunnelServer.GetActiveTunnelCount() != 1 { // Only the fixture's existing tunnel remains.
				t.Fatal("deadline registration left a tunnel behind")
			}
		})
	}
}
