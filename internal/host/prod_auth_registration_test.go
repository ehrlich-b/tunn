package host

import (
	"context"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestProdAuthTunnelRegistrationPrincipals(t *testing.T) {
	for _, principal := range []string{"anonymous", "owner-jwt", "alias-jwt", "other-jwt", "endpoint-token", "consumer-grant", "mcp-oauth", "login-proof", "expired-jwt"} {
		t.Run(principal, func(t *testing.T) {
			f := newProdAuthFixture(t)
			delete(f.p.tunnelServer.tunnels, "tools")
			stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
			var registered *TunnelConnection
			stream.onSend = func(message *pb.TunnelMessage) error {
				if reply := message.GetRegisterResponse(); reply != nil && reply.Success {
					registered, _ = f.p.tunnelServer.GetTunnel("tools")
				}
				return stream.mockTunnelStream.Send(message)
			}
			stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{
				TunnelId: "tools", TunnelKey: f.p.config.WellKnownKey, AuthToken: f.credentials[principal],
				CreatorEmail: "other@example.com", TargetUrl: "mcp", AllowedEmails: []string{"owner@example.com"},
			}}}
			close(stream.recvQueue)
			_ = f.p.tunnelServer.EstablishTunnel(stream)
			if len(stream.sentMsgs) == 0 || stream.sentMsgs[0].GetRegisterResponse() == nil {
				t.Fatal("registration did not produce a protocol response")
			}
			want := principal == "owner-jwt" || principal == "alias-jwt"
			if got := stream.sentMsgs[0].GetRegisterResponse().Success; got != want {
				t.Fatalf("registration allowed = %v, want %v: %s", got, want, stream.sentMsgs[0].GetRegisterResponse().ErrorMessage)
			}
			if want {
				email := "owner@example.com"
				if principal == "alias-jwt" {
					email = "alias@example.net"
				}
				if registered == nil || registered.CreatorEmail != email || registered.AccountID != f.tunnel.AccountID {
					t.Fatal("publisher identity did not come from the authenticated account")
				}
			}
			owner, err := f.p.tunnelServer.accounts.GetSubdomainOwner("tools")
			if err != nil || owner != f.tunnel.AccountID {
				t.Fatalf("registration changed durable ownership: %q, error %v", owner, err)
			}
		})
	}
}

func TestProdAuthTunnelRegistrationSuspendedOwner(t *testing.T) {
	f := newProdAuthFixture(t)
	delete(f.p.tunnelServer.tunnels, "tools")
	// Change the actual persisted operational state, rather than the publisher's
	// cached plan, so the admission exercises the live account lookup.
	admin := accountOperationsAdmin(t, f.tunnel.AccountID)
	if _, err := store.NewOperationsStore(f.p.mcpOAuth.db, nil).Transition(context.Background(), admin, f.tunnel.AccountID, "suspended", "auth fixture", 0); err != nil {
		t.Fatal(err)
	}
	if response := securityRegister(t, f.p.tunnelServer, "tools", f.credentials["owner-jwt"]); response.Success {
		t.Fatal("a suspended owner published a reserved endpoint")
	}
}
