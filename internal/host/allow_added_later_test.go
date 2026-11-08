package host

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/protobuf/proto"
)

func TestWebAllowReconnectDurableDecisions(t *testing.T) {
	f := newMCPOAuthFixture(t)
	p := f.p
	ledger := p.meter.(*metering.Store)
	p.tunnelServer.sharing = ledger
	ctx := context.Background()
	call := func(op, email string) *mp.WebResource {
		t.Helper()
		out, err := ledger.Sharing(ctx, &mp.SharingRequest{Operation: op, Owner: f.tunnel.AccountID, Endpoint: "preview", Mode: "private", Email: email, InitialEmails: []string{"a@x"}, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
		if err != nil {
			t.Fatal(err)
		}
		return out.Resources[0]
	}
	call("register", "")
	call("share", "invited@x")
	register := func(t *testing.T, allow []string, want bool, denied string) {
		t.Helper()
		before := proto.Clone(call("get", ""))
		var auditBefore, auditAfter int
		if err := p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM sharing_audit`).Scan(&auditBefore); err != nil {
			t.Fatal(err)
		}
		stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
		stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "preview", TargetUrl: "http", AuthToken: relayJWT(t, p, "owner@example.com"), TunnelKey: p.config.WellKnownKey, AllowedEmails: allow, ExposureVersion: 1, ExposureMode: "private"}}}
		close(stream.recvQueue)
		_ = p.tunnelServer.EstablishTunnel(stream)
		if len(stream.sentMsgs) == 0 {
			t.Fatal("no response")
		}
		reply := stream.sentMsgs[0].GetRegisterResponse()
		if reply == nil || reply.Success != want {
			t.Fatalf("registration = %v", reply)
		}
		if denied != "" && !strings.Contains(reply.ErrorMessage, "--allow "+denied+" is not in effect for preview.") {
			t.Fatal(reply)
		}
		after := call("get", "")
		if !proto.Equal(before, after) {
			t.Fatalf("reconnect changed decisions: before=%v after=%v", before, after)
		}
		if err := p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM sharing_audit`).Scan(&auditAfter); err != nil {
			t.Fatal(err)
		}
		if auditBefore != auditAfter {
			t.Fatal("reconnect wrote sharing audit")
		}
		if !webPersonAllowed(after, []string{"invited@x"}, "owner@example.com", time.Now()) {
			t.Fatal("reconnect lost invitation")
		}
	}
	t.Run("added email", func(t *testing.T) { register(t, []string{"a@x", "b@x"}, false, "b@x") })
	t.Run("no changes", func(t *testing.T) { register(t, []string{"a@x"}, true, "") })
	t.Run("invited person", func(t *testing.T) { register(t, []string{"a@x", "invited@x"}, true, "") })
	call("unshare", "a@x")
	t.Run("revoked stays revoked", func(t *testing.T) { register(t, []string{"a@x"}, false, "a@x") })
	if webPersonAllowed(call("get", ""), []string{"a@x"}, "owner@example.com", time.Now()) {
		t.Fatal("reinstated revoked person")
	}
	call("share", "b@x")
	t.Run("explicit share repairs added email", func(t *testing.T) { register(t, []string{"b@x"}, true, "") })
	t.Run("expired stays expired", func(t *testing.T) {
		now := time.Now().Add(2 * time.Hour)
		p.tunnelServer.now = func() time.Time { return now }
		defer func() { p.tunnelServer.now = nil }()
		register(t, []string{"b@x"}, false, "b@x")
	})
}
