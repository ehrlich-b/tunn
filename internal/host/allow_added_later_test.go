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
	for _, tc := range []struct{ name, initial, added, visitor string }{
		{"email", "a@x", "b@x", "a@x"},
		{"domain", "@first.example", "@example.com", "a@first.example"},
	} {
		t.Run(tc.name, func(t *testing.T) { testWebAllowReconnect(t, tc.initial, tc.added, tc.visitor) })
	}
}

func testWebAllowReconnect(t *testing.T, initial, added, visitor string) {
	f := newMCPOAuthFixture(t)
	p := f.p
	ledger := p.meter.(*metering.Store)
	p.tunnelServer.sharing = ledger
	ctx := context.Background()
	call := func(op, email string) *mp.WebResource {
		t.Helper()
		out, err := ledger.Sharing(ctx, &mp.SharingRequest{Operation: op, Owner: f.tunnel.AccountID, Endpoint: "preview", Mode: "private", Email: email, InitialEmails: []string{initial}, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
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
	t.Run("added target", func(t *testing.T) { register(t, []string{initial, added}, false, added) })
	t.Run("no changes", func(t *testing.T) { register(t, []string{initial}, true, "") })
	t.Run("invited person", func(t *testing.T) { register(t, []string{initial, "invited@x"}, true, "") })
	call("unshare", initial)
	t.Run("revoked stays revoked", func(t *testing.T) { register(t, []string{initial}, false, initial) })
	if webPersonAllowed(call("get", ""), []string{visitor}, "owner@example.com", time.Now()) {
		t.Fatal("reinstated revoked person")
	}
	call("share", strings.ToUpper(added))
	t.Run("explicit share repairs added target", func(t *testing.T) { register(t, []string{added}, true, "") })
	t.Run("expired stays expired", func(t *testing.T) {
		now := time.Now().Add(2 * time.Hour)
		p.tunnelServer.now = func() time.Time { return now }
		defer func() { p.tunnelServer.now = nil }()
		register(t, []string{added}, false, added)
	})
}
