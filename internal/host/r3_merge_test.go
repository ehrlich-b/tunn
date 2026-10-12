package host

import (
	"context"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/store"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"testing"
)

func TestR3AccountMergePreservesRevocationAndPrivateMode(t *testing.T) {
	f := newMCPOAuthFixture(t)
	p, tunnel := f.p, f.tunnel
	delete(p.tunnelServer.tunnels, "tools")
	tunnel.TunnelID, tunnel.TargetURL, tunnel.EndpointProtocol = "api", "http", "http"
	tunnel.AllowedEmails = nil
	p.tunnelServer.tunnels["api"] = tunnel
	ledger := p.meter.(*metering.Store)
	ctx := context.Background()
	register := func(owner, mode string, initial []string) *mp.WebResource {
		t.Helper()
		r, err := ledger.Sharing(ctx, &mp.SharingRequest{Operation: "register", Owner: owner, Endpoint: "api", Mode: mode, InitialEmails: initial})
		if err != nil {
			t.Fatal(err)
		}
		return r.Resources[0]
	}
	r := register(tunnel.AccountID, "private", []string{"alice@example.com", "bob@example.com"})
	legacy, err := ledger.Sharing(ctx, &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: "legacy-review", Mode: "private"})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.ResourceID = r.Id
	ownerToken := relayJWT(t, p, "owner@example.com")
	if w := sharingCall(t, p, "DELETE", "api", ownerToken, `{"email":"alice@example.com"}`); w.Code != 200 {
		t.Fatal(w)
	}
	if w := webOpen(t, p, "alice@example.com"); w.Code != 403 {
		t.Fatal("pre-merge revocation failed", w.Code)
	}
	accounts := store.NewAccountStore(p.mcpOAuth.db)
	second, err := accounts.FindOrCreateByEmails([]string{"owner-second@example.com"}, "google")
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.UpdatePlan(second.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{"owner@example.com", "owner-second@example.com"}, "github")
	if err != nil || merged.ID != second.ID {
		t.Fatalf("merge=%v err=%v", merged, err)
	}
	var resourceOwner, grantOwner string
	if err = p.mcpOAuth.db.QueryRow("SELECT owner FROM web_resources WHERE endpoint='api'").Scan(&resourceOwner); err != nil {
		t.Fatal(err)
	}
	if err = p.mcpOAuth.db.QueryRow("SELECT owner FROM meter_grants WHERE endpoint=?", r.Id).Scan(&grantOwner); err != nil {
		t.Fatal(err)
	}
	if resourceOwner != grantOwner || resourceOwner != merged.ID {
		t.Fatal("merge split resource and grant ownership")
	}
	if w := sharingCall(t, p, "GET", "api", ownerToken, ""); w.Code != 200 {
		t.Fatalf("merged owner get=%d", w.Code)
	}
	if w := sharingCall(t, p, "DELETE", "api", ownerToken, `{"email":"alice@example.com"}`); w.Code != 200 {
		t.Fatalf("merged owner unshare=%d", w.Code)
	}
	if w := webOpen(t, p, "bob@example.com"); w.Code != 200 {
		t.Fatal("merge lost live grantee access", w.Code)
	}
	if w := webOpen(t, p, "owner@example.com"); w.Code != 200 {
		t.Fatalf("live owner=%d", w.Code)
	}
	if w := webOpen(t, p, "alice@example.com"); w.Code != 403 {
		t.Fatal("live merge restored revoked access", w.Code)
	}
	if _, err := ledger.Sharing(ctx, &mp.SharingRequest{Operation: "get", Owner: tunnel.AccountID, Endpoint: "api", ResourceId: r.Id}); err != nil {
		t.Fatal("obsolete live publisher UUID failed", err)
	}
	t.Logf("merge: web_resource.owner=%s, person_grant.owner=%s; merged owner retains get/unshare authority", resourceOwner, grantOwner)
	// Same person reconnects after merging; revoked seeds must stay revoked.
	r2 := register(merged.ID, "private", []string{"alice@example.com"})
	if r2.Id != r.Id {
		t.Fatal("merge changed resource generation")
	}
	tunnel.AccountID, tunnel.ResourceID = merged.ID, r2.Id
	if w := webOpen(t, p, "alice@example.com"); w.Code != 403 {
		t.Fatalf("revived person=%d", w.Code)
	}
	t.Log("modern reconnect preserved resource generation and revoked Alice access (HTTP 403)")
	// An obsolete live publisher UUID must resolve to the survivor as well.

	p.tunnelServer.sharing = ledger
	stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
	stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "legacy-review", TargetUrl: "http", AuthToken: ownerToken, TunnelKey: p.config.WellKnownKey}}}
	close(stream.recvQueue)
	_ = p.tunnelServer.EstablishTunnel(stream)
	if len(stream.sentMsgs) == 0 || stream.sentMsgs[0].GetRegisterResponse().Success {
		t.Fatalf("legacy registration=%v", stream.sentMsgs)
	}
	got, err := ledger.Sharing(ctx, &mp.SharingRequest{Operation: "get", Owner: merged.ID, Endpoint: "legacy-review"})
	if err != nil || got.Resources[0].Mode != "private" || got.Resources[0].Id != legacy.Resources[0].Id {
		t.Fatalf("legacy mode=%v err=%v", got, err)
	}
	t.Log("actual unversioned gRPC registration refused the private-to-legacy-public downgrade")
}
