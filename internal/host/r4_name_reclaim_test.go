package host

import (
	"context"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/store"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// Reachability check: authenticated gRPC publishers release and reclaim an
// unreserved name. Each replacement retires its predecessor; at most three grants exist before repair.
func TestR4ActualPublisherNameReclaimRetiresObsoletePersonRows(t *testing.T) {
	f := newMCPOAuthFixture(t)
	p := f.p
	delete(p.tunnelServer.tunnels, "tools")
	// Lower the real authority admission cap without filling production limits.
	ledger, err := metering.New(p.mcpOAuth.db, metering.WithOwnerGrantLimit(2))
	if err != nil {
		t.Fatal(err)
	}
	p.meter = ledger
	p.tunnelServer.sharing = ledger
	ctx := context.Background()
	second, err := p.storage.FindOrCreateByEmails(ctx, []string{"second@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	// Fill each Free account's stable-name allowance so review-reclaim remains
	// temporary. Reclaiming a reserved name is now correctly denied.
	for id, name := range map[string]string{f.tunnel.AccountID: "owner-stable", second.ID: "second-stable"} {
		if err := store.NewAccountStore(p.mcpOAuth.db).ReserveSubdomain(id, name); err != nil {
			t.Fatal(err)
		}
	}
	owners := []string{f.tunnel.AccountID, second.ID, f.tunnel.AccountID, second.ID, f.tunnel.AccountID}
	emails := []string{"owner@example.com", "second@example.com", "owner@example.com", "second@example.com", "owner@example.com"}
	ids := map[string]bool{}
	for i, email := range emails {
		var allowed []string
		wantPeople := 0
		if owners[i] == f.tunnel.AccountID {
			allowed = []string{"alice@example.com"}
			wantPeople = 1
		}
		stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
		stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{
			TunnelId: "review-reclaim", TargetUrl: "http", AuthToken: relayJWT(t, p, email), TunnelKey: p.config.WellKnownKey,
			ExposureVersion: 1, ExposureMode: "private", AllowedEmails: allowed,
		}}}
		close(stream.recvQueue)
		_ = p.tunnelServer.EstablishTunnel(stream)
		if len(stream.sentMsgs) == 0 || !stream.sentMsgs[0].GetRegisterResponse().Success {
			t.Fatalf("publisher %d refused: %v", i, stream.sentMsgs)
		}
		out, err := ledger.Sharing(ctx, &mp.SharingRequest{Operation: "get", Owner: owners[i], Endpoint: "review-reclaim"})
		if err != nil || len(out.Resources) != 1 || len(out.Resources[0].People) != wantPeople {
			t.Fatalf("resource %d: %v, %v", i, out, err)
		}
		id := out.Resources[0].Id
		if ids[id] {
			t.Fatal("different owner reused a resource generation")
		}
		ids[id] = true
	}
	var obsolete, total int
	if err := p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM meter_grants g WHERE json_extract(CAST(g.data AS TEXT),'$.consumer') LIKE 'person:%' AND NOT EXISTS (SELECT 1 FROM web_resources r WHERE r.id=g.endpoint AND r.owner=g.owner)`).Scan(&obsolete); err != nil {
		t.Fatal(err)
	}
	if err := p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM meter_grants`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if obsolete != 0 || total != 1 {
		t.Fatalf("obsolete=%d total=%d", obsolete, total)
	}
	restarted, err := metering.New(p.mcpOAuth.db, metering.WithOwnerGrantLimit(2))
	if err != nil {
		t.Fatal(err)
	}
	out, err := restarted.Sharing(ctx, &mp.SharingRequest{Operation: "share", Owner: f.tunnel.AccountID, Endpoint: "review-reclaim", Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil || len(out.Resources) != 1 || len(out.Resources[0].People) != 1 {
		t.Fatalf("third generation sharing after restart: %v %v", out, err)
	}
	if err := p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM meter_grants`).Scan(&total); err != nil || total != 1 {
		t.Fatalf("restart total=%d err=%v", total, err)
	}
	t.Log("third owner generation shares successfully at owner cap two, including after restart")
}
