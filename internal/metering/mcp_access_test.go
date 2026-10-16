package metering

import (
	"testing"

	"github.com/ehrlich-b/tunn/internal/mcpauth"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestSupersededMCPAccessDeniesInflightCharge(t *testing.T) {
	s, db := fixture(t)
	g := newGrant(t, s, 0, 0, 0)
	// A pre-existing request is already admitted when its family rotates.
	e := event(g, 1)
	// No authority binding is needed to exercise the ledger's grant lifecycle.
	if d := admit(t, s, e); !d.Allowed {
		t.Fatal(d)
	}
	if d := charge(t, s, e.RequestId, 2, 3); !d.Allowed {
		t.Fatal(d)
	}
	if _, err := db.Exec(`INSERT INTO mcp_oauth_access(grant_id,authorization,family) VALUES(?,'synthetic-consent',1)`, g.Id); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := mcpauth.PruneFamilyAccess(t.Context(), tx, 1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	d, err := s.Charge(t.Context(), &pb.ChargeRequest{RequestId: e.RequestId, RequestBytes: 4, ResponseBytes: 6})
	if err != nil || d.Allowed || d.Reason != "grant_revoked" || d.Status != 403 || d.RequestBytes != 2 || d.ResponseBytes != 3 {
		t.Fatalf("superseded request charge=%v error=%v", d, err)
	}
	if _, err := s.Finish(t.Context(), &pb.Event{RequestId: e.RequestId, Status: 403, Forwarded: true, ResponseBytes: 3}); err != nil {
		t.Fatal(err)
	}
	out := export(t, s, "2026-10")
	if len(out.Events) != 1 || !out.Events[0].Finished || out.Events[0].Reason != "grant_revoked" || out.OwnerUsage.RequestBytes != 2 || out.OwnerUsage.ResponseBytes != 3 {
		t.Fatal(out)
	}
}
