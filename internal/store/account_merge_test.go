package store_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestAccountMergePreservesMeterBudgetsAndInflightEvents(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	accounts := store.NewAccountStore(db)
	a, err := accounts.FindOrCreateByEmails([]string{"first@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	b, err := accounts.FindOrCreateByEmails([]string{"second@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := metering.New(db, metering.WithAccountPlans(), metering.WithOwnerBudgets(2, 10))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var activeID string
	for i, owner := range []string{a.ID, b.ID} {
		id := fmt.Sprintf("%032x", i+1)
		activeID = id
		if d, err := ledger.Admit(ctx, &pb.Event{RequestId: id, Owner: owner, Endpoint: "site", Caller: "anonymous", Allowed: true}); err != nil || !d.Allowed {
			t.Fatalf("%v %v", d, err)
		}
		if _, err := ledger.Charge(ctx, &pb.ChargeRequest{RequestId: id, RequestBytes: 3}); err != nil {
			t.Fatal(err)
		}
		if err := accounts.RecordUsage(owner, 3); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256([]byte("test-secret"))
	g, err := ledger.CreateGrant(ctx, &pb.Grant{Owner: b.ID, Endpoint: "site", TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{"first@example.com", "second@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	out, err := ledger.Export(ctx, &pb.ExportRequest{Owner: merged.ID})
	if err != nil || out.OwnerUsage.AdmittedRequests != 2 || out.OwnerUsage.TotalBytes != 6 {
		t.Fatalf("%v %v", out, err)
	}
	if usage, err := accounts.GetMonthlyUsage(merged.ID); err != nil || usage != 6 {
		t.Fatalf("legacy usage %d %v", usage, err)
	}
	d, err := ledger.Admit(ctx, &pb.Event{RequestId: fmt.Sprintf("%032x", 3), Owner: merged.ID, Endpoint: "other", Caller: "other", Allowed: true})
	if err != nil || d.Allowed || d.Reason != "owner_request_budget" {
		t.Fatalf("merged cap reset: %v %v", d, err)
	}
	d, err = ledger.Charge(ctx, &pb.ChargeRequest{RequestId: activeID, RequestBytes: 8})
	if err != nil || d.Allowed || d.RequestBytes != 7 {
		t.Fatalf("inflight counts lost: %v %v", d, err)
	}
	resolved, err := ledger.Resolve(ctx, &pb.ResolveRequest{Owner: merged.ID, Endpoint: "site", TokenSha256: digest[:]})
	if err != nil || resolved.Owner != merged.ID || resolved.Id != g.Id {
		t.Fatalf("grant orphaned %v %v", resolved, err)
	}
}
