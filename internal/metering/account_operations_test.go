package metering

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestAccountOperationsLedgerAdmissionGrantAndCharge(t *testing.T) {
	ctx := context.Background()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	account, err := store.NewAccountStore(db).FindOrCreateByEmails([]string{"owner@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	token := "fixture-operator-token-0123456789"
	sum := sha256.Sum256([]byte(token))
	admin, err := store.AuthenticateAdmin([]store.AdminCredential{{Actor: "fixture-operator", TokenSHA256: hex.EncodeToString(sum[:]), Accounts: []string{account.ID}}}, token)
	if err != nil {
		t.Fatal(err)
	}
	event := &pb.Event{RequestId: strings.Repeat("a", 32), Owner: account.ID, Endpoint: "api", Caller: "anonymous", Allowed: true}
	if d, err := ledger.Admit(ctx, event); err != nil || !d.Allowed {
		t.Fatal(d, err)
	}
	if d, err := ledger.Charge(ctx, &pb.ChargeRequest{RequestId: event.RequestId, RequestBytes: 2, ResponseBytes: 3}); err != nil || !d.Allowed {
		t.Fatal(d, err)
	}
	ops := store.NewOperationsStore(db, nil)
	if _, err = ops.Transition(ctx, admin, account.ID, "suspended", "fixture hold", 0); err != nil {
		t.Fatal(err)
	}
	if d, err := ledger.Admit(ctx, event); err != nil || d.Allowed || d.Reason != "account_suspended" {
		t.Fatal("idempotent admission bypass", d, err)
	}
	if d, err := ledger.Charge(ctx, &pb.ChargeRequest{RequestId: event.RequestId, RequestBytes: 4, ResponseBytes: 6}); err != nil || d.Allowed || d.RequestBytes != 2 || d.ResponseBytes != 3 {
		t.Fatal("charge escaped suspension", d, err)
	}
	grantDigest := sha256.Sum256([]byte("fixture-consumer-token"))
	if _, err = ledger.CreateGrant(ctx, &pb.Grant{Owner: account.ID, Endpoint: "api", TokenSha256: grantDigest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err == nil {
		t.Fatal("suspended owner created grant")
	}
	if _, err = ops.Transition(ctx, admin, account.ID, "active", "review complete", 1); err != nil {
		t.Fatal(err)
	}
	if d, err := ledger.Charge(ctx, &pb.ChargeRequest{RequestId: event.RequestId, RequestBytes: 4, ResponseBytes: 6}); err != nil || !d.Allowed || d.RequestBytes != 4 || d.ResponseBytes != 6 {
		t.Fatal("resume changed usage", d, err)
	}
	if _, err = ledger.Finish(ctx, &pb.Event{RequestId: event.RequestId, Status: 200, ResponseBytes: 6}); err != nil {
		t.Fatal(err)
	}
	out, err := ledger.Export(ctx, &pb.ExportRequest{Owner: account.ID})
	if err != nil || out.OwnerUsage.AdmittedRequests != 1 || out.OwnerUsage.RequestBytes != 4 || out.OwnerUsage.ResponseBytes != 6 {
		t.Fatal(out, err)
	}
}
