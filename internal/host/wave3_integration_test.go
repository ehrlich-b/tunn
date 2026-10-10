package host

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestIntegrationAccountCutoffBillingReconciliationAndSuspension(t *testing.T) {
	ctx := context.Background()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	local := storage.NewLocalStorage(db)
	account, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.com"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := local.UpdatePlan(ctx, account.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if err := local.RecordUsage(ctx, account.ID, metering.FreeMonthlyBytes); err != nil {
		t.Fatal(err)
	}
	ledger, err := metering.New(db, metering.WithAccountPlans())
	if err != nil {
		t.Fatal(err)
	}
	p, tunnel, _, stream := meteringRelay(t, false, "ok")
	p.storage, p.meter, p.planMeter = local, ledger, true
	tunnel.AccountID, tunnel.Plan, tunnel.AllowedEmails = account.ID, "free", nil
	ops := local.OperationsStore()
	admin := accountOperationsAdmin(t, account.ID)
	if err := ops.BindBilling(ctx, admin, store.BillingMapping{Provider: "stripe", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: account.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO ops_fixture VALUES(1,'disposable-local')`); err != nil {
		t.Fatal(err)
	}
	request := func(want int) {
		t.Helper()
		stream.mu.Lock()
		before := len(stream.sentMsgs)
		stream.mu.Unlock()
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://api.tunn.test/", nil))
		if w.Code != want {
			t.Fatalf("ingress = %d, want %d: %s", w.Code, want, w.Body)
		}
		stream.mu.Lock()
		after := len(stream.sentMsgs)
		stream.mu.Unlock()
		if want != 200 && after != before {
			t.Fatal("rejected request reached publisher")
		}
		if want == 429 && w.Header().Get("Tunn-Limit-Reason") != "owner_byte_budget" {
			t.Fatalf("cutoff reason = %q", w.Header().Get("Tunn-Limit-Reason"))
		}
	}
	request(200) // The authority's paid plan overrides the free publisher snapshot.
	pending, err := ops.ProcessBillingEvent(ctx, store.BillingEvent{Provider: "stripe", ID: "evt_fixture", Type: "customer.subscription.deleted", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", Plan: "free", Supported: true})
	if err != nil || pending.State != "reconciliation_required" {
		t.Fatalf("unordered billing event: %v %v", pending, err)
	}
	snapshot := store.BillingSnapshot{Provider: "stripe", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: account.ID, Plan: "free", EventIDs: []string{"evt_fixture"}}
	if changes, err := ops.Reconcile(ctx, admin, []store.BillingSnapshot{snapshot}, false); err != nil || changes[0].State != "change_expected" {
		t.Fatalf("reconciliation preview: %v %v", changes, err)
	}
	request(200) // Neither an unordered event nor a preview changes entitlement.
	session := newIngressMeter(p, tunnel)
	if !session.admit(ctx, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://api.tunn.test/", nil)) {
		t.Fatal("active stream admission failed")
	}
	if changes, err := ops.Reconcile(ctx, admin, []store.BillingSnapshot{snapshot}, true); err != nil || changes[0].State != "applied" {
		t.Fatalf("reconciliation apply: %v %v", changes, err)
	}
	request(429)
	var limit *ingressLimitError
	if err := session.checkResponse(ctx, 0); !errors.As(err, &limit) || limit.decision.Reason != "owner_byte_budget" {
		t.Fatalf("live stream retained paid quota: %v", err)
	}
	state, err := ops.Transition(ctx, admin, account.ID, "suspended", "integration fixture hold", 0)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Plan, snapshot.ExpectedVersion, snapshot.EventIDs = "pro", 1, nil
	if _, err := ops.Reconcile(ctx, admin, []store.BillingSnapshot{snapshot}, true); err != nil {
		t.Fatal(err)
	}
	request(403) // A paid upgrade cannot clear the operational hold.
	if _, err := session.charge(ctx, false, 1); !errors.As(err, &limit) || limit.decision.Reason != "account_suspended" {
		t.Fatalf("active stream escaped hold: %v", err)
	}
	before, err := ledger.Export(ctx, &meterpb.ExportRequest{Owner: account.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ops.Transition(ctx, admin, account.ID, "active", "integration fixture reviewed", state.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := session.charge(ctx, false, 1); err != nil {
		t.Fatal(err)
	}
	request(200)
	after, err := ledger.Export(ctx, &meterpb.ExportRequest{Owner: account.ID})
	if err != nil || after.OwnerUsage.AdmittedRequests != before.OwnerUsage.AdmittedRequests+1 || after.OwnerUsage.TotalBytes != before.OwnerUsage.TotalBytes+3 {
		t.Fatalf("resume reset accounting: before=%v after=%v err=%v", before, after, err)
	}
}
