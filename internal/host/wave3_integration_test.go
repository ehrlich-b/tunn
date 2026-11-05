package host

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestIntegrationAccountCutoffBillingReconciliationAndSuspension(t *testing.T) {
	ctx := context.Background()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()
	local := storage.NewLocalStorage(db)
	account, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.com"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	reviewActivate(t, local, account, "cus_fixture", "sub_fixture")
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
	pending, err := ops.ProcessBillingEvent(ctx, store.BillingEvent{Provider: "stripe", ID: "evt_fixture", Type: "customer.subscription.updated", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", Plan: "free", Supported: true})
	if err != nil || pending.State != "reconciliation_required" {
		t.Fatalf("unordered billing event: %v %v", pending, err)
	}
	snapshot := reviewSnapshot(account, "cus_fixture", "sub_fixture", "evt_fixture", 1, "free", "past_due")
	if changes, err := ops.Reconcile(ctx, admin, []store.BillingSnapshot{snapshot}, false); err != nil || changes[0].State != "change_expected" {
		t.Fatalf("reconciliation preview: %v %v", changes, err)
	}
	request(200) // Neither an unordered event nor a preview changes entitlement.
	session := newIngressMeter(p, tunnel)
	if !session.admit(ctx, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://api.tunn.test/", nil)) {
		t.Fatal("active stream admission failed")
	}
	if changes, err := ops.ApplyReviewedBilling(ctx, admin, []store.BillingSnapshot{snapshot}); err != nil || changes[0].State != "applied" {
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
	reviewReceipt(t, local, "cus_fixture", "sub_fixture", "evt_recovered", "customer.subscription.updated")
	snapshot = reviewSnapshot(account, "cus_fixture", "sub_fixture", "evt_recovered", 2, "pro", "active")
	if _, err := ops.ApplyReviewedBilling(ctx, admin, []store.BillingSnapshot{snapshot}); err != nil {
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

func TestIntegrationMCPOAuthStripsCredentialsBeforePublisherInspection(t *testing.T) {
	f := newMCPOAuthFixture(t)
	connector := discoverMCPClient(t, f)
	token := connector.accessToken(t)
	stream := f.tunnel.Stream.(*meteringFixtureStream)
	forward := stream.hook
	const applicationToken = "application-bearer-fixture"
	stream.hook = func(message *pb.TunnelMessage) error {
		if request := message.GetHttpRequest(); request != nil {
			data, err := json.Marshal(request)
			if err != nil || strings.Contains(string(data), token) || strings.Contains(string(data), "tunn_auth") {
				t.Errorf("OAuth credentials reached publisher inspection: %s %v", data, err)
			}
			if request.Headers["Authorization"] != "Bearer "+applicationToken {
				t.Errorf("application credential lost: %v", request.Headers)
			}
		}
		return forward(message)
	}
	r := httptest.NewRequest(http.MethodPost, "https://tools.tunn.test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	r.Header.Set("Tunn-Authorization", "Bearer "+token)
	r.Header.Add("Authorization", "Bearer "+token)
	r.Header.Add("Authorization", "Bearer "+applicationToken)
	r.AddCookie(&http.Cookie{Name: authCookieName, Value: createTestJWT("owner@example.com", f.p.config.JWTSecret)})
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	if w.Code != 200 || f.forwarded != 1 {
		t.Fatalf("OAuth ingress: %d %s", w.Code, w.Body)
	}
	export, err := f.p.meter.Export(context.Background(), &meterpb.ExportRequest{Owner: f.tunnel.AccountID})
	if err != nil {
		t.Fatal(err)
	}
	oauthEvents := 0
	for _, event := range export.Events {
		if event.AuthMethod == "mcp_oauth" && event.Allowed && event.Forwarded && event.Finished {
			oauthEvents++
		}
	}
	data, err := json.Marshal(export)
	if err != nil || strings.Contains(string(data), token) || len(export.Events) != 2 || oauthEvents != 1 || export.OwnerUsage.AdmittedRequests != 1 {
		t.Fatalf("OAuth audit exposed credentials or lost attribution: %s %v", data, err)
	}
}
