package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestFunnelReviewedCheckoutOwnership(t *testing.T) {
	for _, mode := range []string{"review", "binding_claim", "existing_checkout", "write_failure"} {
		t.Run(mode, func(t *testing.T) {
			db, ops, account, _ := operationsFixture(t)
			ctx := context.Background()
			admin := operationsPrincipal(t, account.ID)
			event := BillingEvent{Provider: "stripe", ID: "evt_review", Type: "checkout.session.completed", CustomerID: "cus_review", SubscriptionID: "sub_review", SessionID: "cs_review", Supported: true}
			if _, err := ops.ProcessBillingEvent(ctx, event); err != nil {
				t.Fatal(err)
			}
			stamp := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano)
			if _, err := db.Exec(`UPDATE funnel_events SET occurred_at=? WHERE stage='checkout_completed'`, stamp); err != nil {
				t.Fatal(err)
			}
			if mode == "existing_checkout" {
				RecordFunnel(ctx, db, "checkout_completed", account.ID)
			}
			mapping := BillingMapping{Provider: event.Provider, CustomerID: event.CustomerID, SubscriptionID: event.SubscriptionID, AccountID: account.ID}
			decision := paymentDecision(ops, account, event)
			if mode == "binding_claim" {
				if err := ops.BindBilling(ctx, admin, mapping); err == nil {
					t.Fatal("ownership claim must still require review")
				}
				decision.ExpectedVersion = 1
			}
			if mode == "write_failure" {
				if _, err := db.Exec(`CREATE TRIGGER fail_funnel_reconcile BEFORE INSERT ON funnel_events BEGIN SELECT RAISE(ABORT,'fixture write failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			if err := ops.ReviewCheckoutPayment(ctx, admin, decision); err != nil {
				t.Fatal(err)
			}
			requirePlan(t, db, account.ID, "free")
			if mode == "write_failure" {
				var count int
				if err := db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='checkout_completed'`).Scan(&count); err != nil || count != 1 {
					t.Fatalf("failed write lost checkout: count=%d err=%v", count, err)
				}
				if _, err := db.Exec(`DROP TRIGGER fail_funnel_reconcile`); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				if err := ops.BindBilling(ctx, admin, mapping); err != nil {
					t.Fatal(err)
				}
				if _, err := ops.ProcessBillingEvent(ctx, event); err != nil {
					t.Fatal(err)
				}
			}
			var count int
			var storedStamp, storedHash string
			if err := db.QueryRow(`SELECT count(*),min(occurred_at),min(account_hash) FROM funnel_events WHERE stage='checkout_completed'`).Scan(&count, &storedStamp, &storedHash); err != nil {
				t.Fatal(err)
			}
			if count != 1 || storedStamp != stamp || len(storedHash) != 64 || strings.Contains(storedHash+storedStamp, "@") {
				t.Fatalf("reconciled row: count=%d stamp=%q hash=%q", count, storedStamp, storedHash)
			}
			report, err := ops.FunnelReport(ctx, operationsPrincipal(t, "*"))
			if err != nil || report.CheckoutWithoutPro != 1 {
				t.Fatalf("review alone must not clear alert: report=%+v err=%v", report, err)
			}
			if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{paymentSnapshot(ops, account, event)}); err != nil {
				t.Fatal(err)
			}
			requirePlan(t, db, account.ID, "pro")
			report, err = ops.FunnelReport(ctx, operationsPrincipal(t, "*"))
			if err != nil || report.CheckoutWithoutPro != 0 {
				t.Fatalf("activation must clear alert: report=%+v err=%v", report, err)
			}
		})
	}
}

func TestFunnelUnboundCheckoutAndWindow(t *testing.T) {
	db, ops, account, _ := operationsFixture(t)
	ctx := context.Background()
	event := BillingEvent{Provider: "stripe", ID: "evt_unbound", Type: "checkout.session.completed", CustomerID: "cus_unknown", SubscriptionID: "sub_unknown", Supported: true}
	for i := 0; i < 2; i++ {
		if _, err := ops.ProcessBillingEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	RecordFunnel(ctx, db, "checkout_completed", account.ID)
	RecordFunnel(ctx, db, "pro_active", account.ID)
	if _, err := db.Exec(`UPDATE funnel_events SET occurred_at=? WHERE stage='pro_active'`, time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	report, err := ops.FunnelReport(ctx, operationsPrincipal(t, "*"))
	if err != nil || report.CheckoutWithoutPro != 2 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if _, err := db.Exec(`UPDATE funnel_events SET occurred_at=? WHERE stage='pro_active'`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	report, err = ops.FunnelReport(ctx, operationsPrincipal(t, "*"))
	if err != nil || report.CheckoutWithoutPro != 1 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}
