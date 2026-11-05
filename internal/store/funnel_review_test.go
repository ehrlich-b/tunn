package store

import (
	"context"
	"testing"
	"time"
)

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
