package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func identityCheckout(t *testing.T, ops *OperationsStore, account *Account) BillingEvent {
	t.Helper()
	ref, _, err := ops.PrepareBillingCheckout(context.Background(), account.ID, "https://buy.stripe.com/fixture")
	if err != nil {
		t.Fatal(err)
	}
	event := BillingEvent{Provider: "stripe", ID: "evt_identity", Type: "checkout.session.completed", CustomerID: "cus_identity", SubscriptionID: "sub_identity", SessionID: "cs_identity", CheckoutReference: ref, Supported: true}
	result, err := ops.ProcessBillingEvent(context.Background(), event)
	if err != nil || result.AccountID != account.ID {
		t.Fatalf("checkout: %+v %v", result, err)
	}
	return event
}

func identityActivate(t *testing.T, ops *OperationsStore, account *Account, event BillingEvent) {
	t.Helper()
	ctx := context.Background()
	admin := operationsPrincipal(t, "*")
	mapping := BillingMapping{Provider: event.Provider, CustomerID: event.CustomerID, SubscriptionID: event.SubscriptionID, AccountID: account.ID}
	for i := 0; i < 2; i++ {
		if err := ops.BindBilling(ctx, admin, mapping); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{paymentSnapshot(ops, account, event)}); err != nil {
		t.Fatal(err)
	}
}

func identityAssert(t *testing.T, db *sql.DB, ops *OperationsStore, account *Account, earliest string) {
	t.Helper()
	var count int
	var stamp string
	hash := funnelAccountHash(context.Background(), db, account.ID)
	if err := db.QueryRow(`SELECT count(*),min(occurred_at) FROM funnel_events WHERE stage='checkout_completed' AND account_hash=?`, hash).Scan(&count, &stamp); err != nil || count != 1 || stamp != earliest {
		t.Fatalf("checkout count=%d timestamp=%q want=%q err=%v", count, stamp, earliest, err)
	}
	report, err := ops.FunnelReport(context.Background(), operationsPrincipal(t, "*"))
	if err != nil || report.CheckoutWithoutPro != 1 {
		t.Fatalf("unmatched control: report=%+v err=%v", report, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='checkout_completed'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("checkout deduplication: count=%d err=%v", count, err)
	}
}

func TestFunnelCheckoutReassignedAccount(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	accounts := NewAccountStore(db)
	b, err := accounts.FindOrCreateByEmails([]string{"second@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	event := identityCheckout(t, ops, a)
	earliest := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	if _, err = db.Exec(`UPDATE funnel_events SET occurred_at=? WHERE stage='checkout_completed'`, earliest); err != nil {
		t.Fatal(err)
	}
	RecordFunnel(ctx, db, "checkout_completed", b.ID)
	RecordFunnel(ctx, db, "checkout_completed", "unmatched-control")
	decision := paymentDecision(ops, b, event)
	decision.ReassignOwnership = true
	if err = ops.ReviewCheckoutPayment(ctx, operationsPrincipal(t, "*"), decision); err != nil {
		t.Fatal(err)
	}
	identityActivate(t, ops, b, event)
	identityAssert(t, db, ops, b, earliest)
}

func TestFunnelMergedAccountIdentity(t *testing.T) {
	for _, buyerSurvives := range []bool{false, true} {
		t.Run(map[bool]string{false: "retired_buyer", true: "surviving_buyer"}[buyerSurvives], func(t *testing.T) {
			db, ops, buyer, _ := operationsFixture(t)
			accounts := NewAccountStore(db)
			other, err := accounts.FindOrCreateByEmails([]string{"second@example.invalid"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			event := identityCheckout(t, ops, buyer)
			earliest := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano)
			if _, err = db.Exec(`UPDATE funnel_events SET occurred_at=? WHERE stage='checkout_completed'`, earliest); err != nil {
				t.Fatal(err)
			}
			RecordFunnel(ctx, db, "checkout_completed", other.ID)
			RecordFunnel(ctx, db, "checkout_completed", "unmatched-control")
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			ordered := []*Account{other, buyer}
			if buyerSurvives {
				ordered = []*Account{buyer, other}
			}
			survivor, err := accounts.mergeAccounts(tx, ordered)
			if err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if (survivor.ID == buyer.ID) != buyerSurvives {
				t.Fatal("unexpected survivor")
			}
			identityActivate(t, ops, survivor, event)
			identityAssert(t, db, ops, survivor, earliest)
		})
	}
}

func TestFunnelIdentityWriteFailure(t *testing.T) {
	for _, operation := range []string{"reassign", "merge"} {
		t.Run(operation, func(t *testing.T) {
			db, ops, a, _ := operationsFixture(t)
			accounts := NewAccountStore(db)
			b, err := accounts.FindOrCreateByEmails([]string{"second@example.invalid"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			event := identityCheckout(t, ops, a)
			hash := funnelAccountHash(context.Background(), db, a.ID)
			if _, err = db.Exec(`CREATE TRIGGER fail_identity_copy BEFORE INSERT ON funnel_events BEGIN SELECT RAISE(ABORT,'fixture write failure'); END`); err != nil {
				t.Fatal(err)
			}
			if operation == "reassign" {
				decision := paymentDecision(ops, b, event)
				decision.ReassignOwnership = true
				if err = ops.ReviewCheckoutPayment(context.Background(), operationsPrincipal(t, "*"), decision); err != nil {
					t.Fatal(err)
				}
			} else {
				tx, err := db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				if _, err = accounts.mergeAccounts(tx, []*Account{b, a}); err != nil {
					_ = tx.Rollback()
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			var count int
			if err = db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='checkout_completed' AND account_hash=?`, hash).Scan(&count); err != nil || count != 1 {
				t.Fatalf("original checkout lost: count=%d err=%v", count, err)
			}
		})
	}
}
