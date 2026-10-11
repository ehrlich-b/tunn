package store

import (
	"context"
	"os"
	"testing"
)

// Run only against archived production 110485c. This creates synthetic data.
func TestRereviewSeed110485c(t *testing.T) {
	path := os.Getenv("REREVIEW_DB")
	if path == "" {
		t.Fatal("REREVIEW_DB required")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("seed path must not exist", err)
	}
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accounts, ops := NewAccountStore(db), NewOperationsStore(db, nil)
	ctx := context.Background()
	for _, kind := range []string{"operator", "manual", "stripe-paid", "sequenced", "fixture-reviewed", "merged"} {
		a, err := accounts.FindOrCreateByEmails([]string{kind + "@example.invalid"}, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		p := operationsPrincipal(t, a.ID)
		switch kind {
		case "operator", "merged":
			err = accounts.UpdatePlan(a.ID, "pro")
		case "manual":
			_, err = db.Exec("UPDATE accounts SET plan='pro' WHERE id=?", a.ID)
		case "stripe-paid":
			err = ops.BindBilling(ctx, p, BillingMapping{Provider: "stripe", CustomerID: "cus_paid", SubscriptionID: "sub_paid", AccountID: a.ID})
			if err != nil {
				t.Fatal(err)
			}
			result, e := ops.ProcessBillingEvent(ctx, BillingEvent{Provider: "stripe", ID: "evt_paid", Type: "checkout.session.completed", CustomerID: "cus_paid", SubscriptionID: "sub_paid", Supported: true})
			if e != nil || result.State != "reconciliation_required" {
				t.Fatal(result, e)
			}
			// At 110485c Stripe receipts alone cannot grant Pro. Fulfill via UpdatePlan.
			err = accounts.UpdatePlan(a.ID, "pro")
		case "sequenced":
			err = ops.BindBilling(ctx, p, BillingMapping{Provider: "provider-v1", CustomerID: "cus_seq", SubscriptionID: "sub_seq", AccountID: a.ID})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ops.ProcessBillingEvent(ctx, BillingEvent{Provider: "provider-v1", ID: "evt_seq", Type: "subscription.updated", CustomerID: "cus_seq", SubscriptionID: "sub_seq", Revision: 1, Plan: "pro", Supported: true})
		case "fixture-reviewed":
			_, err = db.Exec("CREATE TABLE ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO ops_fixture VALUES(1,'disposable-local')")
			if err != nil {
				t.Fatal(err)
			}
			err = ops.BindBilling(ctx, p, BillingMapping{Provider: "fixture", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: a.ID})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ops.Reconcile(ctx, p, []BillingSnapshot{{Provider: "fixture", CustomerID: "cus_fixture", SubscriptionID: "sub_fixture", AccountID: a.ID, Revision: 1, Plan: "pro"}}, true)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec("DROP TABLE ops_fixture")
		}
		if err != nil {
			t.Fatal(err)
		}
		if kind == "merged" {
			b, e := accounts.FindOrCreateByEmails([]string{"alias@example.invalid"}, "fixture")
			if e != nil {
				t.Fatal(e)
			}
			a, err = accounts.FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github")
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := accounts.GetByID(a.ID)
		if err != nil || got.Plan != "pro" {
			t.Fatal(got, err)
		}
		if err := accounts.ReserveSubdomain(a.ID, "legacy-"+kind); err != nil {
			t.Fatal(err)
		}
		if err := accounts.RecordUsage(a.ID, 12345); err != nil {
			t.Fatal(err)
		}
		if kind == "operator" {
			if _, err := ops.Transition(ctx, p, a.ID, "suspended", "preserve control", 0); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("110485c kind=%s id=%s plan=pro reservation=legacy-%s", kind, a.ID, kind)
	}
}

func TestRereviewImageRollbackRestoresLegacyBenefits(t *testing.T) {
	db, err := OpenLocal(os.Getenv("REREVIEW_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var paid, reserved int
	if err := db.QueryRow("SELECT count(*) FROM accounts WHERE plan='pro'").Scan(&paid); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM reserved_subdomains").Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	t.Logf("after 110485c image rollback: paid=%d reservations=%d", paid, reserved)
	if paid != 6 || reserved != 6 {
		t.Errorf("image rollback lost original benefits: paid=%d names=%d; want 6/6", paid, reserved)
	}
}
