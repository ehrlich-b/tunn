package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRereviewDeployPreserves110485cAccounts(t *testing.T) {
	path := seedLegacy110485c(t)
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT id,primary_email,plan FROM accounts ORDER BY primary_email")
	if err != nil {
		t.Fatal(err)
	}
	type row struct{ id, email, plan string }
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.email, &r.plan); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	rows.Close()
	if len(got) != 6 {
		t.Fatalf("expected six baseline accounts, got %d", len(got))
	}
	accounts, ops := NewAccountStore(db), NewOperationsStore(db, nil)
	for _, r := range got {
		a, err := accounts.GetByID(r.id)
		if err != nil {
			t.Fatal(err)
		}
		_, checkoutErr := ops.BeginBillingCheckout(context.Background(), r.id)
		t.Logf("deploy email=%s cached=%s derived=%s checkout=%s begin_err=%v", r.email, r.plan, a.Plan, a.BillingState, checkoutErr)
		if a.Plan != "pro" {
			t.Errorf("existing granted/paid account lost Pro: %s", r.email)
		}
		if owner, err := accounts.GetSubdomainOwner("legacy-" + r.email[:len(r.email)-len("@example.invalid")]); err != nil || owner != a.ID {
			t.Errorf("existing reservation lost effective ownership: %s owner=%s err=%v", r.email, owner, err)
		}
		usage, err := accounts.GetMonthlyUsage(r.id)
		if err != nil || usage != 12345 {
			t.Fatal("usage lost", usage, err)
		}
	}
	var reservations, states, events int
	db.QueryRow("SELECT count(*) FROM reserved_subdomains").Scan(&reservations)
	db.QueryRow("SELECT count(*) FROM ops_billing_states").Scan(&states)
	db.QueryRow("SELECT count(*) FROM ops_billing_events").Scan(&events)
	t.Logf("after deploy reservations=%d verified_states=%d billing_events=%d", reservations, states, events)
	if reservations != 6 {
		t.Errorf("migration deleted legacy reservations: got %d want 6", reservations)
	}
}

func TestRereviewScopedMigrationCannotChangeOtherAccounts(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	accounts := NewAccountStore(db)
	b, err := accounts.FindOrCreateByEmails([]string{"outside-scope@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE accounts SET plan='pro' WHERE id=?; INSERT INTO reserved_subdomains VALUES('outside-scope',?,1)", b.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if err = ops.AdminMigrate(context.Background(), operationsPrincipal(t, a.ID), a.ID); err != nil {
		t.Fatal(err)
	}
	var plan string
	var names int
	db.QueryRow("SELECT plan FROM accounts WHERE id=?", b.ID).Scan(&plan)
	db.QueryRow("SELECT count(*) FROM reserved_subdomains WHERE account_id=?", b.ID).Scan(&names)
	t.Logf("scope=%s outside=%s outside_plan=%s names=%d", a.ID, b.ID, plan, names)
	if plan != "pro" || names != 1 {
		t.Error("account-scoped migration modified a different account without authorization")
	}
}

func TestRereviewAbandonedCheckoutCanRetryAfterRestart(t *testing.T) {
	db, ops, a, path := operationsFixture(t)
	reference, err := ops.BeginBillingCheckout(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	db, err = OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ops = NewOperationsStore(db, ops.now)
	var receipts int
	db.QueryRow("SELECT count(*) FROM ops_billing_events").Scan(&receipts)
	retried, err := ops.BeginBillingCheckout(context.Background(), a.ID)
	t.Logf("issued=%s completed_receipts=%d retry_err=%v", reference, receipts, err)
	if errors.Is(err, ErrCheckoutBlocked) {
		t.Error("unpaid abandoned checkout is permanently blocked with no resumable destination")
	}
	if err != nil || retried != reference || receipts != 0 {
		t.Errorf("unpaid retry must resume the same durable intent: %s %v receipts=%d", retried, err, receipts)
	}
}

func TestRereviewUpgradeChangesZeroPlansOrReservations(t *testing.T) {
	path := seedLegacy110485c(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// Also preserve Free plans and stale reservations: startup deletes nothing.
	if _, err = db.Exec(`INSERT INTO accounts VALUES('legacy-free','free@example.invalid','free',1); INSERT INTO reserved_subdomains VALUES('legacy-free','legacy-free',1)`); err != nil {
		t.Fatal(err)
	}
	plans := rereviewRows(t, db, `SELECT id,plan FROM accounts`)
	names := rereviewRows(t, db, `SELECT subdomain,account_id FROM reserved_subdomains`)
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		db, err = OpenLocal(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := rereviewRows(t, db, `SELECT id,plan FROM accounts`); !reflect.DeepEqual(plans, got) {
			t.Errorf("startup changed plans: before=%v after=%v", plans, got)
		}
		if got := rereviewRows(t, db, `SELECT subdomain,account_id FROM reserved_subdomains`); !reflect.DeepEqual(names, got) {
			t.Errorf("startup deleted/changed reservations: before=%v after=%v", names, got)
		}
		if err = db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func rereviewRows(t *testing.T, db *sql.DB, query string) map[string]string {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var a, b string
		if err = rows.Scan(&a, &b); err != nil {
			t.Fatal(err)
		}
		out[a] = b
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRereviewSyntheticReceiptCannotGrantProductionPro(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	var markers int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='ops_fixture'").Scan(&markers); err != nil || markers != 0 {
		t.Fatal(markers, err)
	}
	bindFixture(t, ops, a.ID)
	result, err := ops.ProcessBillingEvent(context.Background(), fixtureEvent("evt_synthetic", 1, "pro"))
	if err != nil {
		t.Log(err)
		return
	}
	got, err := NewAccountStore(db).GetByID(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	var actor string
	db.QueryRow("SELECT actor FROM ops_billing_events WHERE event_id='evt_synthetic'").Scan(&actor)
	t.Logf("unmarked DB synthetic event=%+v account_plan=%s actor=%q", result, got.Plan, actor)
	if got.Plan == "pro" {
		t.Error("unverified synthetic receipt grants Pro in production without reviewed evidence or actor audit")
	}
}

// The fixture is a SQL dump of the actual 110485c implementation, generated with
// TestRereviewSeed110485c (operator/manual/Stripe/sequenced/fixture/merged).
func seedLegacy110485c(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/legacy110485c.sql")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy110485c.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(string(data)); err != nil {
		t.Fatal(err)
	}
	// Retain exact usage amounts while making the historical fixture reusable.
	if _, err = db.Exec("UPDATE account_usage SET month=?", time.Now().UTC().Format("2006-01")); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRereviewImageRollbackRestoresLegacyBenefits(t *testing.T) {
	path := seedLegacy110485c(t)
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	// 110485c reads these same authoritative tables; schema installation is additive.
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var paid, reserved int
	if err = db.QueryRow("SELECT count(*) FROM accounts WHERE plan='pro'").Scan(&paid); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM reserved_subdomains").Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if paid != 6 || reserved != 6 {
		t.Errorf("image rollback lost original benefits: paid=%d names=%d; want 6/6", paid, reserved)
	}
}
