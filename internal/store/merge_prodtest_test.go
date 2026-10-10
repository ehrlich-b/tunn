package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
)

func accountsCorrectnessAdmin(t *testing.T, ids ...string) store.AdminPrincipal {
	t.Helper()
	const token = "accounts-fixture-admin-token-0123456789"
	sum := sha256.Sum256([]byte(token))
	principal, err := store.AuthenticateAdmin([]store.AdminCredential{{Actor: "accounts-fixture", TokenSHA256: hex.EncodeToString(sum[:]), Accounts: ids}}, token)
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func TestAccountsChainedMergePreservesAliasesSuspensionAndUsage(t *testing.T) {
	db := accountCorrectnessDB(t)
	accounts := store.NewAccountStore(db)
	ops := store.NewOperationsStore(db, nil)
	ctx := context.Background()
	var originals []*store.Account
	for i := 0; i < 3; i++ {
		a, err := accounts.FindOrCreateByEmails([]string{fmt.Sprintf("owner-%d@example.invalid", i)}, "magic_link")
		if err != nil {
			t.Fatal(err)
		}
		if err := accounts.RecordUsage(a.ID, int64(11+i)); err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			if err := accounts.UpdatePlan(a.ID, "pro"); err != nil {
				t.Fatal(err)
			}
		}
		originals = append(originals, a)
	}
	if _, err := ops.Transition(ctx, accountsCorrectnessAdmin(t, originals[0].ID), originals[0].ID, "suspended", "initial hold", 0); err != nil {
		t.Fatal(err)
	}
	first, err := accounts.FindOrCreateByEmails([]string{originals[0].PrimaryEmail, originals[1].PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if first.Plan != "pro" || first.OperationalState != "suspended" {
		t.Fatal(first)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{originals[0].PrimaryEmail, originals[2].PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range originals {
		a, err := accounts.GetByID(old.ID)
		if err != nil || a.ID != merged.ID || a.Plan != "pro" || a.OperationalState != "suspended" || len(a.Emails) != 3 {
			t.Fatalf("alias lookup=%+v err=%v", a, err)
		}
		if usage, err := accounts.GetMonthlyUsage(old.ID); err != nil || usage != 36 {
			t.Fatalf("usage through alias %s=%d err=%v", old.ID, usage, err)
		}
		if status, err := ops.LookupAccountStatus(ctx, old.ID); err != nil || status.AccountID != merged.ID || status.State != "suspended" {
			t.Fatalf("status=%v err=%v", status, err)
		}
	}
	var invalidAliases, history int
	if err := db.QueryRow("SELECT count(*) FROM account_merges WHERE account_id <> ?", merged.ID).Scan(&invalidAliases); err != nil || invalidAliases != 0 {
		t.Fatalf("aliases not flattened: %d %v", invalidAliases, err)
	}
	if err := db.QueryRow("SELECT count(*) FROM ops_account_audit WHERE original_account_id=? AND reason='initial hold'", originals[0].ID).Scan(&history); err != nil || history != 1 {
		t.Fatalf("original suspension audit lost: %d %v", history, err)
	}
	if _, err := ops.Transition(ctx, accountsCorrectnessAdmin(t, merged.ID), merged.ID, "active", "review complete", merged.OperationalVersion); err != nil {
		t.Fatal(err)
	}
	if err := accounts.RecordUsage(originals[0].ID, 4); err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpdatePlan(originals[0].ID, "free"); err != nil {
		t.Fatal(err)
	}
	if a, err := accounts.GetByID(merged.ID); err != nil || a.Plan != "free" || a.OperationalState != "active" {
		t.Fatalf("alias update=%v err=%v", a, err)
	}
	if usage, err := accounts.GetMonthlyUsage(merged.ID); err != nil || usage != 40 {
		t.Fatalf("delayed alias usage=%d err=%v", usage, err)
	}
}

func TestAccountsMergeAndAliasFailureRollBackTogether(t *testing.T) {
	db := accountCorrectnessDB(t)
	accounts := store.NewAccountStore(db)
	first, err := accounts.FindOrCreateByEmails([]string{"first@example.invalid"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	second, err := accounts.FindOrCreateByEmails([]string{"second@example.invalid"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpdatePlan(second.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if err := accounts.RecordUsage(first.ID, 11); err != nil {
		t.Fatal(err)
	}
	if err := accounts.RecordUsage(second.ID, 17); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_new_alias BEFORE INSERT ON account_emails
WHEN NEW.email='third@example.invalid' BEGIN SELECT RAISE(ABORT,'fixture alias failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.FindOrCreateByEmails([]string{first.PrimaryEmail, second.PrimaryEmail, "third@example.invalid"}, "github"); err == nil {
		t.Fatal("failed alias committed merge")
	}
	for i, original := range []*store.Account{first, second} {
		a, err := accounts.GetByEmail(original.PrimaryEmail)
		if err != nil || a.ID != original.ID || len(a.Emails) != 1 {
			t.Fatalf("merge survived failed alias: %v %v", a, err)
		}
		want := []int64{11, 17}[i]
		if usage, err := accounts.GetMonthlyUsage(original.ID); err != nil || usage != want {
			t.Fatalf("merge usage changed: %d %v", usage, err)
		}
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM account_merges").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed merge left aliases: %d %v", count, err)
	}
}

func TestAccountsMergedReservationReadAndReleaseResolveAlias(t *testing.T) {
	accounts := store.NewAccountStore(accountCorrectnessDB(t))
	first, err := accounts.FindOrCreateByEmails([]string{"first@example.invalid"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	second, err := accounts.FindOrCreateByEmails([]string{"second@example.invalid"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []*store.Account{first, second} {
		if err := accounts.UpdatePlan(account.ID, "pro"); err != nil {
			t.Fatal(err)
		}
	}
	if err := accounts.ReserveSubdomain(first.ID, "retained-service"); err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{first.PrimaryEmail, second.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	oldID := first.ID
	if oldID == merged.ID {
		oldID = second.ID
	}
	names, err := accounts.GetReservedSubdomains(oldID)
	if err != nil || len(names) != 1 || names[0].AccountID != merged.ID || names[0].Subdomain != "retained-service" {
		t.Fatalf("old UUID cannot read retained reservations: %v %v", names, err)
	}
	if err := accounts.ReleaseSubdomain(oldID, "retained-service"); err != nil {
		t.Fatalf("old UUID cannot release retained reservation: %v", err)
	}
	if owner, err := accounts.GetSubdomainOwner("retained-service"); err != nil || owner != "" {
		t.Fatalf("release left reservation: %s %v", owner, err)
	}
}
