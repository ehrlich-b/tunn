package store_test

import (
	"context"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/store"
)

func TestR3GoogleSubjectBindingSurvivesMergeAndRejectsEmailRebinding(t *testing.T) {
	db := accountCorrectnessDB(t)
	accounts := store.NewAccountStore(db)
	ctx := context.Background()
	owner, err := accounts.FindOrCreateGoogleIdentity(ctx, "stable-subject", "owner@example.com", "example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	other, err := accounts.FindOrCreateByEmails([]string{"other@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = accounts.FindOrCreateGoogleIdentity(ctx, "stable-subject", "other@example.com", "example.com", true); err == nil {
		t.Fatal("bound subject acquired a different email's account")
	}
	if _, err = accounts.FindOrCreateGoogleIdentity(ctx, "third-party-subject", "owner@example.com", "", true); err == nil {
		t.Fatal("third-party identity attached by historical verification")
	}
	if err = accounts.UpdatePlan(other.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{owner.PrimaryEmail, other.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	rebound, err := accounts.FindOrCreateGoogleIdentity(ctx, "stable-subject", "owner@example.com", "example.com", true)
	if err != nil || rebound.ID != merged.ID {
		t.Fatal("subject lost merged account", rebound, err)
	}
	var bound string
	if err = db.QueryRow(`SELECT account_id FROM account_provider_identities WHERE issuer=? AND subject=?`, common.GoogleIssuer, "stable-subject").Scan(&bound); err != nil || bound != merged.ID {
		t.Fatal(bound, err)
	}
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM account_provider_identities`).Scan(&n); err != nil || n != 1 {
		t.Fatal("failed identity created a binding", n, err)
	}
	// A fresh store object must recognize the durable subject.
	again, err := store.NewAccountStore(db).FindOrCreateGoogleIdentity(ctx, "stable-subject", "owner@example.com", "example.com", true)
	if err != nil || again.ID != merged.ID {
		t.Fatal(again, err)
	}
}

func TestR3GoogleIdentityBindingAndAccountCreationAreAtomic(t *testing.T) {
	db := accountCorrectnessDB(t)
	if _, err := db.Exec(`CREATE TRIGGER reject_google_identity BEFORE INSERT ON account_provider_identities BEGIN SELECT RAISE(ABORT,'fixture binding failure'); END`); err != nil {
		t.Fatal(err)
	}
	accounts := store.NewAccountStore(db)
	if _, err := accounts.FindOrCreateGoogleIdentity(context.Background(), "new-subject", "new@gmail.com", "", true); err == nil {
		t.Fatal("failed binding reported success")
	}
	for _, table := range []string{"accounts", "account_emails", "account_provider_identities"} {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("identity failure left partial account", table, n, err)
		}
	}
}
