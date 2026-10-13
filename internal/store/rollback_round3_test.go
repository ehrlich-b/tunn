package store

import (
	"context"
	"errors"
	"testing"
)

// The write sequence is the relevant unmodified 110485c merge and UpdatePlan
// SQL: move old tables, insert the flattened alias, delete, then revoke. Run
// both OpenLocal's FK enforcement and the production InitDB FK-off mode.
func TestR3RedeployAfterOldMergeAndRevocation(t *testing.T) {
	for _, mode := range []string{"ON", "OFF", "pre-journal"} {
		t.Run(mode, func(t *testing.T) {
			path := seedLegacy110485c(t)
			db, err := OpenLocal(path)
			if err != nil {
				t.Fatal(err)
			}
			var from, to string
			if err = db.QueryRow(`SELECT id FROM accounts WHERE primary_email='operator@example.invalid'`).Scan(&from); err != nil {
				t.Fatal(err)
			}
			if err = db.QueryRow(`SELECT id FROM accounts WHERE primary_email='manual@example.invalid'`).Scan(&to); err != nil {
				t.Fatal(err)
			}
			foreignKeys := mode
			if mode == "pre-journal" {
				foreignKeys = "OFF"
				var journal bool
				if err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='ops_rollback_revocations')`).Scan(&journal); err != nil {
					t.Fatal(err)
				}
				if journal {
					if _, err = db.Exec(`DROP TRIGGER ops_old_plan_revoke; DROP TRIGGER ops_old_plan_grant; DROP TRIGGER ops_old_insert_grant; DROP TRIGGER ops_old_merge; DROP TABLE ops_rollback_revocations; DROP TABLE ops_rollback_subscription_holds; DROP TABLE ops_rollback_audit; DROP TABLE ops_projection_guard`); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err = db.Exec("PRAGMA foreign_keys=" + foreignKeys); err != nil {
				t.Fatal(err)
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err = mergeAccountAccounting(tx, from, to); err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"account_emails", "reserved_subdomains", "ops_account_audit", "ops_billing_mappings", "ops_billing_events", "ops_reports"} {
				if _, err = tx.Exec("UPDATE "+table+" SET account_id=? WHERE account_id=?", to, from); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = tx.Exec(`DELETE FROM ops_account_state WHERE account_id=?`, from); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(`UPDATE account_merges SET account_id=? WHERE account_id=?`, to, from); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(`INSERT INTO account_merges VALUES(?,?)`, from, to); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(`DELETE FROM accounts WHERE id=?`, from); err != nil {
				t.Fatalf("old merge failed: %v", err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE accounts SET plan='free' WHERE id=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?)`, from, from); err != nil {
				t.Fatal(err)
			}
			if mode == "pre-journal" {
				ops := NewOperationsStore(db, nil)
				if err = ops.AdminMigrate(context.Background(), operationsPrincipal(t, to), to); !errors.Is(err, ErrDenied) {
					t.Fatal("scoped compatibility recovery", err)
				}
			}
			db.Close()
			db, err = OpenLocal(path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			requirePlan(t, db, to, "free")
			accounts := NewAccountStore(db)
			if names, err := accounts.GetReservedSubdomains(to); err != nil || len(names) != 0 {
				t.Fatalf("revoked paid names survived: %v %v", names, err)
			}
			if err := accounts.ReserveSubdomain(to, "new-free-name"); err != nil {
				t.Fatal(err)
			}
			if err := MigrateOperations(db); err != nil {
				t.Fatal(err)
			}
			if err := MigrateOperations(db); err != nil {
				t.Fatal(err)
			}
			if owner, err := accounts.GetSubdomainOwner("new-free-name"); err != nil || owner != to {
				t.Fatalf("new Free claim lost on restart: %s %v", owner, err)
			}

			var orphans int
			if err = db.QueryRow(`SELECT count(*) FROM ops_legacy_entitlements l LEFT JOIN accounts a ON a.id=l.account_id WHERE a.id IS NULL`).Scan(&orphans); err != nil || orphans != 0 {
				t.Fatal("orphan grants", orphans, err)
			}
			rows, err := db.Query(`PRAGMA foreign_key_check`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			if rows.Next() {
				t.Fatal("rollback left a broken foreign key")
			}
		})
	}
}

func TestR3OldGrantCannotResurrectWithoutGlobalReview(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	if _, err := db.Exec(`UPDATE accounts SET plan='pro' WHERE id=?`, a.ID); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "free")
	decision := LegacyEntitlementDecision{OriginalAccountID: a.ID, AccountID: a.ID, Plan: "pro", Reason: "verified rollback grant request"}
	if err := ops.ReconcileLegacyEntitlements(context.Background(), operationsPrincipal(t, a.ID), []LegacyEntitlementDecision{decision}); !errors.Is(err, ErrDenied) {
		t.Fatal("scoped regrant", err)
	}
	if err := ops.ReconcileLegacyEntitlements(context.Background(), operationsPrincipal(t, "*"), []LegacyEntitlementDecision{decision}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "pro")
	if _, err := db.Exec(`UPDATE accounts SET plan='free' WHERE id=?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE accounts SET plan='pro' WHERE id=?`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := MigrateOperations(db); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, a.ID, "free")
	var cache string
	if err := db.QueryRow(`SELECT plan FROM accounts WHERE id=?`, a.ID).Scan(&cache); err != nil || cache != "free" {
		t.Fatal("metering/domain cache resurrected Pro", cache, err)
	}
	var version int64
	if err := db.QueryRow(`SELECT version FROM ops_legacy_entitlements WHERE original_account_id=?`, a.ID).Scan(&version); err != nil || version != 2 {
		t.Fatal("regrant reset revocation version", version, err)
	}
}

func TestR3LegacyRegrantCannotRestoreHeldSubscription(t *testing.T) {
	ops, snap, _ := orderedStripeFixture(t)
	ctx := context.Background()
	db := ops.db
	if _, err := db.Exec(`UPDATE accounts SET plan='free' WHERE id=?`, snap.AccountID); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, snap.AccountID, "free")
	// The rollback-era grant request enables an explicit legacy decision, not
	// permission to restore the separately revoked verified subscription.
	if _, err := db.Exec(`UPDATE accounts SET plan='pro' WHERE id=?`, snap.AccountID); err != nil {
		t.Fatal(err)
	}
	decision := LegacyEntitlementDecision{OriginalAccountID: snap.AccountID, AccountID: snap.AccountID, Plan: "pro", Reason: "separately approved legacy grant"}
	global := operationsPrincipal(t, "*")
	if err := ops.ReconcileLegacyEntitlements(ctx, global, []LegacyEntitlementDecision{decision}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, snap.AccountID, "pro")
	decision.Plan = "free"
	decision.ExpectedVersion = 1
	if err := ops.ReconcileLegacyEntitlements(ctx, global, []LegacyEntitlementDecision{decision}); err != nil {
		t.Fatal(err)
	}
	requirePlan(t, db, snap.AccountID, "free")
}
