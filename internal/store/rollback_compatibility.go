package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Only release startup or global migration can project journaled rollback
// writes. Align caches used by metering/domains with the reducer before serving;
// untouched legacy accounts and their reservations remain exactly preserved.
func projectRollbackAccounts(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT DISTINCT a.id FROM ops_rollback_audit r JOIN accounts a ON a.id=COALESCE((SELECT account_id FROM account_merges WHERE old_id=r.account_id),r.account_id)`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		if err = projectBillingAccount(context.Background(), tx, id); err != nil {
			return err
		}
	}
	return nil
}

// Compatibility triggers accompany the database through an image rollback.
// New reducers mark their own cache writes inside the same transaction; only
// old/direct plan writes are authoritative revocations. A Pro cache write
// never creates a grant. Revoked legacy grants require global, audited regrant; held subscriptions
// cannot be restored through an unrelated legacy decision.
func migrateRollbackCompatibility(tx *sql.Tx, legacyInstalled bool) error {
	var installed bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='ops_rollback_revocations')`).Scan(&installed); err != nil {
		return err
	}
	if _, err := tx.Exec(`
 CREATE TABLE IF NOT EXISTS free_reservation_claims(subdomain TEXT PRIMARY KEY REFERENCES reserved_subdomains(subdomain) ON DELETE CASCADE);
 CREATE TRIGGER IF NOT EXISTS ops_free_reservation_delete AFTER DELETE ON reserved_subdomains
 BEGIN DELETE FROM free_reservation_claims WHERE subdomain=OLD.subdomain; END;
 CREATE TRIGGER IF NOT EXISTS ops_free_reservation_rename AFTER UPDATE OF subdomain ON reserved_subdomains
 BEGIN DELETE FROM free_reservation_claims WHERE subdomain=OLD.subdomain; END;
 CREATE TRIGGER IF NOT EXISTS ops_free_reservation_upgrade AFTER UPDATE OF plan ON accounts
 WHEN NEW.plan='pro'
 BEGIN DELETE FROM free_reservation_claims WHERE subdomain IN(SELECT subdomain FROM reserved_subdomains WHERE account_id=NEW.id); END;
 CREATE TABLE IF NOT EXISTS ops_projection_guard(account_id TEXT PRIMARY KEY);
 CREATE TABLE IF NOT EXISTS ops_rollback_revocations(account_id TEXT PRIMARY KEY REFERENCES accounts(id),changed_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS ops_rollback_subscription_holds(provider TEXT NOT NULL,subscription_id TEXT NOT NULL,PRIMARY KEY(provider,subscription_id));
 CREATE TABLE IF NOT EXISTS ops_rollback_audit(id TEXT PRIMARY KEY,account_id TEXT NOT NULL,original_account_id TEXT NOT NULL,action TEXT NOT NULL,reason TEXT NOT NULL,changed_at TEXT NOT NULL);
 `); err != nil {
		return err
	}
	// Retrofit 4416eff databases that already experienced an FK-off old merge.
	// This is a one-time, conservative and audited compatibility migration, not
	// an ongoing trust in the cache. Unresolvable orphans stop startup.
	if !installed && legacyInstalled {
		if _, err := tx.Exec(`INSERT INTO ops_rollback_audit SELECT lower(hex(randomblob(16))),m.account_id,l.account_id,'merge','recover recorded old-code merge',strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM ops_legacy_entitlements l JOIN account_merges m ON m.old_id=l.account_id WHERE NOT EXISTS(SELECT 1 FROM accounts a WHERE a.id=l.account_id);
 UPDATE ops_legacy_entitlements SET account_id=(SELECT account_id FROM account_merges WHERE old_id=ops_legacy_entitlements.account_id) WHERE account_id NOT IN(SELECT id FROM accounts) AND account_id IN(SELECT old_id FROM account_merges);
 UPDATE ops_checkout_intents SET account_id=(SELECT account_id FROM account_merges WHERE old_id=ops_checkout_intents.account_id) WHERE account_id NOT IN(SELECT id FROM accounts) AND account_id IN(SELECT old_id FROM account_merges);
 UPDATE ops_checkout_payments SET account_id=(SELECT account_id FROM account_merges WHERE old_id=ops_checkout_payments.account_id) WHERE account_id!='' AND account_id NOT IN(SELECT id FROM accounts) AND account_id IN(SELECT old_id FROM account_merges);
 INSERT INTO ops_rollback_revocations SELECT DISTINCT a.id,strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM accounts a WHERE a.plan='free' AND (EXISTS(SELECT 1 FROM ops_legacy_entitlements l WHERE l.account_id=a.id AND l.plan='pro') OR EXISTS(SELECT 1 FROM ops_billing_mappings m JOIN ops_billing_states s USING(provider,subscription_id) WHERE m.account_id=a.id AND s.plan='pro'));
 INSERT OR IGNORE INTO ops_rollback_subscription_holds SELECT m.provider,m.subscription_id FROM ops_billing_mappings m JOIN ops_rollback_revocations r ON r.account_id=m.account_id;
 INSERT INTO ops_rollback_audit SELECT lower(hex(randomblob(16))),account_id,account_id,'revoke','recover pre-journal old-code revocation',changed_at FROM ops_rollback_revocations;
 INSERT INTO ops_legacy_entitlement_audit SELECT lower(hex(randomblob(16))),original_account_id,account_id,plan,'free',version+1,'recover pre-journal old-code revocation','system:rollback-compatibility',strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM ops_legacy_entitlements WHERE plan='pro' AND account_id IN(SELECT account_id FROM ops_rollback_revocations);
 UPDATE ops_legacy_entitlements SET plan='free',version=version+1 WHERE plan='pro' AND account_id IN(SELECT account_id FROM ops_rollback_revocations);
 `); err != nil {
			return err
		}
	}
	var orphans int
	if err := tx.QueryRow(`SELECT count(*) FROM ops_legacy_entitlements WHERE account_id NOT IN(SELECT id FROM accounts)`).Scan(&orphans); err != nil {
		return err
	}
	if orphans != 0 {
		return fmt.Errorf("rollback legacy ownership unresolved: %d orphan grants", orphans)
	}
	_, err := tx.Exec(`
 CREATE TRIGGER IF NOT EXISTS ops_old_plan_grant AFTER UPDATE OF plan ON accounts
 WHEN NEW.plan='pro' AND NOT EXISTS(SELECT 1 FROM ops_projection_guard WHERE account_id=NEW.id)
 BEGIN
 INSERT INTO ops_rollback_audit VALUES(lower(hex(randomblob(16))),NEW.id,NEW.id,'grant-request','old-code/direct Pro requires global review',strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 INSERT OR IGNORE INTO ops_legacy_entitlements(original_account_id,account_id,plan) VALUES(NEW.id,NEW.id,'free');
 END;
 CREATE TRIGGER IF NOT EXISTS ops_old_insert_grant AFTER INSERT ON accounts
 WHEN NEW.plan='pro'
 BEGIN
 INSERT INTO ops_rollback_audit VALUES(lower(hex(randomblob(16))),NEW.id,NEW.id,'grant-request','old-code/direct inserted Pro requires global review',strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 INSERT OR IGNORE INTO ops_legacy_entitlements(original_account_id,account_id,plan) VALUES(NEW.id,NEW.id,'free');
 END;
 CREATE TRIGGER IF NOT EXISTS ops_old_plan_revoke AFTER UPDATE OF plan ON accounts
 WHEN NEW.plan='free' AND NOT EXISTS(SELECT 1 FROM ops_projection_guard WHERE account_id=NEW.id)
 BEGIN
 INSERT INTO ops_rollback_audit VALUES(lower(hex(randomblob(16))),NEW.id,NEW.id,'revoke','old-code/direct plan revocation',strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 INSERT INTO ops_rollback_revocations VALUES(NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(account_id) DO UPDATE SET changed_at=excluded.changed_at;
 INSERT OR IGNORE INTO ops_rollback_subscription_holds SELECT provider,subscription_id FROM ops_billing_mappings WHERE account_id=NEW.id;
 INSERT INTO ops_legacy_entitlement_audit SELECT lower(hex(randomblob(16))),original_account_id,account_id,plan,'free',version+1,'old-code/direct plan revocation','system:rollback-compatibility',strftime('%Y-%m-%dT%H:%M:%fZ','now') FROM ops_legacy_entitlements WHERE account_id=NEW.id AND plan='pro';
 UPDATE ops_legacy_entitlements SET plan='free',version=version+1 WHERE account_id=NEW.id AND plan='pro';
 END;
 CREATE TRIGGER IF NOT EXISTS ops_old_merge BEFORE DELETE ON accounts
 WHEN EXISTS(SELECT 1 FROM account_merges WHERE old_id=OLD.id)
 BEGIN
 INSERT INTO ops_rollback_audit VALUES(lower(hex(randomblob(16))),(SELECT account_id FROM account_merges WHERE old_id=OLD.id),OLD.id,'merge','old-code verified account merge',strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 INSERT OR IGNORE INTO ops_billing_merged_purchases SELECT provider,subscription_id FROM ops_billing_mappings WHERE account_id=(SELECT account_id FROM account_merges WHERE old_id=OLD.id);
 UPDATE ops_legacy_entitlements SET account_id=(SELECT account_id FROM account_merges WHERE old_id=OLD.id) WHERE account_id=OLD.id;
 UPDATE ops_checkout_intents SET account_id=(SELECT account_id FROM account_merges WHERE old_id=OLD.id) WHERE account_id=OLD.id;
 UPDATE ops_checkout_payments SET account_id=(SELECT account_id FROM account_merges WHERE old_id=OLD.id) WHERE account_id=OLD.id;
 INSERT OR IGNORE INTO ops_rollback_revocations SELECT (SELECT account_id FROM account_merges WHERE old_id=OLD.id),changed_at FROM ops_rollback_revocations WHERE account_id=OLD.id;
 DELETE FROM ops_rollback_revocations WHERE account_id=OLD.id;
 END;
 `)
	return err
}
