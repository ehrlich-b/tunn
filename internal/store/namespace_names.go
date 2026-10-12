package store

import (
	"context"
	"database/sql"
	"time"
)

// MaxNamespaceAppNamesPro bounds hostname and certificate fan-out independently
// of the scarce shared *.tunn.to reservation allowance.
const MaxNamespaceAppNamesPro = 50

// MigrateNamespaceNames is forward-only and transactional. Old wildcard claims
// exposed every owner-reserved label, so preserve those bindings and all global
// reservations. The old schema cannot identify app-only global reservations.
func MigrateNamespaceNames(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS namespace_app_names(
 parent TEXT NOT NULL, target TEXT NOT NULL, label TEXT NOT NULL,
 tunnel TEXT NOT NULL, legacy INTEGER NOT NULL DEFAULT 0 CHECK(legacy IN (0,1)),
 created_at INTEGER NOT NULL, PRIMARY KEY(parent,label));
 CREATE INDEX IF NOT EXISTS namespace_app_names_tunnel ON namespace_app_names(tunnel);
 CREATE UNIQUE INDEX IF NOT EXISTS namespace_app_names_scoped_tunnel ON namespace_app_names(tunnel) WHERE legacy=0;
 CREATE TRIGGER IF NOT EXISTS namespace_claim_deleted AFTER DELETE ON custom_domains BEGIN
 DELETE FROM namespace_app_names WHERE parent=OLD.name AND target=OLD.target;
 DELETE FROM wildcard_certificates WHERE parent=OLD.name AND target=OLD.target;
 DELETE FROM domain_challenges WHERE target=OLD.target;
 END;
 CREATE TRIGGER IF NOT EXISTS namespace_claim_replaced AFTER UPDATE OF target ON custom_domains
 WHEN NEW.target!=OLD.target BEGIN
 DELETE FROM namespace_app_names WHERE parent=OLD.name AND target=OLD.target;
 DELETE FROM wildcard_certificates WHERE parent=OLD.name AND target=OLD.target;
 DELETE FROM domain_challenges WHERE target=OLD.target;
 END;
 CREATE TRIGGER IF NOT EXISTS namespace_app_deleted AFTER DELETE ON namespace_app_names BEGIN
 DELETE FROM wildcard_certificates WHERE parent=OLD.parent AND target=OLD.target AND name=OLD.label||'.'||substr(OLD.parent,3);
 DELETE FROM domain_challenges WHERE target=OLD.target AND name=OLD.label||'.'||substr(OLD.parent,3);
 END;`)
	if err != nil {
		return err
	}
	var done int
	if err = tx.QueryRow(`SELECT count(*) FROM domain_settings WHERE name='namespace-app-names-v1'`).Scan(&done); err != nil {
		return err
	}
	if done == 0 {
		_, err = tx.Exec(`INSERT INTO namespace_app_names(parent,target,label,tunnel,legacy,created_at)
 SELECT d.name,d.target,s.subdomain,s.subdomain,1,s.created_at FROM custom_domains d
 JOIN reserved_subdomains s ON s.account_id=d.owner WHERE d.name LIKE '*.%';
 INSERT INTO domain_settings(name,value) VALUES('namespace-app-names-v1','1');`)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// NamespaceTunnelOwner distinguishes scoped IDs from shared tunnel labels.
// Scoped IDs are reserved to a live, verified namespace and never auto-reserve a
// *.tunn.to slot. Ownership follows the parent account through account merges.
func (s *AccountStore) NamespaceTunnelOwner(ctx context.Context, tunnel string, now time.Time) (owner string, scoped bool, err error) {
	var exists int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='namespace_app_names'`).Scan(&exists); err != nil || exists == 0 {
		return
	}
	err = s.db.QueryRowContext(ctx, `SELECT CASE WHEN d.proven=1 AND d.state='ready' AND d.verified_until>? AND a.plan='pro' THEN d.owner ELSE '' END FROM namespace_app_names n JOIN custom_domains d ON d.name=n.parent AND d.target=n.target JOIN accounts a ON a.id=d.owner WHERE n.tunnel=? AND n.legacy=0`, now.Unix(), tunnel).Scan(&owner)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return owner, err == nil, err
}
