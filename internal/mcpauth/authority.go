// Package mcpauth binds OAuth credentials to durable consent and live resource
// generations on the login authority. It stores identifiers and digests only.
package mcpauth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
)

func Init(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS mcp_oauth_authorizations (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, person TEXT NOT NULL, email TEXT NOT NULL,
 endpoint TEXT NOT NULL, client TEXT NOT NULL, resource TEXT NOT NULL,
 generation TEXT NOT NULL, expires INTEGER NOT NULL, approved INTEGER NOT NULL DEFAULT 0);
 CREATE INDEX IF NOT EXISTS mcp_oauth_authorization_owner ON mcp_oauth_authorizations(owner,endpoint,client);
 CREATE TABLE IF NOT EXISTS mcp_oauth_sessions (family INTEGER PRIMARY KEY, authorization TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS mcp_oauth_access (grant_id TEXT PRIMARY KEY, authorization TEXT NOT NULL, family INTEGER NOT NULL);`)
	return err
}

// Valid runs inside the credential mutation transaction, after taking the DB
// writer lock. A revoked or replaced consent cannot be restored by an exchange.
func Valid(ctx context.Context, tx *sql.Tx, id string, now time.Time) error {
	var found int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM mcp_oauth_authorizations a
 JOIN web_resources r ON r.endpoint=a.endpoint AND r.owner=a.owner AND r.id=a.generation
 JOIN accounts owner ON owner.id=a.owner JOIN accounts person ON person.id=a.person
 WHERE a.id=? AND a.approved=1 AND a.expires>? AND NOT EXISTS (SELECT 1 FROM ops_account_state o WHERE o.account_id IN (a.owner,a.person) AND o.state<>'active')
 AND EXISTS (SELECT 1 FROM account_emails e WHERE e.account_id=a.person AND e.email=a.email)`, id, now.Unix()).Scan(&found)
	return err
}

// ReconcileAllowed revokes consents omitted from a publisher's current MCP
// allow list. The list is used only in this transaction, never as a web ACL.
func ReconcileAllowed(ctx context.Context, tx *sql.Tx, owner, endpoint string, allowed []string) error {
	rows, err := tx.QueryContext(ctx, `SELECT a.id,e.email FROM mcp_oauth_authorizations a
 LEFT JOIN account_emails e ON e.account_id=a.person WHERE a.owner=? AND a.endpoint=? AND a.person<>a.owner`, owner, endpoint)
	if err != nil {
		return err
	}
	permitted := make(map[string]bool)
	for rows.Next() {
		var id string
		var email sql.NullString
		if err := rows.Scan(&id, &email); err != nil {
			rows.Close()
			return err
		}
		if _, ok := permitted[id]; !ok {
			permitted[id] = false
		}
		if !email.Valid {
			continue
		}
		normalized := common.NormalizeEmail(email.String)
		for _, entry := range allowed {
			entry = common.NormalizeEmail(entry)
			if normalized == entry || strings.HasPrefix(entry, "@") && strings.HasSuffix(normalized, entry) {
				permitted[id] = true
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for id, ok := range permitted {
		if !ok {
			if err := RevokeConsent(ctx, tx, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// PruneFamilyAccess revokes the family's previous access grants and unlinks them.
// Retain ledger rows so in-flight requests receive a normal revocation denial.
func PruneFamilyAccess(ctx context.Context, tx *sql.Tx, family int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE meter_grants SET data=json_set(CAST(data AS TEXT),'$.revoked',json('true'))
 WHERE id IN (SELECT grant_id FROM mcp_oauth_access WHERE family=?)`, family); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth_access WHERE family=?`, family)
	return err
}

func RevokeFamily(ctx context.Context, tx *sql.Tx, family int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE meter_grants SET data=json_set(CAST(data AS TEXT),'$.revoked',json('true'))
 WHERE id IN (SELECT grant_id FROM mcp_oauth_access WHERE family=?)`, family); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth_access WHERE family=?`, family); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth_sessions WHERE family=?`, family)
	return err
}

// Revoke removes every credential descended from the selected consent. Empty
// selectors mean all for that owner/resource; email may also be a domain rule.
func Revoke(ctx context.Context, tx *sql.Tx, owner, endpoint, client, email string) error {
	var installed int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='mcp_oauth_codes'`).Scan(&installed); err != nil {
		return err
	}
	if installed == 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM mcp_oauth_authorizations a WHERE owner=? AND endpoint=?
 AND (?='' OR client=?) AND (?='' OR email=? OR person IN
 (SELECT account_id FROM account_emails WHERE email=? OR (? LIKE '@%' AND substr(email,instr(email,'@'))=?)))`, owner, endpoint, client, client, email, email, email, email, email)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := RevokeConsent(ctx, tx, id); err != nil {
			return err
		}
	}
	// Pre-binding credentials cannot identify a person. Conservatively revoke
	// unbound OAuth state for this endpoint, rather than let it bypass unshare.
	for _, query := range []string{
		`DELETE FROM mcp_oauth_consents WHERE owner=? AND endpoint=? AND (?='' OR client=?) AND id NOT IN (SELECT id FROM mcp_oauth_authorizations)`,
		`DELETE FROM mcp_oauth_codes WHERE owner=? AND endpoint=? AND (?='' OR client=?) AND COALESCE(json_extract(CAST(data AS TEXT),'$.consent_id'),'')=''`,
		`UPDATE meter_grants SET data=json_set(CAST(data AS TEXT),'$.revoked',json('true')) WHERE owner=? AND endpoint=? AND (?='' OR json_extract(CAST(data AS TEXT),'$.consumer')='oauth:'||?) AND substr(json_extract(CAST(data AS TEXT),'$.consumer'),1,6)='oauth:' AND id NOT IN (SELECT grant_id FROM mcp_oauth_access)`,
	} {
		if _, err := tx.ExecContext(ctx, query, owner, endpoint, client, client); err != nil {
			return err
		}
	}
	return nil
}

func RevokeConsent(ctx context.Context, tx *sql.Tx, id string) error {
	for _, query := range []string{
		`UPDATE meter_grants SET data=json_set(CAST(data AS TEXT),'$.revoked',json('true')) WHERE id IN (SELECT grant_id FROM mcp_oauth_access WHERE authorization=?)`,
		`DELETE FROM mcp_oauth_refresh_tokens WHERE family IN (SELECT family FROM mcp_oauth_sessions WHERE authorization=?)`,
		`DELETE FROM mcp_oauth_refresh_families WHERE id IN (SELECT family FROM mcp_oauth_sessions WHERE authorization=?)`,
		`DELETE FROM mcp_oauth_sessions WHERE authorization=?`,
		`DELETE FROM mcp_oauth_access WHERE authorization=?`,
		`DELETE FROM mcp_oauth_codes WHERE json_extract(CAST(data AS TEXT),'$.consent_id')=?`,
		`DELETE FROM mcp_oauth_consents WHERE id=?`,
		`DELETE FROM mcp_oauth_authorizations WHERE id=?`,
	} {
		if _, err := tx.ExecContext(ctx, query, id); err != nil {
			return err
		}
	}
	return nil
}

// CheckAccess is used by the shared ledger, including remote resource nodes.
// Unmapped pre-refresh access grants retain their original one-hour contract.
func CheckAccess(ctx context.Context, tx *sql.Tx, grant string, now time.Time) error {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT authorization FROM mcp_oauth_access WHERE grant_id=?`, grant).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return Valid(ctx, tx, id, now)
}

// PruneAccess reclaims spent OAuth access-token storage before grant capacity
// is checked, retaining grants until every admitted request has finished so
// charging can still report revocation or expiry. General machine grants,
// usage and audit are untouched.
func PruneAccess(ctx context.Context, tx *sql.Tx, owner string, now time.Time) error {
	const expired = `SELECT id FROM meter_grants WHERE owner=? AND substr(json_extract(CAST(data AS TEXT),'$.consumer'),1,6)='oauth:' AND (expires<=? OR json_extract(CAST(data AS TEXT),'$.revoked')=1)
 AND id NOT IN (SELECT COALESCE(json_extract(CAST(data AS TEXT),'$.grant_id'),'') FROM meter_events WHERE finished=0)`
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth_access WHERE grant_id IN (`+expired+`)`, owner, now.UnixMilli()); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM meter_grants WHERE id IN (`+expired+`)`, owner, now.UnixMilli())
	return err
}
