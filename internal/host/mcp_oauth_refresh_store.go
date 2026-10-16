package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	mcpRefreshMaxFamilies = 10000
	mcpRefreshMaxTokens   = 128 // includes spent digests needed for replay detection
	mcpRefreshMaxLifetime = 30 * 24 * time.Hour
)

var (
	errMCPRefreshInvalid  = errors.New("invalid or expired refresh credential")
	errMCPRefreshReplay   = errors.New("refresh credential reused; family invalidated")
	errMCPRefreshCapacity = errors.New("refresh storage capacity reached")
)

// mcpRefreshBinding contains trusted, current authorization state. Callers must
// resolve owner and person to canonical account UUIDs and obtain the current
// resource generation before calling the store. Email addresses are not IDs.
// Bindings are immutable and compared exactly; a rename, merge, transfer or
// generation change requires new consent rather than rebinding a family.
type mcpRefreshBinding struct {
	OwnerID, PersonID, ClientID, Resource string
	Generation                            int64
}

func (b mcpRefreshBinding) valid() bool {
	owner, err := uuid.Parse(b.OwnerID)
	if err != nil || owner == uuid.Nil || owner.String() != b.OwnerID {
		return false
	}
	person, err := uuid.Parse(b.PersonID)
	return err == nil && person != uuid.Nil && person.String() == b.PersonID &&
		b.ClientID != "" && len(b.ClientID) <= 256 &&
		b.Resource != "" && len(b.Resource) <= 2048 && b.Generation > 0
}

// The persistence API accepts SHA-256 digests only, never bearer secrets.
// A future wire credential MUST include the returned family ID as well as its
// secret, and submit that ID unchanged on rotation. AUTOINCREMENT IDs survive
// deletion and reopen, so even deliberately repeated secrets cannot resurrect a
// cleaned-up credential. This store does not issue tokens or authenticate users.
func migrateMCPRefreshStore(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`CREATE TABLE IF NOT EXISTS mcp_oauth_refresh_families (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 owner TEXT NOT NULL, person TEXT NOT NULL, client TEXT NOT NULL,
 resource TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0),
 expires INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS mcp_oauth_refresh_expiry ON mcp_oauth_refresh_families(expires);
 CREATE TABLE IF NOT EXISTS mcp_oauth_refresh_tokens (
 family INTEGER NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32),
 used INTEGER NOT NULL DEFAULT 0 CHECK(used IN (0,1)),
 PRIMARY KEY(family,digest),
 FOREIGN KEY(family) REFERENCES mcp_oauth_refresh_families(id) ON DELETE CASCADE);`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// All refresh mutations acquire SQLite's writer lock before reading state. This
// serializes separate store instances and processes too, without a read-to-write
// lock upgrade. The DB connection's busy timeout controls contention waits.
func (s *mcpOAuthStore) refreshTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE mcp_oauth_refresh_families SET id=id WHERE id=-1`); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func deleteMCPRefreshFamily(ctx context.Context, tx *sql.Tx, id int64) error {
	// Delete explicitly too: existing DB connections need not enable foreign keys.
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth_refresh_tokens WHERE family=?`, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth_refresh_families WHERE id=?`, id)
	return err
}

func cleanupMCPRefreshFamilies(ctx context.Context, tx *sql.Tx, now int64) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth_refresh_tokens WHERE family IN (SELECT id FROM mcp_oauth_refresh_families WHERE expires<=?)`, now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth_refresh_families WHERE expires<=?`, now)
	return err
}

// createRefreshFamily starts an absolute lifetime; rotations cannot extend it.
// Capacity is fail-closed, never evicting active families or replay evidence.
func (s *mcpOAuthStore) createRefreshFamily(ctx context.Context, binding mcpRefreshBinding, digest [sha256.Size]byte, expires time.Time) (int64, error) {
	if !binding.valid() || digest == [sha256.Size]byte{} {
		return 0, errMCPRefreshInvalid
	}
	tx, err := s.refreshTx(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now()
	if expires.Unix() <= now.Unix() || expires.After(now.Add(mcpRefreshMaxLifetime)) {
		return 0, errMCPRefreshInvalid
	}
	if err := cleanupMCPRefreshFamilies(ctx, tx, now.Unix()); err != nil {
		return 0, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mcp_oauth_refresh_families`).Scan(&count); err != nil {
		return 0, err
	}
	if count >= mcpRefreshMaxFamilies {
		return 0, errMCPRefreshCapacity
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO mcp_oauth_refresh_families(owner,person,client,resource,generation,expires) VALUES(?,?,?,?,?,?)`, binding.OwnerID, binding.PersonID, binding.ClientID, binding.Resource, binding.Generation, expires.Unix())
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_oauth_refresh_tokens(family,digest) VALUES(?,?)`, id, digest[:]); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func boundMCPRefreshFamily(ctx context.Context, tx *sql.Tx, id int64, binding mcpRefreshBinding) error {
	var found int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM mcp_oauth_refresh_families WHERE id=? AND owner=? AND person=? AND client=? AND resource=? AND generation=? AND expires>?`, id, binding.OwnerID, binding.PersonID, binding.ClientID, binding.Resource, binding.Generation, time.Now().Unix()).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return errMCPRefreshInvalid
	}
	return err
}

// rotateRefresh atomically consumes one digest and installs its successor.
// Reusing any spent digest commits deletion of the entire family, including the
// winner of an earlier rotation. Callers must treat replay as a committed change.
func (s *mcpOAuthStore) rotateRefresh(ctx context.Context, id int64, binding mcpRefreshBinding, previous, next [sha256.Size]byte) error {
	if id <= 0 || !binding.valid() || previous == [sha256.Size]byte{} || next == [sha256.Size]byte{} {
		return errMCPRefreshInvalid
	}
	tx, err := s.refreshTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := boundMCPRefreshFamily(ctx, tx, id, binding); err != nil {
		return err
	}
	var used int
	if err := tx.QueryRowContext(ctx, `SELECT used FROM mcp_oauth_refresh_tokens WHERE family=? AND digest=?`, id, previous[:]).Scan(&used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errMCPRefreshInvalid
		}
		return err
	}
	if used != 0 {
		if err := deleteMCPRefreshFamily(ctx, tx, id); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return errMCPRefreshReplay
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mcp_oauth_refresh_tokens WHERE family=?`, id).Scan(&count); err != nil {
		return err
	}
	if count >= mcpRefreshMaxTokens {
		return errMCPRefreshCapacity
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_refresh_tokens SET used=1 WHERE family=? AND digest=?`, id, previous[:]); err != nil {
		return err
	}
	// Duplicate digests (including rotating to self) fail and roll back consumption.
	if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_oauth_refresh_tokens(family,digest) VALUES(?,?)`, id, next[:]); err != nil {
		return err
	}
	return tx.Commit()
}

// revokeRefreshFamily is idempotent and scoped to the complete binding, so it
// cannot revoke another owner, person, client, resource or resource generation.
func (s *mcpOAuthStore) revokeRefreshFamily(ctx context.Context, id int64, binding mcpRefreshBinding) error {
	tx, err := s.refreshTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var found int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM mcp_oauth_refresh_families WHERE id=? AND owner=? AND person=? AND client=? AND resource=? AND generation=?`, id, binding.OwnerID, binding.PersonID, binding.ClientID, binding.Resource, binding.Generation).Scan(&found)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if err := deleteMCPRefreshFamily(ctx, tx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// cleanupRefreshFamilies is safe to call at startup or from maintenance. Creation
// also performs cleanup; cleanup never removes spent digests of a live family.
func (s *mcpOAuthStore) cleanupRefreshFamilies(ctx context.Context) error {
	tx, err := s.refreshTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := cleanupMCPRefreshFamilies(ctx, tx, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
