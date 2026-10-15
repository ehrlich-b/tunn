package sshfront

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

type Key struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	AccountID   string `json:"-"`
}

// Registry keeps ownership and one-time email challenges in the login database.
// Ownership is a durable account UUID; mailboxes are only enrollment proof.
type Registry struct{ db *sql.DB }

func NewRegistry(db *sql.DB) (*Registry, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ssh_keys (
	 fingerprint TEXT PRIMARY KEY, public_key TEXT NOT NULL, owner_email TEXT NOT NULL);
	 CREATE TABLE IF NOT EXISTS ssh_key_links (
	 digest TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, public_key TEXT NOT NULL,
	 email TEXT NOT NULL, expires INTEGER NOT NULL);
	 CREATE TABLE IF NOT EXISTS ssh_key_generations (
	 fingerprint TEXT PRIMARY KEY, generation INTEGER NOT NULL);
	 CREATE TABLE IF NOT EXISTS ssh_key_proofs (
	 digest TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, public_key TEXT NOT NULL,
	 email TEXT NOT NULL, expires INTEGER NOT NULL, generation INTEGER NOT NULL);`)
	if err != nil {
		return nil, err
	}
	// Legacy pending links did not bind revocation authority. Invalidate them
	// by giving them a generation that can never match a current key.
	var hasGeneration int
	if err := db.QueryRow("SELECT count(*) FROM pragma_table_info('ssh_key_links') WHERE name='generation'").Scan(&hasGeneration); err != nil {
		return nil, err
	}
	if hasGeneration == 0 {
		if _, err := db.Exec("ALTER TABLE ssh_key_links ADD COLUMN generation INTEGER NOT NULL DEFAULT -1"); err != nil {
			return nil, err
		}
	}
	if err := store.MigrateCredentialOwnership(db); err != nil {
		return nil, err
	}
	return &Registry{db: db}, nil
}

func ParseKey(value string) (Key, error) {
	if len(value) > 16*1024 {
		return Key{}, fmt.Errorf("SSH public key too large")
	}
	public, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil || len(options) > 0 || strings.TrimSpace(string(rest)) != "" {
		return Key{}, fmt.Errorf("provide one SSH public key without authorized_keys options")
	}
	return Key{Fingerprint: ssh.FingerprintSHA256(public), PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))}, nil
}

func (r *Registry) OwnerAccount(ctx context.Context, fingerprint string) (*store.Account, error) {
	var id string
	err := r.db.QueryRowContext(ctx, "SELECT account_id FROM ssh_key_owners WHERE fingerprint=?", fingerprint).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return store.NewAccountStore(r.db).GetByIDContext(ctx, id)
}

// CanonicalAccountID follows the same authoritative merge aliases as account lookup.
func (r *Registry) CanonicalAccountID(ctx context.Context, accountID string) (string, error) {
	id, err := uuid.Parse(accountID)
	if err != nil {
		return "", err
	}
	account, err := store.NewAccountStore(r.db).GetByIDContext(ctx, id.String())
	if err != nil {
		return "", err
	}
	return account.ID, nil
}

// Resolve both sides within the challenge transaction so a merge cannot turn an
// authenticated account or pending proof into a different account's credential.
func sameChallengeAccount(ctx context.Context, tx *sql.Tx, a, b string) bool {
	resolve := func(raw string) (uuid.UUID, error) {
		id, err := uuid.Parse(raw)
		if err != nil {
			return uuid.Nil, err
		}
		var canonical string
		err = tx.QueryRowContext(ctx, "SELECT id FROM accounts WHERE id=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?)", id.String(), id.String()).Scan(&canonical)
		if err != nil {
			return uuid.Nil, err
		}
		return uuid.Parse(canonical)
	}
	first, firstErr := resolve(a)
	second, secondErr := resolve(b)
	return firstErr == nil && secondErr == nil && first == second
}

func (r *Registry) Owner(ctx context.Context, fingerprint string) (string, error) {
	account, err := r.OwnerAccount(ctx, fingerprint)
	if err != nil || account == nil {
		return "", err
	}
	return account.PrimaryEmail, nil
}

func (r *Registry) AccountID(ctx context.Context, fingerprint string) (string, error) {
	account, err := r.OwnerAccount(ctx, fingerprint)
	if err != nil || account == nil {
		return "", err
	}
	return account.ID, nil
}

// Add is for trusted callers that have already verified key possession and identity.
// HTTP enrollment must use CompleteProof; email enrollment starts from an authenticated SSH session.
func (r *Registry) Add(ctx context.Context, email, publicKey string) (Key, error) {
	k, err := ParseKey(publicKey)
	if err != nil {
		return Key{}, err
	}
	result, err := r.db.ExecContext(ctx, `INSERT INTO ssh_keys(fingerprint, public_key, owner_email)
     SELECT ?, ?, ? FROM account_emails WHERE email=?
     ON CONFLICT(fingerprint) DO UPDATE SET public_key=excluded.public_key
     WHERE (SELECT COALESCE((SELECT account_id FROM account_merges WHERE old_id=o.account_id),o.account_id) FROM ssh_key_owners o WHERE o.fingerprint=ssh_keys.fingerprint)=(SELECT account_id FROM account_emails WHERE email=excluded.owner_email)`, k.Fingerprint, k.PublicKey, common.NormalizeEmail(email), common.NormalizeEmail(email))
	if err != nil {
		return Key{}, err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return Key{}, fmt.Errorf("key already belongs to another identity")
	}
	return k, nil
}

// ConfirmSessionKey can confirm an already linked authenticating key, but never
// insert it. A concurrent removal must not be undone by an older SSH session.
func (r *Registry) ConfirmSessionKey(ctx context.Context, accountID, publicKey string) (Key, error) {
	id, err := uuid.Parse(accountID)
	if err != nil {
		return Key{}, err
	}
	accountID = id.String()
	k, err := ParseKey(publicKey)
	if err != nil {
		return Key{}, err
	}
	result, err := r.db.ExecContext(ctx, `UPDATE ssh_keys SET public_key=? WHERE fingerprint=? AND (SELECT COALESCE((SELECT account_id FROM account_merges WHERE old_id=o.account_id),o.account_id) FROM ssh_key_owners o WHERE o.fingerprint=ssh_keys.fingerprint)=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?)`, k.PublicKey, k.Fingerprint, accountID, accountID)
	if err != nil {
		return Key{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return Key{}, err
	}
	if n != 1 {
		return Key{}, fmt.Errorf("SSH key no longer linked; enroll with fresh proof")
	}
	return k, nil
}

func (r *Registry) List(ctx context.Context, accountID string) ([]Key, error) {
	id, err := uuid.Parse(accountID)
	if err != nil {
		return nil, err
	}
	accountID = id.String()
	keys := []Key{}
	rows, err := r.db.QueryContext(ctx, `SELECT fingerprint,public_key,(SELECT account_id FROM ssh_key_owners WHERE fingerprint=ssh_keys.fingerprint) FROM ssh_keys WHERE (SELECT COALESCE((SELECT account_id FROM account_merges WHERE old_id=o.account_id),o.account_id) FROM ssh_key_owners o WHERE o.fingerprint=ssh_keys.fingerprint)=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?) ORDER BY fingerprint`, accountID, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.Fingerprint, &k.PublicKey, &k.AccountID); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (r *Registry) Remove(ctx context.Context, accountID, fingerprint string) error {
	id, err := uuid.Parse(accountID)
	if err != nil {
		return err
	}
	accountID = id.String()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM ssh_keys WHERE (SELECT COALESCE((SELECT account_id FROM account_merges WHERE old_id=o.account_id),o.account_id) FROM ssh_key_owners o WHERE o.fingerprint=ssh_keys.fingerprint)=COALESCE((SELECT account_id FROM account_merges WHERE old_id=?),?) AND fingerprint=?`, accountID, accountID, fingerprint)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("key not found in this account")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ssh_key_generations VALUES (?, 1)
		 ON CONFLICT(fingerprint) DO UPDATE SET generation=generation+1`, fingerprint); err != nil {
		return err
	}
	for _, table := range []string{"ssh_key_links", "ssh_key_proofs"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE fingerprint=?", fingerprint); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func linkDigest(token string) string {
	d := sha256.Sum256([]byte(token))
	return hex.EncodeToString(d[:])
}

// BeginLink may only be called with the key verified by SSH authentication.
func (r *Registry) BeginLink(ctx context.Context, publicKey, email string) (string, error) {
	return r.beginChallenge(ctx, "ssh_key_links", publicKey, email, "")
}

// ProofMessage binds the signature to this protocol, identity and random challenge.
func ProofMessage(email, challenge string) []byte {
	return []byte("tunn SSH key enrollment v1\n" + email + "\n" + challenge)
}

func (r *Registry) BeginProof(ctx context.Context, publicKey, email, accountID string) (string, error) {
	return r.beginChallenge(ctx, "ssh_key_proofs", publicKey, email, accountID)
}

func (r *Registry) beginChallenge(ctx context.Context, table, publicKey, email, accountID string) (string, error) {
	k, err := ParseKey(publicKey)
	if err != nil {
		return "", err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	token := hex.EncodeToString(random)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if table == "ssh_key_proofs" {
		var current string
		if err := tx.QueryRowContext(ctx, "SELECT account_id FROM account_emails WHERE email=?", common.NormalizeEmail(email)).Scan(&current); err != nil || !sameChallengeAccount(ctx, tx, current, accountID) {
			return "", fmt.Errorf("SSH proof account changed")
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE expires<=?", time.Now().Unix()); err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO "+table+" (digest, fingerprint, public_key, email, expires, generation, account_id) VALUES (?, ?, ?, ?, ?, COALESCE((SELECT generation FROM ssh_key_generations WHERE fingerprint=?), 0), COALESCE((SELECT account_id FROM account_emails WHERE email=?),''))", linkDigest(token), k.Fingerprint, k.PublicKey, common.NormalizeEmail(email), time.Now().Add(5*time.Minute).Unix(), k.Fingerprint, common.NormalizeEmail(email))
	if err != nil {
		return "", err
	}
	return token, tx.Commit()
}

// CompleteProof verifies possession before recording any exclusive ownership.
func (r *Registry) CompleteProof(ctx context.Context, accountID, email, publicKey, token string, signature *ssh.Signature) (Key, error) {
	return r.completeChallenge(ctx, "ssh_key_proofs", token, accountID, email, publicKey, signature)
}

func (r *Registry) LinkEmail(ctx context.Context, token string) (string, error) {
	var email string
	err := r.db.QueryRowContext(ctx, "SELECT email FROM ssh_key_links WHERE digest=? AND expires>? AND generation=COALESCE((SELECT generation FROM ssh_key_generations WHERE fingerprint=ssh_key_links.fingerprint), 0)", linkDigest(token), time.Now().Unix()).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("invalid, expired or used SSH key link")
	}
	return email, nil
}

// LinkKey exposes only the public fingerprint for deliberate email confirmation.
// Reading a challenge must never enroll a key or consume the challenge.
func (r *Registry) LinkKey(ctx context.Context, token string) (Key, error) {
	var k Key
	err := r.db.QueryRowContext(ctx, "SELECT fingerprint, public_key FROM ssh_key_links WHERE digest=? AND expires>? AND generation=COALESCE((SELECT generation FROM ssh_key_generations WHERE fingerprint=ssh_key_links.fingerprint), 0)", linkDigest(token), time.Now().Unix()).Scan(&k.Fingerprint, &k.PublicKey)
	return k, err
}

func (r *Registry) CompleteLink(ctx context.Context, token string) error {
	_, err := r.completeChallenge(ctx, "ssh_key_links", token, "", "", "", nil)
	return err
}

func (r *Registry) completeChallenge(ctx context.Context, table, token, expectedAccountID, expectedEmail, publicKey string, signature *ssh.Signature) (Key, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Key{}, err
	}
	defer tx.Rollback()
	var k Key
	var email, bound string
	err = tx.QueryRowContext(ctx, "SELECT fingerprint, public_key, email, account_id FROM "+table+" WHERE digest=? AND expires>? AND generation=COALESCE((SELECT generation FROM ssh_key_generations WHERE fingerprint="+table+".fingerprint), 0)", linkDigest(token), time.Now().Unix()).Scan(&k.Fingerprint, &k.PublicKey, &email, &bound)
	if err != nil {
		return Key{}, fmt.Errorf("invalid, expired or used SSH key challenge")
	}
	var current string
	if err := tx.QueryRowContext(ctx, "SELECT account_id FROM account_emails WHERE email=?", email).Scan(&current); err != nil {
		return Key{}, fmt.Errorf("verified account required")
	}
	if bound != "" {
		if !sameChallengeAccount(ctx, tx, bound, current) {
			return Key{}, fmt.Errorf("SSH challenge account changed")
		}
	}
	k.AccountID = current
	if table == "ssh_key_proofs" {
		if bound == "" || !sameChallengeAccount(ctx, tx, current, expectedAccountID) {
			return Key{}, fmt.Errorf("SSH proof account changed")
		}
		submitted, err := ParseKey(publicKey)
		if err != nil || submitted.Fingerprint != k.Fingerprint || email != expectedEmail || signature == nil {
			return Key{}, fmt.Errorf("SSH key proof does not match identity or key")
		}
		public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.PublicKey))
		if err != nil {
			return Key{}, err
		}
		if err := public.Verify(ProofMessage(email, token), signature); err != nil {
			return Key{}, fmt.Errorf("invalid SSH key possession proof")
		}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO ssh_keys(fingerprint,public_key,owner_email) VALUES (?, ?, ?) ON CONFLICT(fingerprint) DO UPDATE SET public_key=excluded.public_key WHERE (SELECT COALESCE((SELECT account_id FROM account_merges WHERE old_id=o.account_id),o.account_id) FROM ssh_key_owners o WHERE o.fingerprint=ssh_keys.fingerprint)=(SELECT account_id FROM account_emails WHERE email=excluded.owner_email)`, k.Fingerprint, k.PublicKey, email)
	if err != nil {
		return Key{}, err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return Key{}, fmt.Errorf("key already belongs to another identity")
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE digest=?", linkDigest(token)); err != nil {
		return Key{}, err
	}
	return k, tx.Commit()
}
