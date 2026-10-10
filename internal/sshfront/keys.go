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

	"golang.org/x/crypto/ssh"
)

type Key struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	AccountID   string `json:"-"`
}

// Registry keeps ownership and one-time email challenges in the login database.
// The owner is a verified email, so account bucket merges retain key ownership.
type Registry struct{ db *sql.DB }

func NewRegistry(db *sql.DB) (*Registry, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS ssh_keys (
	 fingerprint TEXT PRIMARY KEY, public_key TEXT NOT NULL, owner_email TEXT NOT NULL);
	 CREATE TABLE IF NOT EXISTS ssh_key_links (
	 digest TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, public_key TEXT NOT NULL,
	 email TEXT NOT NULL, expires INTEGER NOT NULL);`)
	if err != nil {
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

func (r *Registry) Owner(ctx context.Context, fingerprint string) (string, error) {
	var email string
	err := r.db.QueryRowContext(ctx, "SELECT owner_email FROM ssh_keys WHERE fingerprint=?", fingerprint).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return email, err
}

func (r *Registry) Add(ctx context.Context, email, publicKey string) (Key, error) {
	k, err := ParseKey(publicKey)
	if err != nil {
		return Key{}, err
	}
	result, err := r.db.ExecContext(ctx, `INSERT INTO ssh_keys(fingerprint, public_key, owner_email) VALUES (?, ?, ?)
	 ON CONFLICT(fingerprint) DO UPDATE SET public_key=excluded.public_key WHERE owner_email=excluded.owner_email`, k.Fingerprint, k.PublicKey, email)
	if err != nil {
		return Key{}, err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return Key{}, fmt.Errorf("key already belongs to another identity")
	}
	return k, nil
}

func (r *Registry) List(ctx context.Context, emails []string) ([]Key, error) {
	keys := []Key{}
	for _, email := range emails {
		rows, err := r.db.QueryContext(ctx, "SELECT fingerprint, public_key FROM ssh_keys WHERE owner_email=? ORDER BY fingerprint", email)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var k Key
			if err := rows.Scan(&k.Fingerprint, &k.PublicKey); err != nil {
				_ = rows.Close()
				return nil, err
			}
			keys = append(keys, k)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return keys, nil
}

func (r *Registry) Remove(ctx context.Context, emails []string, fingerprint string) error {
	for _, email := range emails {
		result, err := r.db.ExecContext(ctx, "DELETE FROM ssh_keys WHERE owner_email=? AND fingerprint=?", email, fingerprint)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
	}
	return fmt.Errorf("key not found in this account")
}

func linkDigest(token string) string {
	d := sha256.Sum256([]byte(token))
	return hex.EncodeToString(d[:])
}

func (r *Registry) BeginLink(ctx context.Context, publicKey, email string) (string, error) {
	k, err := ParseKey(publicKey)
	if err != nil {
		return "", err
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	token := hex.EncodeToString(random)
	if _, err := r.db.ExecContext(ctx, "DELETE FROM ssh_key_links WHERE expires<=?", time.Now().Unix()); err != nil {
		return "", err
	}
	_, err = r.db.ExecContext(ctx, "INSERT INTO ssh_key_links VALUES (?, ?, ?, ?, ?)", linkDigest(token), k.Fingerprint, k.PublicKey, email, time.Now().Add(5*time.Minute).Unix())
	return token, err
}

func (r *Registry) LinkEmail(ctx context.Context, token string) (string, error) {
	var email string
	err := r.db.QueryRowContext(ctx, "SELECT email FROM ssh_key_links WHERE digest=? AND expires>?", linkDigest(token), time.Now().Unix()).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("invalid, expired or used SSH key link")
	}
	return email, nil
}

func (r *Registry) CompleteLink(ctx context.Context, token string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var k Key
	var email string
	err = tx.QueryRowContext(ctx, "SELECT fingerprint, public_key, email FROM ssh_key_links WHERE digest=? AND expires>?", linkDigest(token), time.Now().Unix()).Scan(&k.Fingerprint, &k.PublicKey, &email)
	if err != nil {
		return fmt.Errorf("invalid, expired or used SSH key link")
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO ssh_keys VALUES (?, ?, ?) ON CONFLICT(fingerprint) DO UPDATE SET public_key=excluded.public_key WHERE owner_email=excluded.owner_email`, k.Fingerprint, k.PublicKey, email)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return fmt.Errorf("key already belongs to another identity")
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM ssh_key_links WHERE digest=?", linkDigest(token)); err != nil {
		return err
	}
	return tx.Commit()
}
