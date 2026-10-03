package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const MaxOAuthCodeLifetime = 5 * time.Minute

var (
	ErrOAuthInvalidRequest = errors.New("invalid OAuth request")
	ErrOAuthInvalidGrant   = errors.New("invalid OAuth authorization code")
)

// OAuthCodeCreate comes only from an approved owner consent. The host validates
// static client configuration and exact redirect/resource/scope permissions.
// This store also bounds metadata and persists exact bindings as a second check.
type OAuthCodeCreate struct {
	Code           string
	ConsentID      string
	AccountID      string
	EndpointID     string
	ClientID       string
	RedirectURI    string
	Resource       string
	Scope          string
	CodeChallenge  string
	ExpiresAt      time.Time
	GrantExpiresAt time.Time
	RequestLimit   int64
	Label          string
}

// CodeChallenge is the S256 digest calculated by the host from a validated
// verifier. The store never receives or persists the verifier itself.
type OAuthCodeExchange struct {
	Code          string
	ClientID      string
	RedirectURI   string
	Resource      string
	CodeChallenge string
}

func oauthDigestShape(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func oauthBoundString(value string, limit int) bool {
	return value != "" && len(value) <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}

func oauthAbsoluteURI(value string) bool {
	if !oauthBoundString(value, 2048) {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && u.IsAbs() && u.Host != "" && u.User == nil && u.Fragment == "" && (u.Scheme == "https" || u.Scheme == "http")
}

func (q OAuthCodeCreate) Validate(now time.Time) error {
	grant := GrantCreate{AccountID: q.AccountID, EndpointID: q.EndpointID, Label: q.Label, ExpiresAt: q.GrantExpiresAt, RequestLimit: q.RequestLimit}
	if !oauthDigestShape(q.Code) || !oauthBoundString(q.ConsentID, 128) || len(q.ConsentID) < 16 || !oauthBoundString(q.ClientID, 256) || !oauthAbsoluteURI(q.RedirectURI) || !oauthAbsoluteURI(q.Resource) || !oauthBoundString(q.Scope, 256) || !oauthDigestShape(q.CodeChallenge) || !q.ExpiresAt.After(now) || q.ExpiresAt.After(now.Add(MaxOAuthCodeLifetime)) || grant.Validate(now) != nil {
		return ErrOAuthInvalidRequest
	}
	return nil
}

func (q OAuthCodeExchange) Validate() error {
	if !oauthDigestShape(q.Code) || !oauthBoundString(q.ClientID, 256) || !oauthAbsoluteURI(q.RedirectURI) || !oauthAbsoluteURI(q.Resource) || !oauthDigestShape(q.CodeChallenge) {
		return ErrOAuthInvalidRequest
	}
	return nil
}

type OAuthCodeStore struct{ db *sql.DB }

func NewOAuthCodeStore(db *sql.DB) *OAuthCodeStore { return &OAuthCodeStore{db: db} }

func (s *OAuthCodeStore) Create(ctx context.Context, q OAuthCodeCreate) error {
	if err := q.Validate(time.Now().UTC()); err != nil {
		return err
	}
	// A duplicate code or consent nonce must not overwrite bindings or authorize
	// an additional credential. ON CONFLICT covers both unique constraints.
	result, err := s.db.ExecContext(ctx, `INSERT INTO oauth_codes(code_digest,consent_digest,account_id,endpoint_id,client_id,redirect_uri,resource,scope,code_challenge,expires_at,grant_expires_at,request_limit,label)
	 SELECT ?,?,id,?,?,?,?,?,?,?,?,?,? FROM accounts WHERE id=COALESCE((SELECT account_id FROM account_aliases WHERE alias_id=?),?) ON CONFLICT DO NOTHING`,
		grantDigest(q.Code), grantDigest(q.ConsentID), q.EndpointID, q.ClientID, q.RedirectURI, q.Resource, q.Scope, q.CodeChallenge, q.ExpiresAt.UnixMilli(), q.GrantExpiresAt.UnixMilli(), q.RequestLimit, q.Label, q.AccountID, q.AccountID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrOAuthInvalidGrant
	}
	return nil
}

// Owner allows LocalStorage to verify the currently registered publisher while
// holding its registry lock. Exchange repeats every code/binding check in its
// transaction; this lookup alone can never authorize or mint a grant.
func (s *OAuthCodeStore) Owner(ctx context.Context, code string) (string, string, error) {
	if !oauthDigestShape(code) {
		return "", "", ErrOAuthInvalidRequest
	}
	var accountID, endpointID string
	err := s.db.QueryRowContext(ctx, `SELECT account_id,endpoint_id FROM oauth_codes WHERE code_digest=? AND consumed_at=0 AND expires_at>?`, grantDigest(code), time.Now().UnixMilli()).Scan(&accountID, &endpointID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrOAuthInvalidGrant
	}
	return accountID, endpointID, err
}

// Exchange commits code consumption and one new grant together. A retried or
// concurrent exchange cannot mint a second credential, including after restart
// or an ambiguous response. If the response is lost, the owner can find/revoke
// the grant in their existing list; plaintext credentials cannot be recovered.
func (s *OAuthCodeStore) Exchange(ctx context.Context, q OAuthCodeExchange) (*Grant, string, error) {
	if err := q.Validate(); err != nil {
		return nil, "", err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA busy_timeout=5000`); err != nil {
		return nil, "", err
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	// Acquire the SQLite writer lock before observing single-use state.
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_codes SET consumed_at=consumed_at WHERE code_digest=?`, grantDigest(q.Code)); err != nil {
		return nil, "", err
	}
	var accountID, endpointID, clientID, redirectURI, resource, challenge, label string
	var codeExpires, grantExpires, limit, consumed int64
	err = tx.QueryRowContext(ctx, `SELECT account_id,endpoint_id,client_id,redirect_uri,resource,code_challenge,label,expires_at,grant_expires_at,request_limit,consumed_at FROM oauth_codes WHERE code_digest=?`, grantDigest(q.Code)).Scan(&accountID, &endpointID, &clientID, &redirectURI, &resource, &challenge, &label, &codeExpires, &grantExpires, &limit, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrOAuthInvalidGrant
	}
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	if consumed != 0 || codeExpires <= now.UnixMilli() || grantExpires <= now.UnixMilli() || clientID != q.ClientID || redirectURI != q.RedirectURI || resource != q.Resource || subtle.ConstantTimeCompare([]byte(challenge), []byte(q.CodeChallenge)) != 1 {
		return nil, "", ErrOAuthInvalidGrant
	}
	var canonical string
	err = tx.QueryRowContext(ctx, `SELECT id FROM accounts WHERE id=COALESCE((SELECT account_id FROM account_aliases WHERE alias_id=?),?)`, accountID, accountID).Scan(&canonical)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrOAuthInvalidGrant
	}
	if err != nil {
		return nil, "", err
	}
	id, err := grantRandom(18)
	if err != nil {
		return nil, "", err
	}
	secret, err := grantRandom(32)
	if err != nil {
		return nil, "", err
	}
	token := GrantTokenPrefix + secret
	g := &Grant{ID: id, AccountID: canonical, EndpointID: endpointID, Label: label, CreatedAt: now, ExpiresAt: time.UnixMilli(grantExpires).UTC(), RequestLimit: limit}
	if _, err := tx.ExecContext(ctx, `INSERT INTO endpoint_grants(id,account_id,endpoint_id,label,token_digest,created_at,expires_at,request_limit) VALUES(?,?,?,?,?,?,?,?)`, g.ID, g.AccountID, g.EndpointID, g.Label, grantDigest(token), now.UnixMilli(), grantExpires, g.RequestLimit); err != nil {
		return nil, "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE oauth_codes SET consumed_at=?,grant_id=? WHERE code_digest=?`, now.UnixMilli(), g.ID, grantDigest(q.Code)); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(); err != nil {
		return nil, "", err
	}
	return g, token, nil
}
