package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/mcpauth"
)

// The login node owns client registrations and one-use authorization codes.
// Resource nodes validate issued tokens through the existing shared grant ledger.
type mcpOAuthStore struct {
	db                *sql.DB
	now               func() time.Time
	mu                sync.Mutex // serializes code exchange with connected-client revocation
	registrationRates map[string]mcpRegistrationRate
}

type mcpRegistrationRate struct {
	started time.Time
	count   int
}

// Bound unauthenticated registration writes and rate-limit state. The caller
// supplies the socket peer or verified relay metadata, never public XFF values.
func (s *mcpOAuthStore) allowRegistration(peer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.registrationRates == nil {
		s.registrationRates = make(map[string]mcpRegistrationRate)
	}
	entry, exists := s.registrationRates[peer]
	if exists && now.Before(entry.started.Add(5*time.Minute)) {
		if entry.count >= 5 {
			return false
		}
	} else {
		if len(s.registrationRates) >= 4096 {
			for key, value := range s.registrationRates {
				if !now.Before(value.started.Add(5 * time.Minute)) {
					delete(s.registrationRates, key)
				}
			}
			if len(s.registrationRates) >= 4096 && !exists {
				return false
			}
		}
		entry = mcpRegistrationRate{started: now}
	}
	entry.count++
	s.registrationRates[peer] = entry
	return true
}

type mcpOAuthClient struct {
	ID            string   `json:"client_id"`
	Name          string   `json:"client_name"`
	RedirectURIs  []string `json:"redirect_uris"`
	AuthMethod    string   `json:"token_endpoint_auth_method"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	IssuedAt      int64    `json:"client_id_issued_at"`
}

type mcpOAuthConnection struct {
	ClientID  string `json:"client_id"`
	Name      string `json:"client_name"`
	Tunnel    string `json:"tunnel"`
	GrantID   string `json:"grant_id"`
	ExpiresAt int64  `json:"expires_at"`
	Revoked   bool   `json:"revoked"`
}

// Connected clients remain discoverable for the consent lifetime, even after
// their shorter-lived access grants have expired and been reclaimed.
func (s *mcpOAuthStore) connections(ctx context.Context, owner, endpoint string) ([]mcpOAuthConnection, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.client,c.data,a.endpoint,max(a.expires)
 FROM mcp_oauth_authorizations a JOIN mcp_oauth_clients c ON c.id=a.client
 WHERE a.owner=? AND (?='' OR a.endpoint=?) AND a.approved=1 AND a.expires>?
 GROUP BY a.endpoint,a.client ORDER BY a.endpoint,a.client`, owner, endpoint, endpoint, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	connections := []mcpOAuthConnection{}
	for rows.Next() {
		var connection mcpOAuthConnection
		var data []byte
		var expires int64
		if err := rows.Scan(&connection.ClientID, &data, &connection.Tunnel, &expires); err != nil {
			return nil, err
		}
		var client mcpOAuthClient
		if err := json.Unmarshal(data, &client); err != nil {
			return nil, err
		}
		connection.Name = client.Name
		connection.ExpiresAt = time.Unix(expires, 0).UnixMilli()
		connections = append(connections, connection)
	}
	return connections, rows.Err()
}

type mcpAuthorization struct {
	ClientID    string `json:"client_id"`
	Person      string `json:"person"`
	Generation  string `json:"generation"`
	ConsentID   string `json:"consent_id"`
	RedirectURI string `json:"redirect_uri"`
	Resource    string `json:"resource"`
	Challenge   string `json:"code_challenge"`
	State       string `json:"state"`
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`
	Endpoint    string `json:"endpoint"`
	Email       string `json:"email"`
}

func newMCPOAuthStore(db *sql.DB) (*mcpOAuthStore, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
 id TEXT PRIMARY KEY, data BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS mcp_oauth_codes (
 digest BLOB PRIMARY KEY, owner TEXT NOT NULL, endpoint TEXT NOT NULL,
 client TEXT NOT NULL, expires INTEGER NOT NULL, data BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS mcp_oauth_consents (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, endpoint TEXT NOT NULL,
 client TEXT NOT NULL, expires INTEGER NOT NULL);`)
	if err != nil {
		return nil, err
	}
	if err := migrateMCPRefreshStore(db); err != nil {
		return nil, err
	}
	if err := mcpauth.Init(db); err != nil {
		return nil, err
	}
	return &mcpOAuthStore{db: db, now: time.Now}, nil
}

func (s *mcpOAuthStore) client(ctx context.Context, id string) (*mcpOAuthClient, error) {
	var data []byte
	if err := s.db.QueryRowContext(ctx, `SELECT data FROM mcp_oauth_clients WHERE id=?`, id).Scan(&data); err != nil {
		return nil, err
	}
	var client mcpOAuthClient
	if err := json.Unmarshal(data, &client); err != nil {
		return nil, err
	}
	return &client, nil
}

func (s *mcpOAuthStore) register(ctx context.Context, client *mcpOAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mcp_oauth_clients`).Scan(&count); err != nil {
		return err
	}
	if count >= 10000 {
		return fmt.Errorf("client registry capacity reached")
	}
	data, err := json.Marshal(client)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_oauth_clients(id,data) VALUES(?,?)`, client.ID, data); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *mcpOAuthStore) saveConsent(ctx context.Context, id string, auth *mcpAuthorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM mcp_oauth_consents WHERE expires<=?`, s.now().Unix()); err != nil {
		return err
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM mcp_oauth_consents`).Scan(&count); err != nil {
		return err
	}
	if count >= 10000 {
		return fmt.Errorf("consent capacity reached")
	}
	tx, err := s.refreshTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM mcp_oauth_authorizations WHERE expires<=?`, s.now().Unix())
	if err != nil {
		return err
	}
	var expired []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range expired {
		if err := mcpauth.RevokeConsent(ctx, tx, id); err != nil {
			return err
		}
	}
	var total, owned int
	if err := tx.QueryRowContext(ctx, `SELECT count(*),count(CASE WHEN owner=? THEN 1 END) FROM mcp_oauth_authorizations`, auth.Owner).Scan(&total, &owned); err != nil {
		return err
	}
	if total >= 10000 || owned >= 128 {
		return errMCPRefreshCapacity
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO mcp_oauth_consents(id,owner,endpoint,client,expires) VALUES(?,?,?,?,?)`, id, auth.Owner, auth.Endpoint, auth.ClientID, s.now().Add(10*time.Minute).Unix()); err != nil {
		return err
	}
	if auth.Person != "" {
		if _, err = tx.ExecContext(ctx, `INSERT INTO mcp_oauth_authorizations(id,owner,person,email,endpoint,client,resource,generation,expires) VALUES(?,?,?,?,?,?,?,?,?)`, id, auth.Owner, auth.Person, auth.Email, auth.Endpoint, auth.ClientID, auth.Resource, auth.Generation, s.now().Add(10*time.Minute).Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *mcpOAuthStore) saveCode(ctx context.Context, code string, auth *mcpAuthorization, consentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth_codes WHERE expires<=?`, s.now().Unix()); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM mcp_oauth_codes`).Scan(&count); err != nil {
		return err
	}
	if count >= 10000 {
		return fmt.Errorf("authorization capacity reached")
	}
	consumed, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth_consents WHERE id=? AND owner=? AND endpoint=? AND client=? AND expires>?`, consentID, auth.Owner, auth.Endpoint, auth.ClientID, s.now().Unix())
	if err != nil {
		return err
	}
	countConsumed, err := consumed.RowsAffected()
	if err != nil || countConsumed != 1 {
		return fmt.Errorf("expired, revoked or consumed consent")
	}
	if auth.ConsentID != "" {
		result, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_authorizations SET approved=1,expires=? WHERE id=? AND expires>?`, s.now().Add(mcpRefreshMaxLifetime).Unix(), auth.ConsentID, s.now().Unix())
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return errMCPRefreshInvalid
		}
		if err := mcpauth.Valid(ctx, tx, auth.ConsentID, s.now()); err != nil {
			return err
		}
	}
	data, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(code))
	if _, err = tx.ExecContext(ctx, `INSERT INTO mcp_oauth_codes(digest,owner,endpoint,client,expires,data) VALUES(?,?,?,?,?,?)`, digest[:], auth.Owner, auth.Endpoint, auth.ClientID, s.now().Add(5*time.Minute).Unix(), data); err != nil {
		return err
	}
	return tx.Commit()
}

// Caller holds mu until grant issuance completes, so disconnect cannot race
// an already-consented code exchange and leave a surviving access token.
func (s *mcpOAuthStore) takeCode(ctx context.Context, code string, valid func(*mcpAuthorization) bool) (*mcpAuthorization, error) {
	digest := sha256.Sum256([]byte(code))
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT data FROM mcp_oauth_codes WHERE digest=? AND expires>?`, digest[:], s.now().Unix()).Scan(&data)
	if err != nil {
		return nil, err
	}
	var auth mcpAuthorization
	if err := json.Unmarshal(data, &auth); err != nil {
		return nil, err
	}
	if !valid(&auth) {
		return nil, errors.New("invalid authorization code binding")
	}
	consumed, err := s.db.ExecContext(ctx, `DELETE FROM mcp_oauth_codes WHERE digest=? AND expires>? AND data=?`, digest[:], s.now().Unix(), data)
	if err != nil {
		return nil, err
	}
	count, err := consumed.RowsAffected()
	if err != nil || count != 1 {
		return nil, errors.New("authorization code already consumed or expired")
	}
	return &auth, nil
}
