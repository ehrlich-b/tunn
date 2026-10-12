package store

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
)

// HostStore persists machine inventory and reuses the existing account-owned
// reservation table. Connectivity is derived from live relay streams, never a
// durable boolean that could remain online after a relay crash.
type HostStore struct {
	db *sql.DB
	mu sync.Mutex
}

func NewHostStore(db *sql.DB) (*HostStore, error) {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS host_machines (
 account_id TEXT NOT NULL, machine TEXT NOT NULL, last_seen INTEGER NOT NULL,
 PRIMARY KEY (account_id, machine)
);
CREATE TABLE IF NOT EXISTS host_endpoints (
 name TEXT PRIMARY KEY, account_id TEXT NOT NULL, machine TEXT NOT NULL,
 kind TEXT NOT NULL, last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_host_endpoints_account ON host_endpoints(account_id, machine);
`)
	if err != nil {
		return nil, err
	}
	return &HostStore{db: db}, nil
}

// Register atomically reserves every requested name or none. Omitted endpoints
// remain reserved and visible offline until the owner explicitly removes them
// in a future management API; uninstall never releases a stable name.
func (s *HostStore) Register(accountID string, manifest common.HostManifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	status, err := readAccountStatus(context.Background(), tx, accountID)
	if err != nil {
		return err
	}
	if status.State != "active" {
		return ErrSuspended
	}
	accountID = status.AccountID
	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM host_machines WHERE account_id = ?", accountID).Scan(&count); err != nil {
		return err
	}
	var exists int
	if err := tx.QueryRow("SELECT COUNT(*) FROM host_machines WHERE account_id = ? AND machine = ?", accountID, manifest.Machine).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 && count >= 20 {
		return fmt.Errorf("host limit reached (20)")
	}
	now := time.Now().Unix()
	if _, err := tx.Exec("INSERT OR IGNORE INTO host_machines VALUES (?, ?, ?)", accountID, manifest.Machine, 0); err != nil {
		return err
	}
	for _, endpoint := range manifest.Tunnels {
		var owner string
		err := tx.QueryRow("SELECT account_id FROM reserved_subdomains WHERE subdomain = ?", endpoint.Name).Scan(&owner)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if owner == "" {
			if err := CheckNewSharedReservation(endpoint.Name); err != nil {
				return err
			}
		}
		if owner != "" && owner != accountID {
			return fmt.Errorf("name %s is reserved by another account", endpoint.Name)
		}
		var machine, endpointOwner string
		err = tx.QueryRow("SELECT account_id, machine FROM host_endpoints WHERE name = ?", endpoint.Name).Scan(&endpointOwner, &machine)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == nil && (endpointOwner != accountID || machine != manifest.Machine) {
			return fmt.Errorf("name %s belongs to a different machine", endpoint.Name)
		}
		if _, err := tx.Exec("INSERT OR IGNORE INTO reserved_subdomains VALUES (?, ?, ?)", endpoint.Name, accountID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO host_endpoints VALUES (?, ?, ?, ?, 0)
ON CONFLICT(name) DO UPDATE SET kind=excluded.kind`, endpoint.Name, accountID, manifest.Machine, endpoint.Kind); err != nil {
			return err
		}
	}
	if err := tx.QueryRow("SELECT COUNT(*) FROM reserved_subdomains WHERE account_id = ?", accountID).Scan(&count); err != nil {
		return err
	}
	if count > 10 {
		return fmt.Errorf("stable name limit reached (10)")
	}
	return tx.Commit()
}

func (s *HostStore) CheckEndpoint(accountID, machine, name, kind string) error {
	var gotMachine, gotAccount, gotKind string
	err := s.db.QueryRow("SELECT account_id, machine, kind FROM host_endpoints WHERE name = ?", name).Scan(&gotAccount, &gotMachine, &gotKind)
	if err != nil {
		return fmt.Errorf("host endpoint is not registered")
	}
	if gotAccount != accountID || gotMachine != machine || gotKind != kind {
		return fmt.Errorf("host endpoint does not match its reservation")
	}
	return nil
}

func (s *HostStore) Seen(accountID, machine, name string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.Exec("UPDATE host_endpoints SET last_seen = ? WHERE name = ? AND account_id = ? AND machine = ?", at.Unix(), name, accountID, machine); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE host_machines SET last_seen = ? WHERE account_id = ? AND machine = ?", at.Unix(), accountID, machine); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *HostStore) List(accountID string) ([]common.Machine, error) {
	rows, err := s.db.Query(`SELECT m.machine, m.last_seen, e.name, e.kind, e.last_seen
FROM host_machines m LEFT JOIN host_endpoints e ON e.account_id=m.account_id AND e.machine=m.machine
WHERE m.account_id=? ORDER BY m.machine, e.name`, accountID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	machines := []common.Machine{}
	for rows.Next() {
		var name string
		var seen int64
		var endpoint, kind sql.NullString
		var endpointSeen sql.NullInt64
		if err := rows.Scan(&name, &seen, &endpoint, &kind, &endpointSeen); err != nil {
			return nil, err
		}
		if len(machines) == 0 || machines[len(machines)-1].Name != name {
			m := common.Machine{Name: name, Tunnels: []common.HostEndpoint{}}
			if seen != 0 {
				m.LastSeen = time.Unix(seen, 0).UTC()
			}
			machines = append(machines, m)
		}
		if endpoint.Valid {
			e := common.HostEndpoint{Name: endpoint.String, Kind: kind.String}
			if endpointSeen.Int64 != 0 {
				e.LastSeen = time.Unix(endpointSeen.Int64, 0).UTC()
			}
			i := len(machines) - 1
			machines[i].Tunnels = append(machines[i].Tunnels, e)
		}
	}
	return machines, rows.Err()
}
