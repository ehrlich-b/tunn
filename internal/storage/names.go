package storage

import (
	"context"
	"fmt"
	"sort"

	"github.com/ehrlich-b/tunn/internal/store"
)

type AccountName struct {
	Name   string
	Kept   bool
	Active bool
}

// AccountNames reads reservations, independently of successful registrations.
func (s *LocalStorage) AccountNames(ctx context.Context, accountID string) ([]AccountName, error) {
	s.activeTunnelsMu.RLock()
	defer s.activeTunnelsMu.RUnlock()
	account, err := s.accounts.GetByIDContext(ctx, accountID)
	if err != nil {
		return nil, err
	}
	reserved, err := s.accounts.GetReservedSubdomains(account.ID)
	if err != nil {
		return nil, err
	}
	names := map[string]AccountName{}
	for _, r := range reserved {
		owner, err := s.accounts.GetSubdomainOwner(r.Subdomain)
		if err != nil {
			return nil, err
		}
		if owner == account.ID {
			names[r.Subdomain] = AccountName{Name: r.Subdomain, Kept: true}
		}
	}
	for name, id := range s.activeTunnels {
		owner, err := s.accounts.GetByIDContext(ctx, id)
		if err != nil {
			return nil, err
		}
		if owner.ID == account.ID {
			row := names[name]
			row.Name = name
			row.Active = true
			names[name] = row
		}
	}
	out := make([]AccountName, 0, len(names))
	for _, n := range names {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Share registration's lock so neither endpoint can connect during the swap.
// Every relay registers with this login-node authority.
func (s *LocalStorage) ReplaceAccountName(ctx context.Context, accountID, oldName, newName string) error {
	s.activeTunnelsMu.Lock()
	defer s.activeTunnelsMu.Unlock()
	for _, name := range []string{oldName, newName} {
		if _, active := s.activeTunnels[name]; active {
			return fmt.Errorf("stop both tunnels before replacing a kept name")
		}
	}
	// Check effective ownership as well as the transaction's raw owner predicate.
	account, err := s.accounts.GetByIDContext(ctx, accountID)
	if err != nil {
		return err
	}
	owner, err := s.accounts.GetSubdomainOwner(oldName)
	if err != nil {
		return err
	}
	if owner != account.ID {
		return store.ErrNameConflict
	}
	return s.accounts.ReplaceSubdomain(ctx, account.ID, oldName, newName)
}
