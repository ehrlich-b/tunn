package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// LegacyEntitlementDecision explicitly retains or ends an imported grant.
// OriginalAccountID identifies the grant even after verified identity merges.
type LegacyEntitlementDecision struct {
	OriginalAccountID string `json:"original_account_id"`
	AccountID         string `json:"account_id"`
	ExpectedVersion   int64  `json:"expected_version"`
	Plan              string `json:"plan"`
	Reason            string `json:"reason"`
}

// ReconcileLegacyEntitlements is a separate, global operator action. Schema
// installation, scoped billing review and webhook intake cannot revoke legacy
// service. Every decision is reasoned, CAS checked and audited in one transaction.
func (s *OperationsStore) ReconcileLegacyEntitlements(ctx context.Context, p AdminPrincipal, decisions []LegacyEntitlementDecision) error {
	if err := p.authorize("*"); err != nil {
		return err
	}
	if len(decisions) == 0 || len(decisions) > 1000 {
		return fmt.Errorf("require 1..1000 legacy entitlement decisions")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	seen, accounts := map[string]bool{}, map[string]bool{}
	for _, d := range decisions {
		if seen[d.OriginalAccountID] || !boundedText(d.OriginalAccountID, 128) || !boundedText(d.AccountID, 128) || !boundedText(d.Reason, 256) || d.ExpectedVersion < 0 || d.Plan != "pro" && d.Plan != "free" {
			return fmt.Errorf("invalid legacy entitlement decision")
		}
		seen[d.OriginalAccountID] = true
		var account, previous string
		var version int64
		if err = tx.QueryRowContext(ctx, `SELECT account_id,plan,version FROM ops_legacy_entitlements WHERE original_account_id=?`, d.OriginalAccountID).Scan(&account, &previous, &version); err != nil {
			return err
		}
		if account != d.AccountID || version != d.ExpectedVersion {
			return ErrVersionConflict
		}
		if _, err = tx.ExecContext(ctx, `UPDATE ops_legacy_entitlements SET plan=?,version=version+1 WHERE original_account_id=?`, d.Plan, d.OriginalAccountID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO ops_legacy_entitlement_audit(id,original_account_id,account_id,previous_plan,plan,version,reason,actor,changed_at) VALUES(?,?,?,?,?,?,?,?,?)`, uuid.NewString(), d.OriginalAccountID, account, previous, d.Plan, version+1, d.Reason, p.actor, s.now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		accounts[account] = true
	}
	for id := range accounts {
		if err = projectBillingAccount(ctx, tx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
