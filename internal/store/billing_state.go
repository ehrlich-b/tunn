package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
)

var ErrCheckoutBlocked = errors.New("checkout requires billing review")

// billingAccountState reduces the newest verified state of every subscription.
// Unverified mappings and receipts never confer entitlement. Legacy grants
// remain effective until an audited global operator decision ends them.
func billingAccountState(ctx context.Context, q operationQuery, id string) (plan, checkout string, err error) {
	var eligible, legacy, bound, pending, paid bool
	err = q.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM ops_billing_mappings m JOIN ops_billing_states s USING(provider,subscription_id) WHERE m.account_id=? AND s.plan='pro' AND NOT EXISTS(SELECT 1 FROM ops_rollback_subscription_holds h WHERE h.provider=m.provider AND h.subscription_id=m.subscription_id) AND NOT EXISTS(SELECT 1 FROM ops_checkout_payments p WHERE p.provider=m.provider AND p.subscription_id=m.subscription_id AND (p.outcome!='accepted' AND p.resolution!='approved' OR p.resolution='approved' AND (m.version<=p.approval_version OR s.provider_read_at<p.approved_at)))),
 EXISTS(SELECT 1 FROM ops_legacy_entitlements WHERE account_id=? AND plan='pro'),
 EXISTS(SELECT 1 FROM ops_billing_mappings WHERE account_id=?),
 EXISTS(SELECT 1 FROM ops_checkout_intents WHERE account_id=?),
 EXISTS(SELECT 1 FROM ops_checkout_intents i JOIN ops_checkout_payments p USING(reference) WHERE i.account_id=?) OR EXISTS(SELECT 1 FROM ops_checkout_payments WHERE account_id=?)`, id, id, id, id, id, id).Scan(&eligible, &legacy, &bound, &pending, &paid)
	plan, checkout = "free", "available"
	switch {
	case eligible:
		plan, checkout = "pro", "active"
	case legacy:
		plan, checkout = "pro", "legacy"
	case bound:
		checkout = "support"
	case paid:
		checkout = "pending"
	case pending:
		checkout = "resumable"
	}
	return
}

// projectBillingAccount atomically maintains the plan cache used by metering
// and domains and removes paid reservations when the derived entitlement ends.
func projectBillingAccount(ctx context.Context, tx *sql.Tx, id string) error {
	plan, _, err := billingAccountState(ctx, tx, id)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO ops_projection_guard VALUES(?)`, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE accounts SET plan=? WHERE id=?`, plan, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM ops_projection_guard WHERE account_id=?`, id); err != nil {
		return err
	}
	if plan == "free" {
		_, err = tx.ExecContext(ctx, `DELETE FROM reserved_subdomains WHERE account_id=?`, id)
	}
	return err
}

func writeBillingState(ctx context.Context, tx *sql.Tx, provider, sub, plan string, revision int64, readAt time.Time, digest string) error {
	var stamp int64
	if !readAt.IsZero() {
		stamp = readAt.UnixNano()
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO ops_billing_states(provider,subscription_id,plan,revision,provider_read_at,digest) VALUES(?,?,?,?,?,?)
 ON CONFLICT(provider,subscription_id) DO UPDATE SET plan=excluded.plan,revision=excluded.revision,provider_read_at=excluded.provider_read_at,digest=excluded.digest`, provider, sub, plan, revision, stamp, digest)
	return err
}

const CheckoutResumeWindow = 24 * time.Hour

// BeginBillingCheckout resumes the same unpaid intent across tabs/restarts.
func (s *OperationsStore) BeginBillingCheckout(ctx context.Context, id string) (string, error) {
	reference, _, err := s.PrepareBillingCheckout(ctx, id, "")
	return reference, err
}

// PrepareBillingCheckout persists the destination with the intent. Local expiry
// stops further redirects, never releases the hold or creates a replacement:
// Payment Links remain payable at Stripe. Late/duplicate payments are retained
// for operator review and can never automatically create extra entitlements.
func (s *OperationsStore) PrepareBillingCheckout(ctx context.Context, id, destination string) (string, string, error) {
	if destination != "" && !validCheckoutDestination(destination) {
		return "", "", fmt.Errorf("invalid checkout destination")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = tx.Rollback() }()
	status, err := readAccountStatus(ctx, tx, id)
	if err != nil {
		return "", "", err
	}
	if status.State != "active" {
		return "", "", ErrSuspended
	}
	_, state, err := billingAccountState(ctx, tx, status.AccountID)
	if err != nil {
		return "", "", err
	}
	if state != "available" && state != "resumable" {
		return "", "", ErrCheckoutBlocked
	}
	if state == "resumable" {
		var reference, created, saved, expires string
		var intents int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM ops_checkout_intents WHERE account_id=?`, status.AccountID).Scan(&intents); err != nil {
			return "", "", err
		}
		// Merging two outstanding purchases requires review before another redirect.
		if intents != 1 {
			return "", "", ErrCheckoutBlocked
		}
		err = tx.QueryRowContext(ctx, `SELECT i.reference,i.created_at,COALESCE(d.destination,''),COALESCE(d.expires_at,'') FROM ops_checkout_intents i LEFT JOIN ops_checkout_destinations d USING(reference) WHERE i.account_id=?`, status.AccountID).Scan(&reference, &created, &saved, &expires)
		if err != nil {
			return "", "", err
		}
		stamp, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return "", "", err
		}
		deadline := stamp.Add(CheckoutResumeWindow)
		if expires != "" {
			deadline, err = time.Parse(time.RFC3339Nano, expires)
			if err != nil {
				return "", "", err
			}
		}
		if !s.now().Before(deadline) {
			return "", "", ErrCheckoutBlocked
		}
		if saved != "" {
			destination = saved
		} else if destination != "" {
			if _, err = tx.ExecContext(ctx, `INSERT INTO ops_checkout_destinations(reference,destination,expires_at) VALUES(?,?,?)`, reference, destination, deadline.UTC().Format(time.RFC3339Nano)); err != nil {
				return "", "", err
			}
		}
		if err = tx.Commit(); err != nil {
			return "", "", err
		}
		return reference, destination, nil
	}
	reference := uuid.NewString()
	if _, err = tx.ExecContext(ctx, `INSERT INTO ops_checkout_intents(reference,account_id,created_at) VALUES(?,?,?)`, reference, status.AccountID, s.now().UTC().Format(time.RFC3339Nano)); err != nil {
		return "", "", err
	}
	if destination != "" {
		if _, err = tx.ExecContext(ctx, `INSERT INTO ops_checkout_destinations(reference,destination,expires_at) VALUES(?,?,?)`, reference, destination, s.now().Add(CheckoutResumeWindow).UTC().Format(time.RFC3339Nano)); err != nil {
			return "", "", err
		}
	}
	if err = tx.Commit(); err != nil {
		return "", "", err
	}
	return reference, destination, nil
}

func validCheckoutDestination(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 2048 && u.Scheme == "https" && u.Host == "buy.stripe.com" && u.User == nil && u.Fragment == "" && len(u.Path) > 1
}

// updateFixturePlan keeps legacy test helpers out of production fulfillment.
// A disposable fixture grant is itself a sequenced synthetic subscription.
func (s *AccountStore) updateFixturePlan(id, plan string) error {
	if plan != "pro" && plan != "free" {
		return fmt.Errorf("invalid plan")
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var marker string
	if err = tx.QueryRow(`SELECT value FROM ops_fixture WHERE id=1`).Scan(&marker); err != nil || marker != "disposable-local" {
		return fmt.Errorf("direct plan updates require a disposable local fixture; use reviewed billing")
	}
	id, err = canonicalAccount(ctx, tx, id)
	if err != nil {
		return err
	}
	const provider = "fixture-plan"
	// When fixtures downgrade merged accounts, update all of their synthetic
	// grants; real billing mappings still require individually reviewed evidence.
	if _, err = tx.ExecContext(ctx, `UPDATE ops_billing_states SET plan=?,revision=revision+1 WHERE provider=? AND subscription_id IN (SELECT subscription_id FROM ops_billing_mappings WHERE provider=? AND account_id=?)`, plan, provider, provider, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO ops_billing_mappings(provider,subscription_id,customer_id,account_id) VALUES(?,?,?,?) ON CONFLICT(provider,subscription_id) DO NOTHING`, provider, id, id, id); err != nil {
		return err
	}
	var revision int64
	if err = tx.QueryRow(`SELECT COALESCE((SELECT revision FROM ops_billing_states WHERE provider=? AND subscription_id=?),1)`, provider, id).Scan(&revision); err != nil {
		return err
	}
	if err = writeBillingState(ctx, tx, provider, id, plan, revision, time.Time{}, "fixture"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE ops_billing_mappings SET plan=?,revision=?,version=version+1 WHERE provider=? AND subscription_id=?`, plan, revision, provider, id); err != nil {
		return err
	}
	if err = projectBillingAccount(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit()
}
