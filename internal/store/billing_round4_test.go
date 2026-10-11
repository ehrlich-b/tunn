package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func r4PreboundSubscription(t *testing.T, ops *OperationsStore, a *Account, suffix string) BillingEvent {
	t.Helper()
	e := BillingEvent{Provider: "stripe", ID: "evt_" + suffix, Type: "customer.subscription.updated", CustomerID: "cus_" + suffix, SubscriptionID: "sub_" + suffix, Supported: true}
	ctx := context.Background()
	if err := ops.BindBilling(ctx, operationsPrincipal(t, a.ID), BillingMapping{Provider: e.Provider, CustomerID: e.CustomerID, SubscriptionID: e.SubscriptionID, AccountID: a.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ProcessBillingEvent(ctx, e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestR4ReviewedBatchIndependentAndMergedAccounts(t *testing.T) {
	for _, merge := range []bool{false, true} {
		t.Run(fmt.Sprintf("merged=%t", merge), func(t *testing.T) {
			db, ops, a, _ := operationsFixture(t)
			accounts := NewAccountStore(db)
			b, err := accounts.FindOrCreateByEmails([]string{"batch-other@example.invalid"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			e1 := r4PreboundSubscription(t, ops, a, "batch_first")
			e2 := r4PreboundSubscription(t, ops, b, "batch_other")
			if merge {
				a, err = accounts.FindOrCreateByEmails([]string{a.PrimaryEmail, b.PrimaryEmail}, "github")
				if err != nil {
					t.Fatal(err)
				}
				b = a
			}
			out, err := ops.ApplyReviewedBilling(context.Background(), operationsPrincipal(t, a.ID, b.ID), []BillingSnapshot{paymentSnapshot(ops, a, e1), paymentSnapshot(ops, b, e2)})
			if err != nil || len(out) != 2 || out[0].State != "applied" || out[1].State != "applied" {
				t.Fatal(out, err)
			}
			requirePlan(t, db, a.ID, "pro")
			requirePlan(t, db, b.ID, "pro")
			var grants int
			if err = db.QueryRow(`SELECT count(*) FROM ops_billing_states WHERE plan='pro'`).Scan(&grants); err != nil || grants != 2 {
				t.Fatal(grants, err)
			}
		})
	}
}

func TestR4ReviewedBatchTransfersEligibilityAtomically(t *testing.T) {
	for _, replacementFirst := range []bool{false, true} {
		for _, failAudit := range []bool{false, true} {
			t.Run(fmt.Sprintf("replacement-first=%t/fail-audit=%t", replacementFirst, failAudit), func(t *testing.T) {
				db, ops, a, _ := operationsFixture(t)
				ctx := context.Background()
				admin := operationsPrincipal(t, a.ID)
				old := r4PreboundSubscription(t, ops, a, "transfer_old")
				replacement := r4PreboundSubscription(t, ops, a, "transfer_new")
				if _, err := ops.ApplyReviewedBilling(ctx, admin, []BillingSnapshot{paymentSnapshot(ops, a, old)}); err != nil {
					t.Fatal(err)
				}
				if err := NewAccountStore(db).ReserveSubdomain(a.ID, "continuous-name"); err != nil {
					t.Fatal(err)
				}
				now := ops.now().Add(time.Second)
				ops.now = func() time.Time { return now }
				old.ID, old.Type = "evt_transfer_end", "customer.subscription.deleted"
				if _, err := ops.ProcessBillingEvent(ctx, old); err != nil {
					t.Fatal(err)
				}
				end := paymentSnapshot(ops, a, old)
				end.Plan, end.ProviderStatus, end.PaymentConfirmed, end.ExpectedVersion = "free", "canceled", false, 1
				snaps := []BillingSnapshot{end, paymentSnapshot(ops, a, replacement)}
				if replacementFirst {
					snaps[0], snaps[1] = snaps[1], snaps[0]
				}
				if failAudit {
					if _, err := db.Exec(`CREATE TRIGGER fail_transfer_audit BEFORE INSERT ON ops_billing_events WHEN NEW.event_type='snapshot.reconciled' AND NEW.subscription_id='sub_transfer_new' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`); err != nil {
						t.Fatal(err)
					}
				}
				out, err := ops.ApplyReviewedBilling(ctx, admin, snaps)
				if (err != nil) != failAudit {
					t.Fatal(out, err)
				}
				requirePlan(t, db, a.ID, "pro")
				if owner, err := NewAccountStore(db).GetSubdomainOwner("continuous-name"); err != nil || owner != a.ID {
					t.Fatal("batch lost continuous eligibility", owner, err)
				}
				oldState, err := ops.AdminBillingStatus(ctx, admin, "stripe", old.SubscriptionID)
				if err != nil {
					t.Fatal(err)
				}
				newState, err := ops.AdminBillingStatus(ctx, admin, "stripe", replacement.SubscriptionID)
				if err != nil {
					t.Fatal(err)
				}
				if failAudit {
					if oldState.Mapping.Plan != "pro" || oldState.Mapping.Version != 1 || newState.Mapping.Plan != "" || newState.Mapping.Version != 0 || len(oldState.PendingEventIDs) != 1 || len(newState.PendingEventIDs) != 1 {
						t.Fatal("failed transfer changed state or receipts", oldState, newState)
					}
				} else if oldState.Mapping.Plan != "free" || oldState.Mapping.Version != 2 || newState.Mapping.Plan != "pro" || newState.Mapping.Version != 1 {
					t.Fatal("transfer did not move grant", oldState, newState)
				}
			})
		}
	}
}

func TestR4ReviewedBatchAllowsExplicitAdditionalPurchase(t *testing.T) {
	db, ops, a, _ := operationsFixture(t)
	ctx := context.Background()
	admin := operationsPrincipal(t, a.ID)
	var snaps []BillingSnapshot
	events := []BillingEvent{r4PreboundSubscription(t, ops, a, "approved_0"), r4PreboundSubscription(t, ops, a, "approved_1")}
	for i, e := range events {
		e.ID, e.Type, e.SessionID = fmt.Sprintf("evt_completion_%d", i), "checkout.session.completed", fmt.Sprintf("cs_approved_%d", i)
		if _, err := ops.ProcessBillingEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
		// Missing-reference completions on these prebound accounts still need
		// ownership/payment review; an approval must explicitly allow the extra.
		decision := paymentDecision(ops, a, e)
		decision.AllowAdditional = true
		if err := ops.ReviewCheckoutPayment(ctx, admin, decision); err != nil {
			t.Fatal(err)
		}
		snaps = append(snaps, paymentSnapshot(ops, a, e))
	}
	if out, err := ops.ApplyReviewedBilling(ctx, admin, snaps); err != nil || len(out) != 2 {
		t.Fatal(out, err)
	}
	requirePlan(t, db, a.ID, "pro")
	var grants, decisions int
	if err := db.QueryRow(`SELECT count(*) FROM ops_billing_states WHERE plan='pro'`).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM ops_payment_review_audit WHERE action='approve'`).Scan(&decisions); err != nil || grants != 2 || decisions != 2 {
		t.Fatal(grants, decisions, err)
	}
}

func TestR4BillingStatusAccountPaginationAndTargetInclusion(t *testing.T) {
	for _, count := range []int{100, 101, 205} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			db, ops, a, _ := operationsFixture(t)
			ctx := context.Background()
			// Synthetic unresolved receipts for two accounts interleave in the
			// global queue. Account status must page only its own receipts.
			b, err := NewAccountStore(db).FindOrCreateByEmails([]string{"queue-other@example.invalid"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < count; i++ {
				for _, owner := range []struct{ account, prefix string }{{a.ID, "sub_r4_a"}, {b.ID, "sub_r4_b"}, {"", "sub_r4_unowned"}} {
					sub := fmt.Sprintf("%s_%03d", owner.prefix, i)
					if _, err = db.Exec(`INSERT INTO ops_checkout_payments(provider,subscription_id,customer_id,outcome,event_id,account_id) VALUES('stripe',?,?,'duplicate_payment_refund_needed',?,?)`, sub, "cus_"+sub, "evt_"+sub, owner.account); err != nil {
						t.Fatal(err)
					}
				}
			}
			target := fmt.Sprintf("sub_r4_a_%03d", count-1)
			for _, principal := range []AdminPrincipal{operationsPrincipal(t, a.ID), operationsPrincipal(t, "*")} {
				seen := map[string]bool{}
				after := ""
				for page := 0; ; page++ {
					if page > 3 {
						t.Fatal("cursor did not terminate", after)
					}
					status, err := ops.AdminBillingStatusPage(ctx, principal, "stripe", target, after)
					if err != nil {
						t.Fatal(err)
					}
					found, pageSeen := false, map[string]bool{}
					for _, payment := range status.Payments {
						if payment.AccountID != a.ID || pageSeen[payment.SubscriptionID] {
							t.Fatal("unrelated or repeated payment", payment)
						}
						pageSeen[payment.SubscriptionID] = true
						found = found || payment.SubscriptionID == target
						if payment.SubscriptionID != target && seen[payment.SubscriptionID] {
							t.Fatal("page repeated a non-target payment", payment)
						}
						seen[payment.SubscriptionID] = true
					}
					if !found {
						t.Fatal("requested payment omitted", status)
					}
					if page == 0 {
						wantLength, wantNext := count, ""
						if count > 100 {
							wantLength, wantNext = 101, "stripe/sub_r4_a_099"
						}
						if len(status.Payments) != wantLength || status.PaymentsNext != wantNext {
							t.Fatal("incorrect first page or continuation", len(status.Payments), status.PaymentsNext)
						}
					}
					if status.PaymentsNext == "" {
						break
					}
					if status.PaymentsNext <= after {
						t.Fatal("cursor did not advance", status.PaymentsNext, after)
					}
					after = status.PaymentsNext
				}
				if len(seen) != count {
					t.Fatal("account pagination lost payments", len(seen), count)
				}
			}
			if _, err := ops.AdminBillingStatus(ctx, operationsPrincipal(t, b.ID), "stripe", target); !errors.Is(err, ErrDenied) {
				t.Fatal("account scope bypassed", err)
			}
			unowned := fmt.Sprintf("sub_r4_unowned_%03d", count-1)
			status, err := ops.AdminBillingStatus(ctx, operationsPrincipal(t, "*"), "stripe", unowned)
			if err != nil || len(status.Payments) != 1 || status.Payments[0].SubscriptionID != unowned || status.PaymentsNext != "" {
				t.Fatal("unowned target pulled unrelated unowned payments", status, err)
			}
			if _, err := ops.AdminBillingStatus(ctx, operationsPrincipal(t, a.ID), "stripe", unowned); !errors.Is(err, ErrDenied) {
				t.Fatal("unowned receipt leaked to scoped operator", err)
			}
		})
	}
}
