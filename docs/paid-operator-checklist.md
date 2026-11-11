# Paid operator checklist

Existing sales stay enabled as Bryan directed at 12:29. Engineering must quadruple-check offline; the first real customer will be monitored for purchase, activation and support result. Do not change sales or account settings as part of this checklist. His wife's checkout 3–4 months ago is historical context, not fresh proof of the current provider integration. Live [T-01](billing/original-T-01.md) remains **OPEN — deferred by owner**. Offline PASS does not close it. Refill owns launch; independent final Sol review follows engineering readiness.

## Actual purchase path

The pricing/account caller links to `/upgrade?period=monthly` or `yearly`. `internal/host/revenue.go:handleUpgrade` authenticates the owner, selects the existing configured Payment Link, and calls storage `PrepareBillingCheckout`. The authority commits a random account-bound intent and exact destination before the 303 redirect; unpaid retries resume it. Editable email/reference or return parameters cannot grant Pro.

Signed `/webhooks/stripe` intake (`internal/host/stripe.go`) normalizes the event and commits receipt/payment metadata. At the database authority, configured `internal/store/stripe_auto.go:StripeAutomation.Process` retrieves current subscription, expanded invoice and charge using the approved Price allowlist. Only a current active period, approved matching subscription/invoice price and nonzero paid invoice with matching paid, unrefunded, undisputed charge qualify. A consumed on-time server intent or explicit reviewed binding establishes ownership; customer metadata cannot select another account. Unknown ownership, price, completion time, payment or provider response stays queued for review.

Automatic reconciliation atomically projects the entitlement, resolves the receipt and records its audit. `/api/billing/status` and `/account?billing=return` read committed account state; a return URL is not payment proof. Scheduled cancellation retains the paid period. Current cancellation/refund removes that subscription's eligibility, preserving other eligible subscriptions, legacy grants and independent suspension. A failed/delayed read leaves the prior verified entitlement intact pending reconciliation. Existing bindings, including canceled ones, block returning self-service purchases and require support.

## Offline verification

`TestStripeFirstCustomerCheckoutToConsumer` in `internal/host/stripe_auto_test.go` independently exercises monthly/yearly destinations, opaque intents, signed completion, provider verification, automatic account binding, buyer API/page output, wrong customer/price, unpaid/open invoice, unknown response and recovery using the same receipt, repeated/reordered events, renewal, scheduled/current cancellation and charge-associated refund. Each subtest starts a fresh private database; no provider network is used. Ledger mapping/audit counts and an unrelated account are checked alongside buyer outputs.

Retain the existing authority/RPC and checkout tests, including durable-intent failure, unpaid resume and replica authority behavior. Four prior-source lifecycle invariants remain covered: pending payment never grants; replay never double grants; stale events cannot restore revoked eligibility; restart preserves receipt/ownership and suspension. See `stripe_prodtest_test.go`, `billing_review_regression_test.go`, `billing_round3_test.go` and `internal/store/stripe_auto_test.go` for restart/order, quarantined duplicates, late delivery, dispute, other entitlements, CAS and rollback coverage. These local cases verify source behavior, not deployed configuration or actual money/receipt delivery.

Run locally:

```sh
nice -n 10 go test -p 2 -count=1 -timeout=20m ./internal/host -run 'Stripe|Billing|Checkout'
nice -n 10 go test -p 2 -count=1 -timeout=20m ./...
```

## First customer and incident recovery

1. Owner/operator records release/environment, UTC timestamps, primary and secondary support coverage, redacted account/session/event/subscription references, approved monthly/yearly price mapping, provider/local before/after states, receipt delivery and activation elapsed time. Observe the first customer's purchase, committed Pro activation and support outcome. This live observation is deferred; no synthetic receipt can substitute.
2. If activation is pending, tell the buyer not to pay again. Use `/account`, `/api/billing/status` and support@tunn.to; preserve redacted event IDs, error and timing evidence. Unpaid checkout can resume its saved destination; a paid/pending or canceled binding requires support. Never infer success from a browser return or wife's historical purchase.
3. An already authorized operator can inspect the existing read-only commands below using scoped owner-only credentials and explicit database paths. Follow `--after provider/subscription` pagination for the payment queue and `payments_next`/pending-event continuation from billing status. Investigate unbound, duplicate, expired/unknown-time and unresolved rows. See [account operations](ACCOUNT-OPERATIONS.md) and [operator runbook](billing/operator-runbook.md) for current semantics; their default-disabled configuration description does not supersede this owner rollout decision.

```sh
tunn admin payment-queue --db "$DB" --admin-config "$ADMIN_CONFIG" --token-file "$TOKEN_FILE"
tunn admin billing-status --db "$DB" --admin-config "$ADMIN_CONFIG" --token-file "$TOKEN_FILE" --provider stripe --subscription "$SUBSCRIPTION"
tunn admin reconcile --db "$DB" --admin-config "$ADMIN_CONFIG" --token-file "$TOKEN_FILE" --snapshots "$SNAPSHOTS"
```

4. Reconciliation above is a read-only dry run with separately reviewed snapshots, not a provider operation. Stop case closure on ownership/price mismatch, missing receipts, stale evidence, provider uncertainty or unresolved money. Escalate to Bryan and the staffed secondary operator; preserve queue and evidence. A recovery decision needs fresh ownership/payment evidence and local version checks. Do not automatically disable sales, refund, cancel, apply reviewed writes or initiate paid actions. Those are separate operator decisions, not actions authorized by this checklist.
5. After a separately authorized recovery, verify both provider and local outcome, one correct entitlement, buyer-visible status/support response and queue resolution. Capture activation/refund turnaround where applicable, reviewer and evidence digest. Do not close a duplicate solely because Pro is active; a duplicate charge still requires reviewed money recovery.

## Deferred live evidence

All original T-01 cases remain OPEN: current-provider monthly/yearly checkout/ownership/receipt, renewal including failed/delayed payment and outage, duplicate/reordered events and money recovery, cancellation/refund/dispute, returning customer, activation/refund timing and secondary coverage. Observe configuration and the first customer under the owner-approved rollout without gating existing sales on a new receipt. This engineering task makes no real customer/provider/payment calls, uses no credentials, and performs no production writes, deployment or sales-setting changes.

## Public operator facts handoff

`/about` answers who maintains the service and how a buyer can check operator,
merchant and support facts. These are deploy-time facts, not a new launch gate.
Bryan remains the maintainer; that does not establish a legal entity or merchant match.
Before a separately authorized deployment, Bryan can fill the existing service's
protected environment file with confirmed values:

- [ ] `TUNN_OPERATING_NAME`: use the current confirmed operating name; leave unset until confirmed.
- [ ] `TUNN_MERCHANT_DISPLAY_NAME`: default source is the current Stripe merchant identity and receipt/statement display, checked by Bryan in the existing account. No identity has been independently verified here; leave unset until checked.
- [ ] Maintainer: Bryan Ehrlich (already rendered; no legal-operator inference).
- [ ] `TUNN_SUPPORT_WINDOW`: default source is the actual daily report review window Bryan currently staffs, with timezone and days. Leave unset until confirmed; do not infer round-the-clock coverage or a response deadline.
- [ ] `TUNN_MCP_VERIFIED`: list only AI clients and dates Bryan has verified end to end, for example `Claude.ai web 2026-11-12; Claude iOS 2026-11-12`. `/mcp-to-claude` and `/docs/mcp-to-claude` show these as escaped text under “Verified with:”, with up to four semicolon-separated client rows and an inline “+N more” count. Leave unset or whitespace-only to keep the Experimental statement; a protocol check alone does not verify an AI client.

Unset or whitespace-only `/about` facts display “Being confirmed; not currently available.”
Values render as text, including HTML characters. No report form or mail delivery
is added; the current support and abuse mail links remain available. Privacy,
retention and refund terms stay in their existing documents. Current status is
linked when configured; without a collector, checks and history are explicitly
unpublished. Existing sales and launch decisions are unchanged.

Prepared local configuration check (does not deploy or contact Stripe):
`bash scripts/check-operator-facts.sh`. After normal review and merge to main,
Bryan owns the existing production deployment procedure and environment update.

Check the intended billing configuration offline before deployment:

```sh
bash scripts/check-billing-ready.sh /path/to/protected.env
# Or, with the intended service environment already loaded:
bash scripts/check-billing-ready.sh
```

This requires Python 3 and prints one mode: `checkout closed`, `checkout open
with manual activation`, or `checkout open with automatic activation`, followed
by missing or malformed variable names, never values. A file is a complete
snapshot; ambient variables do not fill its gaps. Use literal `NAME=value`
assignments, optionally `export`, quotes and comments; shell expansion and
escapes are rejected and the file is never executed. Unrelated settings are
ignored. Without a file it reads the current environment.

A closed configuration or intentional manual activation exits 0. Malformed
supplied settings, or enabled billing without a webhook secret or any checkout
link, exit 1; treat the mode as descriptive only until these errors are fixed.
One valid monthly or yearly link opens checkout for that period; the other
missing link is reported. Missing API credentials or approved Price IDs means
manual activation. Automatic activation requires both `TUNN_STRIPE_SECRET_KEY`
and `TUNN_STRIPE_PRO_PRICE_IDS`, in addition to the checkout prerequisites.
This check validates configuration shapes only: it cannot verify credentials,
Price ownership, deployed settings, payment, or actual customer activation.
