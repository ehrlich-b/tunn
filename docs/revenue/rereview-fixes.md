# Billing re review fixes for October 11 2026

All five confirmed findings are addressed, including preservation of every legacy
Pro grant and reservation through startup. The Payment Link fallback quarantines
duplicate payments for manual refunds; it cannot prevent duplicate provider
charges. Eight identical safety regressions fail before and pass after.

Baseline: `39d8660db8432ac33c7aa8cb8e85245b30b2c2dc`. Production schema: `110485c`.
All data and receipts used below are synthetic. No production operation, push,
deployment or external communication was performed.

| Finding | Implemented behavior |
| --- | --- |
| 1: legacy Pro loss | Startup installs schema, snapshots grants once, changes zero plans and deletes zero reservations. All six legacy grant kinds retain Pro and effective reservation ownership. Only a separate global, reasoned, versioned, audited decision ends a legacy grant. |
| 2: duplicate Payment Link completion | One intent accepts one subscription. Additional payments commit `duplicate_payment_refund_needed`; both binding and Pro review reject them, including later lifecycle receipts. Refund/cancellation remains Bryan's manual provider action. |
| 3: abandoned checkout | Resume the same stored reference and exact destination across tabs/restarts for 24 hours. Expiry retains the hold; a still-payable link never authorizes a replacement intent. |
| 4: synthetic production fulfillment | Store intake rejects every non-Stripe provider without the exact disposable database marker, including authenticated node RPC calls. |
| 5: scoped migration | Schema installation has no plan/reservation mutations. Legacy reconciliation requires global authority; scoped credentials cannot perform it. |

## Regression proof before and after

The following identical regression bodies all **FAIL on 39d8660** and **PASS after**:

- `TestRereviewDeployPreserves110485cAccounts`
- `TestRereviewScopedMigrationCannotChangeOtherAccounts`
- `TestRereviewAbandonedCheckoutCanRetryAfterRestart`
- `TestRereviewSyntheticReceiptCannotGrantProductionPro`
- `TestRereviewUnmarkedProductionRPCRejectsSyntheticGrant`
- `TestRereviewIssuedLinkAllowsTwoPaidSubscriptions`
- `TestRereviewImageRollbackRestoresLegacyBenefits`
- `TestRereviewUpgradeChangesZeroPlansOrReservations`

The first six port the full independent store/HTTP/RPC reproductions. The
rollback reproduction checks the authoritative tables consumed by `110485c`;
a separate run against the actual archived production implementation also
returns **6 Pro accounts / 6 reservations** after this upgrade.
The additional zero-change test compares every plan and every reservation owner
before/after two startups, including a Free account with a stale reservation.
No safety assertion was removed. The duplicate reproduction now additionally
requires both rejected fulfillment paths, two retained receipts and an audit
outcome, while retaining the original at-most-one-subscription assertion.
Prior migration tests now assert preservation, and concurrency asserts one
shared durable intent across all successful resumes rather than one redirect.

The reusable SQL fixture `internal/store/testdata/legacy110485c.sql` was dumped
from a fresh synthetic database seeded by the unmodified archived `110485c`
implementation. Its seed source is retained alongside it as
`legacy110485c_seed_test.go` (run in the archived production tree only). It
covers operator, direct SQL, Stripe-paid/manual fulfillment, sequenced provider,
fixture review, and merged grants, plus usage and suspension. Tests adjust only
the usage month to keep the historical fixture reusable.

From the clone root, the environment for every Go command was:

```bash
export GOCACHE="$PWD/.scratch/go-build"
export GOMODCACHE="$PWD/.scratch/go-mod"
export GOTMPDIR="$PWD/.scratch/go-tmp"
```

After-fix proof command:

```bash
taskpolicy -b nice -n 15 go test ./internal/store ./internal/storage ./internal/host . -run '^TestRereview' -count=1 -v
```

For the before proof, `git archive 39d8660` was extracted into
`.scratch/rereview-fix/before-source`; only the final two regression files and
SQL fixture were added. The before command was `taskpolicy -b nice -n 15 go test
./internal/store ./internal/host -run '^TestRereview' -count=1 -v`, using the
clone's absolute cache paths. A programmatic check confirmed all eight selected
function bodies match the final files exactly; failures were safety assertions,
not compilation errors.

Logs retained locally under `.scratch/rereview-fix/logs/`: `seed.log`,
`before.log`, `after.log`, `rollback-production-after.log`, `race.log`,
`full-suite.log`, `vet.log`, and `build.log`. Scratch artifacts are excluded from
Git. The original six `TestReview` regressions remain covered.

## Validation and remaining required checks

- Focused race suite: PASS across store, storage, host and CLI, including all
  prior review regressions and the new adversarial tests.
  Command: `taskpolicy -b nice -n 15 go test -race ./internal/store ./internal/storage ./internal/host . -run '^(TestRereview|TestReview|TestReviewedBilling|TestBilling|TestRevenue|TestStripe|TestAccountOperations|TestOpsDBLegacy)' -count=1 -timeout=3m`.
- `go vet ./...`: PASS.
- Linux amd64 production build: PASS (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64
  taskpolicy -b nice -n 15 go build -o .scratch/rereview-fix/tunn-linux .`).
- Full suite: all completed packages pass; client/host/MCP bridge suites hit
  denied loopback binds (`bind: operation not permitted`). These are
  **REQUIRED-UNRUN**, not passing or waived tests. Remaining tests after the
  client/host panics also require a run outside this sandbox.

Exact REQUIRED-UNRUN command, with the cache environment above:

```bash
taskpolicy -b nice -n 15 go test ./... -count=1 -timeout=5m
```

This fallback does not create a Stripe Checkout Session or prevent two provider
charges. Quarantined payments require provider review and manual refunds where
appropriate; eliminating those charges requires real provider Session creation
and idempotent resume. Provider sandbox acceptance remains outside these local
synthetic tests. GO-LIVE.md documents the fallback, safe expiry, global legacy
cutover and the distinction between schema-only rollback and explicit data
cutover.
