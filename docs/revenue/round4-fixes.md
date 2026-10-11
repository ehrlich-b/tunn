# Round-4 billing fixes — 2026-10-11

Baseline: `ebc1c19`, clone `w9-tunn-revenue-20261011`.
Only synthetic local accounts, receipts, provider identifiers and evidence were
used. No production operation, provider write, external message, push or deploy
was performed.

## Reviewed batches

Previously, two first Stripe activations in one reviewed batch both saw the
account's initial Free state and could both grant Pro without an additional
purchase decision. The batch now validates all ownership, scope, CAS, provider
watermark and receipt evidence before writing. Within the same transaction,
ending grants are written first; each Pro activation then applies the existing
additional-purchase guard against the preceding writes. A conflict rolls back
all states, versions, receipts and reconciliation audits. Account projection
still runs only after the entire batch, preserving reserved names when eligible
service continues through a transfer.

Independent accounts, purchases established before a verified account merge,
and explicitly approved additional purchases retain their existing exceptions.
The batch does not create an approval decision. Unapproved extra subscriptions
still require the existing scoped payment review with `allow_additional` and
fresh provider evidence.

## Account payment status

Previously, `billing-status` filtered the first 100 global queue items in memory
and could omit its account's duplicate payment. It now filters by account or the
requested subscription in SQL before the page limit. An account index supports
this lookup; the global payment queue retains its separate pagination.

`billing-status --subscription ID` returns up to 100 unresolved account payments.
The explicitly requested unresolved payment is always included, even if it lies
outside the current page; that can produce 101 items. A nonempty `payments_next`
means another account page exists. Continue using the returned value:

```sh
tunn admin billing-status --db LOCAL_DB --admin-config ADMINS_JSON --token-file TOKEN_FILE --subscription SUBSCRIPTION_ID --after PROVIDER/SUBSCRIPTION_FROM_PAYMENTS_NEXT
```

The requested payment can repeat across pages. The continuation advances the
100-item account page, independently of that extra target item. A status query
for an unowned payment requires global scope and returns only that payment,
without including unrelated unowned receipts. Accepted and resolved payments
remain outside the unresolved payment list.

## Regression proof and local checks

The final identical bodies of
`TestR4BatchPreboundSubscriptionsNeedAdditionalPurchaseDecision` and
`TestR4BillingStatusRetainsTargetPaymentPastFirstQueuePage` compile and fail on
an unmodified `git archive ebc1c19`, then pass with these fixes. The failures are
safety assertions: two Pro grants, and missing direct/account status payments.
The fixed rejected batch retains zero Pro grants, zero CAS increments, zero
reconciled receipts and zero reconciliation audits.

Additional tests cover independent and merged accounts, explicit additional
purchase approvals, eligibility transfers in either input order, audit-failure
rollback, account pagination at 100/101/205 payments, target inclusion beyond the
account page, scope isolation, unowned targets, and CLI continuation.

The portable suite passes all **17 packages with tests** and **626 top-level
tests**. All **90 earlier regressions** from the supplied round-4 log occur and
pass in this run. The portable race checks pass all four selected packages
(store, storage, host and CLI), with **400 top-level tests**. The unchanged
exclusions omit 35 loopback tests; the existing homograph known-gap skip and
three constructor/run skips for missing `certs/cert.pem` remain. This does not
claim unrestricted network acceptance. `git diff --check` passes.

Evidence: [baseline failures](validation-logs/round4-before.txt),
[fixed store regressions](validation-logs/round4-after.txt),
[portable/race summary](validation-logs/round4-checks.txt).

Every Go command uses clone-local caches and background priority:

```sh
mkdir -p .scratch/go-build .scratch/go-mod .scratch/go-tmp
export GOCACHE="$PWD/.scratch/go-build"
export GOMODCACHE="$PWD/.scratch/go-mod"
export GOTMPDIR="$PWD/.scratch/go-tmp"
export GOPROXY=off
```

The focused regression command is:

```sh
taskpolicy -b nice -n 15 go test -p 2 ./internal/store . -run '^TestR4' -count=1 -v
```

The portable and race runs use the exact 35 loopback exclusions and memory
transport wrapper documented in [round-3 validation](round3-validation.md).
Their commands, after creating that wrapper as `.scratch/r4-fix/test-exec`, are:

```sh
R4_SKIP=$(cat .scratch/r3-fix/portable-skip.txt)
taskpolicy -b nice -n 15 go test -p 2 ./... -count=1 -json -exec "$PWD/.scratch/r4-fix/test-exec" -skip "$R4_SKIP"
taskpolicy -b nice -n 15 go test -race -p 2 ./internal/store ./internal/storage ./internal/host . -count=1 -json -exec "$PWD/.scratch/r4-fix/test-exec" -skip "$R4_SKIP"
```

## REQUIRED-UNRUN

The coordinator must run unrestricted tests with normal synthetic certificates
and loopback listeners. These commands have no exclusions or memory transport
substitutions:

```sh
taskpolicy -b nice -n 15 env GOCACHE="$PWD/.scratch/go-build" GOMODCACHE="$PWD/.scratch/go-mod" GOTMPDIR="$PWD/.scratch/go-tmp" GOPROXY=off go test -p 2 ./... -count=1
taskpolicy -b nice -n 15 env GOCACHE="$PWD/.scratch/go-build" GOMODCACHE="$PWD/.scratch/go-mod" GOTMPDIR="$PWD/.scratch/go-tmp" GOPROXY=off go test -race -p 2 ./internal/store ./internal/storage ./internal/host . -count=1
```

The round-4 review's no-Stripe deployment and rollback evidence remains supplied
evidence. Real Stripe sandbox lifecycle, hosted clients, immutable image build,
production inventory and rollout remain separately owned release gates in the
[runbook](round3-fixes.md).
