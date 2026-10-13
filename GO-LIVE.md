# Coordinator launch runbook — Bryan approval required

No deploy, production administration, Stripe writes, external accounts,
submissions or posts were performed. The only live-site access was public GET.
This runbook is staged for the coordinator; its external actions require Bryan's
approval under BRIEF.md. It is not authorization to run them now.

## Approval packet and launch condition

Approve the reviewed code; Free and Pro **$5/month / $48/year**; Stripe objects
below; iad launch economics; a staffed beta activation/cancellation queue;
CLI publication; and the specific DRAFT submissions/posts in DISTRIBUTION.md.
Separately resolve the missing full license text and native Homebrew validation.
Do not advertise hosted Claude/ChatGPT compatibility until real-client
acceptance succeeds. Do not create the deferred $12/year or Usage tier.

This release implements **operator-reviewed fulfillment**, not an automatic
Stripe synchronizer. Operators must own activation, renewal, failed-payment and
cancellation review. Signed events are durable receipts, not authoritative
ordered snapshots. Do not invent revisions from Stripe timestamps. If this
operating model is unacceptable, ship the public pages with checkout disabled
and finish the provider-read worker before selling.

## 1. Import and review without touching the existing worktree

The carrier branch is `codex/tunn-revenue-20261011`, based on `110485c`.
The bundle is self-contained and supports a clean checkout:

```bash
git bundle verify /work/lanes/tunn-revenue/tunn/.scratch/tunn-revenue.bundle
git clone --branch codex/tunn-revenue-20261011 /work/lanes/tunn-revenue/tunn/.scratch/tunn-revenue.bundle /tmp/tunn-revenue-review
cd /tmp/tunn-revenue-review
git diff 110485c..HEAD --stat
umask 077
go vet ./...
go test ./...
go build -trimpath -o /tmp/tunn-revenue-cli .
/tmp/tunn-revenue-cli http --help
```

See [validation](docs/revenue/validation.md) for this lane's Go/cache settings
and loopback tests. Review the six root documents and billing tests. Use the
coordinator's normal reviewed merge/push process; the task did not push a ref.

## 2. Inventory, preserve and build the production release

Before any change, the coordinator records current machine IDs, roles, regions,
mounted volumes, configuration, image digests, release, and secret **names**.
The brief says v38; do not assume it is still current. Do not print secret values.

```bash
fly status --app tunn
fly machines list --app tunn
fly volumes list --app tunn
fly releases --app tunn
fly config show --app tunn
fly secrets list --app tunn
```

Save the actual deployed config as `fly.revenue.rollback.toml` and a reviewed
copy as `fly.revenue.toml`. Do not replace production with `fly.toml.dist`:
it is a template, not an inspected cluster inventory. Preserve JWT/OAuth/TLS,
SSH host keys, custom-domain state, role flags, login-node routing, volume and
current network handlers. Set **TUNN_BILLING_ENABLED=false** for this phase.
Set displayed prices 6/60, with no lower owner caps than the sales copy unless
the rendered limits and approved offer reflect them.

On the authoritative SQLite/login machine, in an approved console:

```bash
fly ssh console --app tunn --machine LOGIN_MACHINE_ID
```

Inside that console, verify the configured DB path first (default
`/data/tunn.db`), verify the backup filename is unused, then take a consistent
SQLite backup. These example paths must match the inventory:

```bash
set -eu
umask 077
test ! -e /data/tunn-revenue-before.db
sqlite3 /data/tunn.db '.backup /data/tunn-revenue-before.db'
sqlite3 -readonly /data/tunn-revenue-before.db 'PRAGMA integrity_check;'
```

Require `ok`, preserve an off-machine encrypted copy with the normal backup
procedure, and record its hash. A raw live `cp` of SQLite/WAL is not a backup.
Keep reservations, ledgers and billing audit history. New reviewed evidence
fields are JSON/CLI fields. Startup installs additive billing/checkout schema and
snapshots legacy Pro grants once into `ops_legacy_entitlements`; it changes no
account plan and deletes no reservation. Do not run fixture-init on real data.

Coordinator builds, pushes and records a new immutable image digest using the
approved release pipeline. The existing Dockerfile uses Go 1.25; complete the
container build as a separate gate because this lane tested Go 1.27.2 and did
not build a Docker image. Keep the previous image digest for rollback. Once
these two variables are set to recorded digests and approved config exists:

```bash
fly deploy --app tunn --config fly.revenue.toml --image "$TUNN_REVENUE_IMAGE" --update-only --ha=false --strategy rolling
```

Do not create spare SQLite writers. Preserve current machine roles and drain
expectations. A rolling relay restart can interrupt tunnels; announce through
the existing approved support process if required.

## 3. Site and CLI acceptance while checkout is disabled

Public GETs: `/`, `/pricing`, `/docs`, `/docs/mcp-to-claude`,
`/ngrok-alternative`, `/terms` return distinct usable pages; an unknown apex
path returns 404. `/account`, `/upgrade` and `/api/billing/status` require login.
Disabled checkout returns 503 for an authenticated Free user and never `#`.
Test storage failure gives 503, not a fabricated Free tier. Check security/CSP
and that publisher subdomains still forward their own `/pricing` paths.

Publish CLI artifacts through the existing approved release mechanism; verify
OS/architecture, install/recovery and `tunn http 8080 --inspect`. Website deploy
alone does not update the installer binary. The staged Homebrew formula pins
the product commit; it must be reachable publicly before installation. Run its
native macOS/Linux checks and resolve licensing before a core/tap claim.

In the approved non-production connector test environment, use the read-only
`examples/mcp/echo.py`: login, private stdio MCP, an existing HTTP MCP target,
OAuth dynamic registration + PKCE, echo invocation, disconnect/reconnect,
refresh and explicit client revocation. Verify denial after revocation in
Claude.ai and in the current ChatGPT custom MCP client. Validate user sharing
and malicious redirect rejection. Use test accounts only when Bryan authorizes
their creation; this task created no external accounts. Record date/client/UI
version; update preview copy only after success. OpenAI also offers its own
Secure MCP Tunnel; account for that substitute rather than promising exclusivity.

## 4. Exact Stripe objects — separate test and live inventories

Create these in Stripe **test mode first**, pointed at the approved sandbox
host with its own signing secret. The live values are:

| Object | Exact settings |
| --- | --- |
| Product | `tunn Pro`; description: 25 concurrent tunnels, 10 reserved tunn.to names, 500 GB combined metered bytes and 10m monthly admissions; hard stop, no automatic overage |
| Monthly Price | USD, recurring licensed, unit_amount `500`, interval `month`, interval_count `1`, lookup_key `tunn_pro_monthly_v1` |
| Annual Price | USD, recurring licensed, unit_amount `4800`, interval `year`, interval_count `1`, lookup_key `tunn_pro_yearly_v1` |
| Payment Link, each Price | One line item, quantity `1`, adjustable quantity disabled, no trial/upsell; subscription checkout; after_completion redirect URL `https://tunn.to/account?billing=return` |
| Webhook endpoint | `https://tunn.to/webhooks/stripe`; events `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted` |
| Customer portal | Payment-method management and cancellation at period end; no arbitrary product/price switching; return URL `https://tunn.to/account` |

Collect checkout email. Use Stripe's one-active-subscription restriction if
available, but do not depend on it to bind ownership. Do not change existing
prices or migrate existing subscriptions. Inventory them read-only first.
Choose tax behavior/collection and refund policy with Bryan's existing business
settings; no new jurisdiction or tax registration is inferred here. Public
prices are USD before applicable tax. Save the exact approved Product, Price,
Link and endpoint IDs in the coordinator's private inventory.

Configuration uses returned values, never placeholders:

```text
TUNN_STRIPE_WEBHOOK_SECRET=<environment-specific whsec_ secret>
TUNN_STRIPE_CHECKOUT_URL_MONTHLY=<returned https://buy.stripe.com/... URL>
TUNN_STRIPE_CHECKOUT_URL_YEARLY=<returned https://buy.stripe.com/... URL>
TUNN_STRIPE_PORTAL_URL=<verified https://billing.stripe.com/... login URL, or empty>
TUNN_PRO_MONTHLY_USD=5
TUNN_PRO_YEARLY_USD=48
TUNN_BILLING_ENABLED=false
```

The application accepts HTTPS on those exact Stripe hosts, with a nonempty
path and no port/userinfo/fragment. Existing `TUNN_STRIPE_SECRET_KEY` is not used
by this operator workflow; it does not turn receipts into fulfillment. Transfer
the signing secret through the coordinator's secret manager/Fly secret import,
not shell history or this repository. A generic portal login uses Stripe payer
email, which may differ from the tunn account; test that path or keep the portal
URL empty and retain the displayed support route.

## 5. Reviewed fulfillment and recurring operations

On the authoritative login machine only, provision owner-only admin credentials
using [account operations](docs/ACCOUNT-OPERATIONS.md). Scope the actor to the
reviewed account UUID; token/config permissions 0600, private parent directory.
Never use a publisher token or an unrestricted web administration route.

The first authenticated checkout commits an opaque intent and its exact Payment
Link destination before redirect. Unpaid retries resume that same reference and
destination across tabs/restarts (including a request for a different period).
The dashboard offers Resume checkout. Redirects expire after 24 hours; expiry
never deletes the intent or issues a replacement, because a saved Payment Link
can still be paid. A paid completion immediately blocks further app redirects.
Multiple merged pending intents require support review. The reference remains
an advisory routing hint, not proof of account ownership.

**Payment Link fallback:** this tree does not create provider Checkout Sessions
or use Stripe API idempotency keys. The provider may charge twice if someone
opens the same Payment Link in two tabs. Exactly one subscription consumes an
intent. Further completions commit `duplicate_payment_refund_needed` in both
`ops_checkout_payments` and `ops_billing_events`, return HTTP 200, and cannot bind
or grant Pro, even with a different customer or a later lifecycle receipt.
Exact retries remain idempotent; the original accepted grant stays effective.
Provider completion time is retained separately from receipt delivery time;
on-time payments delivered after local redirect expiry remain reviewable.
Actual late/unknown-time payments use `checkout_expired_review_required` and
can be explicitly approved with audited `payment-review`, then fulfilled using
a fresh reviewed snapshot. Missing/unknown references persist by provider IDs;
additional purchases require an explicit decision. `payment-queue` includes
unbound entries, and `billing-status` includes payment review records. Customer
notices remain visible independently of active Pro. Follow the exact
[round-3 payment and rollback runbook](docs/revenue/round3-fixes.md). Bryan must
review the actual Stripe objects and perform any cancellation/refund himself.
No automatic Stripe mutation occurs. Never clear a hold or sell a replacement
while its prior Payment Link remains payable. Resuming a Payment Link carries
this duplicate-charge risk; true provider Session creation/resume remains a
separate prerequisite for eliminating it. Previously bound Free accounts still
require support; replacement customer bindings are unsupported.

For a paid checkout, the operator performs a fresh read of the Stripe Session,
Customer, Subscription, exact Price and latest invoice, using Stripe dashboard
or restricted read-only API credentials. Verify environment, real account
ownership, subscription/customer linkage, one approved Price at quantity 1,
currency/amount/interval, `status=active`, no paused collection, and a paid
invoice covering the current billing period. Review refunds/disputes separately.
Email and `client_reference_id` from the Payment Link are **advisory**; the
checkout browser can edit them. A signed completion event alone cannot prove
account ownership or confirmed current payment. Do not auto-bind aliases.

Bind only after ownership review. Read the mapping version and queued receipt
IDs, **then perform the fresh provider read** used for the snapshot:

```bash
/app/tunn admin billing-bind --db /data/tunn.db --admin-config /data/ops/admins.json --token-file /data/ops/token --account ACCOUNT_UUID --provider stripe --customer cus_APPROVED --subscription sub_APPROVED
/app/tunn admin billing-status --db /data/tunn.db --admin-config /data/ops/admins.json --token-file /data/ops/token --provider stripe --subscription sub_APPROVED
```

Missing receipts mean wait for/fix webhook delivery; do not synthesize a
production event with the fixture command. Customer and subscription mappings are unique and cannot be rebound by this
workflow. A scoped operator may bind distinct verified customers to the same
account, including purchases whose pending accounts merged before fulfillment.
Checkout blocks previously bound Free accounts and directs them to support.
No automatic replacement-binding workflow is implemented. Verified-email merges
retain every binding: review each subscription independently at its own version.
Pro remains while any binding has verified active, payment-eligible state; the
last revocation/cancellation makes the account Free after any preserved legacy
grant has separately ended.

Store provider evidence privately, hash it with SHA-256, and write an owner-only
snapshot array such as this, replacing **every** placeholder with reviewed
values. `provider_read_at` is the time of the current provider read, not the
event time, and must be no more than five minutes old. The `expected_version`
comes from `billing-status`, not account suspension status. Never refresh only
that version and reuse older evidence. The stored provider-read watermark rejects
older reads even with current CAS; equal-time conflicting state is rejected.
A newer read advances the watermark even when eligibility stays unchanged. There is no backend
approved-price allowlist: **the scoped operator must verify the Price ID**.

```json
[
  {
    "provider": "stripe",
    "customer_id": "cus_APPROVED",
    "subscription_id": "sub_APPROVED",
    "account_id": "ACCOUNT_UUID",
    "expected_version": 0,
    "revision": 0,
    "plan": "pro",
    "event_ids": ["evt_FROM_PENDING_EVENT_IDS"],
    "provider_read_at": "REPLACE_WITH_FRESH_RFC3339_UTC_TIME",
    "evidence_sha256": "REPLACE_WITH_64_HEX_EVIDENCE_DIGEST",
    "price_id": "price_APPROVED_MONTH_OR_YEAR",
    "provider_status": "active",
    "payment_confirmed": true
  }
]
```

Dry run, inspect `change_expected` or `current`, then explicitly commit within
the freshness window. Re-fetch and regenerate evidence if it expires:

```bash
/app/tunn admin reconcile --db /data/tunn.db --admin-config /data/ops/admins.json --token-file /data/ops/token --snapshots /data/ops/review.json
/app/tunn admin reconcile --db /data/tunn.db --admin-config /data/ops/admins.json --token-file /data/ops/token --snapshots /data/ops/review.json --apply-reviewed
/app/tunn admin billing-status --db /data/tunn.db --admin-config /data/ops/admins.json --token-file /data/ops/token --provider stripe --subscription sub_APPROVED
```

Require `applied`/`current`; any `version_conflict`, `stale` or
`reconciliation_required` is a stop and fresh review. Batches are atomic.
The audit records actor and a digest of the snapshot/evidence digest; retain
original evidence securely outside the repo. Do not use `--apply-fixture` on
production. Billing never resumes an operationally suspended account.

The return page polls committed account state for about one minute and then
offers refresh/support. It neither grants Pro from URL parameters nor promises
instant activation. Confirm a fresh authenticated `/api/billing/status` is
`active`, account shows Pro and new admissions use Pro allowances. Already
admitted transports keep their original allowance; reconnect when testing.

For renewals and queued events, read the provider again. Active plus confirmed
current-period payment stays Pro even if `cancel_at_period_end=true`. At actual
cancellation/delinquency use a fresh snapshot with `plan=free`, current version,
matching receipts, and `provider_status` one of `canceled`, `unpaid`, `past_due`,
`incomplete`, `incomplete_expired`, `paused`, or `trialing`. No grace period is
implemented by this workflow. A refund/dispute while status stays active requires
an explicit operator review: use fresh evidence with `provider_status=active`,
`payment_confirmed=false`, and `plan=free` when that review revokes payment
eligibility. A refund receipt alone does not revoke entitlement. Pro is derived
only from active status plus confirmed current payment; a conflicting `plan`
is rejected. The last eligible subscription ending, with no preserved legacy grant, releases paid name
reservations in the same transaction. Existing online Free tunnels retain their
ordinary live occupancy; offline names become available to other accounts.
Decline trialing/unreviewed/unpaid activation. Receipt order never wins over a
fresh current provider read. Legacy Pro accounts from `110485c` keep their plan
and reservation ownership through schema installation, startup, ordinary billing
review and verified identity merges. Operator grants, direct SQL grants, paid
manual fulfillment, sequenced providers and historical fixture grants are all
preserved; they are not relabeled as verified Stripe subscriptions. Older
hash-only reviews still impose a conservative provider-read ordering floor.

Entitlement cutover is a **separate global operator action**, never startup or
`admin migrate --account`. Inventory every row in `ops_legacy_entitlements` and
its current reservation ownership, review legitimate paid and comp grants, and
retain legitimate grants as `pro`. Review/import current paid subscriptions
before ending their legacy grant. With a global credential (`accounts:["*"]`),
Bryan can run this prepared command after reviewing the exact decisions:

```bash
/app/tunn admin reconcile-legacy --db /data/tunn.db --admin-config /data/ops/global-admins.json --token-file /data/ops/global-token --snapshots /data/ops/legacy-decisions.json
```

Each JSON decision has `original_account_id`, the current canonical `account_id`,
`expected_version`, `plan` (`pro` or `free`), and a nonempty single-line `reason`.
Read versions from `ops_legacy_entitlements`; preserve original UUIDs after
merges. The whole batch commits atomically, auditing previous/new plan, actor,
reason and version in `ops_legacy_entitlement_audit`. Account-scoped credentials
are rejected. Reservations are released only if that explicit decision ends the
last legacy or verified entitlement. Keeping a comp grant Pro needs no Stripe
objects. Never copy disposable fixture markers to a live database; the store
rejects every non-Stripe receipt adapter on an unmarked database.

Operator audits active subscriptions daily and
around each billing boundary; invoice events are not a replacement adapter in
this release. Review unresolved receipt metadata read-only using existing
approved DB tooling; `billing-status` only lists receipts for a known binding.
No queue dashboard or background reconciler is supplied.

## 6. Sandbox gate, enable live checkout, then approved distribution

In the approved sandbox enable its checkout temporarily and prove monthly and
annual completion -> pending -> reviewed activation -> higher new-admission
allowance; signature rejection, duplicate/reordered receipts, abandoned
checkout, wrong account reference, approved-price mismatch, CAS conflict,
subscription failure and actual cancellation -> reviewed Free. Repeat portal
cancel-at-period-end and confirm paid entitlement persists until expiration.
Do not use production payments to discover integration errors.

After Bryan approves the sandbox evidence and staffed queue, create the
approved live objects, set live config/secrets and enable checkout. Roll out
`TUNN_BILLING_ENABLED=true` in the reviewed config via the same immutable-image
deploy command. Its default is false; both links and webhook signing secret
must be valid. Confirm actual checkout price equals displayed price and no
test-mode Link or secret is live. Recheck operator tools against the live DB
without making an unauthorized test payment or account.

Publish only approved assets in DISTRIBUTION.md after hosted-client and billing
gates. Check current Reddit weekly-thread permission, directory eligibility,
source/license, release artifacts and live tutorial URLs. Record submitted
URLs, not invented placement claims. Track actual collected subscription revenue
and reviewed activations; visits and return-page hits are not revenue.

## Rollback

Stop acquisition/posts and new sales first: redeploy the reviewed current image
with `TUNN_BILLING_ENABLED=false`; separately deactivate the two Payment Links
in Stripe after approval. Disabling the app flag cannot disable a Stripe link
someone already has. Keep receipt delivery and queue review running.

If code rollback is required, set the recorded prior image and config:

```bash
fly deploy --app tunn --config fly.revenue.rollback.toml --image "$TUNN_PREVIOUS_IMAGE" --update-only --ha=false --strategy rolling
```

Confirm the old release's sales route cannot resume charging: remove checkout
URLs from the approved rollback environment or keep Stripe links deactivated;
the old binary does not understand the new disable flag. Preserve SQLite and
billing audits, compatibility triggers and the legacy entitlement snapshot.
Use the [round-3 rollback contract](docs/revenue/round3-fixes.md#rollback-runbook):
110485c serving rollback is supported only in the no-sales stage after installing
that compatibility schema. Old-code revocations/merges are journaled; positive
cache writes require a global reviewed grant decision on re-upgrade. Existing
4416eff rollback history requires the documented bootstrap/inventory review.
Once payable Links exist, keep a modern receipt/review authority. There is no
destructive schema rollback to perform.
An explicit legacy cutover changes data: restoring a Pro grant with a fresh
versioned decision does not recreate released reservations. Keep their ownership
inventory before cutover; Bryan must check current name conflicts before repair.
Restoring
the pre-launch DB would erase subsequent account/payment history and is only
an approved disaster recovery action after preserving the current consistent
backup and reconciling every later payment. Do not blanket downgrade paid users,
cancel subscriptions or refund without Bryan's explicit decision. An image
rollback does not unwind Stripe objects or revenue obligations. Verify login,
existing tunnel ingress, OAuth, quotas and webhook receipt ingestion afterward.

## Primary references

Fetched **2026-10-11**: [Stripe subscription reads](https://docs.stripe.com/api/subscriptions/retrieve),
[Payment Link configuration](https://docs.stripe.com/payment-links/customize),
[after-payment redirect](https://docs.stripe.com/payment-links/post-payment),
[Fly deploy flags](https://docs.fly.io/flyctl/cmd/fly_deploy),
[Fly selected-machine console](https://docs.fly.io/flyctl/cmd/fly_ssh_console).
Pricing/economics sources and assumptions are in PRICING.md; directory sources
and eligibility are in DISTRIBUTION.md. Recheck provider dashboards at launch.
