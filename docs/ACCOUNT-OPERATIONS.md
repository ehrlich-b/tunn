# Account operations and local payment reconciliation

Account controls are operational state, separate from `accounts.plan` and the
metering ledger. Default state is `active`, version 0. An authenticated operator
can move `active -> suspended` and `suspended -> active` (resume). Every transition
requires the reviewed current version, a 1–256 byte single-line reason, and a
configured admin principal. The durable audit records the actor, reason, UTC
RFC3339 timestamp, previous/new states and next version. Same-state requests and
stale versions fail. Payment processing never modifies operational state.

The administration surface is the local `tunn admin` CLI. It requires an explicit
existing SQLite path, an operator-owned administration configuration, and a
separate token file. Both credential files must be regular owner-only files.
Configuration supplies the authenticated actor and allowed account UUIDs; `*`
means all accounts. Account aliases require authorization for both the supplied
and surviving UUID. Publisher, visitor, endpoint, grant and payment credentials
are not administrator credentials. There is no HTTP administration endpoint.
Local filesystem/database access remains an operator privilege.

## Existing paths and admission contract

| Path | Ownership/authentication | Suspension behavior |
| --- | --- | --- |
| Hosted gRPC publisher, HTTP/Unix HTTP/MCP, WS and TCP publisher | JWT email resolved by account storage; client account IDs confer no authority | Registration denies suspended/unavailable state; login-node registration checks again |
| Configured per-user publisher tokens | Server-owned token email resolved/created in account storage | Registration observes the same account suspension; claimed creator email is ignored |
| Persistent host manifest / host publisher | JWT or configured self-host token -> verified local account | New manifests and publishers denied; inventory remains readable |
| Public HTTP, cookie/JWT HTTP, endpoint capability, grant HTTP, MCP, WS, CONNECT and Unix ingress | Current publisher UUID resolved through storage on each request | Suspended owner returns 403 `account_suspended` before forwarding; unavailable state returns 503 |
| Grant creation | Owner bearer -> verified account and live endpoint ownership | Denied at management API and inside ledger transaction |
| Ledger admission/retry and byte charge | Server-supplied owner; canonical merged UUID | Suspended state denies admission/replay and charge; existing accounting remains |
| Pro name reservation / host registry | Authenticated caller -> account UUID | New reservations denied; names/usage remain owned |
| Account dashboard, usage/grant reads and revoke, authenticated report intake | Existing account credentials | Retained for visibility, remediation and reporting |
| Explicit anonymous public mode / shared self-host master secret without host mode | Operator chooses accountless relay authentication | No account to suspend; these are unsuitable for hosted account controls |

`FindOrCreateByEmails` derives the merged plan from verified subscriptions and preserved legacy grants,
adds usage, preserves grant
state and redirects old UUIDs. Operational merge uses suspension OR: any suspended
component suspends the survivor and increments its control version. Previous
reasons/actors and original account UUIDs remain in audit history; the merge itself records a system actor.
Billing mappings and event metadata follow the survivor. Each surviving subscription can be reconciled independently; the newest
verified state of every subscription contributes to the account entitlement.

## Billing events and snapshots

`ops_billing_mappings` binds provider customer/subscription identifiers to an
existing account under admin authorization. Conflicting account/customer or
subscription mappings fail. An account may own several distinct customer and
subscription bindings; provider/customer and provider/subscription identity
remain unique. The adapter never establishes ownership from a
webhook email or client-supplied metadata. A supported unbound event remains `reconciliation_required` and cannot create
an account. An issued opaque checkout intent may associate its receipt with an
account for review; arbitrary account UUIDs in editable references are ignored.
A pending purchase alone never grants Pro.

`ops_billing_events` atomically commits a metadata digest and processing result
with any entitlement change. The durable key is `(provider,event_id)`; exact
retries return the original result with `duplicate:true`. Reusing an ID with
changed metadata fails. Storage failures roll back both plan and event state.
Synthetic adapters with monotonic revisions are accepted only on databases
marked `ops_fixture(id=1,value='disposable-local')`; unmarked databases reject
every non-Stripe receipt at the store boundary, including authenticated node
RPC intake. Marked fixtures converge under older, newer and duplicate deliveries. Equal revision/conflicting plan, conflicting
bindings and unorderable events require reconciliation. Unknown types are
recorded `ignored`; they do not modify entitlements. No webhook body is stored.

Stripe `created` and event IDs are not an authoritative subscription revision.
Checkout completion alone is not payment/entitlement proof. Signed intake still
validates signatures and a 64 KiB bound. Non-login nodes forward only normalized
metadata through the authenticated internal `LoginNodeDB.ProcessBillingEvent`
RPC. The database authority performs automatic fulfillment when both
`TUNN_STRIPE_SECRET_KEY` and `TUNN_STRIPE_PRO_PRICE_IDS` are configured. The latter
is a comma-separated allowlist of explicitly approved Stripe Price IDs; an empty
allowlist disables automation. Configure it on the login authority before
serving intake. No price IDs are inferred from checkout links or webhook data.

For checkout completion, subscription creation/update/deletion and paid invoice
notifications, the authority reads the current subscription from Stripe with
API version `2024-06-20`, expanding its latest invoice and charge. Pro requires
one approved subscription item, active status, a current billing period, and a
paid nonzero invoice whose subscription, customer, Price and line period match.
The matching charge must be paid, without any refund or dispute. Manual
out-of-band invoices, incomplete or ambiguous evidence, unknown prices and
provider-read failures leave the durable receipt in `reconciliation_required`.
A server-issued on-time consumed checkout intent can bind its first payment
automatically; existing explicit bindings also qualify. Unknown completion times,
unbound lifecycle events, expired purchases and quarantined duplicates cannot
automatically grant Pro. On-time completions delivered late remain eligible.

Cancellation scheduled for period end retains the paid active period; the
current canceled subscription read ends that subscription's entitlement. Refund
and dispute notifications resolve charge -> invoice -> subscription using Stripe
reads. A refund or dispute on the current paid charge ends its entitlement
immediately; older-period or unassociated charges remain for operator handling.
Replayed receipts do not grant again. Fresh unchanged-state receipts advance the
provider-read watermark without another activation audit or CAS increment.
Each entitlement change, receipt resolution and account projection commits
atomically with a `system:stripe` audit. CAS and provider-read ordering still
protect operator work. Automation never clears operational suspension, legacy
grants or another eligible subscription. No provider writes are performed.
The scoped operator paths below remain available for anomalies. `ops_billing_states` persists the newest verified state per binding,
ordered by authoritative provider revision or the time of the verified current
provider read. Arrival order and refreshed local CAS cannot override its
watermark. Equal-order conflicting state fails; equal-state replay does not
advance versions or append audits. Newer unchanged-state reads still advance
the watermark. The account plan is a projection of these states: any eligible
subscription or preserved legacy grant confers Pro. With neither, the account is Free. Final downgrade
releases paid reservations atomically with billing state, receipt resolution,
plan and audit. Operational suspension remains independent.

`tunn admin reconcile --snapshots FILE` opens the explicit database read-only and
returns `current`, `change_expected`, `stale`, `version_conflict`, or
`reconciliation_required`. A snapshot contains `provider`, `customer_id`,
`subscription_id`, `account_id`, `expected_version`, `revision`, and `plan`.
An optional bounded `event_ids` list identifies the exact pending events reviewed
against that snapshot. Applying records the operator actor and reconciliation ID,
and resolves only those events; unreviewed events remain pending. Versions belong
to the local billing mapping. Revision 0 is a supplied snapshot
for a provider such as Stripe without ordered events; revision >0 belongs only
to a provider with authoritative revisions. Only `free` and `pro` are supported;
sales configuration and quota display are described in PRICING.md.

`tunn admin billing-status --provider stripe --subscription ID` is a scoped,
read-only view of the billing mapping's current version/plan and up to 100
pending receipt IDs. `--apply-reviewed` is the separate production-capable
operator path: it requires Stripe revision 0, matching receipts, a SHA-256
evidence digest, a provider read no more than five minutes old, and an explicitly
reviewed Price ID. Pro requires `provider_status=active` and
`payment_confirmed=true`; all other reviewed eligibility derives Free. An
explicit refund/dispute revocation can use `provider_status=active` with
`payment_confirmed=false`. Refund webhooks alone do not make that decision.
This operator path accepts supplied evidence separately from automatic
retrieval: the scoped operator must verify actual ownership, an approved Price
and current-period payment. Both apply modes are mutually exclusive; default is
still read-only. CAS, complete-batch validation, audit, suspension and usage
preservation apply to reviewed writes as well. Review current provider ownership, payment and subscription state before
activation, renewal or cancellation. Checkout defaults disabled until fulfillment has passed acceptance and anomaly
handling is staffed. `PrepareBillingCheckout` persists a random intent and exact destination
before redirect. Unpaid retries resume that same reference/destination across
tabs and restarts, with a 24-hour redirect window. Paid completions and multiple
merged intents block redirects. Expiry retains the hold and never creates a
replacement while a saved Payment Link remains payable. The store consumes one
subscription per intent and durably quarantines additional payments as
`duplicate_payment_refund_needed`; binding and Pro review reject those
subscriptions even if later receipts are selected. The signed provider completion time is independent of webhook delivery:
on-time payments delivered late remain fulfillable. Actual late or unknown-time
completions use `checkout_expired_review_required`, with a versioned audited
`payment-review` approval path. `payment-queue` includes unbound missing-reference
and duplicate completions; active Pro does not hide customer billing notices.
Require scoped ownership review, explicit additional-purchase decisions, and
recorded refund/cancellation closure. Receipts are acknowledged only after the
payment ledger and receipt commit together. This fallback prevents duplicate
fulfillment, not duplicate provider charges: the tree has no Stripe Session API
integration. The operator must review and perform any required provider refund or
cancellation. Existing bound accounts cannot buy another subscription; support
must resolve the prior purchase. A canceled binding blocks returning self-service checkout because
replacement binding is not yet supported.

`--apply-fixture` requires a database created by `tunn admin fixture-init`, carrying
`ops_fixture(id=1,value='disposable-local')`. It validates the complete bounded
snapshot batch before atomically applying, audits the application, and preserves
suspension and usage. It performs no provider write, invoice/refund/cancellation,
mail or subscription operation. Fixture apply on a production database is prohibited.
Do not copy fixture markers to a live database.

## Intake and mail

`POST /api/reports` requires an account bearer credential and derives the reporter
account from that credential. It accepts only `category` (`abuse`, `billing`,
`availability`) and a DNS-label `endpoint`; unknown fields are rejected. Intake
is capped at 1 KiB, five reports/account/hour and 10,000 stored reports. Stored
metadata has no request body, attachment, raw URL or narrative. Responses are
`received -> triaged -> action_taken -> closed`, or `triaged -> closed`, with
version checks and a configured operator actor. These states record decisions;
no state sends mail, suspends a user, or contacts anyone automatically.

Magic-link request parsing is capped at 4 KiB and rejects additional fields,
invalid addresses and header injection. The existing login-node per-email
limiter normalizes addresses, caps keys at 4,096 and expires inactive keys.
Limiter/storage errors fail closed. Mail requests also use the bounded five per
five-minute signup limiter with the directly connected peer IP. Fake-clock and
mail-sink tests run without sending mail. These limits are local-process windows;
per-email enforcement spans replicas through the existing login-node RPC but
does not survive a login-node restart. A durable fleet-wide IP policy is separate
work.

## Migration and integration hooks

`store.MigrateOperations` installs additive, idempotent schema after the existing
account schema. It changes zero account plans and deletes zero reservations.
On first installation it snapshots existing Pro accounts without verified states
into `ops_legacy_entitlements`. Every kind of legacy grant from `110485c` keeps
Pro and effective reservation ownership until explicit global reconciliation;
ordinary billing review, startup and scoped schema migration cannot revoke it.
Restarts never re-import revoked grants. Identity merges retain each original
grant UUID and move its ownership to the survivor.

`tunn admin reconcile-legacy --snapshots FILE` requires a global credential
(`accounts:["*"]`). Each decision supplies `original_account_id`, current
`account_id`, `expected_version`, `plan`, and `reason`. The bounded batch is
validated and applied atomically with a durable actor/reason/version/plan audit
in `ops_legacy_entitlement_audit`. Legitimate comp grants can stay Pro without
Stripe. Review paid states before explicitly ending the legacy grant; only the
last effective entitlement ending releases reservations. Save a reservation
inventory before cutover: regranting Pro does not recreate released names.
Schema-only rollback retains the old plan and reservation tables untouched.
`admin migrate --account` authorizes the supplied and surviving UUIDs
and installs schema only; it has no account entitlement side effects.

Legacy hash-only review times provide a conservative provider-read ordering
floor, so older evidence cannot undo a prior cancellation. Direct `UpdatePlan`
grants are restricted to marked disposable fixtures. Account merges call
`mergeAccountOperations` in the same inventory/accounting transaction.

Account replies include `operational_state` (field 7), `operational_version`
(field 8), and `billing_state` (field 9) in `proto/internal.proto`. The new
`BeginBillingCheckout` RPC uses the existing authenticated internal node gate
and returns a reference plus persisted destination only after durable authority
commit. Replica decoding preserves legacy Pro replies from old authorities and
explicit `legacy` state during the rolling schema upgrade. `storage.AccountStatusLookup` is implemented by local
and proxy storage; it resolves aliases and returns status/version without trusting
a request account ID. Empty state from an old login authority fails closed at
hosted admission. Upgrade the login authority before replicas. The new billing
and report RPCs inherit the internal node authentication gate. An empty node
secret now rejects all internal RPCs instead of accepting an empty header.

`ProxyServer.watchAccountRequest` observes admitted account requests once/second,
with a five-second lookup deadline. A control version change also cancels the existing request, so a rapid suspend/
resume cannot preserve a prior stream. Suspension or lookup failure cancels the
request, closes its body and calls `TunnelConnection.CloseAccountStreams`, which
reuses `closePendingConnections` for HTTP streaming/WS/CONNECT. Buffered HTTP exits
through its existing request context. Existing publishers can serve new requests
after a correct resume. No quota counter or active-byte-cutoff implementation is
added here.
