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

`FindOrCreateByEmails` retains the strongest plan and adds usage, preserves grant
state and redirects old UUIDs. Operational merge uses suspension OR: any suspended
component suspends the survivor and increments its control version. Previous
reasons/actors and original account UUIDs remain in audit history; the merge itself records a system actor.
Billing mappings and event metadata follow the survivor. Multiple surviving
subscription mappings require explicit reconciliation rather than choosing one.

## Billing events and snapshots

`ops_billing_mappings` binds provider customer/subscription identifiers to an
existing account under admin authorization. Conflicting account/customer or
subscription mappings fail. The adapter never establishes ownership from a
webhook email or client-supplied metadata. A supported unbound event remains
`reconciliation_required` and cannot create an account.

`ops_billing_events` atomically commits a metadata digest and processing result
with any entitlement change. The durable key is `(provider,event_id)`; exact
retries return the original result with `duplicate:true`. Reusing an ID with
changed metadata fails. Storage failures roll back both plan and event state.
Provider adapters with authoritative monotonic revisions converge under older,
newer and duplicate deliveries. Equal revision/conflicting plan, conflicting
bindings and unorderable events require reconciliation. Unknown types are
recorded `ignored`; they do not modify entitlements. No webhook body is stored.

Stripe `created` and event IDs are not an authoritative subscription revision.
Checkout completion is not payment/entitlement proof. The Stripe adapter therefore
records lifecycle events as `reconciliation_required`; it never fetches Stripe
customer data, upgrades by email, or changes a plan based on arrival order.
Configured signed webhook intake still validates signatures and a 64 KiB bound.
Non-login nodes forward only normalized metadata through the authenticated
internal `LoginNodeDB.ProcessBillingEvent` RPC. Do not infer automatic Stripe paid
pilot readiness from passing local provider fixtures. An operator must supply
current authoritative snapshots; automatic snapshot retrieval is outside this
change.

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
prices, quotas and checkout links are unchanged.

`--apply-fixture` requires a database created by `tunn admin fixture-init`, carrying
`ops_fixture(id=1,value='disposable-local')`. It validates the complete bounded
snapshot batch before atomically applying, audits the application, and preserves
suspension and usage. It performs no provider write, invoice/refund/cancellation,
mail or subscription operation. Applying to a production database is prohibited.
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

`store.MigrateOperations` runs the idempotent `OperationsSchema` from
`internal/store/operations.go`, automatically called after the existing account
schema. Additions are isolated `ops_account_state`, `ops_account_audit`,
`ops_billing_mappings`, `ops_billing_events`, and `ops_reports`. They do not alter
account/quota/domain columns or replace existing migrations. Account merges call
`mergeAccountOperations` in the same inventory/accounting transaction. Migration
rerun and rollback fixtures retain all state.

Account replies add `operational_state` (field 7) and `operational_version` (field
8) in `proto/internal.proto`. `storage.AccountStatusLookup` is implemented by local
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

**RELEASE BLOCKER: combined-head active-stream and restart acceptance.** Local
pipe fixtures establish active HTTP/SSE, upgraded WS and CONNECT termination,
unaffected B traffic, restart denial, merge preservation and resumed grants. They
do not certify the domains lane's combined HTTP/WS/
CONNECT behavior, active byte cutoff, restart persistence or multi-node failure
handling. The coordinator must retain H3/M6 and run the combined acceptance case:
open idle and transferring HTTP/SSE, established WS, and authenticated CONNECT for
two accounts; suspend A; require every A stream and pending admission to terminate
within six seconds while B continues; change A's plan and merge an active account
into A without clearing suspension; restart login/ingress; require A's old JWT,
endpoint token and grants plus publisher reconnect to remain denied; resume with
the current version; require new A traffic to work with pre-suspension usage and
grant budgets intact. Repeat across login and replica ingress, then replay H3/M6.

The existing `test-account-operations` target supplies local fixtures only.
The combined-head gate is `TUNN_DOMAINS_HEAD=<pinned-integrated-domains-commit>
make -j1 test-account-operations-combined`. It requires Git ancestry of the supplied
domains pin and runs the lifecycle fixture plus account and metering contracts.
This gate is REQUIRED/UNRUN until the domains branch is integrated and the target
runs on that exact combined head. Retain the domains lane's H3/M6 and domain/ACME
acceptance targets in addition to this gate. Also rerun `make -j1 build vet
test-metering-contract`, `make -j1 test`, `make -j1 test-race`,
`make -j1 test-account-operations` and `git diff --check` on the combined head.
No real-host, production billing or deployed-service evidence is asserted.

The installed Homebrew `protoc` could not load
`libabsl_die_if_null.2601.0.0.dylib`. Checked-in protobuf files were produced offline
by the installed Go generators from the existing descriptor plus the additive
fields/messages/methods. After repairing that external toolchain, the coordinator
should regenerate with `make -j1 proto-internal` and review source/generated
consistency. No dependency was downloaded or installed here.
