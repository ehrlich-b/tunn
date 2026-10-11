# Round 3 fixes and deploy/rollback contract — 2026-10-11

This release addresses all four findings against `4416eff`. The no-Stripe
rollout remains the first stage; paid checkout still needs real provider
acceptance and a staffed review/refund queue. All verification here uses
synthetic local data. No push, deployment, provider operation or message was
performed. Bryan alone executes any prepared production commands below.

| Finding | Result |
| --- | --- |
| Rollback compatibility | Database triggers journal old-code revocations and grant requests and move new ownership records during old-code merges, with FK enforcement both on and off. Re-upgrade cannot restore a journaled revoked grant from the old plan cache. |
| Edited reference bypass | Every subscription checkout completion persists by provider Subscription and Session IDs, even without a recognized reference. An additional purchase requires a separate explicit decision; lifecycle receipts cannot bypass quarantine. |
| Delayed delivery | Retain the signed Event creation time and Session ID. Redirect expiry never invalidates a real payment. On-time completions delivered late remain eligible for ordinary reviewed fulfillment; actual late or timestamp-less completions have a scoped, audited review path. |
| Silent duplicate | Account pages and status responses expose an unresolved notice independently of Pro. Operator status includes unbound payments; `payment-queue` is a paginated queue. Recorded cancellation/refund closes the notice without disturbing valid Pro. |

Stripe's [Event object](https://docs.stripe.com/api/events/object) supplies the
creation timestamp; the application's delivery time is separate. An Event
creation time is routing evidence, never a subscription revision or proof of
current eligibility. [Webhook retries](https://docs.stripe.com/webhooks#automatic-retries)
can outlast the redirect window. [Payment Link references](https://docs.stripe.com/payment-links/url-parameters)
are editable and can be discarded; they confer no ownership or entitlement.
The operator still verifies the current Session, payment, Subscription, Customer,
Price, billing period and actual account ownership using provider reads.

## Rollback data contract

Install this release on the authoritative DB **before** a serving rollback to
`110485c`. Keep the additive tables, indexes and triggers through rollback.
The new reducer marks its cache writes transactionally using
`ops_projection_guard`; those writes cannot revoke unrelated legacy grants.
Old-code `UpdatePlan(...,"free")`, including a repeated Free write, instead
journals the revocation, ends the account's legacy grants with versions and
immutable audits, and holds its existing verified subscriptions. Holds attach
to Subscription IDs, so a merge cannot revive them or cancel another identity's
valid subscription. Old-code verified merges move legacy grants, intents,
payment ownership and revocation records before the old account is deleted.
The same database then reopens under this release with no orphan legacy grants.
Release startup projects only accounts named in the rollback journal before
serving, so metering/domain plan caches also respect revocation and pending
grant review. Initial deployment with an empty journal preserves all old rows.
Scoped migration does not project other accounts.

An old/direct Pro write records a `grant-request` and creates a Free placeholder
legacy grant if necessary. It never automatically grants Pro under the new
release. Bryan verifies that request and, if appropriate, uses the existing
global `reconcile-legacy` operation with a reason and current grant version.
A global Pro decision regrants only the named legacy entitlement. It cannot
release a held subscription or restore stale provider evidence; scoped billing
review cannot release holds either. This old-image contract is for the no-sales
stage, not a way to resume billing after paid subscriptions exist. A subsequent old Free write wins again.
The original grant ID survives merges. Never drop the journal, suppress its
triggers, copy a fixture marker into this DB, or import Pro from the cache.

For an existing `4416eff` DB that already underwent FK-off rollback writes,
the first compatibility migration recovers ownership from recorded flattened
`account_merges` aliases and conservatively records a revocation when a Free
cache disagrees with preserved Pro. It audits that recovery and ends those
legacy grants, rather than repeatedly treating the cache as authority. Scoped
`admin migrate` cannot authorize this global bootstrap. Ordinary release startup
owns that transactional migration; unresolved orphan grants fail startup.
This cannot reconstruct an unrecorded revoke/regrant history whose final cache
matches the snapshot. Bryan must compare the saved rollback case/inventory and
apply global decisions for that history before serving the re-upgrade.
Subsequent rollbacks from this release have the durable journal and do not
have that ambiguity. No startup imports a positive old-code cache change.

Legacy cutover and explicit revocation can release name eligibility. Code
rollback does not recreate previously released names: retain the saved owner
inventory and check conflicts before any separate repair. Do not restore an old
DB over subsequent identity, usage, payment or audit history.

## Operator payment queue and decisions

Use the authoritative local DB with owner-only credentials from
[account operations](../ACCOUNT-OPERATIONS.md). Global readers see unowned
payments; scoped readers see only their known accounts. The queue has 100 rows
per page, ordered by provider/subscription; continue with the last returned
`provider/subscription` as `--after`. These examples are prepared for Bryan.

```sh
/app/tunn admin payment-queue --db /data/tunn.db --admin-config /data/ops/admins.json --token-file /data/ops/token
/app/tunn admin payment-queue --db /data/tunn.db --admin-config /data/ops/admins.json --token-file /data/ops/token --after stripe/sub_LAST
/app/tunn admin billing-status --db /data/tunn.db --admin-config /data/ops/admins.json --token-file /data/ops/token --provider stripe --subscription sub_REVIEW
```

A binding attempt for an unowned completion records the scoped ownership claim
and any duplicate classification, **then returns an error without binding**.
Use the queue's updated version in the explicit decision; do not retry binding
to bypass review. A first unowned payment can also be reviewed directly.
The original event and provider IDs remain retained. An unknown reference is
never discarded merely because it cannot identify a customer locally.

After verifying the provider objects and payment, save one decision in a private
file; substitute real reviewed IDs, the returned version, a fresh provider-read
time (within five minutes), and the SHA-256 of privately retained evidence:

```json
{
  "provider": "stripe",
  "subscription_id": "sub_REVIEW",
  "customer_id": "cus_REVIEW",
  "session_id": "cs_REVIEW",
  "event_id": "evt_REVIEW",
  "account_id": "ACCOUNT_UUID",
  "expected_version": 0,
  "action": "approve",
  "reason": "Verified first paid purchase and account ownership",
  "provider_read_at": "REPLACE_WITH_FRESH_RFC3339_TIME",
  "evidence_sha256": "REPLACE_WITH_EVIDENCE_SHA256",
  "allow_additional": false,
  "reassign_ownership": false
}
```

```sh
/app/tunn admin payment-review --db /data/tunn.db --admin-config /data/ops/admins.json --token-file /data/ops/token --snapshots /data/ops/payment-decision.json
```

Approval records the full reasoned decision, actor, evidence and CAS version.
It unlocks binding and a **new** reviewed billing snapshot; it cannot expose an
older verified Pro state. Bind, read `billing-status`, and use the fresh
`reconcile --apply-reviewed` procedure in [GO-LIVE.md](../../GO-LIVE.md).
The snapshot must not predate the payment approval evidence. An actual late
purchase with no conflict is fulfillable through this procedure; expiry never
clears its intent or sells a replacement. For an intentionally retained
additional purchase, set `allow_additional:true` and explain why both purchases
are legitimate, including any account merge. Existing distinct subscriptions
established before a verified identity merge retain their ordinary lifecycle
review path. A conflicting same-Customer replacement binding remains unsupported;
approval rejects it and retains the queue item for ownership repair or refund.

An edited recognized reference can point at the wrong account. Reassignment
requires `reassign_ownership:true`, a reason, and authorization for **both** the
previously hinted owner and the reviewed owner. It preserves the original
reference as evidence. Session/Customer/Subscription/Event IDs cannot be edited
by the review. Historical payments predating Session-ID retention have an empty
`session_id`; preserve that stored value and verify the actual provider Session
in the private evidence rather than inventing a stored ID.

For a redundant purchase, Bryan reads both purchases and their actual invoices,
charges, refunds and current subscriptions. He cancels the redundant subscription
immediately to prevent another renewal, refunds the correct charge once, and
verifies both actions using the provider. Preserve the accepted subscription.
Follow [Stripe cancellation](https://docs.stripe.com/billing/subscriptions/cancel)
and [Payment Link refunds](https://docs.stripe.com/payment-links/post-payment#refund-payment-links).
Then submit the same decision shape with `action:"refunded"`, the current version,
`refund_id` and `cancellation_id` from that verified provider evidence. The latter
is the canceled Subscription ID or the corresponding provider audit identifier.
The local operation performs no provider mutation. It closes the queue/customer
notice, leaves immutable payment intake/audit evidence, and keeps the redundant
subscription ineligible even if a later lifecycle receipt arrives. Never erase
rows to close a case. Customer correspondence requires Bryan's approval of its
exact text and destination before sending.

Before enabling sales, assign a queue owner and response target. Check every
page as receipts arrive and in the daily/billing-boundary audit. Also inspect
unresolved lifecycle receipts and multiple verified subscriptions; some merged
purchases are legitimate. `billing-status` is a per-account aid; the complete
payment queue requires pagination, including unbound entries.

## Deployment runbook — no Stripe objects

1. Record approved immutable release/rollback image digests, the actual machine
   roles and sole authoritative volume/writer, DB path and current configuration.
   Preserve JWT/OAuth/TLS/SSH keys, routing, flags, caps and volumes. Set
   `TUNN_BILLING_ENABLED=false`; empty both checkout URLs, portal URL, Stripe key
   and webhook secret on every replica and on the prepared old-image rollback
   configuration. An old binary does not understand the disable flag.
2. Bryan takes a consistent current backup and an off-machine encrypted copy.
   The following assumes the inventoried DB is `/data/tunn.db` and the chosen
   backup filename is unused:

   ```sh
   umask 077
   test ! -e /data/tunn-round3-before.db
   sqlite3 -readonly /data/tunn.db '.backup /data/tunn-round3-before.db'
   sqlite3 -readonly /data/tunn-round3-before.db 'PRAGMA integrity_check;'
   sha256sum /data/tunn-round3-before.db
   sqlite3 -readonly -csv /data/tunn-round3-before.db 'SELECT id,primary_email,plan FROM accounts ORDER BY id;' > /data/round3-before-plans.csv
   sqlite3 -readonly -csv /data/tunn-round3-before.db 'SELECT subdomain,account_id,created_at FROM reserved_subdomains ORDER BY subdomain;' > /data/round3-before-names.csv
   ```

   Require integrity `ok`, no disposable marker, and an inventory of aliases,
   suspension, usage, endpoints and operator grants. Rehearse on a copy:
   startup, restart, old-code merge/revoke/grant-request, and re-upgrade. Compare
   all old rows exactly before new activity; check both integrity and foreign
   keys. Review any pre-journal rollback history as described above.
3. Build and verify the immutable image with the existing release workflow.
   Upgrade the authority before exposing new checkout on replicas, preserving
   the volume and writer count. Bryan runs the prepared deployment:

   ```sh
   fly deploy --app tunn --config fly.revenue.toml --image "$TUNN_REVENUE_IMAGE" --update-only --ha=false --strategy rolling
   ```

4. Require healthy authority/routing, no SQLite/schema/FK errors, preserved
   plans/names/usage/suspension, and working login, OAuth, device flow and tunnel
   reconnect/ingress. Free/Pro account pages and `/pricing` must work without
   buy destinations; anonymous `/upgrade` redirects to login, authenticated Free
   `/upgrade` returns 503 without Stripe redirects. Require zero new intents,
   payments or quarantine rows during this no-objects phase. Audit legacy grants
   against the saved inventory and inspect the journal and grant-request rows.
   Read-only `PRAGMA integrity_check` must be `ok`; `PRAGMA foreign_key_check`
   must be empty. Stop rollout on unexpected entitlement/name loss, orphans,
   authority outage or Stripe redirects. Restart only in the rehearsal to test
   durability; verify ordinary client reconnects after production rollout.
5. Paid checkout is a later approval gate: real Stripe sandbox lifecycle,
   missing/edited references, delayed delivery, duplicate cancellation/refund,
   portal cancellation, replay/CAS checks and a staffed queue must pass first.
   This release still uses reusable Payment Links and cannot prevent duplicate
   provider charges. Do not use a production payment as an integration test.

## Rollback runbook

Keep the no-objects configuration above and take a backup of the **current** DB.
A rollback to unmodified `110485c` is supported for this no-sales stage only
when this release's compatibility schema/triggers are installed and retained.
Bryan restores the recorded digest/config, preserving the authoritative volume:

```sh
fly deploy --app tunn --config fly.revenue.rollback.toml --image "$TUNN_COMPATIBLE_ROLLBACK_IMAGE" --update-only --ha=false --strategy rolling
```

Do not restore the pre-deploy DB or drop additive tables/triggers. Verify login,
OAuth, existing tunnels, quota/name ownership, usage, suspension and integrity
again. Record any old manual grant requests; they need a global reviewed decision
on re-upgrade. Old revocations and merges are journaled in their own transaction,
and re-upgrade retains those decisions. Inspect `ops_rollback_audit`,
`ops_legacy_entitlement_audit`, `ops_rollback_subscription_holds` and the account
merge inventory before returning the new image to service.

If payment objects or issued payable Links exist, **do not use unmodified
110485c as the billing authority**: its old webhook fulfillment is outside this
contract. Keep a compatible modern receipt/review image. Disabling app checkout
cannot invalidate already issued Links; Bryan must separately decide provider
deactivation, cancellation and refunds. Retain receipt delivery and queue review.
Production mutations and customer messages remain Bryan's actions; none were
executed while preparing this runbook.

## Validation and remaining gates

See [round-3 validation](round3-validation.md) for identical before/after
regressions, final suite/race results and the exact REQUIRED-UNRUN command.
Earlier round-1/round-2 evidence in [rereview fixes](rereview-fixes.md) remains
historical; this document supersedes their checkout and serving-rollback limits.
