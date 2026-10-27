# Paid operator checklist

T-01 remains **OPEN**. The [original acceptance](billing/original-T-01.md) is the governing requirement. Local tests and synthetic receipts are preparation, not live acceptance. Keep the billing gate in place until the owner reviews configuration and separately authorized provider acceptance is complete. Do not infer deployment or enabled checkout from source behavior.

## Processing and recovery

The configured path in [account operations](ACCOUNT-OPERATIONS.md) automatically processes eligible Pro payments when the login authority has both its Stripe secret and the explicitly approved Price ID allowlist configured. It reads current provider subscription, invoice and charge state; an active current period, matching approved price and paid nonzero invoice and charge without refund or dispute are required. A server-issued, on-time consumed checkout intent or an existing explicit binding establishes ownership. A completion or notification by itself is not proof of entitlement. This describes source capability, not observed live configuration.

The commercial-copy `a5246b7` operator runbook is the separately reviewed runtime-consistent reference for integration; use it together with account operations once integrated. Its file is maintained separately from this checklist.

For future authorized operator acceptance:

- Verify approved monthly and yearly price mapping, account ownership, payment and the resulting single entitlement against current provider and local records. Capture receipt delivery and renewal, including failed or delayed payment and provider outage. Record activation turnaround from payment to entitlement and the refund turnaround; establish secondary coverage when the primary operator is unavailable.
- Treat pending, unknown ownership, unknown price, ambiguous payment, expired or unknown completion time, provider-read failure and unbound events as requiring review. Route the customer to support; preserve the receipt and do not promise activation or retry a purchase blindly. Verify support intake, acknowledgement, ownership and recovery with redacted evidence.
- Compare all provider payments with the local payment queue and billing status, following every page and using authorized scope for unbound entries. Investigate duplicate charges and quarantined payments. A replay must not grant twice; event arrival order must not override a newer verified provider read. Complete the authorized provider refund and cancellation when needed, verify both sides, then record the reviewed queue closure. Local reconciliation itself makes no provider write.
- Verify period-end cancellation retains the paid active period and current cancellation ends that subscription's entitlement. For a current charge refund or dispute, verify provider and local state; older or unassociated charges need operator review. Preserve other eligible subscriptions and operational suspension. Record reservation effects and recovery as appropriate.
- A canceled binding blocks returning self-service checkout. Route returning customers to support for a reviewed recovery; do not invent a replacement purchase or imply it is already supported. Reconcile provider ownership, approved price and payment before any reviewed local decision.

Use the reviewed operator procedures for provider reads, payment review, version checks and reconciliation. Stop on mismatched ownership, stale or ambiguous state, missing receipts, uncertain provider responses or unresolved money. Retain redacted case evidence and escalate rather than marking a case complete.

## Acceptance record

Every original T-01 requirement is **OPEN** until supported by real, dated, owner-reviewed evidence. For each case record the environment and release identity, UTC time, responsible operator and secondary coverage, case and account references in redacted form, provider and local before/after states, relevant event and confirmation IDs, approved price mapping, action and result, receipt delivery, elapsed activation or refund time where applicable, reviewer and evidence digest. Include owner-reviewed configuration and any separately authorized final provider acceptance. A test-mode rehearsal or local fixture does not attest live configuration or money movement. Never label a synthetic receipt as a provider or owner receipt.
