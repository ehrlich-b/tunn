# Billing operator runbook

Checkout remains subject to its existing configuration and acceptance gates. A
payment return or notification alone does not grant Pro. The committed account
plan reflects eligible entitlement; see [account operations](../ACCOUNT-OPERATIONS.md).

When the login authority has the Stripe secret key and approved Price IDs
configured, supported notifications can trigger automatic verification of
current provider state, payment and ownership and commit entitlement. Missing
configuration, failed reads, incomplete evidence and anomalies remain for
operator review. Inspect the durable reconciliation queue and use the scoped
reviewed workflow in account operations. Do not ask a customer who has paid
to pay again; direct them to support. Do not infer activation from a paid notice.

This runbook belongs to the commercial-copy work. Billing continuation owns
original-T-01.md and paid-operator-checklist.md; original T-01 remains OPEN.
PMUI-10 separately owns the exhausted-byte notice. Reconcile these boundaries
on the integrated candidate before release.
