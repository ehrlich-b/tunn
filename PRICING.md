# Hosted plans

| Plan | Price | Concurrent tunnels | Monthly requests | Monthly metered transfer | Reserved tunn.to names |
| --- | --- | --- | --- | --- | --- |
| Free | $0 | 5 | Unlimited (fair use) | 10 GB | 1 |
| Pro | $5/month or $48/year | 25 | Unlimited (fair use) | 500 GB | 10 |

Budgets apply across the account and reset on the first day of each UTC month.
GB means 1,000,000,000 bytes. Admission counts include HTTP/MCP requests and
WebSocket/TCP opens. Transfer includes HTTP bodies, WebSocket wire frames and
TCP payloads in both directions; TLS, HTTP and relay framing are excluded.
See [metering](docs/METERING.md) for exact counting and stream cutoff behavior.
Explicit operator budgets can lower the displayed and enforced allowances.

At a limit, traffic stops. There are no automatic overage charges. Upgrading
raises the allowance without resetting usage. Per-tunnel bandwidth ceilings
remain abuse guards, with burst allowances; they are not advertised speeds.

Publishing automatically attempts to reserve names, including random names,
within the plan allowance. Choose `--subdomain` before publishing. Additional
names remain temporary. Retry of an owned reservation consumes no extra slot.
Paid entitlement ending releases its reservations; Free can then reserve one
name again. Account merges retain existing names but grant no extra new slots.

## ngrok comparison

ngrok Free includes 1 GB transfer out and 20,000 HTTP requests. Hobbyist costs
$10/month or $96/year and includes 5 GB transfer out and 100,000 HTTP requests;
usage credit can cover additional usage. Accessed **2026-10-12**:
[ngrok pricing](https://ngrok.com/pricing),
[pricing limits](https://ngrok.com/docs/pricing-limits/).

Units differ: tunn counts admissions across HTTP/MCP/WS/TCP and metered bytes
in both directions; ngrok counts HTTP requests and data transfer out. These are
included allowances, not a benchmark of performance or identical traffic cost.

## Display and checkout configuration

`TUNN_PRO_MONTHLY_USD` defaults to `5`; `TUNN_PRO_YEARLY_USD` defaults to `48`.
Display amounts must match the Stripe recurring prices behind the configured
monthly/yearly checkout links. Existing Stripe prices and subscriptions are
not changed by a code deployment. Checkout remains unavailable unless the
billing gate, valid Stripe checkout URL and webhook secret are configured.

Payment returns and client references do not grant entitlements. When configured,
automatic processing verifies current payment and ownership before committing
entitlement. Otherwise, or when evidence needs review, operators use the reviewed
fulfillment workflow; see [account operations](docs/ACCOUNT-OPERATIONS.md).
A paid notice alone does not establish Pro: the committed account plan governs.
If payment is pending or needs review, contact support before paying again.
No usage billing, automatic overage, SLA or unvalidated capacity promise is
included in these plans. Custom domains retain their existing feature gates.
