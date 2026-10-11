# Recommended launch pricing

Recommendation for Bryan's approval: **Free + Pro $6/month or $60/year**.
Use the existing enforced quotas; don't sell unimplemented usage billing.
All competitor/provider sources below were fetched **2026-10-11 UTC**.

| Tier | Price | Account limits | Reason to upgrade |
| --- | --- | --- | --- |
| Free | $0 | 3 concurrent tunnels; 100,000 monthly admissions; 1 GB monthly combined metered bytes; random names, no reservations; 200 Mbps per tunnel | Try HTTPS, MCP OAuth, webhooks, grants and local inspector; no extra visitor warning on public endpoints |
| Pro | $6/month or $60/year ($5/month equivalent, $12 saved) | 10 concurrent tunnels; 1,000,000 monthly admissions; 50 GB combined metered bytes; 4 reserved tunn.to names; 500 Mbps per tunnel | Keep connector/webhook names across restarts, more room, predictable bill |
| Usage — future, not sold | Proposed $12/month, 100 GB/2m admissions; optional prepaid $0.15/GB and $1/100k admissions in NA/EU | Explicit spend ceiling; stop before unpaid usage; 20 tunnels only after capacity work | Heavy callbacks; needs approved invoice units, per-account allowances, billing adapter, capacity/load validation |

Current reservations require Pro (`internal/store/accounts.go`); named free
endpoints can be requested while available but are not protected while offline.
No enterprise SLA/SSO/team billing promise. Custom domains are feature-gated and
excluded from the initial sales promise until DNS/ACME acceptance. “200/500 Mbps”
are configured ceilings, **not guaranteed speeds**. Price display is shared
config; Stripe actual price must match before enabling checkout.

## Competitive position

ngrok Hobbyist is $10 monthly/$96 annual, 5 GB and 100k requests included; Free
is 1 GB/20k requests. Pro offers lower base price and higher included account
budgets, while Free offers five times the admission count.
[ngrok pricing](https://ngrok.com/pricing),
[limits](https://ngrok.com/docs/pricing-limits/how-ngrok-charges/).
Units differ: tunn sums ingress and response bodies/transport bytes, excludes
framing and counts admissions; ngrok measures outbound transfer and HTTP
requests. Do not imply a benchmarked 10× economic saving for identical traffic.
ngrok offers gateway/policy/compliance capabilities tunn does not match. Free
stable assigned ngrok domains already exist. [Free documentation](https://ngrok.com/docs/pricing-limits/free-plan-limits/).
Pinggy Pro's $3 monthly/$30 annual is cheaper; Cloudflare's free options and
zrok's 5 GB/day are strong substitutes. See [REALITY.md](REALITY.md).

## Fly unit economics: model, not measured production bill

[Fly pricing](https://fly.io/pricing/) lists shared-cpu-1x/256 MB at $2.19/month,
additional RAM $6/GB-month, volume $0.15/GB-month, snapshot $0.08/GB-month,
dedicated IPv4 $2/month. Egress: NA/EU $0.02/GB, APAC/Oceania/South America
$0.04/GB, Africa/India $0.12/GB. Prices vary by region/configuration; don't
substitute an old free allowance or blog price for the actual bill.

Repo `fly.toml.dist` specifies iad, shared-cpu-1x/512 MB, persistent /data.
Illustrative one-machine fixed budget: $2.19 + $1.50 extra RAM + $1.50 for
10 GB volume + $2 IPv4 + $0.80 snapshots = **$7.99/month**. Volume size,
IP assignment, replication and active prod machine count were not inspected.
Two identical nodes would be $15.98 before networking/support. At 100 active
accounts allocate $0.08/account; at 10 allocate $0.80. This allocation changes
with load; connection limits in the template (soft 200/hard 250) are not a
validated users-per-machine capacity.

`docs/METERING.md` defines counted units: admitted HTTP/MCP requests and
WS/TCP opens; HTTP bodies, WS wire frames and TCP payload; both directions,
attributed to admission month. TLS/HTTP/gRPC overhead is excluded. A body-byte
unit is not a Fly egress byte or a finalized invoice. Allow **25% overhead**
as a modeling assumption for framing, retransmits and routing; small messages
or multi-node copies may need much more. Measure actual Fly bytes against
ledger exports before offering overage or increasing capacity.

Model variable networking cost = metered GB × $0.02 × 1.25, for launch in iad.

| Usage per account/month | Networking estimate | Total at 100 accounts, $0.08 fixed allocation |
| --- | --- | --- |
| Free at 1 GB cap | $0.025 | $0.105 |
| Typical Pro, assumed 5 GB | $0.125 | $0.205 |
| Pro at 50 GB cap | $1.25 | $1.33 |

Payment-fee model is an explicit assumption: 2.9% + $0.30 per charge, plus 0.7%
subscription billing, excluding international cards/tax/refunds/disputes.
Use Bryan's actual Stripe contract before approval. Net on $6 is about $5.48;
net on $60 annual averages $4.795/month. At full Pro transfer cap and 100 active
accounts, contribution is roughly $4.15 monthly/$3.47 annual before CPU scaling,
staff time, email, free-user subsidy and tax. At Africa/India rates the same
50 GB is $7.50 networking alone: **do not promise global economics**. If actual
traffic causes two full-cost egress legs in iad, networking becomes $2.50 and
the Pro contribution remains positive in this model, with less room for subsidy.

At 10 paid full-cap monthly accounts and 90 maxed Free accounts: revenue $60;
modeled payment fees $5.16; network $12.50 + $2.25; fixed $7.99; remainder
**$32.10/month before CPU/support**. Every additional machine reduces this.
1,000 maxed free accounts cost about $25 in body-related egress alone. Bound
abuse, monitor ledger capacity and signup rate; hard byte caps already exist.

## $12/year entry instinct

At $12/year, net after assumed fees is $11.268/year ($0.939/month). A 1 GB/month
entry tier could cover its network cost, but cannot fund generous Pro limits,
staffed billing or enough free acquisition at low scale. At 50 GB it loses money
even in iad. A future $12/year “reserved-name” tier could mean 1 reservation,
3 tunnels, 1–2 GB/100k admissions; **not implemented** because the account model
currently has only free/pro. Launch $60 annual Pro first; test willingness to
pay before adding a third tier. Do not map a $12 annual price to full Pro.

## Exact Stripe setup for coordinator, after approval

No Stripe objects were created or changed here. In Stripe **test mode first**:

1. Product `tunn Pro`, description: 10 concurrent tunnels, 4 reserved names,
   50 GB combined metered bytes and 1m monthly admissions; hard stop, no overage.
2. USD recurring licensed Price, `unit_amount=600`, interval `month`, quantity 1;
   lookup key `tunn_pro_monthly_v1`. Second Price `unit_amount=6000`, interval
   `year`, lookup key `tunn_pro_yearly_v1`. No trial, usage meter or quantity upsell.
3. Two subscription Payment Links, one exact Price each, quantity fixed 1;
   collect email, allow no adjustable quantity. Limit customers to one active
   subscription where supported; no repeat purchase from pending account view.
   After-payment redirect `https://tunn.to/account?billing=return`.
4. Webhook `https://tunn.to/webhooks/stripe` for checkout.session.completed and
   customer.subscription.created/updated/deleted. Keep secret in
   `TUNN_STRIPE_WEBHOOK_SECRET`; test/live environments use different secrets.
5. Customer portal: allow payment-method updates and cancellation at period end;
   exclude arbitrary plan changes; set return URL `https://tunn.to/account`.
   Set configured portal URL only after verifying it actually identifies the
   Stripe customer (a generic portal login uses the payer's Stripe email).
6. Put returned buy.stripe.com URLs into the existing monthly/yearly config;
   display `TUNN_PRO_MONTHLY_USD=6`, `TUNN_PRO_YEARLY_USD=60`. Enable
   `TUNN_BILLING_ENABLED=true` **only after** fulfilling a sandbox payment and
   cancellation with the reviewed operator workflow in GO-LIVE.md and staffing
   the activation queue. Payment link email/reference is advisory; operator
   must verify customer/subscription-to-account ownership.

Repeat the approved objects in live mode only after the sandbox gate. Existing
prices/subscribers are not migrated or edited; coordinator inventories them
read-only and gets approval for any later migration. No Usage/Entry object now.
