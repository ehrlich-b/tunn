# Funnel audit — baseline 110485c / production v38

Read-only GETs with `curl https://tunn.to/...` on 2026-10-11 at 13:39 UTC.
No login submission, checkout, account creation, Stripe API call or production
mutation was performed. Deployment version is supplied by BRIEF.md, not inferred
from HTML. Authenticated production behavior and actual configured Payment Links
remain unverified. Source references below are relative to this checkout.

## Observed route journey

| Step | Live evidence / source | Finding |
| --- | --- | --- |
| Discover | `/` 200; `templates/homepage.html` | Hero emphasizes email sharing, not MCP or webhooks. One installer; no Get Pro CTA in pricing cards. |
| Install | `/install.sh` 200; `install.sh`, duplicate embedded string in `proxy.go` | Latest GitHub release downloader, macOS/Linux amd64/arm64 only; no checksum verification or atomic replacement; README labels it legacy and links recovery guide. PATH setup left to user. |
| Signup/login | `/login` 200; `/account` 302 to `/auth/login?return_to=%2Faccount`; `auth.go`, `device.go`, `magiclink.go` | No separate signup: verified login creates account. GitHub and magic email offered. CLI requires `tunn login`; install hero omits it. Device-code expiry can confuse, although renewal is implemented. Hosted GitHub/SMTP credentials not verified. |
| First tunnel | `main.go:runServe`, `cliopts/serve.go` | Public without --allow; private email allow-list requires interactive login. Don't put interactive email sharing in the webhook example. Login is needed to attribute quotas. |
| Free usage | `storage/storage.go`, `host/limits.go`, `metering/store.go`, `docs/METERING.md` | 3 concurrent tunnels, 100,000 admissions/month, 1 GB/month across all tunnels; 200 Mbps per tunnel. Website says unlimited tunnels and omits requests. Quotas already enforce HTTP/MCP/SSE/WebSocket/TCP and reset in UTC. |
| Upgrade intent | `templates/account.html` | $5 monthly/$48 yearly, defaults yearly; 50 GB/10 concurrent tunnels and priority support. Homepage says 4 reservations and vaguely unlimited enterprise bandwidth/SSO/SLA. Account links become `#` when missing config, without explanation. |
| Checkout | `config/config.go:StripeCheckoutURLMonthly`, `auth.go:handleAccount` | URLs are config-driven already (`TUNN_STRIPE_CHECKOUT_URL_MONTHLY/YEARLY`), with prefilled email. Homepage price is hardcoded. No server upgrade route or readiness check; yearly toggle can select an unavailable link. Editable email identifies no account safely. `StripeSecretKey` is loaded but not used for checkout/fulfillment. |
| Fulfillment | `host/stripe.go`, `store/billing.go`, `storage/local.go/proxy.go` | HMAC signatures verified, 5-minute tolerance, 64 KiB body cap; receipts commit durably and duplicates are detected. Stripe event timestamps are correctly not authoritative revisions. Events yield `reconciliation_required`, not Pro. Email/checkout completion never grant a plan. Billing mapping must be bound by an operator. Reconcile can apply only to disposable fixtures. |
| Payment return | `auth.go:handleAccount`, account template | No dedicated return/entitlement view; no polling current plan; no “payment received but activation pending” message; easy to pay again while still Free. |
| Manage subscription | Account template | Configurable portal, but missing portal silently becomes `#`. Cancellation webhook also requires operator reconciliation; otherwise a stale Pro plan can persist. |
| Pricing/docs | `/pricing`, `/docs`, `/upgrade` all 200 with same homepage; `webproxy.go:handleApexDomain` | Every unknown apex path falls through to homepage. No dedicated docs/pricing content or honest 404. Documentation link goes to GitHub; MCP capability hard to discover. |
| MCP | `main.go:runMCP`, `client/serve.go`, `MCP-CONNECTOR.md` | Close: stdio bridge, HTTP target remapping to /mcp, private by default, resource discovery, PKCE, dynamic registration, consent and revocation already implemented. CLI prints connector URL. No first-class hosted tutorial; actual Claude.ai/ChatGPT acceptance still needs owner validation. |

## Ranked friction / breaks

Rank is expected revenue impact **by inference**, not measured conversion data.

1. **Paid checkout cannot currently deliver Pro in production.** Gate selling on
   fulfillment readiness; add an explicit reviewed operator apply path with
   current-provider snapshots, account mapping, CAS and audit; never trust the
   redirect, editable email, or event arrival order. Staff activation/cancellation
   reconciliation before opening checkout. Automation can follow a measured beta.
2. **No public actionable pricing path.** A visitor sees prices without an
   upgrade button; /pricing is the homepage; account buttons can silently do
   nothing. Add real pricing, authenticated config-driven redirect, monthly and
   annual availability independently, visible unavailability and portal fallback.
3. **Advertised limits and product promises contradict enforcement.** Publish
   3/10 concurrent tunnels, 100k/1m admissions, 1/50 GB, 4 Pro reservations;
   clarify account-wide limits, UTC reset and hard stop/no overage. Remove
   unsupported SSO/SLA/unlimited enterprise and unsupported license claims.
4. **No payment-confirmation feedback.** Read current account entitlement after
   return; show pending until committed Pro; retry failures visibly, prevent a
   pending view from offering another checkout, and link support.
5. **High-intent MCP users miss a working capability.** Ship private stdio and
   existing-HTTP tutorials, harmless example, cloud-side diagnosis and CLI next
   steps. Preserve OAuth/consent; don't recommend a public filesystem server.
6. **Install-to-login transition is missing and distribution depends on stale
   release assets.** Add `tunn login` in hero/docs, preserve recovery guide,
   prepare a Homebrew formula built from the reviewed source commit, verify
   release/checksum route before promoting the downloader.
7. **ngrok users must translate syntax.** Add `tunn http 8080` alias with existing
   --subdomain name alias; document unsupported ngrok authtoken/domain/config
   semantics precisely. Do not advertise a drop-in binary.
8. **Trust and operations gaps.** No real SLA/priority-support commitment,
   actual infra capacity or billing portal verified. Manual fulfillment needs
   an explicit queue owner and turnaround promise approved before launch.
9. **No measured funnel.** Existing HTTP logs include IP/UA and should not be
   called conversion analytics. Start with aggregate activation/quota/billing
   receipt counts, separate from tool data. No external tracking is added here.

## Change acceptance

Verify server routes, URL configuration and auth boundaries, outage/empty config,
payment return still Free versus committed Pro, operator dry-run/apply CAS and
cancellation, shared limit copy and actual quota headers. Existing metering tests
are the enforcement gate. Hosted-client acceptance, a real Stripe sandbox payment,
native install/Homebrew and production operations remain coordinator gates.
