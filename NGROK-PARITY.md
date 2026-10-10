# Can tunn become an open-source ngrok alternative?

2026-10-10. Offline assessment; no network access. Repository baseline: `dc26320b1f0c1da40641fa4710849f026bee1f24`.

**Yes, as a product direction. A fully open implementation can sell managed connectivity. The sensible first target is a reliable, authenticated developer endpoint, followed by team policy and platform integrations. Full feature breadth and a globally operated enterprise service are separate investments.**

There is a material evidence problem: this working directory is a planning repository, not the source clone described in the brief. At the inspected baseline it contained only `BET.md` and `THESIS.md`, one local branch, no remote, and no implementation objects found by the checks below. Consequently this report cannot certify tunn's features from code. It distinguishes local facts, earlier reports of code, and proposed work. It does not turn absent evidence into a claim that a feature is absent everywhere.

The existing [THESIS.md](THESIS.md), especially lines 5, 17–42, remains the commercial decision: an authenticated OpenClaw phone-browser recipe, $12/year Starter and $48/year Pro, a staged $2,000 experiment, and explicit retention and cost gates. This report is an expansion map, not authorization to replace that experiment with a platform build.

All competitor descriptions, license recollections, tier assignments and competitor prices in this document are **from training knowledge, verify**. They are not an October 2026 market audit. Fly prices are explicitly hypothetical planning inputs drawn from the local memos, not verified tariffs. No cited external page or sibling repository was opened.

## 1. Evidence boundary and branch inventory

These commands ran only in this directory and did not contact a remote:

```text
git status --short                         -> empty at start
git branch -a                             -> * master
git remote -v                             -> empty
git show-ref                              -> dc26320… refs/heads/master
git rev-parse --is-shallow-repository      -> false
git ls-tree -r --name-only HEAD            -> BET.md, THESIS.md
git log --all --format='%h %s' --name-only -> five commits, these two files only
git fsck --full --no-reflogs --unreachable -> no findings
```

There is no tracked `LICENSE`, `COPYING`, source manifest, test suite, or `AGENTS.md` in this checkout. The user supplied the working agreements directly. An empty `git fsck` result does not prove what exists in other repositories; it means no recoverable implementation was found here. No fetch was attempted because the brief forbids network access.

| Requested branch family | Actual local result | Secondary evidence in this checkout |
| --- | --- | --- |
| `master` | Present at `dc26320`; planning documents only | Five local commits, beginning with `ba180cb` |
| `codex/tunn-*`, including fetched `origin/*` | No matching local or remote-tracking refs; no configured remote | The brief's expected clone and the actual repository differ |
| lifecycle | Unavailable | `BET.md` lines 210, 1038 report candidate `006d3ca` and bridge fixes |
| dogfood | Unavailable | `BET.md` lines 890–995 describe acceptance proposals; those are not a branch inspection or test receipt |
| hostmode | Unavailable | No implementation evidence for this branch in the available files |
| websocket | Unavailable | `BET.md` lines 1052–1054 report a baseline gap; `THESIS.md` lines 33, 46 require authenticated WebSocket acceptance |
| metering | Unavailable | `BET.md` lines 546–579 report `codex/tunn-metering-20261010`, committed core `b1f9a53`, plus then-uncommitted integration |
| secfix | Unavailable | `THESIS.md` line 33 specifies security acceptance, but supplies no secfix SHA or result |

Do not add these branches' purported features together and call the sum a release. Source review must establish their bases, overlapping changes, merge status, tests and the exact build being evaluated.

### Local evidence references

The references below identify files that actually exist here. Paths mentioned inside the memos are recorded only as leads for later verification; they were not read for this report.

| ID | Inspected local reference | What it establishes, and the limit |
| --- | --- | --- |
| D0 | [THESIS.md](THESIS.md), lines 3–50 | Latest offer, security/quotas requirements, budgets and commercial gates; proposals, not release evidence |
| D1 | [BET.md](BET.md), lines 203–218, 245–250 | Reports HTTPS/browser auth, CONNECT TCP, MCP, relay plaintext visibility and lifecycle limitations |
| D2 | [BET.md](BET.md), lines 1033–1038 | Reports baseline `5b2c06c`, `README.md`, `docs/PRODUCT-ROADMAP.md`, `docs/DESIGN-2.0.md`, `docs/self-hosting.md`; inspector claimed implemented; lifecycle `internal/mcpbridge/bridge.go` and `modern.go` at `006d3ca` |
| D3 | [BET.md](BET.md), lines 544–585, 1048–1049 | Reports `proto/metering.proto`, `internal/metering/store.go` and `store_test.go` at `b1f9a53`; draft `metering_cli.go` and `internal/host/metering.go` were uncommitted when that memo was written |
| D4 | [BET.md](BET.md), lines 411–462, 1045–1046 | Reports `fly.toml`, `docs/how-it-works.md`, `docs/multi-node.md`; assumed machine shape and routing design, no measured capacity or current invoice |
| D5 | [BET.md](BET.md), lines 942–995 | Revocation distinctions and proposed failure/recovery tests; no new field results here |
| D6 | [BET.md](BET.md), lines 302–363; [THESIS.md](THESIS.md), lines 17–31 | Entitlement and pricing proposals; THESIS removes BET's intermediate $24 tier |

**No code line references are available.** Adding plausible function names or line numbers would fabricate evidence. D1–D6 preserve the useful reported paths and SHAs without presenting them as inspected code.

## 2. ngrok's feature surface and tiers

**Entire section: from training knowledge, verify.** Product names, packaging, limits and prices may have changed. The tier columns are procurement buckets, not asserted current plan names:

- **Free/development:** constrained personal evaluation. A remembered free entitlement does not establish present availability.
- **Paid/self-service:** historically Personal/Pro and/or usage-based commercial offers. Included units, minimum charges and add-ons need checking.
- **Enterprise/contract:** organization controls, contractual support and negotiated scale. A feature in this column may also be purchasable below enterprise.

`Check` means the exact entitlement cannot be responsibly recalled. It is not a statement that the feature is unavailable. Endpoint authentication and organization/dashboard SSO are different features; purchasing one does not imply the other.

| Feature surface | Free/development recollection | Paid/self-service recollection | Enterprise/contract recollection or question |
| --- | --- | --- | --- |
| Public HTTP/HTTPS endpoints, managed certificates | Core development use, with limits and possible browser interstitial | Production use, larger limits and commercial controls | Contractual capacity and support; verify guarantees |
| WebSockets, streaming HTTP and gRPC | Transport support remembered; limits/check | Broader production use; verify HTTP/2, trailers, idle timeouts | Verify behavior under policy and regional routing |
| Raw TLS endpoints | Check eligibility; distinct from HTTPS termination | TLS forwarding and termination configuration remembered | Certificate/key ownership and regional termination requirements |
| Raw TCP endpoints | Remembered conditional availability, possibly account/payment verification | TCP forwarding and reserved address options | Larger address/connection needs; verify dedicated IP options |
| Custom domains and certificate automation | Free assigned development domain remembered; arbitrary domains check | Bring a domain, automate certificates, domain-based routing | Organization ownership and certificate management |
| Wildcard domains | Check | Paid capability remembered | Wildcard ownership, ACME and tenant isolation |
| Reserved names and TCP addresses | A stable assigned dev domain may exist; do not equate it with arbitrary reservation | Reserved domain/address resources | Allocation limits, portability and contractual retention |
| OAuth social login at an endpoint | Check policy access and limits | Identity-provider login as ingress policy | Enterprise provider and group restrictions |
| OIDC at an endpoint | Check | OIDC policy remembered; verify provider coverage | Enterprise identity integration and claims controls |
| SAML | Do not assume included | Endpoint SAML and/or organization SSO packaging check | Enterprise identity and organization SSO remembered; verify each separately |
| IP restrictions | Check free policy eligibility | CIDR allow/deny policies | Central administration and audit |
| Mutual TLS | Check | Client certificate validation and TLS controls remembered | Certificate lifecycle, CA rotation and policy integration |
| Webhook verification | Check provider actions and metering | Provider signature verification at ingress remembered | Supported-provider list and failure diagnostics |
| Traffic Policy | Limited policy use may be available; check | Conditional actions, deny/respond, headers and request/response transformations | Organization controls, limits and change audit |
| URL/host rewriting, redirects, routing | Check | Policy-driven routing and transformations | Complex shared ingress and delegated ownership |
| Rate limits and security controls | Platform safety limits differ from configurable customer policy | Customer policy, JWT/auth actions and circuit protections; exact action list check | Central enforcement; WAF/bot/DDoS product scope needs verification |
| Load balancing | Check endpoint pooling limits | Endpoint pooling and policy routing remembered | Health, weights, failover and stickiness semantics need independent verification |
| API gateway | Not merely the basic reverse tunnel | Auth, JWT/policy, routing, limits and transformations composed into gateway behavior | Governance, isolation and support; verify API-management scope |
| Kubernetes operator/ingress | Open-source integration remembered; hosting entitlements separate | Operator-managed resources and ingress integration | Gateway API/Ingress coverage and support matrix check |
| Agent SDKs | Go, Rust, Python and JavaScript/Node integrations remembered | Embed tunnels in applications; service charges still apply | Distribution, lifecycle and support terms |
| Local traffic inspection UI | Local development inspector remembered | Inspector plus commercial traffic tooling | Sensitive payload controls and access governance |
| Request replay | Local request replay remembered | Cloud inspection/replay availability and retention check | Retention, authorization and audit of replay |
| Observability and log export | Basic local diagnostics/dashboard counters | Traffic inspection, events and export products remembered | Destinations, retention, audit and data residency check |
| SSH reverse tunnels | SSH-based access using the standard SSH client remembered | Domain/auth/resource entitlements still apply | Verify supported SSH forwarding modes and fleet suitability |
| Edge/global points of presence | Hosted edge reachability | Regions, routing options and edge policy execution | SLA, residency, private connectivity and failover guarantees check |
| Private endpoints/internal services | Check current packaging | Internal/service-to-service endpoint concepts remembered | Private integration and identity topology; not evidence of a full mesh VPN |
| Device/IoT access | An outbound agent can support device access | Embedded agent/SDK, stable endpoints, remote maintenance story | Fleet enrollment, per-device credentials, OTA and support are distinct capabilities to verify |
| Dashboard, REST API, credentials and automation | Account and endpoint management | Programmatic provisioning and usage controls | RBAC, SSO, audit, SCIM and Terraform coverage each need checking |
| Cloud-hosted or persistent endpoint configuration | Exact present product taxonomy uncertain | Control-plane endpoint definition separate from a running agent remembered | Persistence does not keep an offline customer's origin alive |
| MCP/agent access and emerging gateway products | Current scope unknown | Do not infer full MCP auth/lifecycle support from HTTP reachability | Verify current catalog, connector compatibility and AI-specific gateway features separately |
| Support, SLA and compliance assurances | Community/self-service expectation | Paid support scope check | Contractual service and audit artifacts; software alone does not supply these |

This is a broad inventory of remembered product families, not a claim that every current SKU/action is covered. UDP, arbitrary IP subnet routing, mesh peer-to-peer networking, managed databases and running a customer's application are not established by the remembered ngrok feature list. Do not define “full connectivity” as all of those by accident.

### Pricing recollection and comparison discipline

**From training knowledge, verify:** ngrok has offered a $0 free plan; older Personal and Pro pricing is remembered at roughly $8 and $20 per month respectively, often shown as monthly equivalents with annual billing. Those are historical recollections, not a current quote, purchasing recommendation or asserted current tier structure. Usage-based packaging, enterprise contracts and account-specific entitlements may supersede that comparison. Exact included bandwidth, requests, endpoints, concurrent connections, policy actions and overage rates are unknown here.

A later price comparison must calculate the same workload for both products: active endpoint hours, paid/reserved domains, TCP addresses, requests, transfer direction, simultaneous streams, policy executions, log retention, identities and support. A remembered subscription floor is not an all-in cost. The $12/year tunn offer in D0 buys a deliberately narrow, capped service; it cannot honestly be advertised as all ngrok features at that price.

## 3. tunn parity matrix: reported status, evidence and remaining work

Status labels satisfy the requested have/partial/missing inventory, with an essential qualifier:

- **Have (reported):** a local memo explicitly describes an implementation. No source or executable was available to confirm it.
- **Partial (reported):** a related implementation is described, but the requested scope or acceptance remains unfinished.
- **Missing (evidence):** no implementation evidence here. This is a planning placeholder, not proof of absence in the real source tree.

**The code-verified status of every row is unknown.** Estimates are conditional on the reported baseline surviving source review. One agent-day is approximately eight hours of supervised implementation, testing and documentation effort by one coding agent, not eight hours of unattended tokens or one human engineer-day. Security approval, operating history and external interoperability take additional elapsed time and human work. Row estimates include finishing and acceptance for that surface, even for reported existing features. Shared components overlap; do not sum the rows. Section 6 supplies non-additive work packages and budget ranges.

| Feature | Status | Local reference and specific gap | Remaining agent-days | Epic |
| --- | --- | --- | ---: | --- |
| Public HTTP/HTTPS, managed TLS | Partial (reported) | D1 reports HTTPS and streaming; arbitrary HTTP compatibility, certificate lifecycle and origin failure behavior unverified | 4–8 | E1/E4 |
| WebSockets, SSE, streaming, gRPC | Partial (reported) | D1 reports HTTP streaming; D0 requires WS work; no gRPC/trailer proof | 5–10 | E1/E4 |
| Raw TLS forwarding/termination | Missing (evidence) | D1's HTTPS termination does not establish arbitrary SNI/TLS passthrough | 6–12 | E5 |
| Authenticated TCP transport | Have (reported) | D1: HTTP/2 CONNECT and `tunn connect`; verify half-close, reset, backpressure, auth and reconnect | 3–6 | E1 |
| Public raw TCP and reserved host:port | Partial (reported) | D1 has TCP through a tunn consumer; no evidence of arbitrary native TCP clients or reserved public listeners | 7–12 | E5 |
| Custom domains and automatic certificates | Missing (evidence) | D6 proposes reserved names, explicitly excludes custom-domain promises; domain proof/ACME not evidenced | 5–9 | E4 |
| Wildcard domains | Missing (evidence) | No source evidence; needs ownership proof, wildcard certificate flow and tenant-safe routing | 3–6 after domains | E5 |
| Reserved service subdomains | Partial (reported) | D6 describes paid naming; reservation ownership, races, reclamation and persistence are not proven | 3–5 | E3/E4 |
| Browser email allow-list and GitHub/magic-link login | Have (reported) | D1; D0 still requires exact matching, single-use expiry, cookie/origin and bypass tests | 3–6 | E1 |
| General OAuth/OIDC endpoint auth | Partial (reported) | GitHub login is not arbitrary OIDC, caller delegation or OAuth authorization-server support; D1/D2 | 6–12 | E5 |
| MCP OAuth/client interoperability | Partial (reported) | D1: tokens and stdio/HTTP bridge; D2 reports OAuth gap; live connectors untested | 6–12 | E2/E5 |
| SAML endpoint auth and organization SSO | Missing (evidence) | No source evidence; use a maintained identity broker, separate endpoint and operator sessions | 8–14 | E7 |
| IP allow/deny | Missing (evidence) | D0 requires header-spoofing review; no implemented trusted-client-IP policy shown | 2–4 | E5 |
| Mutual TLS at ingress/upstream | Missing (evidence) | Ordinary TLS in D1 does not imply client certificates, identity mapping or CA rotation | 4–8 | E5 |
| Webhook signature verification | Missing (evidence) | BET proposes app-side verification; no edge verifier source; raw bytes/time/replay semantics matter | 3–6 for two providers | E4 |
| Traffic policy, rewrites and redirects | Missing (evidence) | No policy-engine source; compile typed rules with explicit order and bounded execution | 8–14 | E5 |
| Account rate/byte/request/stream limits | Partial (reported) | D3 ledger has grant limits; D0 requires aggregate account limits and active-stream cutoff | 5–9 | E3 |
| HTTP load balancing, health and failover | Missing (evidence) | D4 multi-node routing is not multiple healthy origins, selection or safe retry behavior | 6–12 | E6 |
| API gateway | Partial (reported) | D1 reverse proxy/auth are ingredients; routing, policy, secrets, API governance and tests remain | 8–15 beyond policy | E5/E7 |
| Kubernetes operator, Ingress/Gateway integration | Missing (evidence) | No manifests, CRDs, controller or tests available | 10–18 | E7 |
| Embedded Go/Rust/Python/JS SDKs | Missing (evidence) | A CLI implementation does not prove a supported SDK; shared native core or subprocess strategy undecided | 10–18 for four thin SDKs | E7 |
| Local traffic inspection UI | Have (reported) | D2 specifically reports an implemented inspector; source, retention and redaction unavailable | 3–5 | E4 |
| Replay | Missing (evidence) | Inspector in D2 does not establish replay; D6's webhook offer is a proposal | 3–6 | E4 |
| Metrics, structured logs and export | Partial (reported) | D3 counters and bounded event storage exist by report; not a complete security audit or export pipeline | 5–9 | E3/E6 |
| Standard SSH reverse-tunnel ingress | Missing (evidence) | D1's SSH over `tunn connect` is a different client path; no SSH server/forwarding implementation shown | 5–9 | E7 |
| Hosted edge and global points of presence | Partial (reported) | D4 describes Fly routing; no evidence of deployed global relays, tenant placement, failover or SLA | 10–18 | E6 |
| Private endpoints/internal services | Partial (reported) | D1 has authenticated public-edge access; no private-only namespace, internal routing or network isolation proven | 7–13 | E6 |
| Device/IoT connectivity | Partial (reported) | Outbound publisher/CONNECT could transport maintenance access; no fleet provisioning/update/offline lifecycle proof | 12–24 | E8 |
| Dashboard and management API | Partial (reported) | D1/D3 describe login, CLI and draft usage/grant commands; no full organization/API/dashboard coverage | 8–14 | E3/E7 |
| Billing and entitlements | Partial (reported) | D3 core exists by report; account-wide limits, payment reconciliation and safe upgrades unproven | 6–10 | E3 |
| Revocable per-caller credentials/RBAC | Partial (reported) | D3 grant core; D5 distinguishes new requests, streams and admitted application work | 6–10 | E3/E5 |
| Publisher lifecycle/service install | Partial (reported) | D1 lifecycle fixes cover MCP children, not necessarily Windows/macOS/Linux daemon enrollment/update | 5–9 | E1/E2 |
| Self-hosted complete distribution | Partial (reported) | D2 names self-hosting docs; no checked license, release artifacts or fresh install proof here | 5–9 | E2/E6 |
| Abuse response, tenant suspension and free-tier controls | Missing (evidence) | D0 requires safety and quota gates; no response queue, domain reputation or enforcement proof | 5–9 initially | E3 |
| Enterprise audit/RBAC/SCIM/support readiness | Missing (evidence) | D3 bounded ledger explicitly cannot promise full annual request history; no contractual assurance evidence | 10–20 plus operations | E7 |

Cross-cutting acceptance should include large and empty bodies, host/header confusion, cookies and redirects, TLS/SNI separation, streaming backpressure, origin disconnect, simultaneous publishers, tenant isolation and lost acknowledgments. Replaying a payment webhook or retrying a non-idempotent POST can cause real application actions: replay must be explicit, authenticated, clearly labeled and local by default. Do not make automatic origin retry the default after request bytes have been sent.

For auth changes, test anonymous, wrong account, forged forwarding headers, expired/reused magic links and open streams during revocation. The trust boundary is browser/client → edge → authenticated publisher → application. Ingress identity does not create host authorization. D1 reports that ordinary HTTPS terminates at the relay; advertise end-to-end encryption only for a separately verified protocol whose keys stay at the endpoints.

## 4. Keeping the product open source

The existing tunn license cannot be determined in this repository. No license change is performed or presumed authorized. The decision below is a proposed policy to validate against the actual source license, copyright holders and dependencies.

**Recommendation: a fully open service stack, with AGPL-3.0-or-later for the relay, control plane, policy engine and dashboard; Apache-2.0 for independently separable client/SDK components and protocol specifications where ownership permits.** Keep core self-hosted authentication, custom domains, SSO and policy available in source. Offer the same features as a managed service; monetize their operation and support. If existing ownership or integration constraints prevent this split, retain the current lawful license until those constraints are resolved rather than promising a unilateral relicense.

This recommendation favors a contribution-back obligation on modified hosted server code and permissive integration at the client boundary. License compatibility and component separation require review against real dependencies. An Apache-2.0-only stack is the simpler alternative if maximizing embedding and permissive adoption matters more than contribution-back. Neither choice creates distribution or a business by itself.

Offline license principles, requiring verification before adoption: AGPL allows commercial use and forks; its network-use source obligations are not a prohibition on competing hosting and do not require competitors to pay tunn. Apache-2.0 permits broad reuse subject to its conditions and includes patent provisions. Do not label a license with field-of-use, noncommercial, or anti-cloud restrictions “open source” merely because the code can be read. Preserve notices and provenance, establish a contribution policy, and keep trademarks separate from code permissions. Dual licensing requires adequate rights; it cannot be assumed for third-party contributions.

### Fully open versus open core

| Choice | What users receive | Business effect and risk | Recommendation |
| --- | --- | --- | --- |
| Fully open, managed service paid | All transport, auth, policy, management and self-hosting code | Forks/rehosting remain possible; compete through service quality, migration ease, support and distribution | Preferred for the stated promise |
| Open core | Open transport; proprietary team/security/control-plane features | More software upsell, but “full feature set stays open” would be false | Only if Bryan explicitly changes that promise |
| Source-available anti-hosting license | Readable code with commercial restrictions | May deter a hosting competitor, but changes the category and adoption bargain | Do not market as fully open source |
| Fully permissive Apache-2.0 | Complete open stack without server copyleft | Easiest integrations and forks; least obligation for modified hosted versions to contribute back | Credible alternative if adoption wins over reciprocity |

### What remains paid without closing the code

| Item | Open/self-hosted entitlement | Paid hosted offer |
| --- | --- | --- |
| Relay and policy | Run all components and rules yourself | Operated relays, capacity, patching, backups and response |
| Bandwidth/concurrency | Bring infrastructure and pay its provider | Capped transfer, streams and clearly priced capacity; no unlimited promise |
| Names/custom domains | Own DNS and certificates; feature available | Reserved service names, automated domain lifecycle and quotas; first reserved name remains in $12 Starter |
| SSO and authorization | Protocol adapters and enforcement available | Managed identity integration, organization administration and support; basic security is not disabled on free/self-hosted use |
| Logs and inspection | Local inspection/export and configurable self-hosted storage | Managed retention, searchable traffic metadata, export delivery and storage |
| Regions/private deployment | Deploy wherever your provider allows | Verified regional placement, dedicated deployments and support; price real operating costs |
| Enterprise service | Same core security and management code | Contractual response, audits, migration assistance and customer-specific operations |

Charging for hosted custom-domain slots or SSO administration is compatible with shipping their implementations openly. It should not imply that a self-hosted user needs a paid license key for those features. A sustainable managed offer must remain worthwhile even when the customer can leave.

### How adjacent projects approached it

**Every row below: from training knowledge, verify.** Licenses refer to remembered components, not a verified current repository or whole-company license. Check exact versions, dependencies, changes and hosted terms before using this commercially.

| Project | Remembered approach | Lesson for tunn |
| --- | --- | --- |
| ngrok | Commercial managed edge/service; open integrations and SDK components do not establish a fully open hosted control plane | A service sells identity, policy, convenience and reliable operations as much as byte transport |
| Cloudflare Tunnel | `cloudflared` remembered as Apache-2.0; managed Cloudflare network/Access services have separate commercial terms | An open connector can drive a paid service without making the service stack self-hostable |
| Tailscale | Open client components remembered as BSD-3-Clause; managed coordination/service features separate; Headscale is an independent self-hosted control-server alternative, remembered as BSD-3-Clause | Client openness and a fully open control plane are different claims; successful services can coexist with alternatives |
| frp | Apache-2.0 reverse proxy, focused on self-hosted transport | A capable transport baseline is freely available; onboarding and operations must justify hosted pricing |
| rathole | Apache-2.0, lightweight self-hosted reverse proxy | Simplicity and efficiency can be valuable without an enterprise gateway feature catalog |
| zrok / OpenZiti | zrok remembered as Apache-2.0 and built on OpenZiti, also remembered as Apache-2.0; self-hosting and hosted offerings coexist | Share links, private overlay access and embedded zero-trust networking are related but distinct product scopes |
| bore | MIT-licensed minimal TCP tunneling tool remembered | A tiny public tunnel has a small code surface; managed auth, abuse and scale are the added product |
| localtunnel | MIT-licensed client/server ecosystem remembered; public shared service | Open transport does not pay for public endpoint abuse or domain reputation handling |
| Pangolin | AGPL-3.0 core remembered, with commercial/enterprise offerings; exact component and feature boundaries uncertain | Copyleft plus commercial service/support is a relevant pattern; do not claim all enterprise features are open without checking |
| Inlets | Historical open-source roots and later commercial Pro licensing remembered; current repository/product split uncertain | Transport licensing can change; published exit paths and precise feature/license boundaries matter |

### Forks, rehosting and abuse

**From training knowledge, verify:** ngrok and localtunnel public links have been abused for phishing and have used warning/interstitial or access-friction mechanisms. Exact incidents, dates and current policies were not researched here. The transferable risk is a shared domain serving attacker-controlled content: account creation, support, takedowns, blocklisting, provider complaints and payment disputes can exceed the bandwidth bill.

Proposed controls are product operations, not a substitute for correct auth: authenticated private endpoints by default; a deliberately limited free cohort; account and stream budgets; signup and mail rate controls; a report channel; a tenant suspension mechanism; domain verification; metadata sufficient to investigate reports; and explicit retention/deletion rules. Any public-demo mode needs its own abuse budget and review. Avoid collecting request bodies by default. Separate control/login origins from untrusted customer content and isolate cookies and DNS routing so one tenant cannot impersonate another.

An interstitial can break webhooks, APIs and automation. Do not impose a human click-through on machine endpoints and call them API-compatible; design the account verification or plan rules for that endpoint class. Keep an emergency administrative route and a clear operator escalation path. Production suspensions, deployment or billing actions remain Bryan's work under the working agreements.

Forks and competing hosts are an accepted cost of the open-source promise. Sensible defenses are a recognizable brand, an excellent hosted path, documented APIs, reliable upgrades and customer trust. An intentionally unusable self-hosted distribution would undermine the proposed differentiator.

## 5. Fly.io anycast economics and self-hosting

### What is bought, and what still has to be built

D4 reports Fly anycast ingress and a login/proxy split. This report has not inspected `fly.toml` or contacted Fly. As an architectural model, anycast can provide a common ingress address and route users into a provider network. It does not establish replicated tunn state, endpoint ownership, nearby origins, successful stream migration, cheap egress or an application SLA.

```text
visitor -> ingress -> relay owning publisher connection -> customer origin
                         |
                    account / policy / quota state
```

If ingress arrives away from the owning relay, an extra network hop and potentially extra billed transfer appear. A publisher's existing TCP connection cannot simply move to another machine. Failover generally requires reconnection and route re-registration; live application requests may fail and must not be silently replayed. Regional policy/cache replication and account quotas need their own consistency design.

A credible multi-region design needs authenticated registration, endpoint ownership fencing, relay discovery, draining, bounded stale routes, recoverable credentials/certificates, healthy origin selection and regional accounting. Start with one verified billing region, then add placement only for an observed need. Two machines on a provider network are not evidence of control-plane high availability.

### Cost model and unit margins

All amounts below are USD, excluding tax. Use D0's latest assumptions rather than the superseded machine allowances in BET:

- Fixed pilot budget `F = $20/month`: two $3.69 machine allowances, one $2 shared app-level dedicated ingress IPv4 allowance, $0.30 storage and $10.32 other operations.
- Payload `Q` counts bytes in both directions, decimal GB. Approximate billed internet egress as `B = 1.25 × Q`. That multiplier is an assumption, not an upper bound.
- Illustrative internet egress rates `r = $0.02 / $0.04 / $0.12 per GB`; these are sensitivity points, not a current geographic tariff map.
- Variable operations `v = $0.10/account/month`; support `s = $0.15/payer/month`. Higher request tiers may cost more; these optimistic allowances must be measured.
- Annual payment fee assumption `2.9% + $0.30`, amortized over 12 months. Thus Starter fee is $0.054/month and Pro $0.141/month. This is not a verified payment-provider quote.
- Pilot cohort `N = 100` payers and `U = 20` free accounts, each free account using its full 1 GB. Fixed cost is allocated to payers, free variable costs also charged to payers. No free-tier revenue is invented.

```text
Monthly revenue R = annual plan price / 12
Gross per payer G = R - payment fee - F/N - v - 1.25*Q*r
                    - (U/N)*(v + 1.25*1*r)
Contribution before acquisition/development = G - s
```

| Plan at full cap | Egress $/GB | Gross/payer/month | Gross margin | After $0.15 support |
| --- | ---: | ---: | ---: | ---: |
| $12/year, 1 GB | $0.02 | $0.596 | 59.6% | $0.446 |
| $12/year, 1 GB | $0.04 | $0.566 | 56.6% | $0.416 |
| $12/year, 1 GB | $0.12 | $0.446 | 44.6% | $0.296 |
| $48/year, 50 GB | $0.02 | $2.284 | 57.1% | $2.134 |
| $48/year, 50 GB | $0.04 | $1.029 | 25.7% | $0.879 |
| $48/year, 50 GB | $0.12 | −$3.991 | −99.8% | −$4.141 |

This reproduces THESIS's 59.6% and 57.1% low-cost gross margins, including the free cohort. It also reproduces its approximately $3.99 Pro loss in the high-cost case. Offering 50 GB globally at $48/year is therefore not supported by these assumptions.

At the low-cost Starter contribution, three months earns `$0.446 × 3 = $1.338`, supporting THESIS's $1.25 acquisition target. At $60/hour, $0.15 buys nine seconds of support per month. A single five-minute support interaction costs $5, more than eleven months of that contribution. Annual cash collection is not immediate annual profit.

Uploads relayed to the publisher and downloads relayed to a visitor each have an outbound leg. Counting both payload directions once is different from charging every response twice. Protocol headers, TLS framing, auth mail, retries, health traffic and cross-region forwarding add costs; body-byte counters alone will not reconcile an invoice. D4's hypothetical `$0.006/GB` additional transit leg would add `$0.0075` per payload GB at the same multiplier, or $0.375/month for a full 50 GB account. Verify actual topology and tariffs.

### Scaling scenarios, not measured capacity

Assume 80% Starter and 20% Pro payers, all using full allowances; free users equal 20% of payers at 1 GB; low-cost egress; and a **placeholder fixed-capacity budget of $0.20 per payer/month**, growing with the fleet. This intentionally does not hold a $20 two-machine fleet constant at large scale. The linear budget is still unverified and is not a hardware sizing claim.

| Payers / free accounts | Monthly revenue | Total payload/month | Egress cost | Fleet/base budget | Payment + variable operations | Gross | After modeled support |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 / 20 | $160 | 1.1 TB | $27.50 | $20 | $19.14 | $93.36 | $78.36 |
| 1,000 / 200 | $1,600 | 11 TB | $275 | $200 | $191.40 | $933.60 | $783.60 |
| 10,000 / 2,000 | $16,000 | 110 TB | $2,750 | $2,000 | $1,914 | $9,336 | $7,836 |
| 100,000 / 20,000 | $160,000 | 1.1 PB | $27,500 | $20,000 | $19,140 | $93,360 | $78,360 |

These exclude acquisition, engineering, incident coverage, taxes, refunds/disputes and enterprise obligations. They do not establish that request costs or support stay linear. An additional $0.50/payer/month of capacity or operations removes $5,000/month at 10,000 payers; the modeled $7,836 becomes $2,836. One minute of support per payer costs $1 rather than $0.15 and makes that scale case negative before acquisition. A $5,000/month incident/support function also consumes most of its contribution.

The capacity constraints are connections, memory, CPU, ledger throughput and correlated bursts, not merely average GB. At 10,000 payers in this mix, payer stream caps permit `8,000×4 + 2,000×40 = 112,000` simultaneous forwarded streams; the 2,000 free accounts add 4,000, before publisher/control connections. Monthly payer request caps total 1.08 billion, about 417 requests/second averaged over 30 days, before free users and bursts. D4 reports a 250-connection service/machine limit in the earlier config, but a provider connection is not necessarily identical to a multiplexed application stream. Measure both before converting the caps into machine counts.

At low-cost egress, 1,000 fully used free accounts cost at least $125/month in this model before extra fixed capacity, support and abuse. Ten TB of unmetered payload costs about $250 at $0.02/GB or $1,500 at $0.12/GB with the assumed multiplier. Abuse that sends tiny requests or opens idle connections can exhaust other resources without much bandwidth. Enforce account-wide bytes, admissions and streams; protect authentication separately; do not let new grants multiply an account allowance.

### Where self-hosting fits

Self-hosting is the exit path, adoption channel and appropriate choice for users with existing infrastructure, high-volume transit or specific locality requirements. Supply the same server features, a versioned configuration, migration/export, backup/restore, and an honest single-node reference deployment. Also document the DNS, public reachability, TLS, database, upgrade and abuse-response obligations the operator assumes.

At an assumed $5–10/month small-server budget, a low-volume self-hosted relay might cost more cash than Starter but less than metered high-volume hosted transit. That is a scenario, not a current hosting quote, and it excludes labor, redundancy and any bandwidth surcharge. Do not promise that one VPS reproduces a global edge or enterprise availability. An organization can pay tunn for managed dedicated deployment/support while retaining the ability to run it itself.

Avoid one machine or IPv4 address per $12/year customer. Under the memo's assumed $2/month address cost, an individual dedicated address alone exceeds Starter revenue. Shared infrastructure, quota enforcement and low-support operation are necessary to the proposed price.

## 6. Sequenced epic and budget

### What would make a developer switch?

These are ranked hypotheses, not claims that competitors lack the capabilities. Any implied competitor comparison remains **from training knowledge, verify** until measured on the same task.

| Rank | Differentiator to earn | Observable switching reason | Falsifier |
| --- | --- | --- | --- |
| 1 | One safe private bookmark to an existing AI host | Install, authenticate and open an actual app from a phone without managing another machine; stable identity/name survives reconnect | Fewer than 8/10 outsiders complete the task unaided, or no repeat use |
| 2 | Fully open hosted/self-hosted portability | Same config and policy work locally or hosted; export names/config/identity mappings without a proprietary core | A documented clean self-host install or migration cannot be completed |
| 3 | Predictable small bill | $12/year entry, visible account caps, clear upgrade and no surprise overages | Required support/cost exceeds contribution or users repeatedly hit unusable limits |
| 4 | Useful local debugging | Redacted inspection, correlation and deliberate webhook replay save debugging time | Developers keep their existing tunnel because workflow is no easier |
| 5 | Identity that fits both browsers and agents | Visitor login plus scoped expiring machine access; independently tested supported clients | Shared tokens are still the only practical path or revocation cannot bound active access |
| 6 | Cross-vendor host/tool recipes | OpenClaw, an HTTP app, SSH and two supported MCP clients work without host credential export | Integration support becomes a bespoke project per customer |

Anycast by itself is an infrastructure choice, not a durable differentiator. “Cheaper” alone loses when an adequate alternative is free. A long checklist does not establish why someone changes an existing working setup.

### Packages and acceptance

Estimates are speculative until E0 restores source evidence. Packages share components; the per-feature rows above are standalone investigation/finishing ranges and must not be added to these totals. Basic HTTP/TCP functionality and the described grant ledger are assumed reusable. If that assumption fails, re-estimate rather than spending the contingency invisibly.

| Epic | Scope and dependencies | Required result before moving on | Agent-days | Token planning range |
| --- | --- | --- | ---: | ---: |
| E0: establish the real baseline | Obtain authorized in-scope source snapshots; inspect every requested branch, license and test; select a coherent integration candidate | File/function/line citations, branch/merge map, actual have/partial/missing inventory and revised estimates | 2–4 | $40–320 |
| E1: safe transport and lifecycle | After E0, integrate relevant lifecycle/secfix/WebSocket work; authentication, CONNECT behavior, bounded buffers, reconnect/service lifecycle | Synthetic isolation/auth tests and independent review; HTTP/WS/CONNECT failure suite; no unsafe host exposure | 10–18 | $200–1,440 |
| E2: one compelling recipe and self-host path | After E1, supported OpenClaw browser recipe, packaging, diagnostic guide; minimal same-config self-host install; wingthing remains optional | Day-14 dogfood and clean install/reconnect evidence; phone browser uses tunn and application auth | 6–10 | $120–800 |
| E3: sustainable hosted pilot | After E1, integrate parent-account budgets, stream cutoff, usage, entitlements, payment sandbox reconciliation, basic management API and abuse controls | Concurrency/rollover/restart tests; cost sample reconciles; paid pilot only after Bryan's release approval | 12–22 | $240–1,760 |
| E4: credible developer alternative | After E2/E3, stable names/custom domains, polished HTTP compatibility, local inspect/replay, two webhook verifiers and support docs | Domain ownership/renewal and takeover tests; debugging tasks pass; outsiders choose and pay for the workflow | 14–24 | $280–1,920 |
| E5: team policy and protocol breadth | After E4 and demonstrated demand, common policy engine, OAuth/OIDC, scoped callers, IP/mTLS, wildcard, public TCP reservations and raw TLS | Policy ordering and tenant isolation reviewed; raw TCP/TLS tests; revocation bound; supported MCP OAuth clients pass | 18–32 | $360–2,560 |
| E6: operated multi-region service | After E3/E5, endpoint ownership, replicated control state, placement, healthy pooling, private endpoints, export and recovery | Region/relay loss exercise, restore proof, quota behavior across partitions, invoice attribution and no false SLA | 20–36 | $400–2,880 |
| E7: platform and enterprise integrations | After stable API/policy, four thin SDKs, Kubernetes controller, SSH ingress, organization UI/RBAC, SAML/SCIM and auditable administration | SDK conformance, controller reconciliation/upgrade tests, identity lifecycle and export evidence; funded operating owner | 32–60 | $640–4,800 |
| E8: device/fleet product | After E1/E5/E6, device enrollment, keys, renewal/rotation, offline lifecycle, supported packaging and maintenance flows | Per-device isolation, revoke/recover/update tests on two target platforms; defined support and update commitments | 20–40 | $400–3,200 |

**Focused developer alternative, E0–E4: 44–78 agent-days**, or 58–102 with 30% contingency rounded up. This is HTTP/WS/authenticated CONNECT plus developer workflow and a managed pilot. It does not claim raw TCP/TLS, every enterprise feature or global service equivalence.

**Broad listed feature scope, E0–E8: 134–246 agent-days**, or 188–345 with 40% contingency rounded up. This buys an implementation and acceptance effort under the baseline assumptions, not proven ngrok-scale reliability. Full security accreditation, enterprise procurement, staffed 24/7 operations, regional partnerships, long-term OS/device support and an arbitrary IP/UDP mesh are outside the estimate. Those are additional business or product commitments. Native wingthing-mobile delivery is also outside these packages; the first phone experience is a browser recipe.

The larger phases, especially E5/E7, are coarse estimates with substantial coupling. Reusable maintained protocol libraries, a single policy model, generated API clients and an established identity broker are assumed. Building novel cryptography, four independent transports or a custom SAML implementation would invalidate the ranges. Broad feature claims require new comparison/acceptance work as the competitor changes.

### Token dollars, human effort and calendar time

No current model prices were retrieved. Use an explicit hypothetical workload per agent-day:

```text
4 million uncached input tokens × $3 / million   = $12.00
12 million cached input tokens × $0.30 / million =  $3.60
0.3 million output tokens × $15 / million        =  $4.50
Illustrative daily model cost                   = $20.10
```

For coarse planning, round to **$20–80 per agent-day**, spanning roughly one to four times that workload. This is an assumption about model usage/rates, not observed productivity or a provider quote. Packages include agent testing/review iterations; billed hidden/reasoning tokens, cache misses, tool charges or a different model can change the invoice. Keep a token ledger during E0/E1 and reprice on actual work.

| Scope | Base agent-days | Base token budget | With contingency | Contingency token budget |
| --- | ---: | ---: | ---: | ---: |
| Credible developer alternative | 44–78 | $880–6,240 | 58–102 days | $1,160–8,160 |
| Broad listed scope | 134–246 | $2,680–19,680 | 188–345 days | $3,760–27,600 |

These are token dollars only. Reserve an additional **10–20 human engineer/reviewer-days** for the focused scope and **35–70** for the broad scope as an initial planning allowance. At a hypothetical $800/day those are $8,000–16,000 and $28,000–56,000, excluding infrastructure, ongoing operations, distribution, legal/license review and specialized security assessment. Human effort is not necessarily proportional to token spend. Low token prices do not remove responsibility for identity, payments and outages.

At one full-time agent the base focused scope represents roughly 9–16 five-day working weeks, broad scope 27–49, before observation time and human availability. Additional agents cannot safely divide these numbers by their count: API/identity design, integration, review, field tests and sequential dependencies remain. No agents were delegated for this report.

The $2,000 THESIS test is therefore a demand experiment against an already substantial reusable baseline, not funding for complete parity. Preserve its $450 first tranche, later earned commitments and 26-hour founder ceiling. If source review reveals the narrow safety/quotas fixes cannot fit, stop or reduce the advertised scope. Do not silently use a cheap token estimate to turn it into a larger commitment.

Use THESIS's gates: day 14 requires phone use on five days plus auth/recovery on both hosts; day 30 requires 8/10 unaided installs, repeat use and three stranger payments; day 60 requires ten payers, week-four retention, CAC/support limits and reconciled bills. Day 90 requires positive recurring contribution and another retained cohort. E5–E8 should require identifiable paying demand for their exact capabilities. A credible alternative is earned through retained customers and reliable supported tasks before feature-count parity.

## 7. Verification checklist

Nothing below is recorded as passed merely because it appears in a memo. This checklist ends the report and is the handoff for a later separately scoped verification pass.

- [ ] **Restore source evidence within the permitted workspace.** Obtain the actual tunn clone/snapshots through an authorized process; record baseline and release SHAs. This report did not fetch or inspect siblings.
- [ ] **Inspect every requested branch.** List `codex/tunn-*` and any available origin refs; examine lifecycle, dogfood, hostmode, websocket, metering and secfix diffs, bases and merges. Replace D1–D6 secondary claims with exact source paths/lines and test results.
- [ ] **Check the license and ownership.** Read actual LICENSE/SPDX/dependency terms, contributor rights, trademarks and client/server boundaries before choosing or promising AGPL/Apache terms. Verify all competitor license recollections at pinned versions.
- [ ] **Verify ngrok's current catalog and tiers.** Use official pricing, endpoint, Traffic Policy, identity, private endpoint, SSH, Kubernetes, SDK and observability documentation; record date, plan names, exact inclusions, restrictions and all usage rates. Check MCP and emerging gateway products rather than assuming the remembered inventory is complete.
- [ ] **Verify alternatives and abuse history.** Check official Cloudflare, Tailscale/Headscale, frp, rathole, zrok/OpenZiti, bore, localtunnel, Pangolin and Inlets repositories/docs/terms; obtain primary evidence before publishing any feature, license, price or phishing/interstitial claim. All such recollections above are **from training knowledge, verify**.
- [ ] **Build one integrated candidate and prove transport semantics.** HTTP redirects/cookies, WebSocket upgrade/idle/reconnect, SSE, claimed gRPC/trailers, CONNECT half-close/reset, bounded streaming and publisher loss; test public TCP/raw TLS separately if offered.
- [ ] **Prove authentication and domain isolation.** Exact allow-list, expiring single-use links, forwarding-header spoofing, cross-tenant access, session/origin policy, domain ownership/renewal/reassignment and wildcard isolation; independent review before real host traffic.
- [ ] **Measure revocation and authority.** Expire/revoke one caller during HTTP/WS/TCP and relay reconnect; distinguish new admissions, active streams and already-admitted application work. Verify host-side authorization and the declared encryption boundary.
- [ ] **Prove budgets and payments on isolated fixtures.** Parent account across grants/transports/nodes, no reset by grant recreation, atomic boundary admission, byte cutoff, UTC rollover, durable recovery, fail-closed behavior and idempotent payment/entitlement reconciliation. No production writes by agents.
- [ ] **Load-test and reconcile Fly costs.** Check official current tariffs, resale/service terms, addresses, regions, transfer legs and invoices; measure memory/CPU/connection limits, policy/ledger throughput, bursts, idle connections and actual billed-versus-payload bytes. Replace all economic assumptions with observations.
- [ ] **Run self-host/migration and recovery acceptance.** Clean install by someone other than the author; same documented config/policy, certificate renewal, backup/restore, data export, upgrade rollback and relay/region loss. Confirm SDK/controller/device claims only on supported tested platforms.
- [ ] **Earn the switching claim.** Run the same useful task through tunn and the buyer's existing solution; record onboarding time, abandonment, recovery, cost, repeat use, payment and support. Apply THESIS's day 14/30/60/90 gates before expanding the epic.
- [ ] **Re-estimate from evidence.** Replace provisional feature statuses and package ranges, measure token/human effort, and fund operating ownership separately. Keep enterprise SLA/compliance claims outside a feature checklist until independently established.
- [ ] **Respect the handoff boundary.** Any later public wording needs Bryan's approval of exact text and destination; Bryan executes production changes. This deliverable is a local Markdown report and commit only, with no code changes, network access or push.
