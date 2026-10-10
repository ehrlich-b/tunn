# Can tunn become an open-source ngrok alternative?

2026-10-10. Offline source verification in `tunn-parity-20261010`. Main baseline: `c5e5f23f584f78d1028de94543b497f13a9e5dc4`; imported draft: `065c643`. Only this document was edited; no network, deployment, code changes or push.

**Yes, as a product direction. The code already supplies much of the developer workflow, but its newest capabilities live on divergent branches. The next deliverable is a secure integrated release with sustainable account limits, not a transport rewrite.**

The 35-row inventory now contains **6 have (1 on main, 5 on branches), 17 partial and 12 missing**. These are source-presence classifications, not deployment or runtime certifications. Remaining focused scope is **30–54 agent-days**, or **39–71 with 30% contingency**. Broad listed scope is **114–210**, or **160–294 with 40% contingency**. Estimates and arithmetic are detailed in section 6.

The imported draft carried a commercial proposal from `THESIS.md`/`BET.md`: an authenticated OpenClaw phone-browser recipe, $12/year Starter and $48/year Pro, a staged $2,000 experiment, and retention/cost gates. Those files are not in this clone and were not reopened. Their numbers are retained as **inherited planning assumptions**, not checked commercial decisions or implemented plans. Code has free/pro plans and Stripe integration; it does not implement that whole proposed offer.

All competitor descriptions, license recollections, tier assignments, prices and implied uniqueness claims remain **from training knowledge, verify**. No current competitor catalog was checked. Fly/model/payment prices are hypothetical inputs. This source audit does not authorize a platform build or change the demand experiment.

## 1. Evidence boundary and branch inventory

All code references below use `alias:path:line` (or a line range), with aliases pinned to these inspected local Git objects. For example, `L:internal/client/inspector.go:178` means line 178 in `git show 006d3ca:internal/client/inspector.go`, not the working-tree file. Branch names are local remote-tracking snapshots; no fetch was attempted.

| Alias | Inspected ref | SHA | Relationship and code found |
| --- | --- | --- | --- |
| M | `origin/main` | `c5e5f23` | HTTP proxy, browser auth, account UI, Stripe billing, SQLite usage/reservations, multi-node routing; includes the older storage/auth test work |
| F | `origin/feature/tunn-2-ai-ingress` | `86cbc03` | Descends from `21e71ec`; adds initial MCP, streaming and authenticated TCP; ancestor of L |
| L | `origin/codex/tunn-lifecycle-20261010` | `006d3ca` | Descends from F through `4dad58a` and `5b2c06c`; includes inspector/replay, modern MCP bridge, deadline/correlation fixes and lifecycle CI |
| D | `origin/codex/tunn-dogfood-20261010` | `4b6bee6` | Descends from L; isolated credentials and guarded AI-host supervisor/canary kit |
| H | `origin/codex/tunn-hostmode-20261010` | `1c5910c` | Descends from L; persistent host registry, names, service commands and reconnect; standalone authenticated relay only |
| W | `origin/codex/tunn-websocket-20261010` | `f389477` | Descends from L; authenticated WebSocket upgrade/data path, token rotation, limits and tests |
| S | `origin/codex/tunn-secfix-20261010` | `41754d1` | Descends from D; shared reservation enforcement, persistent magic-link consumption, CSRF, credential stripping and account UUID quota fixes |
| O | `origin/hygiene/hosted-mcp-onboarding-20261005` | `bb8a158` | Forks at `5b2c06c`, before L fixes; HTTP ingress ledger/export, private grants, bounded MCP OAuth and preflight |
| A082 | `origin/arli/082-tunn-storage-tests-clean` | `ba5914d` | Storage hardening and tests |
| A360 | `origin/arli/360-tunn-storage-tunnel-limits` | `11fd4cf` | Tunnel-limit tests |
| A361 | `origin/arli/361-tunn-storage-magiclink-security` | `c951168` | Magic-link storage tests |
| A363 | `origin/arli/363-tunn-device-clientip-ratelimit` | `78d26e6` | Device rate-limit tests |
| A364 | `origin/arli/364-tunn-magiclink-jwt` | `ad8926f` | Magic-link JWT tests |
| A365 | `origin/arli/365-tunn-normalize-email` | `9b78cb4` | Email normalization tests; M changes the Cyrillic characterization test into a skipped desired-behavior test (`M:internal/common/normalize_email_test.go:56–78`) |
| — | Metering | Not present | **In progress**, per brief; not pushed and not inspected. Existing quota/grant/accounting code below is not evidence that this work is complete |

Main and every F/L/D/H/W/S/O tip have merge base `21e71ec`; none of those feature tips is on main. S includes D and L, but not H, W or O. H and W are siblings of D. O lacks the later L lifecycle changes. Main's `c5e5f23` also changes `internal/storage/local.go`, so preserve its hardening/tests when integrating S/H/O. The diff against a feature branch is not simply a set of additions to today's main. No merge was performed and no combined build exists from this audit.

Inspection used `git for-each-ref`, `git log --all --graph`, `git merge-base`, `git diff`, `git ls-tree`, `git grep` and numbered `git show` reads. The working tree began clean, one documentation commit ahead of origin/main. Production code, test source and branch ancestry were read; no build/test suite or remote acceptance was executed. Test files establish coverage intent, not a passing result in this session. O's `docs/HOSTED-MCP-EVIDENCE.md:81–95` explicitly leaves actual hosted-client/browser acceptance unverified.

### How missing features were checked

For every local `origin/*` tip above, inspect the file inventory and search production `.go`, `.proto`, `.sh`, `.yml` and `go.mod` content, excluding generated protobuf and tests. Missing rows below cite the closest implemented boundary plus this search scope; an absence cannot be proven by citing one source line. No claim is made about unpublished work.

| Search family | Inspected terms/surfaces | Result |
| --- | --- | --- |
| Enterprise identity | `SAML`, `SCIM`, `RBAC`; auth handlers and account schema | No implementation found; GitHub login and MCP grants are narrower |
| Kubernetes and SDKs | `k8s.io`, `sigs.k8s`, `CustomResourceDefinition`, `GatewayClass`, `IngressClass`, `kubebuilder`; dependency/package trees | No controller/CRD or supported tunn SDK surface; `pkg/proto` is generated wire code; the MCP SDK dependency is a consumed library |
| IP policy, mTLS, raw TLS | `ParseCIDR`, `netip.Prefix`, allow/deny policy, `ClientAuth`, `ClientCAs`, `GetCertificate`, `GetConfigForClient`, `ClientHello`, `VerifyPeerCertificate`; TLS configs/listeners | Internal bad-node-secret blacklist and server TLS exist; no customer CIDR policy, client-cert configuration or public raw-TLS adapter |
| SSH and public TCP | `ssh.NewServerConn`, `golang.org/x/crypto/ssh`, `tcpip-forward`, `direct-tcpip`; protocol dispatch and listeners | No SSH ingress or public TCP address allocator; TCP consumers use authenticated CONNECT |
| Domains and routing | `autocert`, `acme`, `certbot`, custom-domain/wildcard terms; host parsing and registry | Operator-owned base-domain wildcard automation exists on L; no per-tenant custom-domain ownership/ACME or customer wildcard route |
| Policy, pooling, trailers | Policy engine, round-robin/weighted backends, health checks; stream schema/forwarders; `Trailer`, `grpc-status` | Fixed path rewriting and publisher liveness exist; no general rule engine, origin pool or HTTP trailer transport |
| Operations | Prometheus/OpenTelemetry/export, suspension fields/routes, Stripe event handlers and schema | Structured logs and O ingress export exist; no metrics exporter, tenant suspension workflow or full payment reconciliation found |

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

A later price comparison must calculate the same workload for both products: active endpoint hours, paid/reserved domains, TCP addresses, requests, transfer direction, simultaneous streams, policy executions, log retention, identities and support. A remembered subscription floor is not an all-in cost. The inherited $12/year tunn offer buys a deliberately narrow, capped service; it cannot honestly be advertised as all ngrok features at that price.

## 3. tunn parity matrix: code-verified status and remaining work

- **have-on-main:** implementation for the named surface exists on M; still subject to release acceptance and identified fixes.
- **have-on-branch:** implementation exists on the named branch (alias resolves in section 1), but is not merged into M.
- **partial:** a material part exists; the row's full scope does not. Each row names the supplying refs and the remaining gap.
- **missing:** no implementation of the specified capability found in the inspected tips. Nearby primitives are not counted as the feature.

All 35 original feature rows are retained. Bundled rows remain partial when one part is missing: e.g. W has WebSockets and L has SSE, but neither establishes gRPC application forwarding. “Have” counts code presence rather than proven safety, reliability or commercial parity. One agent-day is eight hours of supervised implementation/testing/documentation effort; row estimates cover residual work and overlap. **Do not sum row estimates.** Section 6 budgets shared packages once.

| Feature | Status | Code evidence and remaining gap | Remaining agent-days | Epic |
| --- | --- | --- | ---: | --- |
| Public HTTP/HTTPS, managed TLS | partial | M: `internal/host/proxy.go:123–131`, `internal/host/webproxy.go:209–327` implement TLS termination and buffered HTTP. L: `renew-certs.sh:93–155` automates operator base-domain wildcard issuance/renewal/Fly publication. General HTTP semantics and integrated certificate lifecycle still need acceptance; no tenant certificate service | 2–4 | E1/E4 |
| WebSockets, SSE, streaming, gRPC | partial | W: `internal/host/websocket.go:28–173` implements WS; L: `internal/host/http_stream.go:20–101` streams HTTP/SSE. L: `proto/tunnel.proto:163–204` has no trailer message; `internal/client/http_stream.go:292–331` joins headers and sends body/EOF only. The gRPC tunnel itself is not gRPC application support | 3–6 | E1/E4 |
| Raw TLS forwarding/termination | missing | M: `internal/host/proxy.go:123–131` terminates HTTPS; L: `proto/tunnel.proto:154–169` defines HTTP/TCP adapters. No public raw TLS/SNI routing or TLS endpoint configuration (section 1 searches) | 6–12 | E5 |
| Authenticated TCP transport | have-on-branch (L: lifecycle) | L: `internal/client/connect.go:26–124`, `internal/host/tcp_stream.go:12–135` and `internal/client/http_stream.go:106–177` implement CONNECT, byte forwarding and half-close messages; `internal/client/tcp_stream_test.go:283` covers HTTP/2 CONNECT. Integrate and verify disconnect/backpressure semantics | 1–3 | E1 |
| Public raw TCP and reserved host:port | missing | S: `internal/host/webproxy.go:232–239` explicitly requires tunn CONNECT; L: `internal/client/connect.go:26–45` binds the consumer's local listener. No arbitrary-client public port or address reservation service | 7–12 | E5 |
| Custom domains and automatic certificates | missing | M: `internal/host/auth.go:636–655` extracts names beneath one configured domain; L: `renew-certs.sh:93–111` handles that operator's domain. No per-tenant domain registry, DNS ownership proof, SNI certificates or customer ACME lifecycle | 5–9 | E4 |
| Wildcard domains | partial | M: `setup-certs.sh:23–36` and L: `renew-certs.sh:101–111` supply the relay's wildcard certificate. M: `internal/host/auth.go:643–655` routes literal tunnel names. Customer-owned wildcard endpoints and tenant-safe wildcard matching are missing | 3–6 after domains | E5 |
| Reserved service subdomains | have-on-branch (S: secfix) | M: `internal/store/accounts.go:257–355` persists Pro reservations; S: `internal/storage/local.go:153–205` enforces ownership/auto-claim through shared registration. H: `internal/store/hosts.go:38–95` adds atomic persistent machine names. Reconcile H's standalone ten-name model with hosted plan limits and removal UX | 1–3 | E3/E4 |
| Browser email allow-list and GitHub/magic-link login | have-on-main | M: `internal/host/webproxy.go:127–185`, `internal/host/auth.go:303–332`, `internal/host/magiclink.go:161–218`. S: `internal/host/csrf.go:53–120`, `internal/storage/local.go:249–268` add CSRF/browser binding and durable single-use consumption. These fixes need integration despite the feature existing on main | 2–4 | E1 |
| General OAuth/OIDC endpoint auth | partial | M: `internal/host/auth.go:303–332` supplies GitHub OAuth; O: `internal/host/mcp_oauth.go:118–150` supplies MCP authorization metadata. No configurable arbitrary OIDC identity provider, claims/group policy or general endpoint OAuth adapter | 5–10 | E5 |
| MCP OAuth/client interoperability | partial | L: `internal/mcpbridge/bridge.go:84–152` supplies stdio-to-HTTP bridging. O: `internal/host/mcp_oauth.go:220–270,364–425` implements owner consent and S256 PKCE exchange; `internal/client/mcp_check.go:45` implements preflight. Static clients, no refresh/DCR, and actual hosted-client acceptance remains open (`docs/HOSTED-MCP-EVIDENCE.md:81–95`) | 3–6 | E2/E5 |
| SAML endpoint auth and organization SSO | missing | M: `internal/host/proxy.go:667–685` routes GitHub/magic-link/device auth; O: `internal/host/mcp_oauth.go:118–126` is MCP-only. No SAML protocol or organization SSO model in the searched sources | 8–14 | E7 |
| IP allow/deny | missing | M: `internal/host/proxy.go:389–451` blacklists failed internal node-secret callers; `internal/host/device.go:268–297` rate-limits login IPs. Neither is a customer endpoint CIDR allow/deny policy; none found | 2–4 | E5 |
| Mutual TLS at ingress/upstream | missing | M: `internal/host/proxy.go:128–131,772–782` configures server certificates and explicitly no internal client auth; L: `internal/client/http_stream.go:268–274` configures upstream verification, not client certificates. No customer mTLS/CA rotation controls | 4–8 | E5 |
| Webhook signature verification | missing | M: `internal/host/stripe.go:90–102,278–325` verifies tunn's own billing webhook only. M: `internal/host/proxy.go:685–688` routes that separately from customer traffic. No configurable ingress verifier for customer webhooks; reuse the primitive, not the billing handler | 3–6 for two providers | E4 |
| Traffic policy, rewrites and redirects | partial | L: `internal/client/serve.go:526–553` rewrites fixed public/upstream paths and queries. No typed conditional policy engine, general header/response actions, configurable redirects or policy administration | 7–12 | E5 |
| Account rate/byte/request/stream limits | partial | M: `internal/host/limits.go:15–38` and `internal/storage/local.go:198–243` supply monthly bytes, per-tunnel rate and publisher limits. S: `internal/host/proxy.go:1039–1061` fixes fail-closed account admission; O: `internal/store/grants.go:185–262` caps grant requests. L: `internal/host/http_stream.go:161–164`, W: `internal/host/websocket.go:115–118` account at stream completion. Atomic parent-account admission/active byte cutoff and aggregate stream limits remain **in progress (metering)** | 5–9 | E3 |
| HTTP load balancing, health and failover | missing | M: `internal/host/webproxy.go:72–108` finds the one relay owning a tunnel; `internal/host/grpc_server.go:365–378` rejects duplicate publishers. No pool of independently health-checked origins, weights, retries or origin failover | 6–12 | E6 |
| API gateway | partial | M: `internal/host/webproxy.go:127–205` composes browser auth/quota/proxy; L: `internal/client/serve.go:526–553` adds path mapping. O has scoped MCP grants. General routing/policy, API governance, versioning and customer secrets management remain | 7–13 beyond policy | E5/E7 |
| Kubernetes operator, Ingress/Gateway integration | missing | L: `go.mod:7–43` has no controller dependencies; `proto/tunnel.proto:9–15` is a tunnel RPC. All-tip tree/search inspection found no CRD/controller/Ingress/Gateway manifests or reconciliation implementation | 10–18 | E7 |
| Embedded Go/Rust/Python/JS SDKs | missing | L: `internal/client/connect.go:26–124` is internal client code; `go.mod:12` consumes an MCP SDK. Public `pkg/proto` contains generated protobuf stubs only. No supported tunn SDK packages/examples for the four languages | 10–18 for four thin SDKs | E7 |
| Local traffic inspection UI | have-on-branch (L: lifecycle) | L: `internal/client/inspector.go:21–23,60–83,241–314` implements a secret-protected random loopback UI with 50 events and 64 KiB request-body cap. `internal/client/inspector_test.go:100–159` covers Host/token checks. Request headers/bodies are retained unredacted in process; add redaction/UX acceptance | 1–2 | E4 |
| Replay | have-on-branch (L: lifecycle) | L: `internal/client/inspector.go:178–238,261–276` explicitly replays complete captured requests to the configured local target with token/origin checks; `internal/client/inspector_test.go:17–69` covers replay/truncation. No cloud retention/replay implied | 1–2 | E4 |
| Metrics, structured logs and export | partial | M: `internal/common/logging.go:43–78` uses structured slog; O: `internal/store/ingress.go:100–155`, `internal/host/ingress.go:143–200` implement idempotent HTTP completion counters and owner-scoped export. Queue overflow can lose events (`internal/host/ingress.go:81–102`); no full transport metrics/OTel export or security audit trail | 3–6 | E3/E6 |
| Standard SSH reverse-tunnel ingress | missing | L: `internal/client/connect.go:75–87` is authenticated HTTP CONNECT. SSH carried through its local TCP socket is not `ssh -R` to a tunn SSH server. No SSH server/forwarding request handler found | 5–9 | E7 |
| Hosted edge and global points of presence | partial | M: `internal/host/proxy.go:280` discovers peers; `internal/host/webproxy.go:72–108,338–379` routes to an owner and invalidates a stale cache. L: `fly.toml.dist:1–49` configures one primary region and limits. No inspected deployment, replicated login authority, regional failover proof or SLA | 10–18 | E6 |
| Private endpoints/internal services | partial | S: `internal/host/webproxy.go:124–183` authenticates public-edge routes; H: `internal/host/hosts.go:18–24` requires standalone authenticated host mode. These are access-controlled endpoints, not a private-only network namespace, internal-only edge or service mesh | 7–13 | E6 |
| Device/IoT connectivity | partial | H: `internal/store/hosts.go:20–41,110–160` persists machine inventory/last-seen state; `internal/hostmode/runtime.go:117–178` reconnects publishers. Per-device provisioning identity, rotation, OTA and fleet policy are absent. CLI device-code login on M is user OAuth, not fleet enrollment | 10–20 | E8 |
| Dashboard and management API | partial | M: `internal/host/auth.go:768–859` renders plan/usage/checkout/portal UI. H: `internal/host/hosts.go:62–154` adds authenticated host list/register; O: `internal/host/grants.go:97–190` adds grant CRUD. General endpoint/team administration and a stable public API remain | 5–9 | E3/E7 |
| Billing and entitlements | partial | M: `internal/host/stripe.go:62–140,183–232` verifies Stripe webhooks and upgrades/downgrades free/pro; `internal/host/auth.go:806–845` supplies checkout/portal links. No durable event ordering/idempotency/reconciliation or full proposed Starter entitlement model; metering is **in progress** | 4–7 | E3 |
| Revocable per-caller credentials/RBAC | partial | O: `internal/store/grants.go:101–127,168–262` stores hashed, expiring, endpoint-scoped grants with revoke/request caps; `internal/host/grants.go:57–95` admits them. L: `proto/tunnel.proto:206–209` rotates an endpoint digest. Per-grant active-stream cutoff, general roles and tool-level authority are not supplied by those grants | 3–6 | E3/E5 |
| Publisher lifecycle/service install | have-on-branch (H: hostmode) | H: `internal/hostmode/runtime.go:117–178`, `internal/hostmode/service.go:58–114,139–184` implement reconnect and launchd/systemd-user/Windows logon-task install. D: `deploy/ai-hosts/runner.py:105–167` supplies a guarded supervisor/health kit. Service test fixtures are not proof of installs on every OS; integrate, package and run acceptance | 2–4 | E1/E2 |
| Self-hosted complete distribution | partial | M: `main.go:203–242`, `internal/store/db.go:19–61`, `Dockerfile:1–21` ship relay/SQLite/container source; `.github/workflows/release.yml:15–28` builds macOS/Linux binaries. `README.md:66–68` declares MIT, but no full LICENSE text is tracked. Integrated features, portable install/upgrade/restore and license packaging still need completion | 3–6 | E2/E6 |
| Abuse response, tenant suspension and free-tier controls | partial | M: `internal/host/device.go:268–297`, `internal/storage/local.go:292–328`, `internal/host/limits.go:15–30` implement auth throttles and free/pro limits. `internal/store/db.go:95–120` has no suspended-account state; no suspension/report/takedown workflow found. S hardens quotas; aggregate metering remains unfinished | 3–6 initially | E3 |
| Enterprise audit/RBAC/SCIM/support readiness | missing | M: `internal/store/db.go:95–129` models accounts/emails/usage/names, not organizations/roles/SCIM. O: `internal/store/ingress.go:15–43` records traffic metadata, not administrative audit actions. No enterprise identity lifecycle or contractual/operational assurance established | 10–20 plus operations | E7 |

**Counts: 35 = 1 have-on-main + 5 have-on-branch + 17 partial + 12 missing.** Branch have rows are authenticated TCP, reservations, inspector, replay and publisher service lifecycle. WebSockets/MCP/host inventory add real capabilities within partial bundled rows; the count does not erase them.

### Release blockers supported by the code

Main passes a creator email into the account-ID quota API (`M:internal/host/webproxy.go:189–197`) and allows traffic when usage cannot be read (`M:internal/host/proxy.go:997–1019`). S switches to AccountID and fails closed (`S:internal/host/webproxy.go:220–229`, `S:internal/host/proxy.go:1039–1061`). S also persists consumed magic links and enforces reservation ownership centrally. These are existing fixes to integrate, not proof that main is ready for an advertised safe hosted pilot. Relevant regression sources include `S:internal/host/security_regression_test.go:159,207,248,369,492` and `S:internal/host/csrf_test.go:27–220`; they were not run here.

HTTP compatibility still needs real work: L joins response header values into a string and sends no trailers (`L:internal/client/http_stream.go:282–331`). Its origin client follows redirects by default, unlike the inspector replay client (`L:internal/client/inspector.go:215–217`). Verify cookies, redirects, trailers, streaming, empty/large bodies and publisher disconnect together after integration. WebSocket tests are substantial (`W:internal/host/websocket_integration_test.go:387–850`), but they do not include S/H/O merely because their branches exist.

### What tunn has that ngrok doesn't

The requested comparison cannot establish ngrok's absence offline. The table therefore records **tunn capabilities proven in source and candidate differentiators**, without claiming verified exclusivity. Every inference that ngrok lacks an equivalent remains **from training knowledge, verify**; email auth and WebSockets especially must not be advertised as unique merely because tunn implements them.

| Evidence-backed tunn capability | Implementation and boundary |
| --- | --- |
| Email-gated sharing | M: `internal/host/webproxy.go:127–185,427–456` supports individual addresses, email-domain allow-lists and verified account email buckets; M: `internal/host/magiclink.go:161–218` permits email-only login. This is concrete sharing behavior, not just a password on the URL |
| Built-in stdio MCP bridge and child lifecycle | L: `internal/mcpbridge/bridge.go:84–152,282–293,465–533` starts a local child behind loopback HTTP, gates tools, bounds queue/write/wait and uses per-request child IDs; `internal/mcpbridge/modern.go:107–153` handles child initialization/discovery. O separately adds bounded consent/PKCE and per-caller grants; it must be integrated with L fixes |
| Persistent machine/host mode | H: `internal/store/hosts.go:38–95,127–160`, `internal/hostmode/runtime.go:117–178`, `internal/hostmode/service.go:58–114` preserve names/offline inventory and supervise multiple endpoints with native per-user service definitions. `internal/host/hosts.go:18–24` limits it to one authenticated standalone relay; it is not hosted multi-node fleet management |
| Authenticated WebSockets tied to tunn access | W: `internal/host/webproxy.go:134–189` authenticates before upgrade; `internal/host/websocket.go:28–99` binds pending connections to access and closes them on revocation/disconnect. Token rotation is exercised in `internal/host/websocket_integration_test.go:553–647`. No general email-session revocation bound or ngrok absence is inferred |
| Self-hostable relay and client source | M: `main.go:203–242`, `Dockerfile:1–21`, `internal/store/db.go:19–61` include server startup, packaging and SQLite state; L: `internal/host/grpc_server.go:302–314` supports self-hosted secret/user-token authentication. README declares MIT; complete license text/rights and fresh-install portability still need checking. A proprietary hosted control plane is not required by these code paths |

## 4. Keeping the product open source

The README declares **MIT** (`M:README.md:66–68`; also `L:README.md:195–197`). No LICENSE/COPYING/NOTICE file was found in any inspected tip. That corrects the draft's “unknown license” claim without inventing missing license text or contributor rights. No relicense is performed. The following AGPL/Apache split is retained as a proposed future policy, not the current license; resolve ownership, notices and dependency terms before adopting it.

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

The code contains login-node storage and relay routing (`M:internal/store/db.go:19–21`, `M:internal/host/webproxy.go:72–108`); the inspected config is `fly.toml.dist`, not `fly.toml`. L configures `iad`, a 512 MB shared CPU VM, and 250/200 hard/soft connection limits (`L:fly.toml.dist:1–49`); M's older example instead names `ewr` (`M:fly.toml.dist:1–23`). Neither file is a deployment receipt. Fly was not contacted. As an architectural model, anycast can provide a common ingress address and route users into a provider network. It does not establish replicated tunn state, endpoint ownership, nearby origins, successful stream migration, cheap egress or an application SLA.

```text
visitor -> ingress -> relay owning publisher connection -> customer origin
                         |
                    account / policy / quota state
```

If ingress arrives away from the owning relay, an extra network hop and potentially extra billed transfer appear. A publisher's existing TCP connection cannot simply move to another machine. Failover generally requires reconnection and route re-registration; live application requests may fail and must not be silently replayed. Regional policy/cache replication and account quotas need their own consistency design.

A credible multi-region design needs authenticated registration, endpoint ownership fencing, relay discovery, draining, bounded stale routes, recoverable credentials/certificates, healthy origin selection and regional accounting. Start with one verified billing region, then add placement only for an observed need. Two machines on a provider network are not evidence of control-plane high availability.

### Cost model and unit margins

All amounts below are USD, excluding tax. Retain the imported draft's planning inputs (the original memos were not read in this clone):

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

Recalculation confirms 59.6% and 57.1% low-cost gross margins, including the free cohort, and approximately $3.99 Pro loss in the high-cost case. Offering 50 GB globally at $48/year is therefore not supported by these assumptions.

At the low-cost Starter contribution, three months earns `$0.446 × 3 = $1.338`, supporting the inherited $1.25 acquisition target. At $60/hour, $0.15 buys nine seconds of support per month. A single five-minute support interaction costs $5, more than eleven months of that contribution. Annual cash collection is not immediate annual profit.

Uploads relayed to the publisher and downloads relayed to a visitor each have an outbound leg. Counting both payload directions once is different from charging every response twice. Protocol headers, TLS framing, auth mail, retries, health traffic and cross-region forwarding add costs; body-byte counters alone will not reconcile an invoice. The inherited hypothetical `$0.006/GB` additional transit leg would add `$0.0075` per payload GB at the same multiplier, or $0.375/month for a full 50 GB account. Verify actual topology and tariffs.

### Scaling scenarios, not measured capacity

Assume 80% Starter and 20% Pro payers, all using full allowances; free users equal 20% of payers at 1 GB; low-cost egress; and a **placeholder fixed-capacity budget of $0.20 per payer/month**, growing with the fleet. This intentionally does not hold a $20 two-machine fleet constant at large scale. The linear budget is still unverified and is not a hardware sizing claim.

| Payers / free accounts | Monthly revenue | Total payload/month | Egress cost | Fleet/base budget | Payment + variable operations | Gross | After modeled support |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 / 20 | $160 | 1.1 TB | $27.50 | $20 | $19.14 | $93.36 | $78.36 |
| 1,000 / 200 | $1,600 | 11 TB | $275 | $200 | $191.40 | $933.60 | $783.60 |
| 10,000 / 2,000 | $16,000 | 110 TB | $2,750 | $2,000 | $1,914 | $9,336 | $7,836 |
| 100,000 / 20,000 | $160,000 | 1.1 PB | $27,500 | $20,000 | $19,140 | $93,360 | $78,360 |

These exclude acquisition, engineering, incident coverage, taxes, refunds/disputes and enterprise obligations. They do not establish that request costs or support stay linear. An additional $0.50/payer/month of capacity or operations removes $5,000/month at 10,000 payers; the modeled $7,836 becomes $2,836. One minute of support per payer costs $1 rather than $0.15 and makes that scale case negative before acquisition. A $5,000/month incident/support function also consumes most of its contribution.

The capacity constraints are connections, memory, CPU, ledger throughput and correlated bursts, not merely average GB. At 10,000 payers in this mix, payer stream caps permit `8,000×4 + 2,000×40 = 112,000` simultaneous forwarded streams; the 2,000 free accounts add 4,000, before publisher/control connections. The inherited aggregate monthly payer request assumption is 1.08 billion, about 417 requests/second over 30 days, before free users and bursts; the draft does not specify enough per-plan inputs to reconstruct that aggregate, so it is an unverified scenario input. These request/stream caps are scenario inputs, not enforced code limits. L's `fly.toml.dist:29–32` sets a 250-connection service/machine limit, but a provider connection is not necessarily identical to a multiplexed application stream. Measure both before converting the caps into machine counts.

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

Source inspection completes E0's inventory work. The remaining ranges credit inspected implementations, but include integration and acceptance. They do not credit unpublished metering as finished. No productivity measurement or new runtime receipt supports treating these estimates as commitments. Per-feature rows overlap these packages and must not be added.

| Epic | Scope and dependencies | Required result before moving on | Remaining agent-days | Token planning range |
| --- | --- | --- | ---: | ---: |
| E0: establish the real baseline | This document pins refs, verifies all rows and corrects estimates | Completed source inventory; integrated build/acceptance moves to E1 | 0 | $0 |
| E1: safe transport and lifecycle | Integrate M/L/S/W/H and relevant O changes; preserve main's tests; resolve auth, credential, registry and stream overlaps | One pinned candidate; independent security review; HTTP/WS/CONNECT/MCP lifecycle and failure tests; no unsafe host exposure | 8–14 | $160–1,120 |
| E2: one compelling recipe and self-host path | Reuse H service/config and D kit; supported OpenClaw browser recipe, license packaging and clean install/reconnect | Day-14 dogfood, phone/app auth and repeatable standalone install; service definitions exercised on supported OSes | 3–6 | $60–480 |
| E3: sustainable hosted pilot | Reuse M Stripe/account UI and O grants/export; finish in-progress account metering, active cutoff, durable payment reconciliation, entitlements and abuse controls | Atomic concurrent limits, rollover/restart/revoke tests, sandbox billing reconciliation and measured cost; Bryan owns production release | 10–18 | $200–1,440 |
| E4: credible developer alternative | Reconcile existing names, add customer domains/cert lifecycle; fix HTTP compatibility, redact/polish existing inspect/replay, two webhook verifiers and docs | Domain ownership/renewal/takeover tests; correct headers/cookies/redirects; debugging tasks and outsider adoption | 9–16 | $180–1,280 |
| E5: team policy and protocol breadth | After E4/demand, policy engine, arbitrary OAuth/OIDC, caller authority, IP/mTLS, wildcard/public TCP/raw TLS; integrate O's bounded OAuth and prove supported clients | Reviewed policy/tenant isolation, protocol conformance and revocation bound; hosted MCP-client acceptance | 18–32 | $360–2,560 |
| E6: operated multi-region service | Reuse node discovery/forwarding, but build replicated control state, placement/fencing, healthy origin pools, private-only endpoints and resilient export/recovery | Relay/region loss and restore exercises, partition-safe accounting, measured placement/cost; no inferred SLA | 18–32 | $360–2,560 |
| E7: platform and enterprise integrations | Stable API/policy first; four thin SDKs, Kubernetes controller, SSH ingress, organization UI/RBAC, SAML/SCIM and administration audit | SDK/controller conformance, identity lifecycle/export and funded operating owner | 30–56 | $600–4,480 |
| E8: device/fleet product | Reuse H inventory/services; add per-device credentials, provisioning/rotation, offline lifecycle, update/maintenance workflows | Two target-platform revoke/recover/update tests and explicit support/OTA commitments | 18–36 | $360–2,880 |

**Focused developer alternative, remaining E0–E4: 30–54 agent-days**, or **39–71 with 30% contingency rounded up**. The previous 44–78 assumed more missing code: E0 2–4 → 0; E1 10–18 → 8–14; E2 6–10 → 3–6; E3 12–22 → 10–18; E4 14–24 → 9–16. Inspector/replay, service installation, billing and reservations need finishing/integration rather than first implementation. This scope is HTTP/WS/authenticated CONNECT plus a useful developer workflow and managed pilot; gRPC application parity, public raw TCP/TLS and enterprise/global equivalence remain outside it.

**Broad listed feature scope, remaining E0–E8: 114–210 agent-days**, or **160–294 with 40% contingency rounded up**. Existing discovery/export and host services reduce E6/E8; existing account/API building blocks modestly reduce E7. E5 retains the original range because general policy and public protocol breadth remain substantial despite bounded MCP OAuth reuse. Full accreditation, staffed 24/7 operations, regional partnerships, long-term OS/device support, arbitrary IP/UDP mesh and native mobile delivery remain outside this implementation estimate.

### Top five gaps for a credible developer alternative

1. **One secure integrated release:** combine S's quota/auth/ownership fixes, W's authenticated sockets, H's persistence and L's lifecycle without losing O's grant checks or main's tests; prove HTTP semantics and recovery on that exact build.
2. **Account-wide metering and active cutoff:** atomic bytes/requests/streams across grants, transports and nodes, durable restart/rollover behavior and fail-closed admission. Metering is still in progress.
3. **Customer domains and certificate lifecycle:** ownership verification, automatic renewal, takeover prevention and a coherent hosted stable-name entitlement model.
4. **Reliable paid-pilot operations:** durable/idempotent payment reconciliation, correct entitlements, tenant suspension and cost/usage visibility across all supported transports.
5. **A repeatable supported workflow:** real phone/OpenClaw and self-host install/reconnect acceptance, redacted debugging/replay, customer webhook verification and complete license/release packaging.

The larger phases, especially E5/E7, are coarse estimates with substantial coupling. Reusable maintained protocol libraries, a single policy model, generated API clients and an established identity broker are assumed. Building novel cryptography, four independent transports or a custom SAML implementation would invalidate the ranges. Broad feature claims require new comparison/acceptance work as the competitor changes.

### Token dollars, human effort and calendar time

No current model prices were retrieved. Use an explicit hypothetical workload per agent-day:

```text
4 million uncached input tokens × $3 / million   = $12.00
12 million cached input tokens × $0.30 / million =  $3.60
0.3 million output tokens × $15 / million        =  $4.50
Illustrative daily model cost                   = $20.10
```

For coarse planning, round to **$20–80 per agent-day**, spanning roughly one to four times that workload. This is an assumption about model usage/rates, not observed productivity or a provider quote. Packages include agent testing/review iterations; billed hidden/reasoning tokens, cache misses, tool charges or a different model can change the invoice. Keep a token ledger during E1 and reprice on actual work.

| Scope | Base agent-days | Base token budget | With contingency | Contingency token budget |
| --- | ---: | ---: | ---: | ---: |
| Credible developer alternative | 30–54 | $600–4,320 | 39–71 days | $780–5,680 |
| Broad listed scope | 114–210 | $2,280–16,800 | 160–294 days | $3,200–23,520 |

These are token dollars only. Reserve an additional **10–20 human engineer/reviewer-days** for the focused scope and **35–70** for the broad scope as an initial planning allowance. At a hypothetical $800/day those are $8,000–16,000 and $28,000–56,000, excluding infrastructure, ongoing operations, distribution, legal/license review and specialized security assessment. Human effort is not necessarily proportional to token spend. Low token prices do not remove responsibility for identity, payments and outages.

At one full-time agent the base focused scope represents roughly 6–11 five-day working weeks, broad scope 23–42, before observation time and human availability. Additional agents cannot safely divide these numbers by their count: API/identity design, integration, review, field tests and sequential dependencies remain. No agents were delegated for this report.

The inherited $2,000 demand test is therefore a demand experiment against an already substantial reusable baseline, not funding for complete parity. Preserve its $450 first tranche, later earned commitments and 26-hour founder ceiling. If integration and metering cannot fit the narrow safety/quotas budget, stop or reduce the advertised scope. Do not silently use a cheap token estimate to turn it into a larger commitment.

Retain the imported proposal's gates (not revalidated commercial instructions): day 14 requires phone use on five days plus auth/recovery on both hosts; day 30 requires 8/10 unaided installs, repeat use and three stranger payments; day 60 requires ten payers, week-four retention, CAC/support limits and reconciled bills. Day 90 requires positive recurring contribution and another retained cohort. E5–E8 should require identifiable paying demand for their exact capabilities. A credible alternative is earned through retained customers and reliable supported tasks before feature-count parity.

## 7. Verification results and remaining acceptance

Completed in this audit:

- [x] Read the task brief in full, then inspected only the permitted clone; edited only `NGROK-PARITY.md`.
- [x] Pinned main, all five current codex branches, AI-ingress, all six arli branches and the additional onboarding branch; checked ancestry and code boundaries.
- [x] Replaced every inventory row with a source-grounded classification and file:line evidence; kept unpublished metering in progress and competitor facts **from training knowledge, verify**.
- [x] Inspected license declarations/package inventory: README says MIT; full license text is absent in the inspected trees. No licensing change made.
- [x] Recomputed the 35-row status counts, epic totals, contingency rounding, token budgets, unit margins and scaling arithmetic. The aggregate request allowance lacks its original per-plan inputs and remains explicitly unverified.

Arithmetic receipt (decimal units; ceiling only where stated):

```text
Focused: 0+8+3+10+9 = 30; 0+14+6+18+16 = 54
Broad:   30+18+18+30+18 = 114; 54+32+32+56+36 = 210
Contingency: ceil(30*1.30)=39; ceil(54*1.30)=71
             ceil(114*1.40)=160; ceil(210*1.40)=294
Token budgets: low days*$20; high days*$80 (both base and contingency)
Payment fees: (12*.029+.30)/12=.054; (48*.029+.30)/12=.141
100-payer mix: payload=80*1+20*50+20*1=1,100 GB
Revenue=$160; egress=1,100*1.25*.02=$27.50
Fees+variable=80*.054+20*.141+120*.10=$19.14
Gross=160-27.50-20-19.14=$93.36; after support=$78.36
Other scenario rows scale by 10, 100 and 1,000 under the stated linear assumption
Streams: 8,000*4+2,000*40+2,000*2=116,000 (proposed caps, not code)
1.08e9/(30*24*3600)=416.667 requests/second (aggregate input unverified)
Daily tokens: 4*3+12*.30+.3*15=$20.10
```

Still required before advertising or operating the corresponding feature:

- [ ] Build and test one integrated candidate; this session ran no source tests, merge, production command or external acceptance. Existing test sources/recorded historical receipts do not certify the combined release.
- [ ] Prove authentication/domain isolation, persistent single-use links, forwarding-header/credential handling and caller revocation during HTTP/WS/TCP/reconnect; distinguish new admissions from active streams and already-admitted application work.
- [ ] Complete and test account-wide budgets on isolated fixtures; verify concurrency, active cutoff, UTC rollover, durable recovery, fail-closed storage and payment ordering/reconciliation. Bryan executes production changes.
- [ ] Verify HTTP cookies/redirects/header multiplicity/streaming and the exact claimed protocol set; trailers/gRPC and raw TCP/TLS need separate implementation/acceptance.
- [ ] Run clean self-host install, supported OS service lifecycle, upgrade/rollback, backup/restore and host/region-loss acceptance. Resolve license text/rights before distribution claims or any relicense.
- [ ] Verify current ngrok/alternative catalogs, tiers, licenses and prices from primary sources in a separately network-authorized task. The requested uniqueness heading is not evidence of competitor absence.
- [ ] Measure Fly capacity, transfer legs, current tariffs, invoices, support and usage; the financial tables are internally consistent scenarios, not validated unit economics.
- [ ] Earn switching/retention/payment evidence on supported tasks before expanding E5–E8; re-estimate from observed integration work and operating costs.

The deliverable is this local report and its commit. No network, push or production mutation is part of this task.
