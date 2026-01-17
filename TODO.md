# TODO.md: tunn Reboot

## TOP PRIORITY: Fix Issues in REVIEW.md

**Code Audit Date:** 2025-01-17

A comprehensive audit found critical security issues, bugs, and dead code. **See [REVIEW.md](REVIEW.md) for the full list.**

### Quick Summary of REVIEW.md

**P0 - Security (Deferred - OAuth not core value prop):**
- [ ] Fix `validateToken` - currently returns hardcoded `user@example.com`
- [ ] Fix `exchangeCodeForToken` - currently returns auth code as token
- [ ] Fix `getJWTSigningKey` - currently returns `"TODO_CONFIGURE_JWT_SECRET"`
- [x] Remove token logging from debug output - **FIXED 2025-01-17**
- [ ] Fix `ExtractEmailFromJWT` trust boundary

**P1 - Bugs:**
- [x] Fix multi-value header handling (Cookie, Set-Cookie broken) - **FIXED 2025-01-17**
- [x] Use config domain in public URL (hardcoded "tunn.to") - **FIXED 2025-01-17**

**P2 - Dead Code:**
- [x] Remove legacy `ProxyResponse` handler - **FIXED 2025-01-17**
- [x] Remove legacy `handleProxyRequest` - **FIXED 2025-01-17**

**P3 - Code Quality:**
- [x] Remove emoji from output - **FIXED 2025-01-17**
- [x] Fix excessive INFO logging - **FIXED 2025-01-17**
- [x] Consolidate duplicate AuthTransport types - **FIXED 2025-01-17**

**P4 - Test Suite:**
- [x] Add `handleHttpRequest` tests - **ADDED 2025-01-17**
- [x] Add `proxyHTTPOverGRPC` tests - **ADDED 2025-01-17**
- [x] Add multi-header tests - **ADDED 2025-01-17**
- [x] Add allow-list enforcement tests - **ADDED 2025-01-17**
- [x] Add timeout tests - **ADDED 2025-01-17**
- [x] Add concurrent request tests - **ADDED 2025-01-17**

**P5 - Features:**
- [x] Implement reconnection with exponential backoff - **ADDED 2025-01-17**

---

## Legacy TODO (Pre-Reboot)

**Important:** Always use `make` for building and testing. See CLAUDE.md for details.

## Phase 0: Project Setup & Prototyping ✅

- [x] **Define Protobuf API:** Create the `.proto` file for the gRPC control plane. Define the `TunnelService` with a bidirectional `EstablishTunnel` RPC. Define messages for client registration, proxy instructions, and health checks.
- [x] **Generate gRPC Code:** Generate the Go client and server code from the `.proto` file.
- [x] **Vendor Dependencies:** Remove `h2rev2` (will be removed when code is refactored). Add `google.golang.org/grpc`, `google.golang.org/protobuf`, `github.com/quic-go/quic-go`, `github.com/golang-jwt/jwt/v4`, and `github.com/alexedwards/scs/v2`.
- [x] **Create Mock OIDC Server:** Build a simple, test-only HTTP server that implements the minimal OIDC and Device Flow endpoints needed for local testing.

## Phase 1: The New `tunn` Proxy ✅

- [x] **Implement Dual-Listener Server:** Structure the main `host` application to launch two goroutines: one for the HTTP/3 (QUIC) server and one for the HTTP/2 (TCP) server.
- [x] **Implement gRPC Server:** Create the gRPC server and implement the `EstablishTunnel` method. Accepts connections, handles registration, health checks, and maintains active tunnel connections.
- [x] **Implement HTTPS/gRPC Router:** On the HTTP/2 listener, created a router that examines `Content-Type` header to route between gRPC and HTTPS traffic.
- [x] **Add Local Testing Config:** Created config package with dev/prod environments. Dev mode uses nip.io domains, local certs, and automatically starts mock OIDC server on :9000.

## Phase 2: The New `tunn serve` ("Sharer") ✅

- [x] **Refactor `serve` Command:** Created new gRPC-based ServeClient in `internal/client/serve.go` (legacy h2rev2 code remains in `client.go` for now).
- [x] **Implement gRPC Client:** ServeClient establishes bidirectional stream to proxy's `TunnelService` and sends `RegisterClient` message.
- [x] **Implement Control Loop:** Client processes incoming messages (ProxyRequest, HealthCheckResponse) and sends periodic health checks every 30 seconds. *(Note: The handler for `ProxyRequest` is currently a stub and does not yet forward data.)*

## Phase 3: Inter-Node Communication

- [x] **Define Internal Protobuf API:** Create `internal.proto` for node-to-node communication (e.g., `FindTunnel`).
- [x] **Generate Internal gRPC Code:** Generate the Go code from `internal.proto`.
- [x] **Implement Internal gRPC Server:** Add the internal gRPC service to the main proxy server to handle `FindTunnel` requests.
- [x] **Implement Node Discovery:** Add a mechanism for nodes to discover each other (e.g., via DNS).
- [x] **Implement Sequential Probing:** When a node receives a request for a tunnel it doesn't have, it will probe other nodes.
- [x] **Implement Inter-Node Proxying:** Proxy requests to the correct node after discovery.
- [x] **Secure Inter-Node Communication:** Secure the internal gRPC channel using TLS with a private CA.

## Phase 4: Browser Auth Flow (Web) ✅

- [x] **Integrate Session Manager:** Initialize and add the `scs.SessionManager` middleware to the web request handler chain.
- [x] **Implement Web Auth Handlers:** Create the `/auth/login` and `/auth/callback` handlers that use the (mock) OIDC service to authenticate a user.
- [x] **Implement `CheckAuth` Middleware:** Create the middleware to check for a valid session cookie on incoming web requests to subdomains.
- [ ] **Connect Web Proxy:** When an authenticated web request arrives, the proxy handler will find the appropriate `Server Client` via the gRPC control plane. Full data plane proxying will be implemented in a future phase. *(Critique: Unchecked because while the control plane lookup is implemented, the data plane is not. A web request to a tunnel does not yet proxy data, so the feature is not "working" end-to-end.)*

## Phase 5: CLI Auth ✅

- [x] **Implement Device Flow (`tunn login`):** Create the `tunn login` command that performs the OAuth Device Authorization Grant against the (mock) OIDC provider to retrieve and save a JWT.
- [x] **Implement `CheckJWT` Middleware:** Create middleware to validate JWTs on incoming API requests.

## Phase 6: V1 Launch Features - FREE TIER WITH GOOGLE AUTH ✨

**NEW ARCHITECTURE DECISION (2025-11-16):** Launch with Google OAuth only, no billing, no tunn-auth. Use WELL_KNOWN_KEY for free tunnel creation.

**The 4-Layer Auth Model:**
1. **Identity:** Google OAuth (proves WHO you are via `tunn login`)
2. **Tunnel Creation:** WELL_KNOWN_KEY check (proves you're ALLOWED to create tunnels)
3. **Access Control:** Email allow-lists (proves you can ACCESS a specific tunnel)
4. **Inter-Node Trust:** mTLS (nodes trust each other)

### 6.1: Email Allow-Lists & Tunnel Creation Auth ✅

- [x] **Add Email Allow-List to Proto:** Update `RegisterClient` with `creator_email`, `allowed_emails`, and `tunnel_key` fields.
- [x] **Add Data Plane Messages:** Define `HttpRequest`, `HttpResponse`, and `StreamClosed` in `tunnel.proto`.
- [x] **Add JWT Email Extraction:** Create helper function in `internal/common/auth.go` to extract email from JWT.
- [x] **Add WELL_KNOWN_KEY Config:** Add `WellKnownKey` field to config (default: "tunn-free-v1-2025").
- [x] **Validate Tunnel Registration:** Update `grpc_server.go` to validate JWT, extract email, check tunnel_key, and build allow-list.
- [x] **Update TunnelConnection:** Store `CreatorEmail` and `AllowedEmails` in tunnel state.

### 6.2: Data Plane Implementation ✅

- [x] **Add Allow-List Enforcement:** Update `webproxy.go` to check visitor's email against tunnel's allow-list before proxying.
- [x] **Implement HTTP-over-gRPC (Proxy):** Send `HttpRequest` messages to tunnel client, wait for `HttpResponse`, forward to visitor.
- [x] **Add HttpRequest Routing:** Update `grpc_server.go` message loop to route `HttpRequest` messages to correct tunnel.
- [x] **Update Client Registration:** Modify `serve.go` to load JWT, extract email, send to `RegisterClient` with tunnel_key.
- [x] **Implement HTTP-over-gRPC (Client):** Handle `HttpRequest` messages, call local target, send `HttpResponse` back.
- [x] **Add --allow Flag:** Add `--allow` flag to `main.go` serve command for specifying additional emails.
- [x] **Add -tunnel-key Flag:** Add `-tunnel-key` flag to `main.go` serve command (defaults to WELL_KNOWN_KEY from env).

### 6.3: Testing & Validation ✅

- [x] **Write E2E Test Script:** Create `test-local.sh` for manual testing and `test-headless.sh` for automated testing.
- [x] **Add Public Mode:** Add `PUBLIC_MODE` config flag to disable auth for headless testing.
- [x] **Verify Core Tunneling:** All 9 headless E2E tests passing - gRPC tunnels, HTTP-over-gRPC, concurrent requests verified.
- [ ] **Update `README.md`:** Document the architecture, Google Doc sharing model, and local testing procedure.
- [ ] **Replace Mock OIDC with Google:** Update config to use real Google OAuth endpoints in production.
- [ ] **Secure Configuration:** Ensure all secrets (OIDC client secret, JWT signing key) are loaded from environment variables.
- [ ] **Add Usage Examples:** Document the full flow: `tunn login` → `tunn serve -tunnel-key=WELL_KNOWN_KEY --allow alice@gmail.com` → visit URL → Google login → access.

## V1 COMPLETE - READY FOR DEPLOYMENT 🚀

**Status:** Core tunneling functionality complete and tested. Ready for production deployment.

**What's Working:**
- ✅ HTTP/HTTPS tunneling over gRPC
- ✅ Google OAuth (browser + CLI device flow)
- ✅ Email allow-lists (Google Doc sharing model)
- ✅ Session cookies + JWT tokens
- ✅ Inter-node sync (mesh architecture)
- ✅ Headless E2E tests (all passing)
- ✅ TLS termination at proxy

**Remaining for Launch:**
- Update README.md with production docs
- Switch from mock OIDC to real Google OAuth
- Deploy to Fly.io
- Set up tunn.to DNS

---

## V1.1: UDP Tunneling - COMPLETE ✅

**Status:** UDP tunneling support has been fully implemented (2025-11-17).

**Architecture:**
```
[Game Client] → UDP → [tunn connect] → HTTP/2 wrapper → [Proxy] → gRPC → [tunn serve] → UDP → [Game Server]
                        ↑ Tunnel ID in path: /udp/abc123, not in packet
```

**Implementation Complete:**
- ✅ **Define UDP Protobuf Messages:** Added `UdpPacket` message to `tunnel.proto`
- ✅ **Implement `tunn connect` Command:** Client-side UDP listener that wraps packets in HTTP/2 (internal/client/connect.go)
- ✅ **Implement UDP Proxy Handler:** Server-side unwrapping and forwarding (internal/host/udpproxy.go)
- ✅ **Add UDP Message Routing:** gRPC server routes UDP packets to correct tunnels
- ✅ **Add UDP Forwarding in Serve Client:** Serve client forwards UDP to local target and returns responses
- ✅ **Add Protocol Support:** `--protocol` flag supports "http", "udp", or "both"
- ✅ **Add UDP Target Flag:** `--udp-target` flag specifies local UDP service address
- ✅ **E2E Test Script:** Created `test-udp-local.sh` for manual testing

**Usage:**
```bash
# Terminal 1: Start UDP tunnel (serve)
./bin/tunn -mode=client -id=minecraft -protocol=udp -udp-target=localhost:25565 -tunnel-key=$WELL_KNOWN_KEY

# Terminal 2: Start local UDP proxy (connect)
./bin/tunn -mode=connect -id=minecraft -local=localhost:25566

# Terminal 3: Connect game client
# Point your game client to localhost:25566 and it will tunnel through to the server
```

**Known Limitations:**
- Single UDP connection per serve client (can be extended to support multiple game servers in future)

---

## V1.2: TLS Passthrough for Paid Customers - FUTURE PAID FEATURE 💎

**Architectural Decision (2025-11-17):** Offer TLS passthrough as a premium feature where customer terminates TLS on their machine and proxy does blind SNI routing.

**Current V1 (Free Tier):**
```
Browser → HTTPS → Proxy (terminates TLS, sees plaintext) → gRPC → Client → HTTP → localhost
```

**V1.2 Paid Tier:**
```
Browser → HTTPS → Proxy (SNI routing ONLY, blind) → TCP tunnel → Client (has cert) → HTTPS → localhost
```

**Benefits:**
- End-to-end encryption: proxy can't see customer traffic
- Marketing angle: "We can't see your data!"
- Good for enterprise customers with compliance requirements
- Custom subdomain + ACME cert automation included

**Implementation Tasks (Future):**
- [ ] **Implement SNI Peeking:** Read SNI from TLS ClientHello without consuming bytes
- [ ] **Add Passthrough Mode:** New tunnel mode that does raw TCP forwarding instead of TLS termination
- [ ] **Integrate ACME Automation:** Automated Let's Encrypt cert issuance via DNS-01 challenge
- [ ] **Add Custom Subdomain Support:** Allow customers to claim `mycoolapp.tunn.to` subdomain
- [ ] **Add `--passthrough` Flag:** Client flag to enable passthrough mode and load local cert
- [ ] **Update Billing:** Add passthrough as paid tier feature (requires tunn-auth)

**Trade-offs:**
- ✅ Pro: Privacy, compliance, enterprise trust
- ❌ Con: Can't do HTTP-level rate limiting (only TCP-level)
- ❌ Con: Can't log/debug HTTP for customers
- ❌ Con: More complex DNS + ACME integration

---

## Phase 7: Commercial Auth Provider (tunn-auth) - DEFERRED TO V2 ⏸

This phase implements a separate, private authentication service that acts as an OIDC provider with integrated billing. The open-source `tunn` will remain fully functional without this - users can choose to use Google/GitHub OAuth, run their own fork of tunn-auth, or operate without authentication.

**Architecture Pattern:** External Identity Provider (IdP) with custom claims for quota enforcement.

**Repository:** `tunn-auth` (private) - A separate web application that:
1. Acts as a standards-compliant OIDC provider
2. Handles user signup, login, and account management
3. Integrates with Stripe for subscription billing
4. Issues JWTs with custom claims for quota enforcement

**Chain of Trust:** tunn validates JWTs signed by tunn-auth using standard JWKS verification. No direct database connection or tight coupling required.

### 7.1: tunn-auth Service (Private Repo)

- [ ] **Create tunn-auth Repository:** Initialize private repo with similar structure to tunn. Use shared UI components for consistent look/feel.
- [ ] **Implement OIDC Provider Endpoints:**
  - `/.well-known/openid-configuration` - OIDC discovery
  - `/.well-known/jwks.json` - Public keys for JWT validation
  - `/authorize` - OAuth authorization endpoint
  - `/token` - Token exchange endpoint
  - `/device/code` - Device flow for CLI (same as mock OIDC)
  - `/userinfo` - User info endpoint
- [ ] **Implement User Management:**
  - Sign up flow with email verification
  - Login with email/password or social providers
  - Account dashboard (profile, billing, usage)
  - API key generation for programmatic access
- [ ] **Integrate Stripe:**
  - Create Stripe customer on signup
  - Subscription plans (Free, Pro, Enterprise)
  - Billing portal integration
  - Webhook handler for subscription events
- [ ] **Implement JWT Issuance with Custom Claims:**
  ```go
  type TunnClaims struct {
      jwt.StandardClaims
      Email         string `json:"email"`
      Plan          string `json:"tunn_plan"`          // "free", "pro", "enterprise"
      TunnelsMax    int    `json:"tunn_tunnels_max"`   // Concurrent tunnel limit
      QuotaGB       int    `json:"tunn_quota_gb"`      // Monthly bandwidth quota
      BandwidthMbps int    `json:"tunn_bandwidth_mbps"`// Rate limit
  }
  ```
- [ ] **Implement Usage Tracking API:**
  - Endpoint for tunn to report usage metrics
  - Store bandwidth, connection count, tunnel hours
  - Calculate monthly usage for billing

### 7.2: tunn OSS Integration Points

- [ ] **Add Quota Enforcement Middleware:** Extract custom claims from JWT and enforce limits in tunnel registration and proxy handlers.
- [ ] **Add Usage Reporting (Optional):** If OIDC provider exposes a usage reporting endpoint, report metrics. Make this optional - OSS deployments can skip it.
- [ ] **Document Multi-Provider Support:** Update docs to show how to configure different OIDC providers:
  - `tunn.to` (default, uses auth.tunn.to)
  - Google OAuth
  - GitHub OAuth
  - Self-hosted tunn-auth
  - No auth (token-only mode)
- [ ] **Add Plan Display in CLI:** Show user's plan and limits in `tunn status` command.

### 7.3: Deployment Configuration

**For tunn.to (SaaS):**
```bash
ENV=prod
OIDC_ISSUER=https://auth.tunn.to
OIDC_CLIENT_ID=tunn-production
USAGE_REPORTING_ENABLED=true
USAGE_REPORTING_URL=https://auth.tunn.to/api/usage
```

**For Self-Hosted (OSS):**
```bash
ENV=prod
# Option 1: No auth
TOKEN=super_secret

# Option 2: Use Google OAuth
OIDC_ISSUER=https://accounts.google.com
OIDC_CLIENT_ID=your-google-client-id
OIDC_CLIENT_SECRET=your-google-secret

# Option 3: Use self-hosted tunn-auth fork
OIDC_ISSUER=https://auth.yourcompany.com
OIDC_CLIENT_ID=custom-client-id
```

### 7.4: Pricing Tiers (Example)

- **Free Tier:** 1 concurrent tunnel, 10GB/month, community support
- **Pro Tier ($9/month):** 5 concurrent tunnels, 100GB/month, email support, custom domains
- **Enterprise Tier ($49/month):** Unlimited tunnels, 1TB/month, priority support, SSO, audit logs

### 7.5: Open Source Considerations

**What stays OSS (tunn repo):**
- ✅ Core tunnel proxy functionality
- ✅ gRPC control plane
- ✅ OIDC client integration (works with any provider)
- ✅ Quota enforcement middleware (enforces claims from any JWT)
- ✅ All CLI commands
- ✅ Documentation for self-hosting

**What's private (tunn-auth repo):**
- 🔒 Stripe integration code
- 🔒 Subscription management logic
- 🔒 Billing portal
- 🔒 tunn.to branding and marketing site
- 🔒 Usage-based billing calculations
- 🔒 Customer support tools

**Key Principle:** Anyone can run tunn without tunn-auth. The OSS version is fully functional and production-ready on its own.
