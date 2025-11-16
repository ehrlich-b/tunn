# TODO.md: V1 Implementation Plan

This checklist details the steps to build the robust, production-ready V1 of `tunn`, incorporating gRPC, dual auth flows, and a comprehensive testing strategy.

**Important:** Always use `make` for building and testing. See CLAUDE.md for details.

**Code Review:** A comprehensive code review was completed on 2025-11-16. See REVIEW.md for detailed findings, security issues, and recommendations.

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

## Phase 5: CLI Auth & UDP Tunneling

- [x] **Implement Device Flow (`tunn login`):** Create the `tunn login` command that performs the OAuth Device Authorization Grant against the (mock) OIDC provider to retrieve and save a JWT.
- [x] **Implement `CheckJWT` Middleware:** Create middleware to validate JWTs on incoming API requests.
- [ ] **Implement UDP-over-H2 Handler:** Create the `/udp-tunnel/{id}` handler, protected by the `CheckJWT` middleware. This handler will hijack the HTTP/2 connection to create a raw bidirectional stream.
- [ ] **Implement `tunn connect` Command:** Create the `connect` command. It will load the JWT, start a local UDP listener, and make the authenticated `POST` request to the `/udp-tunnel/` endpoint.
- [ ] **Implement UDP Proxy Logic:** Implement the logic in both the `connect` command and the proxy handler to frame UDP packets (length-prefix) and proxy them over the hijacked HTTP/2 stream.

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

### 6.2: Data Plane Implementation (IN PROGRESS)

- [ ] **Add Allow-List Enforcement:** Update `webproxy.go` to check visitor's email against tunnel's allow-list before proxying.
- [ ] **Implement HTTP-over-gRPC (Proxy):** Send `HttpRequest` messages to tunnel client, wait for `HttpResponse`, forward to visitor.
- [ ] **Add HttpRequest Routing:** Update `grpc_server.go` message loop to route `HttpRequest` messages to correct tunnel.
- [ ] **Update Client Registration:** Modify `serve.go` to load JWT, extract email, send to `RegisterClient` with tunnel_key.
- [ ] **Implement HTTP-over-gRPC (Client):** Handle `HttpRequest` messages, call local target, send `HttpResponse` back.
- [ ] **Add --allow Flag:** Add `--allow` flag to `main.go` serve command for specifying additional emails.
- [ ] **Add -key Flag:** Add `-key` flag to `main.go` serve command (defaults to WELL_KNOWN_KEY from env).

### 6.3: Final Integration & Docs

- [ ] **Write E2E Test Script:** Create a shell script (`test-local.sh`) that automates the full local testing process.
- [ ] **Update `README.md`:** Document the architecture, Google Doc sharing model, and local testing procedure.
- [ ] **Replace Mock OIDC with Google:** Update config to use real Google OAuth endpoints in production.
- [ ] **Secure Configuration:** Ensure all secrets (OIDC client secret, JWT signing key) are loaded from environment variables.
- [ ] **Add Usage Examples:** Document the full flow: `tunn login` → `tunn serve -key=WELL_KNOWN_KEY --allow alice@gmail.com` → visit URL → Google login → access.

## Phase 7: Commercial Auth Provider (tunn-auth) - DEFERRED ⏸

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
