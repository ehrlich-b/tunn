# TODO.md: tunn Launch Checklist

## Code Quality Philosophy

**Every file needs to spark joy.** If a senior dev reviews line-by-line and says "wrong, no, eep" - we've failed.

### Tech Debt to Fix
- [x] **Extract inline HTML from webproxy.go** - Done via `//go:embed`
      - Homepage now in `internal/host/templates/homepage.html`
      - Embedded at compile time, zero external dependencies

---

## CODE NOW (No External Setup Required)

### 1. Subdomain Reservations (Pro Feature) ✅
- [x] **Add subdomain reservation** - Pro users get 4 reserved subdomains
      - SQLite `reserved_subdomains` table in `internal/store/db.go`
      - Store methods in `internal/store/accounts.go`: ReserveSubdomain, GetSubdomainOwner, GetReservedSubdomains, ReleaseSubdomain
      - gRPC server checks reservations and auto-claims for Pro users in `grpc_server.go`
      - CLI `--subdomain` flag added as alias for `--id`
      - Tests in `internal/store/store_test.go`

### 2. Stripe Webhook Handler ✅
- [x] **Add Stripe webhook handler** - `/webhooks/stripe` (tunn.to only)
      - Signature verification with STRIPE_WEBHOOK_SECRET env var
      - Handles `customer.subscription.created/updated/deleted` events
      - Implementation in `internal/host/stripe.go`
      - Tests in `internal/host/stripe_test.go`
      - Note: Requires customer email lookup via Stripe API or metadata to update accounts

### 3. Mesh Auto-Discovery (Fly.io) ✅
- [x] **Auto-discover nodes via internal DNS** - No manual NODE_ADDRESSES
      - `discoverNodes()` in `proxy.go` resolves `<FLY_APP_NAME>.internal`
      - Filters out self using `getSelfIPs()`
      - Falls back to `NODE_ADDRESSES` env var if DNS fails
      - Node connections are non-fatal (logs error, continues startup)
      - **Fly.io specific** - uses IPv6 for internal networking

### 4. Homepage & Templates ✅
- [x] **Create tunn.to homepage** - ntfy.sh inspired, simple dev-focused
      - Hero: one-liner + install command
      - Pricing table (Free / Pro $4/mo / Enterprise contact)
      - Code examples + self-host instructions
      - Serve from app at `/` when no tunnel subdomain
      - Implementation in `internal/host/webproxy.go` (`handleApexDomain`)
- [x] **Refactor HTML to shared templates** - `internal/host/templates.go`
      - Base CSS styles in `baseCSS` constant
      - Helper functions: `writePageStart`, `writePageEnd`, `writeErrorPage`, `writeSuccessPage`
      - Login, success, and error pages now use shared templates

---

## BLOCKED (Needs External Setup)

### GitHub OAuth App (Manual)
- [ ] Create OAuth App in GitHub, get client ID/secret
- [ ] Test CLI login end-to-end
- [ ] Test browser auth end-to-end

### Infrastructure (Manual)
- [ ] Deploy to Fly.io
- [ ] Set up tunn.to DNS (Cloudflare DNS-only)
- [ ] Configure SMTP provider for magic links
- [ ] Configure Let's Encrypt (automatic on Fly)

---

## COMPLETED

### Auth Implementation (GitHub OAuth + Device Flow)

**Architecture Decision:** GitHub OAuth only (not Google). Target audience is developers, GitHub is universal, simpler to set up.

**CLI Login (`tunn login`) - Device Code Flow:**
```
$ tunn login
Opening browser...
[browser opens to tunn.to/login?device_code=ABC123, code pre-filled]
[user clicks "Login with GitHub" in browser]
Waiting... ✓
Logged in as alice@example.com
```

1. CLI: `POST /api/device/code` → server creates device code in SQLite, returns code
2. CLI: opens browser to `tunn.to/login?device_code=ABC123` (pre-filled, no typing!)
3. User: clicks "Login with GitHub" in browser → GitHub OAuth flow
4. Server: on OAuth callback, marks device code as authorized, stores JWT
5. CLI: polls `GET /api/device/token?code=ABC123` every 3 sec (max 3 min)
6. Server: returns JWT once device code is authorized
7. CLI: saves JWT to `~/.tunn/token`, done

**Browser Auth (visiting tunnel URLs):**
- User visits `https://abc123.tunn.to`
- If not authenticated, redirect to `/auth/login`
- User clicks "Login with GitHub" → GitHub OAuth
- On success, session cookie set, user redirected back to tunnel

**Multi-Node Handling:**
- Device codes stored in SQLite
- LiteFS replicates SQLite across all Fly.io nodes (<1 sec)
- Poll can hit any node, auth can happen on any node - same DB

**Completed:**
- [x] Implement device code endpoints - `POST /api/device/code`, `GET /api/device/token`
- [x] Update CLI login - Use device code flow with browser auto-open
- [x] Browser OAuth flow - `/auth/login`, `/auth/callback` with GitHub
- [x] Configure JWT signing - `JWT_SECRET` env var for signing our JWTs
- [x] Add domain suffix matching - `--allow @slide.com` allows anyone with that email domain
- [x] Reserved subdomain list - Prevent phishing/squatting (~60 names in `grpc_server.go`)

### Magic Link Auth (tunn.to)

**Why:** Not everyone has GitHub. Magic link is the simplest "direct" login.

**Stateless Design:** Magic link token is a JWT, not stored anywhere. Any Fly node can verify it.

**Flow:**
```
1. User: POST /auth/magic {email: "alice@example.com"}
2. Server: Generate JWT {email, type: "magic_link", exp: +5min}
3. Server: Send email via Resend API with link: /auth/verify?token=<JWT>
4. User: Clicks link (hits ANY node - no coordination needed)
5. Server: Verify JWT signature + expiry + type="magic_link"
6. Server: Create session JWT (24hr), set cookie, redirect
```

**Why stateless:** Multiple Fly machines. No LiteFS needed for magic links. Any node can verify.

**Trade-off:** Link is replayable within 5-min window. Acceptable because:
- Email is already the weak link (compromised email = game over)
- 5 minutes is short
- This is how Slack, Notion, etc. do it

**Completed:**
- [x] SMTP integration - Generic SMTP support (works with AWS SES, Resend, any SMTP provider)
- [x] POST /auth/magic endpoint - Generate magic link JWT, send email
- [x] GET /auth/verify endpoint - Verify JWT (type=magic_link), create session
- [x] Login page update - `/auth/login` shows both GitHub and email options

**Config:** `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` env vars

### Self-Hoster Auth (Simple Shared Secrets)

**Philosophy:** Self-hosters don't want to set up GitHub OAuth or email. Give them the simplest possible thing.

**Option 1: Master Client Secret (whole team shares one secret)**
```bash
# Server config
CLIENT_SECRET=mysecretkey123

# Client usage
tunn serve 8080 --secret=mysecretkey123
# or
export TUNN_SECRET=mysecretkey123
tunn serve 8080
```

Like `NODE_SECRET` but for clients. Entire team uses the same secret. Zero setup.

**Option 2: Per-User Tokens (users.yaml)**
```yaml
users:
  alice@company.com:
    token: "tunn_sk_abc123..."
  bob@company.com:
    token: "tunn_sk_xyz789..."
```

Admin generates tokens, gives to users. More granular than master secret.

**Auth Priority (server checks in order):**
1. JWT token (from `tunn login` via OAuth/magic link)
2. User token (from users.yaml)
3. Client secret (master key)
4. Reject

**Completed:**
- [x] CLIENT_SECRET config - Master key for all clients (CLIENT_SECRET env var)
- [x] --secret flag for CLI - Pass secret on command line or TUNN_SECRET env
- [x] users.yaml loader - Set USERS_FILE env var to path
- [x] Auth middleware - Check: public mode → client secret → JWT

**Note:** tunn.to will NOT set CLIENT_SECRET - forces real auth (GitHub/magic link).

### Integration Testing

See **[integration_test_framework.md](integration_test_framework.md)** for full details.

**Run tests:** `make integration-test` or `make integration-test-smoke`

**Completed:**
- [x] HTTP ports configurable (`HTTP2_ADDR`, `HTTP3_ADDR` env vars)
- [x] `scripts/gen-test-certs.sh` for localhost wildcard certs
- [x] Smoke test, Device login E2E, Multi-node gRPC, Full auth flow

### CI/CD

**Completed:**
- [x] GitHub Actions for releases - `.github/workflows/release.yml` triggers on v* tags
- [x] install.sh - Script in repo root + served from app at `/install.sh`

### Identity Model (Email Buckets)

**Core Concept:** An "account" is a bucket of verified emails. Any email in the bucket works for allow-lists, Pro access, etc.

**Why this matters:**
- User has `work@company.com` (GitHub) and `personal@gmail.com` (password login)
- Both emails should be treated as the same person
- If `--allow work@company.com`, logging in with `personal@gmail.com` should work
- If one email has Pro, all emails in the bucket get Pro

**Data Model (SQLite):**
```sql
accounts:
  id: uuid
  primary_email: string
  plan: free|pro
  created_at: timestamp

account_emails:
  account_id: uuid
  email: string (unique!)
  verified_via: github|password
  added_at: timestamp
```

**On OAuth Callback (Account Merge Logic):**
1. GitHub returns emails: `[A, B, C]`
2. Look up which account(s) own those emails
3. **0 accounts:** Create new account with all emails
4. **1 account:** Add any new emails to that account
5. **2+ accounts:** MERGE them:
   - Union all emails into one account
   - Take best plan (Pro > Free)
   - Merge reserved subdomains (cap at 4)
   - Delete the other account(s)

**Security:** GitHub requires email verification, so if you prove ownership via GitHub, merging is safe.

**Allow-List Check (updated logic):**
```go
func isAllowed(sessionEmail string, allowList []string) bool {
    // Get all emails in user's bucket
    userEmails := getUserEmailBucket(sessionEmail)

    for _, allowed := range allowList {
        if strings.HasPrefix(allowed, "@") {
            // Domain wildcard: check if ANY user email matches
            for _, email := range userEmails {
                if strings.HasSuffix(email, allowed) {
                    return true
                }
            }
        } else {
            // Exact match: check if ANY user email matches
            for _, email := range userEmails {
                if email == allowed {
                    return true
                }
            }
        }
    }
    return false
}
```

**Completed:**
- [x] Accounts schema - SQLite tables in `internal/store/`, auto-detects LiteFS at `/litefs/tunn.db`
- [x] Account merge on OAuth - FindOrCreateByEmails handles 0/1/2+ account cases
- [x] Allow-list check uses email bucket - webproxy.go checks ANY email in bucket
- [x] users.yaml support - Simple config for self-hosters (`internal/store/users.go`)

### Cluster Security (One Secret) ✅
- [x] **Replace mTLS with NODE_SECRET auth** - Done in commit 0569be1
      - `NODE_SECRET=""` → single node, no mesh (self-hosted default)
      - `NODE_SECRET=xxx` → mesh enabled, nodes auth with shared secret
      - IP blacklisting on failed auth attempts

### ~~LiteFS Replication~~ → Login Node Architecture
- [x] ~~**LiteFS support for SQLite replication**~~ - **Replaced by Login Node architecture**
      - LiteFS had complexity: FUSE, Consul leases, autoscale footguns
      - New approach: One login node owns SQLite + Litestream backup to S3
      - See [docs/login-node-architecture.md](docs/login-node-architecture.md)

**Note:** GitHub OAuth is implemented. PUBLIC_MODE=true bypasses auth for testing only.

---

## Fly.io Vendor Lock-In

**What's Fly-specific:**

| Feature | Fly.io | Portable Alternative |
|---------|--------|---------------------|
| `<app>.internal` DNS | Fly-native | `NODE_ADDRESSES` env var, Consul, K8s Service DNS |
| Volumes | Fly Volumes | Any persistent disk (EBS, GCE PD, local) |
| Tigris (S3) | Fly-native | Any S3-compatible storage |

**What's portable:**
- Core tunneling (pure Go, runs anywhere)
- NODE_SECRET auth (just HMAC, no vendor deps)
- SQLite storage (standard library)
- Litestream backup (works with any S3)
- Login Node architecture (just gRPC, no Fly deps)
- FileStore (yaml file, works everywhere)

**Self-hosted users are NOT locked in.** They use `users.yaml` + single node. No Fly, no mesh, no cloud backup needed.

**tunn.to is lightly locked in.** The mesh auto-discovery is Fly-specific, but:
- Auto-discovery can fall back to `NODE_ADDRESSES` env var
- Litestream works with any S3-compatible storage
- Migration path: ~1 day of work to run on K8s or bare metal

---

## Pre-Launch Code (Required)

### Security Fixes ✅ - See [REVIEW.md](REVIEW.md)

1. [x] **JWT Validation on Tunnel Registration** - `grpc_server.go`
      - Added `validateJWTAndExtractEmail()` that properly validates JWT signatures
      - Refactored `TunnelServer` to use `*config.Config` for cleaner parameter passing

2. [x] **Magic Link Session Key** - `magiclink.go:113`
      - Changed `"email"` to `"user_email"` for session consistency

3. [x] **Remove Secret from Logs** - `grpc_server.go`
      - Removed `provided_key` from log output

4. [x] **Fail on Missing JWT_SECRET** - `auth.go`
      - Production mode now panics if JWT_SECRET not configured
      - Dev mode falls back with warning

5. [x] **Remove InsecureSkipVerify for Internal TLS** - `proxy.go`
      - Uses system CA pool by default (tunn.to uses Let's Encrypt)
      - Self-hosters: `TUNN_CA_CERT` env var for custom CA chain

6. [x] **README Google → GitHub** - `README.md`
      - Updated to reference GitHub auth (complete README rewrite)

### Architecture

1. [ ] **Login Node Architecture** - See [docs/login-node-architecture.md](docs/login-node-architecture.md)
      - One node designated as "login node" (`LOGIN_NODE=true`) owns SQLite
      - Other nodes discover it via config (self-host) or Fly DNS (tunn.to)
      - Graceful degradation: buffer usage if login node down, fail auth with 503
      - Self-hosting first: works with static config, no Fly dependency
      - **Must be implemented before rate limiting**

2. [ ] **Rate Limiting** - See [docs/rate-limiting-design.md](docs/rate-limiting-design.md)
      - Concurrent tunnels: 3 (free) / 10 (pro)
      - Bandwidth per tunnel: 100 Mbps (free) / 250 Mbps (pro) - not advertised
      - Monthly quota: 100 MB (free) / 50 GB (pro)
      - 20 MB threshold flush, 30 sec quota refresh
      - **Depends on Login Node architecture**

### Features

- [ ] **Account page + Stripe Checkout** - `/account` dashboard, "Upgrade to Pro" button creates Stripe Checkout session
- [ ] **ToS and Privacy Policy pages** - Currently placeholder `#` links in footer
- [x] **Sync page templates** - Login, error, success pages now match homepage look

### CLI & Config (Breaking Changes - Must Do Pre-Launch)

- [ ] **.env file support** - Load config from `.env` file (standard dotenv format), simpler than env vars for self-hosters
- [ ] **Prefix all env vars with TUNN_** - Standardize env var names (e.g., `TUNN_JWT_SECRET`, `TUNN_NODE_SECRET`)
- [ ] **Support double-dash flags** - Fix flag parsing to properly handle `--flag` style in subcommands
- [ ] **Hide raw UDP support** - Don't advertise `tunn connect` (raw UDP ingress)
      - Port scarcity problem unsolved (65k ports globally vs infinite subdomains)
      - Multi-node routing probably broken (no Host header equivalent)
      - No auth story for "dumb UDP clients"
      - Leave code in place, just don't document/expose
      - Pro UDP solution is `tunn relay` (V1.3) - both ends run tunn, JWT auth

## Pre-Launch Manual Setup (Required)

- [ ] GitHub OAuth App - Create app, get client ID/secret
- [ ] SMTP provider - Configure for magic link emails
- [ ] Fly.io deploy + DNS - Deploy app, configure tunn.to domain

---

## Post-Launch (When Needed)

### Features

- [ ] Windows support - signal handling (`syscall.SIGTERM`), install script (PowerShell)
- [ ] Remote tunnel kill from dashboard
- [ ] Bandwidth tracking UI in account page
- [ ] Abuse handling (ban tunnels)
- [ ] Enterprise tier (manual Stripe subscription for custom domains)
- [ ] Homebrew formula (free, handles macOS trust)
- [ ] macOS code signing ($99/year Apple Developer) - eliminates Gatekeeper warnings
- [ ] Windows code signing ($200+/year) - only if enterprise customers need it

**Code signing notes:** For launch, skip signing - devs know `xattr -d com.apple.quarantine ./tunn`. Add Homebrew first (free), then macOS signing if friction complaints pile up. One $4/month customer covers Apple Developer for 2 years.

---

## Completed (2025-01-17)

- [x] CLI UX: `tunn 8080` instead of `tunn -mode=client -to=localhost:8000`
- [x] README rewritten as user-focused docs
- [x] Dev docs moved to CONTRIBUTING.md
- [x] Multi-value header bug fixed
- [x] Dead code removed (legacy ProxyRequest/ProxyResponse handlers)
- [x] Reconnection with exponential backoff
- [x] Comprehensive test coverage for core tunneling
- [x] Code quality cleanup (logging, emoji, duplicates)

---

## Reference: What's Working

Core tunneling is complete and tested:
- HTTP/HTTPS tunneling over gRPC
- HTTP/2 + HTTP/3 (QUIC) support
- Multi-value headers (Cookie, Set-Cookie)
- Concurrent requests
- Automatic reconnection with exponential backoff
- Email allow-lists
- PUBLIC_MODE for auth-free testing
- All tests pass (`make test`, `make test-race`)

Note: UDP code exists but is not advertised. See V1.3 UDP Relay for the supported Pro UDP solution.

See [REVIEW.md](REVIEW.md) for full audit summary.

---

## Archive: Historical Phases

<details>
<summary>Click to expand completed phases (for reference only)</summary>

### Phase 0: Project Setup ✅
- [x] Define Protobuf API
- [x] Generate gRPC Code
- [x] Vendor Dependencies
- [x] Create Mock OIDC Server

### Phase 1: Proxy Server ✅
- [x] Dual-Listener Server (HTTP/2 + HTTP/3)
- [x] gRPC Server
- [x] HTTPS/gRPC Router
- [x] Local Testing Config

### Phase 2: Serve Client ✅
- [x] gRPC Client
- [x] Control Loop
- [x] Health Checks

### Phase 3: Inter-Node Communication ✅
- [x] Internal Protobuf API
- [x] Node Discovery
- [x] Sequential Probing
- [x] Inter-Node Proxying
- [x] mTLS for Inter-Node

### Phase 4: Browser Auth ✅
- [x] Session Manager
- [x] Auth Handlers (/auth/login, /auth/callback)
- [x] CheckAuth Middleware

### Phase 5: CLI Auth ✅
- [x] Device Flow (tunn login)
- [x] CheckJWT Middleware

### Phase 6: V1 Features ✅
- [x] Email Allow-Lists
- [x] Data Plane (HTTP-over-gRPC)
- [x] E2E Tests

### V1.1: UDP Tunneling (Pro Only) ✅
- [x] UdpPacket proto messages
- [x] tunn connect command
- [x] UDP proxy handler
- [ ] Gate behind Pro tier - see V1.4 design (inherently raw, no L7 intercept)

### V1.2: Enterprise SSO (Enterprise Tier)

**Corporate login providers for enterprise customers:**

- [ ] **Google Workspace** - Google OAuth with domain restrictions (easy, reuses OAuth flow)
- [ ] **Microsoft Entra ID** - Azure AD / Office 365 orgs (huge market, OIDC)
- [ ] **Okta** - Popular enterprise IdP (OIDC)
- [ ] **Generic SAML 2.0** - Covers OneLogin, Ping Identity, etc.
- [ ] **Generic OIDC** - Any OpenID Connect provider

**Implementation approach:**
- Start with Google Workspace (trivial - just add domain claim check)
- Microsoft Entra next (large enterprise market)
- SAML 2.0 last (complex but covers everything else)

**Business model:** Enterprise tier only. Self-hosters configure their own IdP.

---

### V1.3: UDP Relay (Pro Only)

**Escape restrictive networks that block UDP.** See [docs/udp-relay-design.md](../docs/udp-relay-design.md).

Use case: Intern trapped on school WiFi that blocks UDP, needs WireGuard to reach home/work.

```bash
# Home server: accept relay from company emails (same --allow as HTTP tunnels!)
tunn relay 51820 --id=home-wg --allow @company.com

# Intern laptop (school WiFi, UDP blocked)
tunn relay 51820 --to=home-wg
```

Both run `tunn login` first. Same email-based auth as HTTP tunnels. Server relays UDP packets between them over TCP:443.

- [ ] Add `target_tunnel` field to UdpPacket proto
- [ ] Server-side relay logic (reuses `isEmailBucketAllowed`)
- [ ] Client `tunn relay` command
- [ ] `@self` shorthand for same-account relay
- [ ] Pro tier gating

**~500 lines total.** Builds on existing UDP tunneling.

---

### V1.4: Custom Domains + Raw Mode (Pro Only)

**The Design:**

Customer CNAMEs `app.customer.com` → `<id>.tunn.to`. tunn provisions Let's Encrypt cert for `app.customer.com` (rate limits are per customer domain, not per tunn.to - we can do thousands).

Then customer chooses:

**Option A: tunn terminates TLS (default)**
```
browser → app.customer.com → tunn.to (terminates TLS, L7 intercept) → tunnel → localhost
```
- Allow-list works
- tunn sees traffic

**Option B: Raw mode (`-raw`) - tunn hands cert to client**
```
browser → app.customer.com → tunn.to (SNI routing only) → tunnel → localhost (terminates TLS)
```
- tunn provisions cert, securely sends to client
- Client terminates TLS locally
- tunn never sees plaintext traffic
- No L7 intercept = no allow-list (user handles auth)

**Why this is elegant:**
- Customer doesn't manage certs (we do ACME)
- Customer chooses trust level: "let tunn see" vs "end-to-end encrypted"
- Same cert provisioning, two modes

**Implementation needed:**
- ACME client for Let's Encrypt (HTTP-01 challenge)
- Cert storage (SQLite or S3)
- Cert renewal (90-day expiry)
- Secure cert delivery to client (for raw mode)
- SNI peek + raw TCP forwarding (for raw mode)
- UDP gating behind Pro (inherently raw)

### Future: Phase 7 tunn-auth ⏸
- Commercial auth provider
- Stripe integration
- Deferred to V2

</details>
