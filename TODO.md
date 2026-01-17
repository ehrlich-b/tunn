# TODO.md: tunn Launch Checklist

## SHIP IT (Ordered)

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

**Tasks:**
1. [ ] **GitHub OAuth App setup** - Create OAuth App in GitHub, get client ID/secret
2. [x] **Implement device code endpoints** - `POST /api/device/code`, `GET /api/device/token`
3. [x] **Update CLI login** - Use device code flow with browser auto-open
4. [x] **Browser OAuth flow** - `/auth/login`, `/auth/callback` with GitHub
5. [x] **Configure JWT signing** - `JWT_SECRET` env var for signing our JWTs
6. [ ] **Test CLI login** - Verify device flow works end-to-end
7. [ ] **Test browser auth** - Verify tunnel access prompts GitHub login

### Code Fixes
8. [x] **Add domain suffix matching** - `--allow @slide.com` allows anyone with that email domain
      - `@company.com` matches any email ending in `@company.com`
      - Case-insensitive matching for both exact and wildcard
      - Example: `tunn 8080 --allow @slide.com,external@gmail.com`
      - **Pro feature:** Free tier limited to 3 exact emails, no @domain wildcards

9. [x] **Reserved subdomain list** - Prevent phishing/squatting
      - Block: www, api, app, admin, auth, login, google, paypal, amazon, etc.
      - Check on tunnel registration, return error if reserved
      - Implemented in `grpc_server.go` with ~60 reserved names

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

**Tasks:**
10. [ ] **Resend integration** - Sign up, get API key, ~15 lines to send email
11. [ ] **POST /auth/magic endpoint** - Generate magic link JWT, send email
12. [ ] **GET /auth/verify endpoint** - Verify JWT (type=magic_link), create session
13. [ ] **Login page update** - Add "Login with Email" option alongside GitHub

**Config:**
- `RESEND_API_KEY` env var (tunn.to only)
- Self-hosters: leave empty, magic link disabled

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

**Tasks:**
15. [ ] **Add CLIENT_SECRET config** - Master key for all clients
16. [ ] **Add --secret flag to CLI** - Pass secret on command line or TUNN_SECRET env
17. [ ] **users.yaml loader** - Parse YAML, check tokens
18. [ ] **Update auth middleware** - Check JWT → user token → client secret → reject

**tunn.to will NOT set CLIENT_SECRET** - forces real auth (GitHub/magic link).

### Integration Testing

See **[integration_test_framework.md](integration_test_framework.md)** for full details.

**Required code changes:**
- [x] Make HTTP ports configurable (`HTTP2_ADDR`, `HTTP3_ADDR` env vars)
- [x] Create `scripts/gen-test-certs.sh` for localhost wildcard certs

**Test scenarios:**
- [x] **Smoke test** - Single node, PUBLIC_MODE, basic tunnel flow
- [x] **Device login E2E** - Full device code flow without real browser
- [x] **Multi-node gRPC** - Two nodes discovering tunnels across mesh
- [x] **Full auth flow** - Allow-list enforcement, domain wildcards

**Run tests:**
- `make integration-test` - Run all integration tests
- `make integration-test-smoke` - Run smoke test only

### CI/CD (Before Infrastructure)
9. [ ] **GitHub Actions for releases** - Build binaries for darwin-amd64, darwin-arm64, linux-amd64
10. [ ] **Create install.sh** - README promises `curl -fsSL https://tunn.to/install.sh | sh`

### Infrastructure
11. [ ] **Deploy to Fly.io** - Get the app running
12. [ ] **Set up tunn.to DNS** - Point domain to Fly (Cloudflare DNS-only)
13. [ ] **Serve install.sh from app** - Static route at `/install.sh`

### Marketing & Homepage
14. [ ] **Create tunn.to homepage** - ntfy.sh inspired, simple dev-focused
      - [ ] Refactor HTML responses to use shared Go template (login success, access denied, error pages)
      - [ ] Light static generation for consistent branding across all pages
      - Hero: one-liner + install command
      - Live demo or GIF
      - Pricing table (Free / Pro $4/mo / Enterprise contact)
      - Code examples
      - Self-host instructions
      - Serve from app at `/` when no tunnel subdomain

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

**Tasks:**
14. [ ] **Create accounts schema** - SQLite tables for accounts + account_emails
15. [ ] **Implement account merge on OAuth** - Handle 0/1/2+ account cases
16. [ ] **Update allow-list check** - Check against email bucket, not just session email
17. [ ] **Add users.yaml support** - Simple config for self-hosters
      ```yaml
      alice@gmail.com:
        plan: pro
      "@mycompany.com":  # domain wildcard
        plan: pro
      ```
18. [ ] **Add Stripe webhook handler** - `/webhooks/stripe` (tunn.to only)
      - Verify Stripe signature with STRIPE_WEBHOOK_SECRET
      - On subscription.created: update account plan='pro'
      - On subscription.deleted: update account plan='free'

### Cluster Security (One Secret) ✅
- [x] **Replace mTLS with NODE_SECRET auth** - Done in commit 0569be1
      - `NODE_SECRET=""` → single node, no mesh (self-hosted default)
      - `NODE_SECRET=xxx` → mesh enabled, nodes auth with shared secret
      - IP blacklisting on failed auth attempts

### Mesh Auto-Discovery (Fly.io)
18. [ ] **Auto-discover nodes via internal DNS** - No manual NODE_ADDRESSES
      - Resolve `<appname>.internal` → returns all instance IPs
      - Filter out self, connect to others
      - New nodes auto-join mesh on boot
      - **Fly.io specific** - see vendor lock-in notes below

### LiteFS Replication (tunn.to)
19. [ ] **Add LiteFS support for SQLite replication** - Fly.io native
      - Mount `/litefs`, SQLite lives there
      - Writes go to primary (auto-elected), replicate in <1s
      - All nodes see same data
      - **Fly.io specific** - see vendor lock-in notes below

### Subdomain Reservations (Pro Feature)
20. [ ] **Add subdomain reservation** - Pro users get 4 reserved subdomains
      - Store in UserStore: `email → [subdomain1, subdomain2, ...]`
      - `tunn 8080 --subdomain myapp` claims/uses reservation
      - Validation: 3+ chars, alphanumeric + hyphens, not reserved
      - Reserved list: www, api, app, admin, auth, static, cdn, etc.
      - No nesting (x.y.tunn.to) - wildcard certs only cover one level

**GitHub OAuth is implemented. PUBLIC_MODE=true bypasses auth for testing only.**

---

## Fly.io Vendor Lock-In

**What's Fly-specific:**

| Feature | Fly.io | Portable Alternative |
|---------|--------|---------------------|
| `<app>.internal` DNS | Fly-native | `NODE_ADDRESSES` env var, Consul, K8s Service DNS |
| LiteFS replication | Fly's lease API for primary election | Consul/etcd for leader election, or just don't replicate (single node) |
| Volumes | Fly Volumes | Any persistent disk (EBS, GCE PD, local) |

**What's portable:**
- Core tunneling (pure Go, runs anywhere)
- CLUSTER_SECRET auth (just HMAC, no vendor deps)
- SQLite storage (standard library)
- FileStore (yaml file, works everywhere)

**Self-hosted users are NOT locked in.** They use `users.yaml` + single node. No Fly, no LiteFS, no mesh.

**tunn.to is lightly locked in.** The mesh auto-discovery and LiteFS are Fly-specific, but:
- Auto-discovery can fall back to `NODE_ADDRESSES` env var
- LiteFS can be replaced with single-node SQLite + manual failover
- Migration path: ~1 day of work to run on K8s or bare metal

---

## Post-Launch (When Needed)

- [ ] ToS and Privacy Policy pages
- [ ] Stripe checkout for Pro tier ($4/month or $40/year)
- [ ] Rate limiting (Free: 100 MB/month, Pro: 50 GB/month hard cap)
- [ ] Bandwidth tracking per user
- [ ] Abuse handling (ban tunnels)
- [ ] Enterprise tier (manual Stripe subscription for custom domains)
- [ ] Homebrew formula (free, handles macOS trust)
- [ ] macOS code signing ($99/year Apple Developer) - eliminates Gatekeeper warnings
- [ ] Windows code signing ($200+/year) - only if enterprise customers need it

**Code signing notes:** For launch, skip signing - devs know `xattr -d com.apple.quarantine ./tunn`. Add Homebrew first (free), then macOS signing if friction complaints pile up. One $4/month customer covers Apple Developer for 2 years.

---

## Deferred (Post-Launch Hardening)

- [ ] Fix `ExtractEmailFromJWT` - add signature validation (trust boundary issue, low priority)

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
- UDP tunneling
- Email allow-lists
- PUBLIC_MODE for auth-free testing
- All tests pass (`make test`, `make test-race`)

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

### V1.1: UDP Tunneling ✅
- [x] UdpPacket proto messages
- [x] tunn connect command
- [x] UDP proxy handler

### Future: V1.2 TLS Passthrough 💎
- SNI-based routing for paid tier
- Customer terminates TLS
- Deferred to paid tier

### Future: Phase 7 tunn-auth ⏸
- Commercial auth provider
- Stripe integration
- Deferred to V2

</details>
