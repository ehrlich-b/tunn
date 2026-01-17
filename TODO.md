# TODO.md: tunn Launch Checklist

## SHIP IT (Ordered)

### Infrastructure
1. [ ] **Deploy to Fly.io** - Get the app running
2. [ ] **Set up tunn.to DNS** - Point domain to Fly (Cloudflare DNS-only)
3. [ ] **Create install.sh** - README promises `curl -fsSL https://tunn.to/install.sh | sh`
4. [ ] **Serve install.sh from app** - Static route at `/install.sh`
5. [ ] **GitHub Actions for releases** - Build binaries for darwin-amd64, darwin-arm64, linux-amd64

### OAuth (Required for `tunn login` + browser portal)
6. [ ] **Google Cloud OAuth setup** - Create project, OAuth consent screen, get client ID/secret
7. [ ] **Fix `exchangeCodeForToken`** - Actually parse Google's token response (currently returns auth code as token)
8. [ ] **Fix `validateToken`** - Extract real email from Google token (currently returns hardcoded `user@example.com`)
9. [ ] **Configure JWT signing** - Set real secret via env var (currently hardcoded `TODO_CONFIGURE_JWT_SECRET`)
10. [ ] **Test `tunn login`** - Verify CLI device flow works with real Google
11. [ ] **Test browser portal** - Verify visiting tunnel URL prompts Google login, enforces allow-list

### Sharing (Domain-based teams, no database needed)
12. [ ] **Add domain suffix matching** - `--allow @slide.com` allows anyone with that email domain
      - Current: exact email match only
      - Change: if allow entry starts with `@`, use `strings.HasSuffix(email, entry)`
      - Example: `tunn 8080 --allow @slide.com,external@gmail.com`
      - **Pro feature:** Free tier limited to 3 exact emails, no @domain wildcards

### User Store (Config-First, No External DB)
13. [ ] **Implement UserStore interface** - Pluggable user storage
      - `FileStore`: reads `users.yaml` (self-hosted default)
      - `SQLiteStore`: reads local `users.db` (self-hosted + tunn.to)
      - Config file is the primary interface, SQLite is implementation detail
14. [ ] **Add users.yaml support** - Simple config for self-hosters
      ```yaml
      alice@gmail.com:
        plan: pro
      "@mycompany.com":  # domain wildcard
        plan: pro
      ```
15. [ ] **Add Stripe webhook handler** - `/webhooks/stripe` (tunn.to only)
      - Verify Stripe signature with STRIPE_WEBHOOK_SECRET
      - On subscription.created: add user to SQLite with plan='pro'
      - On subscription.deleted: update plan='free'

### Cluster Security (One Secret)
16. [ ] **Replace mTLS with CLUSTER_SECRET auth** - Simpler mesh security
      - `CLUSTER_SECRET=""` → single node, no mesh (self-hosted default)
      - `CLUSTER_SECRET=xxx` → mesh enabled, nodes auth with HMAC
      - Node handshake: `Authorization: Bearer HMAC(timestamp, CLUSTER_SECRET)`
      - Wrong secret = ignore that node, stop retrying

### Mesh Auto-Discovery (Fly.io)
17. [ ] **Auto-discover nodes via internal DNS** - No manual NODE_ADDRESSES
      - Resolve `<appname>.internal` → returns all instance IPs
      - Filter out self, connect to others
      - New nodes auto-join mesh on boot
      - **Fly.io specific** - see vendor lock-in notes below

### LiteFS Replication (tunn.to)
18. [ ] **Add LiteFS support for SQLite replication** - Fly.io native
      - Mount `/litefs`, SQLite lives there
      - Writes go to primary (auto-elected), replicate in <1s
      - All nodes see same data
      - **Fly.io specific** - see vendor lock-in notes below

### Subdomain Reservations (Pro Feature)
19. [ ] **Add subdomain reservation** - Pro users get 4 reserved subdomains
      - Store in UserStore: `email → [subdomain1, subdomain2, ...]`
      - `tunn 8080 --subdomain myapp` claims/uses reservation
      - Validation: 3+ chars, alphanumeric + hyphens, not reserved
      - Reserved list: www, api, app, admin, auth, static, cdn, etc.
      - No nesting (x.y.tunn.to) - wildcard certs only cover one level

### Marketing & Homepage
20. [ ] **Create tunn.to homepage** - ntfy.sh inspired, simple dev-focused
      - Hero: one-liner + install command
      - Live demo or GIF
      - Pricing table (Free / Pro $4/mo / Enterprise contact)
      - Code examples
      - Self-host instructions
      - Serve from app at `/` when no tunnel subdomain

**OAuth is blocking if you want real Google login. PUBLIC_MODE=true bypasses auth for testing only.**

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
- [ ] Rate limiting (Free: 10 MiB/month, Pro: 50 GB/month hard cap)
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
