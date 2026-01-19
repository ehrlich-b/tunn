# tunn 1.1 Design: Zero Trust for Humans

**Status:** Draft
**Author:** behrlich + Claude Code
**Date:** 2026-01-19

---

## The Vision

> **tunn is identity-aware routing for the post-VPN world.**
>
> Instead of routing packets through a network tunnel, we route requests through an identity check.
> Instead of "are you on the VPN?", we ask "are you in the eng group?"
> Instead of self-signed certs, we give your internal services real browser-trusted TLS.
>
> One command to expose. One flag to grant access. Zero network configuration.

**The killer line:** "Why are we routing packets when we can route identities?"

---

## Roadmap

| Version | Features | Theme |
|---------|----------|-------|
| **1.0** | Email allow-lists, `*.tunn.to` subdomains | Share localhost |
| **1.1** | Groups lite, Custom domains | Zero trust positioning |
| **1.2** | TCP/UDP mode, `tunn connect` | Beyond HTTP |
| **1.3** | LDAP/OIDC groups | Enterprise identity |
| **2.0** | Model B (tunnel terminates TLS) | Zero knowledge |

---

## 1.1 Scope: Groups Lite + Custom Domains

### Feature 1: Groups Lite

Groups are **syntactic sugar for email lists**. Nothing more.

```bash
# Create a group (stored in your account)
tunn group create eng alice@gmail.com bob@corp.com charlie@corp.com

# Use it
tunn 8080 -a group:eng

# Equivalent to:
tunn 8080 -a alice@gmail.com -a bob@corp.com -a charlie@corp.com
```

**Properties:**
- Groups belong to ONE account (yours)
- Groups cannot be shared with other accounts
- Groups are just saved email lists
- Edit via CLI (`tunn group add eng dave@corp.com`) or web UI
- No permissions, no hierarchy, no complexity

**Storage:**
```sql
CREATE TABLE groups (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  name TEXT NOT NULL,
  emails TEXT NOT NULL,  -- JSON array: ["alice@gmail.com", "bob@corp.com"]
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  UNIQUE(account_id, name)
);
```

**CLI:**
```bash
tunn group create <name> <emails...>
tunn group list
tunn group show <name>
tunn group add <name> <email>
tunn group remove <name> <email>
tunn group delete <name>
```

---

### Feature 2: Custom Domains

Customers bring their own domain. tunn.to issues and manages certs.

#### The Customer Experience

```bash
# Step 1: Register domain with tunn
$ tunn domain add tunn.mycompany.com

tunn: To verify ownership, add these DNS records to mycompany.com:

      *.tunn.mycompany.com                    CNAME  tunn.to
      _acme-challenge.tunn.mycompany.com      CNAME  a7x9k2._acme.tunn.to

      (a7x9k2 is your unique account identifier)

tunn: Waiting for DNS propagation...
tunn: Verified! *.tunn.mycompany.com is now registered to your account.

# Step 2: Use it
$ tunn 8080 -n grafana -a group:eng

🔗 https://grafana.tunn.mycompany.com → localhost:8080
   Allowed: group:eng (3 emails)
```

**Two CNAMEs, one-time setup, done forever.**

#### Who Configures What?

| Party | DNS Zone | Action | Frequency |
|-------|----------|--------|-----------|
| **Customer** | `mycompany.com` (their nameserver: Route53, GoDaddy, Cloudflare, etc.) | Add 2 CNAMEs | Once |
| **tunn.to** | `tunn.to` (our Cloudflare) | Create/delete TXT records for ACME challenges | Automated per cert issuance |

The customer never touches their DNS after initial setup. tunn.to's Cloudflare automation handles all certificate lifecycle operations.

#### Why Two CNAMEs?

| CNAME | Purpose |
|-------|---------|
| `*.tunn.mycompany.com → tunn.to` | Routes traffic to tunn.to |
| `_acme-challenge.tunn.mycompany.com → <id>._acme.tunn.to` | Delegates Let's Encrypt verification to tunn.to |

The second CNAME is the magic. It lets tunn.to answer DNS-01 challenges for wildcard certs without needing ongoing access to customer's DNS.

#### How Certificate Issuance Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CERTIFICATE ISSUANCE FLOW                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Customer runs: tunn 8080 --name=grafana                                  │
│                                                                              │
│  2. tunn.to checks: do we have a cert for *.tunn.mycompany.com?              │
│     - YES → use it                                                           │
│     - NO → issue one (on-demand TLS)                                         │
│                                                                              │
│  3. tunn.to starts ACME DNS-01 challenge:                                    │
│     a. Generate challenge token: "abc123xyz"                                 │
│     b. Set TXT record via Cloudflare API:                                    │
│        a7x9k2._acme.tunn.to  TXT  "abc123xyz"                               │
│                                                                              │
│  4. Let's Encrypt verifies:                                                  │
│     a. Look up _acme-challenge.tunn.mycompany.com                            │
│     b. Follow CNAME → a7x9k2._acme.tunn.to                                  │
│     c. Find TXT record: "abc123xyz" ✓                                        │
│     d. Domain verified!                                                      │
│                                                                              │
│  5. Let's Encrypt issues wildcard cert for *.tunn.mycompany.com              │
│                                                                              │
│  6. tunn.to stores cert (encrypted at rest)                                  │
│                                                                              │
│  7. tunn.to deletes TXT record (cleanup)                                     │
│                                                                              │
│  8. Traffic flows with valid TLS                                             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Implementation: CertMagic

Use [CertMagic](https://github.com/caddyserver/certmagic) - the battle-tested Go library from Caddy.

```go
import "github.com/caddyserver/certmagic"

// Configure ACME with Cloudflare DNS provider
certmagic.DefaultACME.Email = "certs@tunn.to"
certmagic.DefaultACME.DNS01Solver = &cloudflare.Provider{
    APIToken: os.Getenv("CLOUDFLARE_API_TOKEN"),
}

// On-demand TLS: issue certs during TLS handshake
cfg := certmagic.NewDefault()
cfg.OnDemand = &certmagic.OnDemandConfig{
    DecisionFunc: func(name string) error {
        // Check: is this domain registered to an account?
        if !isDomainRegistered(name) {
            return fmt.Errorf("domain not registered")
        }
        return nil
    },
}

tlsConfig := cfg.TLSConfig()
```

**On-Demand TLS** (invented by Caddy):
- First request arrives with SNI `grafana.tunn.mycompany.com`
- No cert? Issue one RIGHT NOW during the handshake
- Cache it for future requests
- Auto-renew before expiry

#### Let's Encrypt Rate Limits

| Limit | Value | Impact |
|-------|-------|--------|
| Certs per Registered Domain per week | 50 | Per CUSTOMER domain, not tunn.to |
| New orders per account per 3 hours | 300 | tunn.to's ACME account |
| Failed validations per hostname per hour | 5 | Retry limit |

**Why this isn't a problem:**
- The 50/week limit applies to `mycompany.com`, not `tunn.to`
- Each customer has their own limit
- Wildcard certs cover unlimited subdomains with ONE issuance
- Renewals don't count against new cert limits

**Example:**
- 1000 customers, each with one wildcard domain
- 1000 certs total, each renewed every 60 days
- ~17 renewals/day across all customers
- Nowhere near any limits

#### Cloudflare DNS Management

tunn.to manages ONE zone: `tunn.to`

```
tunn.to zone (managed by us):
├── tunn.to                    A      203.0.113.1 (Fly anycast)
├── *.tunn.to                  A      203.0.113.1
├── _acme.tunn.to              TXT    (managed by CertMagic, ephemeral)
├── a7x9k2._acme.tunn.to      TXT    (challenge for customer A)
├── b8y3m1._acme.tunn.to       TXT    (challenge for customer B)
└── ...
```

**Cloudflare limits:**
- Free plan: 3,500 DNS records per zone
- TXT records are EPHEMERAL (created for challenge, deleted after)
- At any moment: maybe 10-100 concurrent challenges
- Not a scaling concern

**Cost:** $0 (Cloudflare free plan)

#### Domain Storage

```sql
CREATE TABLE domains (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  domain TEXT NOT NULL,           -- "tunn.mycompany.com"
  acme_identifier TEXT NOT NULL,  -- "a7x9k2" (unique per account)
  allowed_users TEXT,             -- JSON array: ["@mycompany.com"] or null (owner only)
  verified_at TIMESTAMP,
  cert_issued_at TIMESTAMP,
  cert_expires_at TIMESTAMP,
  created_at TIMESTAMP,
  UNIQUE(domain)
);
```

#### Domain Sharing (Team Access)

Domains belong to one account, but the owner can grant usage rights to others:

```bash
# Grant your whole company access to create tunnels on this domain
$ tunn domain share tunn.mycompany.com @mycompany.com

# Or specific people
$ tunn domain share tunn.mycompany.com alice@company.com,bob@company.com

# Revoke
$ tunn domain unshare tunn.mycompany.com bob@company.com

# Check who can use it
$ tunn domain show tunn.mycompany.com
Domain: tunn.mycompany.com
Owner:  bryan@tunn.to
Shared: @mycompany.com (domain wildcard)
Status: verified
```

**Sharing semantics:**
- `@mycompany.com` - anyone with a verified `*@mycompany.com` email can create tunnels
- Explicit emails for contractors or external collaborators
- Domain owner retains full control (can revoke, delete domain)
- Shared users can only create/delete their own tunnels, not manage the domain

This is intentionally simple - no roles, no permissions hierarchy. The owner shares, others use.

#### TLS Termination: Model A (1.1 Default)

**tunn.to terminates TLS.** This is the Cloudflare model.

```
Browser ──TLS──► tunn.to ──TLS──► tunnel ──HTTP──► localhost
                   │
           (tunn.to has cert for *.tunn.mycompany.com)
           (tunn.to CAN see plaintext)
```

**Why this is okay:**
- Same trust model as Cloudflare, Fastly, every CDN
- Simpler implementation (no client-side cert handling)
- Enables L7 features (auth redirects, logging, future WAF)
- 99% of users accept this tradeoff

**Model B (tunnel terminates TLS) is 2.0.** Zero-knowledge is a feature for paranoid enterprises, not 1.1.

---

## Architecture

### Current (1.0): `*.tunn.to` Only

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            tunn.to (Fly.io)                              │
│                                                                          │
│  Holds: *.tunn.to wildcard cert                                          │
│  Terminates: TLS for all *.tunn.to traffic                               │
│  Routes: by subdomain (abc123.tunn.to → tunnel abc123)                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.1: Custom Domains Added

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            tunn.to (Fly.io)                              │
│                                                                          │
│  Certs (all managed by CertMagic):                                       │
│  - *.tunn.to (our wildcard)                                              │
│  - *.tunn.mycompany.com (customer A's wildcard)                          │
│  - *.tunn.acme.corp (customer B's wildcard)                              │
│  - ... (on-demand, as customers register)                                │
│                                                                          │
│  TLS Termination:                                                        │
│  - All certs stored encrypted in SQLite/LiteFS                           │
│  - Loaded into memory via CertMagic                                      │
│  - GetCertificate callback selects correct cert by SNI                   │
│                                                                          │
│  Routing:                                                                │
│  - grafana.tunn.mycompany.com → account A's tunnel "grafana"             │
│  - jenkins.tunn.acme.corp → account B's tunnel "jenkins"                 │
│                                                                          │
│  Auth:                                                                   │
│  - Check session cookie                                                  │
│  - Verify user is in tunnel's allow list                                 │
│  - Redirect to login if needed                                           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Request Flow (1.1)

```
1. Browser visits https://grafana.tunn.mycompany.com

2. DNS resolution:
   grafana.tunn.mycompany.com
   → CNAME *.tunn.mycompany.com → tunn.to
   → A record → 203.0.113.1 (Fly anycast)

3. TLS handshake:
   - Browser sends ClientHello with SNI: grafana.tunn.mycompany.com
   - tunn.to looks up cert for *.tunn.mycompany.com (CertMagic)
   - If no cert: issue on-demand via DNS-01
   - Complete handshake

4. HTTP request (now decrypted at tunn.to):
   - Check session cookie
   - No session? → Redirect to /auth/login?return=...
   - Has session? → Check allow list for tunnel "grafana" on account A
   - Allowed? → Proxy to tunnel
   - Denied? → 403

5. Proxy to tunnel:
   - Look up: which Fly node has account A's tunnel "grafana"?
   - Forward request via internal gRPC
   - Tunnel forwards to localhost:8080
   - Response flows back
```

---

## CLI Changes for 1.1

**Adopt [cobra](https://github.com/spf13/cobra)** for standard CLI ergonomics: short flags, subcommands, shell completion, auto-generated help.

### Tunnel Command

```bash
tunn 8080                                    # Random subdomain
tunn 8080 -n grafana                         # Named tunnel
tunn 8080 -n grafana -a group:eng            # With group access
tunn 8080 -n grafana -a group:eng -a alice@gmail.com  # Multiple allows
tunn 8080 -n grafana -d tunn.mycompany.com   # Explicit domain
```

| Flag | Long | Description |
|------|------|-------------|
| `-n` | `--name` | Tunnel name (subdomain) |
| `-a` | `--allow` | Add to allow list (repeatable) |
| `-d` | `--domain` | Which custom domain to use |

### Subcommands

```bash
# Groups
tunn group create <name> <emails...>
tunn group add <name> <email>
tunn group rm <name> <email>
tunn group list
tunn group delete <name>

# Domains
tunn domain add <domain>
tunn domain share <domain> <emails...>
tunn domain unshare <domain> <email>
tunn domain list
tunn domain delete <domain>
```

### Domain Resolution

When `-d` is omitted:
1. One custom domain → use it
2. Zero custom domains → use `*.tunn.to`
3. Multiple custom domains → error, require `-d`

---

## Security Model (1.1)

### What tunn.to CAN See

| Data | Visible? | Notes |
|------|----------|-------|
| SNI (domain name) | Yes | Needed for routing |
| Source IP | Yes | Standard proxy behavior |
| Request/response content | **Yes** | Model A: we terminate TLS |
| Timing, bytes transferred | Yes | Standard proxy behavior |
| User identity | Yes | We do auth |

### What tunn.to CANNOT Do

| Action | Possible? | Notes |
|--------|-----------|-------|
| Issue certs for domains we don't control | No | DNS verification required |
| Access tunnels without allow-list permission | No | Auth enforced |
| Persist private keys for Model B | No | Model B not implemented in 1.1 |

### Trust Model

**You trust tunn.to like you trust Cloudflare:**
- We can see your traffic (Model A)
- We could theoretically log/modify it
- We won't, but you're trusting us not to

**This is acceptable for:**
- Dev/staging environments
- Internal tools
- Non-sensitive services
- Anything you'd put behind Cloudflare Access

**For zero-knowledge (tunn.to can't see plaintext):** Wait for Model B in 2.0.

---

## Storage Schema (1.1 Additions)

```sql
-- Groups (new)
CREATE TABLE groups (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  name TEXT NOT NULL,
  emails TEXT NOT NULL,  -- JSON array
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  UNIQUE(account_id, name)
);

-- Domains (new)
CREATE TABLE domains (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  acme_identifier TEXT NOT NULL,
  allowed_users TEXT,      -- JSON array: ["@mycompany.com"] or null (owner only)
  verified_at TIMESTAMP,
  cert_pem TEXT,           -- Full cert chain
  key_pem_encrypted TEXT,  -- Private key (encrypted at rest)
  cert_expires_at TIMESTAMP,
  created_at TIMESTAMP,
  UNIQUE(domain)
);

-- Updated tunnels table
ALTER TABLE tunnels ADD COLUMN name TEXT;
ALTER TABLE tunnels ADD COLUMN domain_id TEXT REFERENCES domains(id);
```

---

## Implementation Checklist

### 1.1.0: Groups Lite
- [ ] `groups` table schema
- [ ] `tunn group` CLI commands
- [ ] `--allow=group:name` flag parsing
- [ ] Group expansion in auth check
- [ ] Web UI for group management

### 1.1.1: Custom Domains
- [ ] Adopt cobra for CLI
- [ ] `domains` table schema (with `allowed_users`)
- [ ] `tunn domain add` CLI with DNS instructions
- [ ] DNS verification (check CNAME exists)
- [ ] CertMagic integration
- [ ] Cloudflare DNS provider for ACME
- [ ] On-demand TLS in proxy
- [ ] `-n`, `-a`, `-d` flags
- [ ] Domain auto-selection (single custom domain → use it)
- [ ] Cert storage (encrypted)
- [ ] Auto-renewal (CertMagic handles this)

### 1.1.2: Domain Sharing
- [ ] `tunn domain share` command
- [ ] `tunn domain unshare` command
- [ ] `tunn domain show` to display shared users
- [ ] Authorization check: can this user create tunnels on this domain?

### 1.1.3: Polish
- [ ] `--allow=@domain.com` syntax
- [ ] Better error messages for DNS issues
- [ ] Domain verification status in web UI
- [ ] Cert expiry monitoring/alerts

---

## Future: Model B (2.0)

For enterprises who won't trust tunn.to with plaintext:

```
Browser ──TLS────────────────────► tunnel ──HTTP──► localhost
                                      │
                              (tunnel has cert)
                              (tunn.to sees only encrypted bytes)
```

**Requirements:**
- Client-side key generation
- CSR submission to control plane
- Cert delivery (public only, never private key)
- SNI-based TCP passthrough (no TLS termination)

**Complexity:** High. Different code paths, different proxy mode, client changes.

**When:** After proving Model A works and customers ask for it.

---

## Competitive Position

| Feature | ngrok | Cloudflare Access | Tailscale | zrok | tunn 1.1 |
|---------|-------|-------------------|-----------|------|----------|
| Setup time | 1 min | 30 min | 5 min | 5 min | 1 min |
| Custom domains | Pro ($) | Yes | N/A | ? | Yes (free) |
| Identity access control | Basic auth | IdP integration | Device-based | Token-based | Email/group |
| Browser access | Yes | Yes | No (app) | Yes | Yes |
| TLS certs | Managed | Managed | N/A | Managed | Managed |
| Who terminates TLS | ngrok | Cloudflare | N/A | zrok | tunn.to |
| Open source | No | No | No | Yes | Yes |

**tunn's niche:** One-command setup + identity-based access + custom domains + open source.

---

## Open Questions

- [ ] **Domain transfer:** Can you transfer a domain to another account? (Probably yes, rare operation)
- [ ] **Subdomain limits:** Max subdomains per wildcard domain? (Probably unlimited - it's one cert)
- [ ] **Cert caching:** Store in LiteFS or memory-only with re-issuance on restart? (LiteFS preferred)
- [ ] **Monitoring:** Alert when cert renewal fails? (Yes, critical)
- [ ] **Shared domain cleanup:** When someone leaves the company, do their tunnels on shared domains auto-expire?

---

*Draft. Ready for implementation planning.*
