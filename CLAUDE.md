# CLAUDE.md: tunn V1 Architecture Blueprint

**Project Status:** Claude Code is driving implementation to launch.

**Last Updated:** 2025-11-16

This document outlines the production-ready V1 architecture for `tunn`, designed for deployment on Fly.io as a **free, open-source hosted service**.

## Core Philosophy

`tunn` is a **radically simple, free-forever reverse tunnel service with Google Doc-style sharing**.

Share your local dev server like you'd share a Google Doc:
```bash
$ tunn serve -to localhost:8000 --allow alice@gmail.com,bob@company.com
🔗 https://abc123.tunn.to → localhost:8000
   Accessible by: you@gmail.com, alice@gmail.com, bob@company.com
```

**Business Model:** Run it for free. If it gets busy enough to need >4 Fly.io nodes, we'll add optional paid tiers. If not, it stays free forever.

**Abuse Prevention:** Per-tunnel rate limiting (10MiB/month baseline) + GitHub OAuth prevents free-tier abuse while keeping infrastructure costs near-zero.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                  tunn.to (Free Hosted)                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Fly.io Edge (443/tcp, 443/udp)                      │   │
│  └────────┬─────────────────────────────────────────────┘   │
│           │                                                  │
│  ┌────────▼─────────────────────────────────────────────┐   │
│  │  tunn Proxy Nodes (1-4 instances)                    │   │
│  │  - HTTP/2 + HTTP/3 listeners                         │   │
│  │  - gRPC control plane                                │   │
│  │  - Per-IP rate limiting (10MiB/month)                │   │
│  │  - Full mesh inter-node sync                         │   │
│  └────────┬─────────────────────────────────────────────┘   │
│           │ Internal gRPC Mesh                               │
│  ┌────────▼─────────────────────────────────────────────┐   │
│  │  Node 1 ←→ Node 2 ←→ Node 3 ←→ Node 4               │   │
│  │  (Sync: tunnel locations, rate limit usage)          │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         ▲ gRPC tunnel
         │
    ┌────┴─────┐
    │   tunn   │  $ tunn serve -to localhost:8000
    │   serve  │  🔗 https://abc123.tunn.to → localhost:8000
    └──────────┘
```

## Technical Architecture

### 1. The `tunn` Proxy (Central Server)

The Proxy is a stateless Go application designed to run on Fly.io with 1-4 instances.

**Listeners:**
- **HTTP/2 Server (TCP:8443):** Serves gRPC control plane + HTTPS data plane
- **HTTP/3 Server (UDP:8443):** Modern QUIC-based listener for browser clients
- **Internal gRPC (TCP:50051):** Node-to-node communication (tunnel discovery + rate limit sync)

**Authentication:**
- **GitHub OAuth:** Users log in with GitHub (devs all have GitHub, simpler than Google)
- **Device Code Flow for CLI:** `tunn login` opens browser, user authenticates, CLI polls for token
- **Email Allow-Lists:** Tunnel creator specifies allowed emails (Google Doc sharing model)
- **Session Cookies:** Browser users get session cookie after GitHub login
- **JWT Tokens:** CLI users get JWT after device flow, stored in `~/.tunn/token`
- **Multi-Node Auth:** Device codes stored in SQLite, replicated via LiteFS across nodes

**CLI Login Flow (`tunn login`):**
1. CLI: `POST /api/device/code` → server creates device code in SQLite
2. CLI: opens browser to `tunn.to/login?device_code=ABC123` (pre-filled, no typing)
3. User: clicks "Login with GitHub" → standard OAuth redirect flow
4. Server: on callback, marks device code authorized, stores JWT
5. CLI: polls `GET /api/device/token?code=ABC123` every 3s until authorized
6. CLI: saves JWT to `~/.tunn/token`

**Browser Auth Flow (visiting tunnels):**
1. User visits `https://abc123.tunn.to`
2. If no session, redirect to `/auth/login?return_to=...`
3. User clicks "Login with GitHub" → GitHub OAuth
4. On callback, session cookie set, redirect back to tunnel

**Identity Model (Email Buckets):**
- An "account" is a bucket of verified emails, not a username
- When you OAuth with GitHub, all your GitHub emails join your bucket
- Allow-list checks match against ANY email in your bucket
- If `--allow work@company.com` and you login with `personal@gmail.com` (same bucket), access granted
- Pro status applies to the whole bucket, not individual emails
- Account merge: if GitHub proves you own emails from 2 different accounts, they merge automatically

**Rate Limiting:**
- **Per-IP bandwidth quota:** 10MiB/month baseline (configurable via env var)
- **Distributed state:** Each node tracks IPs it sees, syncs with other nodes every 30s
- **Enforcement:** Proxy rejects requests when IP exceeds quota
- **Reset:** Monthly on calendar month boundary

**Control Plane:**
- gRPC bidirectional stream between proxy and `tunn serve` clients
- Multiplexed: all tunnels and data streams go over one gRPC connection
- Messages: RegisterClient, ProxyRequest, DataChunk, StreamClosed, HealthCheck

### 2. The `tunn serve` Client ("Sharer")

**Setup:**
```bash
# Private tunnel (only you can access)
$ tunn serve -to http://localhost:8000
🔗 https://abc123.tunn.to → localhost:8000
   Accessible by: you@gmail.com

# Shared tunnel (Google Doc model)
$ tunn serve -to http://localhost:8000 --allow alice@gmail.com,bob@company.com
🔗 https://abc123.tunn.to → localhost:8000
   Accessible by: you@gmail.com, alice@gmail.com, bob@company.com
```

**Access Control:**
- Creator must be logged in (`tunn login` first)
- Creator's email automatically added to allow-list
- `--allow` flag adds additional emails
- Visitors must log in with GitHub and be on the allow-list
- Unauthorized visitors see "Access denied"

**Transport:**
- Single persistent gRPC bidirectional stream to proxy
- Sends health checks every 30s
- Receives ProxyRequest messages when public HTTP request arrives
- Sends DataChunk messages with HTTP response data

### 3. Local Testing Strategy

The entire system is designed to be testable on a single machine:

1. **Wildcard DNS:** Use `nip.io` (e.g., `*.tunn.local.127.0.0.1.nip.io`) for subdomain routing on localhost
2. **Self-Signed Certificates:** Dev mode auto-generates certs for local TLS
3. **Single Process:** Can run proxy + multiple clients on one machine for testing

## Data Plane Architecture (Critical Missing Piece)

**Current Status:** Control plane exists, data plane is **stubbed**.

**What Needs Implementation:**

The proxy needs to forward HTTP request/response data through the gRPC tunnel:

1. **Incoming HTTP request** to `https://abc123.tunn.to/foo`
2. **Proxy finds tunnel** via gRPC TunnelServer
3. **Proxy sends ProxyRequest** to client over gRPC stream
4. **Proxy waits for DataChunk messages** from client with HTTP response
5. **Client receives ProxyRequest**, makes HTTP request to localhost:8000
6. **Client streams response** back as DataChunk messages
7. **Proxy reconstructs HTTP response** and sends to original browser

**Protocol Addition Required:**

```protobuf
message TunnelMessage {
  oneof message {
    // ... existing messages ...
    DataChunk data_chunk = 7;
    StreamClosed stream_closed = 8;
  }
}

message DataChunk {
  string connection_id = 1;    // Matches ProxyRequest.connection_id
  bytes data = 2;               // HTTP response bytes
  bool from_client = 3;         // true = response, false = request
}

message StreamClosed {
  string connection_id = 1;
  string reason = 2;
}
```

## Rate Limiting Architecture

**Goal:** Prevent abuse while keeping infrastructure costs ~$0.

**Strategy:** Track bandwidth usage per source IP, sync across nodes.

**Baseline Quota:** 10MiB/month per IP (configurable via `RATE_LIMIT_MB_PER_MONTH`)

**Why 10MiB?**
- Enough for testing (a few page loads)
- Not enough for abuse (hosting video streaming, etc.)
- Keeps bandwidth costs negligible
- Can be raised if needed

**Implementation:**

Each node maintains in-memory map:
```go
map[string]*IPUsage {
  "1.2.3.4": {
    BytesThisMonth: 5242880,  // 5 MiB used
    LastReset: time.Date(2025, 11, 1, ...),
    MonthlyLimit: 10485760,   // 10 MiB limit
  }
}
```

**Inter-Node Sync:**

Every 30 seconds, each node broadcasts to all other nodes:
```protobuf
message SyncUsage {
  map<string, int64> ip_usage = 1;  // IP -> bytes used this month
  int64 timestamp = 2;
}
```

Nodes merge by taking `max(local, remote)` for each IP. This is eventually consistent and prevents double-counting.

**Full Mesh:** With 1-4 nodes, a full mesh is simple (max 6 connections). If we ever need >4 nodes, we're charging money and can use Redis.

## Technology Choices

- **Control Plane:** gRPC (over HTTP/2) for robust, multiplexed communication
- **Data Plane:** HTTP reverse proxy over gRPC DataChunk messages
- **HTTP/3:** `github.com/quic-go/quic-go` for modern browser support
- **Protobuf:** `google.golang.org/protobuf` for gRPC API definitions
- **Rate Limiting:** In-memory, synced via gRPC mesh
- **No Database:** Fully stateless, ephemeral tunnels

## Build and Test Commands

**CRITICAL: Always use `make` for building and testing. Never run `go` commands directly.**

This project uses a comprehensive Makefile to ensure consistent builds and tests across all environments.

### Essential Commands

**Building:**
- `make build` - Build the binary for the current OS
- `make proto` - Regenerate protobuf/gRPC code (run after modifying `.proto` files)
- `make clean` - Remove all build artifacts

**Testing:**
- `make test` - Run all tests (use this by default)
- `make test-race` - Run tests with race detection (use before commits)
- `make test-coverage` - Generate HTML coverage report

**Code Quality:**
- `make fmt` - Format all Go code
- `make tidy` - Tidy Go module dependencies
- `make verify` - Format and test (quick pre-commit check)
- `make check` - Comprehensive check: format, tidy, and test with race detection (thorough pre-commit)

**Common Workflows:**
- Before committing: `make check`
- After modifying proto files: `make proto && make test`
- Quick iteration: `make build && ./bin/tunn`
- Full verification: `make clean && make check && make build`

### Why Make Only?

1. **Consistency:** Ensures all builds use identical flags and configurations
2. **Protobuf Generation:** The `make proto` target handles code generation correctly
3. **Future-Proofing:** Build complexity is abstracted away
4. **Discoverability:** `make help` shows all available commands

**Exception:** You may use `go mod` commands directly for dependency management when needed, but prefer `make tidy`.

## Deployment Strategy

**Phase 1: Launch (Now → 2 Weeks)**
- Deploy single Fly.io node with tunn.to domain
- Open source the entire codebase on GitHub
- WELL_KNOWN_KEY hardcoded (or well-known secret)
- 10MiB/month rate limit per IP
- Free for everyone
- No analytics, no tracking, no user accounts

**Phase 2: Scale (If Needed)**
- Add 2-4 Fly.io nodes as traffic grows
- Full mesh inter-node communication
- Shared rate limiting state
- Still free

**Phase 3: Monetize (If We Get Here)**
- If sustained >4 nodes for >3 months → add paid tiers
- Free tier: 10MiB/month (same as now)
- Paid tier: Higher limits + custom domains + support
- Implement auth provider (see archive of TODO.md Phase 7)

**Target:** Launch Phase 1 within 1 week.

## What's NOT Included (For Now)

**Removed from V1:**
- ❌ Billing / Stripe integration (premature)
- ❌ Custom auth provider (tunn-auth)
- ❌ User database (stateless via GitHub OAuth)
- ❌ UDP tunneling (Phase 5 - defer to v1.1)
- ❌ Custom domains (can add later if paid tiers)

**What We're Building:**
- ✅ HTTP/HTTPS tunneling over gRPC
- ✅ GitHub OAuth (browser + CLI device flow)
- ✅ Email allow-lists (sharing by email, like Google Docs)
- ✅ Session cookies + JWT tokens
- ✅ Per-tunnel rate limiting
- ✅ Inter-node sync
- ✅ Horizontal scaling (1-4 nodes)
- ✅ Free hosted service at tunn.to
- ✅ Open source everything

## Implementation Status

**Completed:**
- ✅ gRPC control plane (bidirectional streaming)
- ✅ Tunnel registration and management
- ✅ Health checks
- ✅ Inter-node tunnel discovery
- ✅ HTTP/2 + HTTP/3 listeners
- ✅ GitHub OAuth browser flow (login, callback, sessions)
- ✅ Device code flow for CLI (`tunn login` command)
- ✅ Session cookie management
- ✅ JWT validation middleware
- ✅ Dev/prod configuration

**In Progress (Claude Code Driving):**
- 🚧 Email allow-list protocol (add to RegisterClient)
- 🚧 Allow-list enforcement (check email in webproxy.go)
- 🚧 Data plane: HTTP forwarding over gRPC (CRITICAL)
- 🚧 Per-tunnel rate limiting (10MiB/month)
- 🚧 Implement device code endpoints for CLI login
- 🚧 Wire up GitHub OAuth (replace mock OIDC)

**Next Up:**
- ⏸ E2E testing
- ⏸ Fly.io deployment
- ⏸ Documentation
- ⏸ Open source launch

## Developer Notes

**This project is now being driven by Claude Code** (as of 2025-11-16).

**Key Decisions:**
1. **Free forever by default** - monetize only if forced to by scale
2. **Google Doc sharing model** - share tunnels by email, familiar UX
3. **GitHub OAuth only** - devs all have GitHub, simpler setup than Google
4. **Per-tunnel rate limiting** - 10MiB/month keeps costs near-zero
5. **Full mesh <4 nodes** - simple, no distributed system complexity
6. **OSS everything** - build in public, no secret sauce

**Philosophy:**
- Launch fast, iterate based on usage
- Don't build billing until we need it
- Keep it radically simple
- If successful → charge, if not → free forever

**Contact:**
- Owner: behrlich
- Implementation: Claude Code (Anthropic)
- Status: Active development
