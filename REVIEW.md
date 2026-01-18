# REVIEW.md: Pre-Launch Security & Quality Audit

**Last Updated:** 2026-01-18
**Sources:** Internal review (2025-01-17), Third-party review (codex, 2025-01-18)
**Status:** P0 critical FIXED, P1 mostly FIXED (1 deferred)

---

## Executive Summary

Third-party review identified multiple security and correctness issues. **All 5 P0 critical issues have been fixed.** Most P1 issues fixed; 1 deferred (requires proto change).

**P0 Critical Issues:** 5/5 FIXED
**P1 High Issues:** 6/7 FIXED (1 deferred - proto change)
**P2 Medium Issues:** 2/4 fixed (cosmetic)

---

## Critical (P0) - All Fixed

### 1. JWT Validation Bypass on Tunnel Registration

**Status:** FIXED (2025-01-18)
**Verified:** YES
**Location:** `internal/host/grpc_server.go:227-259`

**The Bug:** If a client sends `CreatorEmail` already populated, the server uses it directly WITHOUT validating the JWT signature. JWT validation only happens when `CreatorEmail == ""`.

```go
// grpc_server.go:227-228
creatorEmail = regClient.CreatorEmail
if creatorEmail == "" {
    // JWT validation happens here - but SKIPPED if CreatorEmail already set!
```

**Impact:** Malicious client can:
- Create tunnels as any email (impersonation)
- Bypass allow-list ownership checks
- Steal quota from other accounts
- Claim reserved subdomains

**Fix:** Always validate JWT signature on server. IGNORE client-provided `CreatorEmail`. Derive email only from validated token.

---

### 2. Session Cookies Leaked to Tunnel Owners

**Status:** FIXED (2025-01-18)
**Verified:** YES
**Locations:**
- `internal/host/proxy.go:177` - cookie domain set to `.<domain>`
- `internal/host/webproxy.go:179-183` - all headers forwarded to tunnel target

**The Bug:** Session cookie domain is `.tunn.to`, making it available on ALL tunnel subdomains (`*.tunn.to`). HTTP requests forward all headers including `Cookie` to the user's local service.

```go
// proxy.go:177
sessionManager.Cookie.Domain = "." + cfg.Domain

// webproxy.go:179-183 - Includes Cookie header!
for key, values := range r.Header {
    headers[key] = strings.Join(values, ", ")
}
```

**Impact:** Tunnel owner can read `tunn_session` cookie for ANY visitor who's logged in. Enables session hijacking and account takeover.

**Fix Options:**
1. **Strip platform cookies** before proxying to tunnel target (recommended for V1)
2. Use separate domain for auth (e.g., `auth.tunn.to` with cookies scoped only there)
3. Host tunnels on different apex domain (e.g., `*.tunnels.to`)

---

### 3. Concurrent gRPC Stream.Send (Data Race)

**Status:** FIXED (2025-01-18)
**Verified:** YES
**Locations:**
- Client: `internal/client/serve.go:166` (health checks in goroutine)
- Client: `internal/client/serve.go:194` (request handlers spawn goroutines)
- Client: `internal/client/serve.go:275,303,326` (all call `stream.Send`)
- Server: `internal/host/webproxy.go:215` (concurrent HTTP requests call `tunnel.Stream.Send`)

**The Bug:** gRPC streams are NOT thread-safe for concurrent `Send()`. Multiple goroutines call `Send()` without synchronization.

```go
// serve.go - health checks run in separate goroutine
go s.sendHealthChecks(ctx, stream)  // line 166

// serve.go - each request spawns a goroutine that calls stream.Send
go s.handleHttpRequest(stream, m.HttpRequest)  // line 194
```

**Impact:** Data races, corrupted frames, random stream failures, intermittent tunnel drops under load.

**Fix:** Serialize all sends through a single goroutine with a channel, or protect `Send()` with a mutex.

---

### 4. Response Channel Close Race (Panic)

**Status:** FIXED (2025-01-18)
**Verified:** YES
**Locations:**
- `internal/host/webproxy.go:205` - channel closed in defer
- `internal/host/grpc_server.go:429` - send to potentially-closed channel

**The Bug:** The response channel is closed after timeout in `proxyHTTPOverGRPC`. The server receive loop can still try to send to this closed channel, causing a panic.

```go
// webproxy.go:205 - closes channel on return
defer func() {
    ...
    close(respChan)
}()

// grpc_server.go:429 - sends to channel that might be closed
case respChan <- m.HttpResponse:  // PANIC if closed
```

The `select` with `default` only handles a full channel, NOT a closed one.

**Impact:** `panic: send on closed channel` - crashes request handling, can drop tunnels.

**Fix:** Use a non-closing channel pattern, or add synchronization (e.g., `sync.Once` for close, check before send).

---

### 5. Open Redirect Vulnerability

**Status:** FIXED (2025-01-18)
**Verified:** YES
**Locations:**
- `internal/host/auth.go:35-39` - stores `return_to` without validation
- `internal/host/auth.go:220` - redirects to it
- `internal/host/webproxy.go:92` - embeds without URL escaping

**The Bug:** `return_to` parameter accepted from query string and used as redirect target without validation.

```go
// auth.go:35-39
returnTo := r.URL.Query().Get("return_to")
p.sessionManager.Put(r.Context(), "return_to", returnTo)

// webproxy.go:92 - not escaped
loginURL := fmt.Sprintf("/auth/login?return_to=%s", returnTo)
```

**Impact:** Phishing vector - attacker crafts `tunn.to/auth/login?return_to=https://evil.com` to redirect users after login.

**Fix:**
1. Validate `return_to` is a relative path only (reject if contains `://` or starts with `//`)
2. Always use `url.QueryEscape()` when embedding

---

## High (P1) - Should Fix Before Launch

### 6. Multi-Node Proxying Host Rewriting

**Status:** FIXED (2026-01-18)
**Verified:** YES
**Location:** `internal/host/webproxy.go:327-356`

**The Bug:** `httputil.NewSingleHostReverseProxy` rewrites `Host` header to the target node address. The remote node uses `r.Host` to extract tunnel ID, so it won't find the tunnel.

**Impact:** Multi-node routing broken - remote tunnels may 503 or show homepage.

**Fix:** Custom Director function preserves original Host header before proxying.

---

### 7. Internal gRPC TLS Hostname Verification Fragile

**Status:** FIXED (2026-01-18)
**Verified:** YES
**Location:** `internal/host/proxy.go:248-253`

**The Bug:** Internal clients dial by IP (`[ipv6]:port`) but don't set `ServerName` in TLS config. Certificate validation fails unless cert has IP SANs.

**Impact:** Multi-node auth fails in production.

**Fix:** Set `tlsConfig.ServerName = cfg.Domain` so TLS validation uses the domain name.

---

### 8. Unbounded Goroutine Creation

**Status:** FIXED (2025-01-18)
**Verified:** YES
**Location:** `internal/client/serve.go:194`

**The Bug:** Each inbound HTTP request spawns a new goroutine without limit.

**Impact:** DoS on client - flood of requests exhausts memory/scheduler.

**Fix:** Use worker pool or semaphore to limit concurrent in-flight requests.

---

### 9. No Request/Response Size Limits

**Status:** FIXED (2025-01-18)
**Verified:** YES
**Locations:**
- `internal/host/webproxy.go:173` - `io.ReadAll(r.Body)`
- `internal/client/serve.go:248` - `io.ReadAll(resp.Body)`

**The Bug:** Unbounded `io.ReadAll` can consume all memory.

**Impact:** Memory exhaustion on both proxy and client.

**Fix:** Use `io.LimitReader` with reasonable cap (e.g., 100MB).

---

### 10. Tunnel ID Not Validated Against DNS Labels

**Status:** FIXED (2026-01-18)
**Verified:** YES
**Location:** `internal/host/grpc_server.go:57-86,201-214`

**The Bug:** Tunnel IDs can contain invalid DNS characters or dots.

**Impact:** User-visible failures, URL confusion.

**Fix:** Added `isValidDNSLabel()` function that validates RFC 1123 DNS labels. Tunnel IDs are normalized to lowercase and rejected if invalid.

---

### 11. Header Map Flattens Multi-Value Headers (Set-Cookie Broken)

**Status:** DEFERRED (>2hr - requires proto change)
**Verified:** YES
**Locations:**
- `proto/tunnel.proto:113,126` - `map<string, string> headers`
- `internal/client/serve.go:255-259` - joins with ", "

**The Bug:** Proto uses `map<string, string>` which loses multi-value headers. `Set-Cookie` values contain commas in dates, so joining breaks them.

**Note:** This requires changing the proto schema and updating all code that handles headers. Deferred to post-launch.

**Fix:** Change proto to `repeated HeaderEntry` with `repeated string values`.

---

### 12. NodeSecret Not Enforced in Production

**Status:** FIXED (2026-01-18)
**Verified:** YES
**Location:** `internal/host/proxy.go:93-96`

**The Bug:** If `NodeSecret` is empty, internal RPC auth is a no-op.

**Impact:** Internal APIs exposed if port is reachable.

**Fix:** `NewProxyServer()` returns error if `NodeAddresses` is set but `NodeSecret` is empty.

---

## Medium (P2) - Fix Before Launch

### 13. AI Placeholder Comment

**Verified:** YES
**Location:** `internal/host/proxy.go:242`

Contains `// ... (rest of the file)` - looks unprofessional.

**Fix:** Delete the comment.

---

### 14. Missing Documentation

**Verified:** YES
**Location:** `README.md:46,58`

References docs that don't exist:
- `docs/self-hosting.md`
- `docs/DEVELOPMENT.md`

**Fix:** Create the docs or remove references.

---

### 15. No Cache TTL for tunnelCache

**Location:** `internal/host/webproxy.go`

Tunnel routing cache has no expiry - stale if tunnel moves nodes.

**Fix:** Add TTL (e.g., 30 seconds).

---

### 16. Duplicate Install Script

**Locations:** `install.sh` and embedded in `internal/host/proxy.go`

Same script in two places can drift.

**Fix:** Use `//go:embed install.sh` instead of duplicating.

---

## Already Tracked (Accepted V1 Limitations)

- **Usage tracking uses email instead of account ID** - See TODO.md lines 377-383

---

## Positive Notes

Solid aspects from the review:
- TLS termination correctly configured for HTTP/2 and HTTP/3
- OAuth state parameter uses crypto-secure randomness
- Device code storage uses secure random generation
- Session cookie settings include `Secure` and `SameSite=Lax`
- Structured logging doesn't expose secrets

---

## Recommended Test Additions

1. **Auth bypass regression** - Ensure tunnel registration fails with forged JWT
2. **gRPC stream concurrency** - Run with `-race` after fixing
3. **Cookie isolation** - Ensure `tunn_session` NOT forwarded to targets
4. **Return-to validation** - Only relative paths allowed
5. **Header fidelity** - `Set-Cookie` survives round-trip

---

## Previously Fixed (2025-01-17)

These issues were fixed in the previous review cycle:

1. ✅ **JWT validation on tunnel registration** - `grpc_server.go` now uses `validateJWTAndExtractEmail()`
2. ✅ **Magic link session key** - Changed `"email"` to `"user_email"` in magiclink.go
3. ✅ **Secret logging** - Removed `provided_key` from log output
4. ✅ **JWT_SECRET fallback** - Production panics if not configured
5. ✅ **InsecureSkipVerify** - Removed, uses system CA or `TUNN_CA_CERT`
6. ✅ **README Google → GitHub** - Updated

**Note:** Issue #1 in the new review (JWT bypass when CreatorEmail is set) is a DIFFERENT bug than the one fixed. The previous fix added signature validation but only when `CreatorEmail` is empty.
