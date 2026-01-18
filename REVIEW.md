# REVIEW.md: Pre-Launch Security & Quality Audit

**Last Updated:** 2026-01-18
**Sources:** Internal review (2025-01-17), Third-party review (codex, 2025-01-18), Comprehensive review (Claude Opus 4.5, 2026-01-18)
**Status:** Critical issues FIXED, remaining items are lower priority

---

## Executive Summary

This document consolidates all security reviews for tunn.to. The original third-party review (2025-01-18) identified critical issues that have been fixed. A comprehensive follow-up review (2026-01-18) identified additional security concerns, with the critical ones now fixed.

**Original Review (2025-01-18):**
- P0 Critical Issues: 5/5 FIXED
- P1 High Issues: 6/7 FIXED (1 deferred - proto change)
- P2 Medium Issues: 2/4 fixed

**Comprehensive Review (2026-01-18):**
- Critical Issues: 3/4 FIXED (C1, C2, C3), 1 remaining (C4 - cookie domain, mitigated by stripping)
- High Priority: 2/6 FIXED (H2, H4), 4 remaining (H1, H3, H5, H6)
- Medium Priority: 7 items (lower priority, acceptable for launch)

---

## New Findings (2026-01-18 Comprehensive Review)

### Critical Issues (NEW - MUST FIX)

#### NEW-C1. Non-Constant-Time Token Comparisons [HIGH SEVERITY]

**Status:** FIXED (2026-01-18)
**Location:** `internal/host/proxy.go:410`, `internal/host/grpc_server.go:599`, `internal/common/auth.go:21`

**The Bug:** Token/secret comparisons used `!=` and `==` which are vulnerable to timing attacks.

**Fix Applied:** All three locations now use `crypto/subtle.ConstantTimeCompare()`:
- `proxy.go`: Node secret validation in `nodeSecretInterceptor`
- `grpc_server.go`: User token validation in `validateUserToken`
- `common/auth.go`: Bearer token validation in `AuthMiddleware`

---

#### NEW-C2. Email Allow-List Vulnerable to Unicode Homograph Attacks [HIGH SEVERITY]

**Status:** FIXED (2026-01-18)
**Location:** `internal/host/webproxy.go:376-392`, `internal/store/accounts.go:48`

**The Bug:** Email comparisons used `strings.EqualFold` which doesn't handle Unicode normalization. Cyrillic lookalikes could bypass allow-lists.

**Fix Applied:**
- Added `common.NormalizeEmail()` function in `internal/common/utils.go` that applies Unicode NFKC normalization + lowercase
- `webproxy.go:isEmailAllowed()` now uses `common.NormalizeEmail()` for both email and allow-list entries
- `accounts.go:FindOrCreateByEmails()` now uses `common.NormalizeEmail()` instead of `strings.ToLower()`
- Added dependency: `golang.org/x/text/unicode/norm`

---

#### NEW-C3. Magic Link Tokens Are Replayable [MEDIUM-HIGH SEVERITY]

**Status:** FIXED (2026-01-18)
**Location:** `internal/host/magiclink.go`

**The Bug:** Magic link JWTs had no unique identifier and could be replayed within the 5-minute window.

**Fix Applied:**
- Added `jti` (JWT ID) claim with 16-byte random hex value to `generateMagicLinkToken()`
- Added in-memory `usedMagicTokens` map to track used JTIs
- `verifyMagicLinkToken()` now extracts and validates `jti`, rejecting already-used tokens
- Added cleanup goroutine that removes expired entries every minute
- Note: Per-node tracking (not cross-node). Sufficient for single-node and most multi-node cases.

---

#### NEW-C4. Session Cookie Accessible to Subdomain Tunnel Owners [MEDIUM-HIGH SEVERITY]

**Status:** OPEN (partially mitigated by cookie stripping)
**Location:** `internal/host/proxy.go:182`

```go
sessionManager.Cookie.Domain = "." + cfg.Domain
```

**Impact:** Setting the cookie domain to `.tunn.to` means the session cookie is sent to ALL subdomains, including attacker-controlled tunnels. While `platformCookies` stripping prevents forwarding to tunnel targets, verify this is bulletproof.

---

### High Priority Issues (NEW)

#### NEW-H1. Rate Limiting Check Occurs After Response Received

**Status:** OPEN
**Location:** `internal/host/webproxy.go:278-286`

**Impact:** Bandwidth rate limit is checked AFTER the full response is received. Concurrent requests can bypass quota before usage is recorded.

**Fix:** Check rate limit BEFORE forwarding the request.

---

#### NEW-H2. XSS Vulnerability in Error Pages

**Status:** FIXED (2026-01-18)
**Location:** `internal/host/webproxy.go:172`

**The Bug:** User email was inserted into HTML without escaping.

**Fix Applied:** Now uses `html.EscapeString(userEmail)` before rendering in error page.

---

#### NEW-H3. Domain Wildcard in Allow-List Edge Cases

**Status:** OPEN
**Location:** `internal/host/webproxy.go:377-380`

**Impact:** Domain wildcards use `HasSuffix` without validation. May have edge cases with subdomains.

**Fix:** Validate that domain wildcards are well-formed and document matching behavior.

---

#### NEW-H4. IP Blacklist Memory Leak

**Status:** FIXED (2026-01-18)
**Location:** `internal/host/proxy.go:430-449`

**The Bug:** The `ipBlacklist` map had no cleanup goroutine, causing unbounded memory growth.

**Fix Applied:** Added `cleanupBlacklist()` goroutine that runs every 30 seconds and removes expired entries from the map. Started via `init()` function.

---

#### NEW-H5. Tunnel Cache Never Invalidated

**Status:** OPEN
**Location:** `internal/host/webproxy.go:79-85, 100-102`

**Impact:** Tunnel location cache has no TTL. If a tunnel moves nodes, requests route to wrong node.

**Fix:** Add TTL to cache entries or implement cache invalidation on tunnel disconnect.

---

#### NEW-H6. Stripe Webhook Handler Incomplete

**Status:** OPEN (known, documented in TODO.md)
**Location:** `internal/host/stripe.go:159-161`

**Impact:** Stripe webhook logs events but doesn't update user plans. Pro upgrades don't work.

**Fix:** Complete implementation before accepting payments.

---

### Medium Priority Issues (NEW)

#### NEW-M1. No Rate Limiting on Authentication Endpoints

**Status:** OPEN
**Locations:** `/api/device/code`, `/auth/magic`, `/api/device/token`

**Impact:** Enables device code flooding, magic link spam, brute-force attempts.

**Fix:** Add IP-based rate limiting middleware.

---

#### NEW-M2. No Body Size Limit on JSON Endpoints

**Status:** OPEN
**Location:** `internal/host/magiclink.go:31`

**Impact:** Memory exhaustion via large request bodies.

**Fix:** Use `io.LimitReader(r.Body, 1024)`.

---

#### NEW-M3. Weak Email Validation

**Status:** OPEN
**Location:** `internal/host/magiclink.go:37`

**Impact:** Accepts malformed emails like `@` or `@@`.

**Fix:** Use proper email validation regex.

---

#### NEW-M4. Device Code User Code Entropy

**Status:** ACCEPTABLE
**Location:** `internal/store/device_codes.go:165-182`

**Impact:** 30^6 combinations with 3-minute window. Not practically exploitable but margin is thin.

**Mitigation:** Current design acceptable with short expiry. Consider rate limiting lookups.

---

#### NEW-M5. Subdomain Extraction Edge Cases

**Status:** OPEN
**Location:** `internal/host/auth.go:458-478`

**Impact:** Doesn't explicitly reject malformed hostnames like `..tunn.to`.

**Fix:** Add explicit validation for extracted tunnel ID format.

---

#### NEW-M6. Concurrent Request Semaphore Can Block

**Status:** OPEN
**Location:** `internal/client/serve.go:229-239`

**Impact:** Slowloris-style attack can fill semaphore, blocking legitimate requests.

**Mitigation:** Consider timeout on semaphore acquisition.

---

#### NEW-M7. RandID Has Slight Bias

**Status:** LOW PRIORITY
**Location:** `internal/common/utils.go:14`

**Impact:** `256 % 36 = 4`, slight bias toward first 4 characters. Not practically exploitable.

**Fix:** Use rejection sampling or `crypto/rand.Int()`.

---

### Security Audit Trail (2026-01-18)

#### Authentication

| Location | Status | Notes |
|----------|--------|-------|
| `auth.go:26-46` sanitizeReturnTo | ✓ OK | Rejects absolute URLs, protocol-relative |
| `auth.go:136-141` OAuth state | ✓ OK | 32-byte crypto/rand |
| `grpc_server.go:282-311` JWT validation | ✓ OK | Explicit HMAC check |
| `proxy.go:410` node secret | ✓ FIXED | Now uses subtle.ConstantTimeCompare |
| `grpc_server.go:599` user token | ✓ FIXED | Now uses subtle.ConstantTimeCompare |
| `common/auth.go:21` AuthMiddleware | ✓ FIXED | Now uses subtle.ConstantTimeCompare |
| `magiclink.go` token replay | ✓ FIXED | JTI claim + single-use tracking |

#### Authorization

| Location | Status | Notes |
|----------|--------|-------|
| `webproxy.go:125-138` auth check | ✓ OK | Redirects to login |
| `webproxy.go:376-392` allow-list | ✓ FIXED | Now uses Unicode NFKC normalization |
| `webproxy.go:27-58` cookie stripping | ✓ OK | Strips tunn_session |
| `grpc_server.go:217-229` reserved names | ✓ OK | Comprehensive list |
| `webproxy.go:172` XSS in error | ✓ FIXED | Now uses html.EscapeString |

#### Cryptography

| Location | Status | Notes |
|----------|--------|-------|
| `device_codes.go:156-162` device codes | ✓ OK | crypto/rand, 32 bytes |
| `auth.go:426-432` OAuth state | ✓ OK | 32 bytes crypto/rand |
| `stripe.go:207` Stripe signature | ✓ OK | Uses hmac.Equal correctly |

---

## Original Findings (2025-01-18) - Previously Fixed

### Critical (P0) - All Fixed

#### 1. JWT Validation Bypass on Tunnel Registration

**Status:** FIXED (2025-01-18)
**Location:** `internal/host/grpc_server.go:227-259`

**The Bug:** If a client sends `CreatorEmail` already populated, the server uses it directly WITHOUT validating the JWT signature.

**Impact:** Malicious client can create tunnels as any email (impersonation), bypass allow-list ownership checks, steal quota.

**Fix:** Always validate JWT signature on server. IGNORE client-provided `CreatorEmail`.

---

#### 2. Session Cookies Leaked to Tunnel Owners

**Status:** FIXED (2025-01-18)
**Locations:** `internal/host/proxy.go:177`, `internal/host/webproxy.go:179-183`

**The Bug:** Session cookie domain is `.tunn.to`, making it available on ALL tunnel subdomains. HTTP requests forward all headers including `Cookie` to the user's local service.

**Impact:** Tunnel owner can read `tunn_session` cookie for ANY visitor.

**Fix:** Strip platform cookies before proxying to tunnel target.

---

#### 3. Concurrent gRPC Stream.Send (Data Race)

**Status:** FIXED (2025-01-18)
**Locations:** `internal/client/serve.go:166,194,275,303,326`, `internal/host/webproxy.go:215`

**The Bug:** gRPC streams are NOT thread-safe for concurrent `Send()`.

**Impact:** Data races, corrupted frames, random stream failures.

**Fix:** Serialize all sends through mutex.

---

#### 4. Response Channel Close Race (Panic)

**Status:** FIXED (2025-01-18)
**Locations:** `internal/host/webproxy.go:205`, `internal/host/grpc_server.go:429`

**The Bug:** Response channel closed after timeout, server can send to closed channel.

**Impact:** `panic: send on closed channel`

**Fix:** Use non-closing channel pattern or `sync.Once` for close.

---

#### 5. Open Redirect Vulnerability

**Status:** FIXED (2025-01-18)
**Locations:** `internal/host/auth.go:35-39,220`, `internal/host/webproxy.go:92`

**The Bug:** `return_to` parameter accepted without validation.

**Impact:** Phishing vector via redirect after login.

**Fix:** Validate `return_to` is relative path only, use `url.QueryEscape()`.

---

### High (P1) - Mostly Fixed

#### 6. Multi-Node Proxying Host Rewriting - FIXED
#### 7. Internal gRPC TLS Hostname Verification - FIXED
#### 8. Unbounded Goroutine Creation - FIXED
#### 9. No Request/Response Size Limits - FIXED
#### 10. Tunnel ID Not Validated Against DNS Labels - FIXED
#### 11. Header Map Flattens Multi-Value Headers - DEFERRED (requires proto change)
#### 12. NodeSecret Not Enforced in Production - FIXED

### Medium (P2)

#### 13. AI Placeholder Comment - cosmetic
#### 14. Missing Documentation - cosmetic
#### 15. No Cache TTL for tunnelCache - see NEW-H5
#### 16. Duplicate Install Script - cosmetic

---

## Positive Security Practices

The codebase demonstrates several good security practices:

- TLS termination correctly configured for HTTP/2 and HTTP/3
- OAuth state parameter uses crypto-secure randomness
- Device code storage uses secure random generation
- Session cookie settings include `Secure` and `SameSite=Lax`
- Structured logging doesn't expose secrets
- Reserved subdomain blocking prevents phishing
- Request/response body size limits prevent memory exhaustion
- Concurrent request limiting caps resource usage
- Stripe signature verification using `hmac.Equal` (correct)

---

## Recommended Fix Priority

1. **NEW-C1** (constant-time comparisons) - Quick fix, high impact
2. **NEW-C3** (magic link replay) - Requires DB change
3. **NEW-C2** (Unicode normalization) - Requires new dependency
4. **NEW-H2** (XSS) - Quick fix
5. **NEW-H4** (memory leak) - Quick fix
6. Address remaining items based on launch timeline

---

## Files Reviewed (2026-01-18)

| File | Lines | Status |
|------|-------|--------|
| `internal/host/proxy.go` | 979 | Reviewed |
| `internal/host/auth.go` | 683 | Reviewed |
| `internal/host/grpc_server.go` | 641 | Reviewed |
| `internal/host/webproxy.go` | 400 | Reviewed |
| `internal/store/accounts.go` | 408 | Reviewed |
| `internal/host/device.go` | 175 | Reviewed |
| `internal/host/magiclink.go` | 167 | Reviewed |
| `internal/host/stripe.go` | 213 | Reviewed |
| `internal/host/internal_server.go` | 147 | Reviewed |
| `internal/host/usage_buffer.go` | 153 | Reviewed |
| `internal/host/login_node_db.go` | 197 | Reviewed |
| `internal/client/serve.go` | 379 | Reviewed |
| `internal/client/login.go` | 245 | Reviewed |
| `internal/store/device_codes.go` | 183 | Reviewed |
| `internal/store/users.go` | 102 | Reviewed |
| `internal/store/db.go` | 143 | Reviewed |
| `internal/storage/*.go` | 617 | Reviewed |
| `internal/config/config.go` | 273 | Reviewed |
| `internal/common/*.go` | 73 | Reviewed |
| `main.go` | 418 | Reviewed |
| `proto/*.proto` | 340 | Reviewed |
