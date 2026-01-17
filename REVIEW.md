# Code Review: tunn Reboot Audit

**Review Date:** 2025-01-17
**Reviewer:** Claude Code (with Bryan)
**Scope:** Full codebase audit for "goofy AI-generated" code, security issues, dead code, test gaps

## Status: h2rev2 Removed

As of this review, the legacy `h2rev2` dependency has been completely removed:
- Deleted `internal/host/server.go` (legacy server)
- Deleted `internal/host/server_test.go` (legacy tests)
- Deleted `internal/client/client.go` (legacy client)
- Deleted `internal/client/client_test.go` (legacy tests)
- Removed from `go.mod`

Build and tests pass. Binary is 14MB.

---

## Critical Issues (MUST FIX)

### 1. SECURITY: Fake OAuth Token Exchange

**File:** `internal/host/auth.go:104-128`

```go
func (p *ProxyServer) exchangeCodeForToken(code string) (string, error) {
    // ... makes HTTP request to token endpoint ...
    // For simplicity in V1, we'll just return the code as the token
    return code, nil  // <-- RETURNS THE AUTH CODE AS THE TOKEN
}
```

**Impact:** OAuth flow is theatrical. The authorization code is returned as-is without parsing the token response.

### 2. SECURITY: Mock Token Validation

**File:** `internal/host/auth.go:132-138`

```go
func (p *ProxyServer) validateToken(token string) (map[string]string, error) {
    // In V1 with mock OIDC, we'll just return a mock user
    return map[string]string{
        "email": "user@example.com",  // <-- HARDCODED EMAIL
    }, nil
}
```

**Impact:** ANY token is accepted. User is always `user@example.com`. Complete auth bypass.

### 3. SECURITY: Hardcoded JWT Secret

**File:** `internal/host/auth.go:281-293`

```go
func (p *ProxyServer) getJWTSigningKey() []byte {
    // ... dev mode check ...
    // TODO: Implement JWKS-based validation for production
    return []byte("TODO_CONFIGURE_JWT_SECRET")  // <-- HARDCODED SECRET
}
```

**Impact:** In production, JWT validation uses a hardcoded key. Attackers can forge tokens.

### 4. SECURITY: Token Logging - **FIXED 2025-01-17**

**File:** `internal/common/auth.go`

Token logging was removed from AuthMiddleware. The LogAuthTransport in logging.go still logs tokens but is only used in tests.

### 5. SECURITY: JWT Extraction Without Validation

**File:** `internal/common/auth.go:58-77`

```go
func ExtractEmailFromJWT(tokenString string) (string, error) {
    // Parse without validation (signature already validated by proxy)
    parser := jwt.Parser{SkipClaimsValidation: true}
    token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
```

The comment says "signature already validated by proxy" but it's used in `serve.go:69` where there's NO prior validation. Anyone can craft a JWT with any email.

---

## Bugs

### 6. Multi-Value Headers Dropped

**File:** `internal/host/webproxy.go:160-165`

```go
for key, values := range r.Header {
    headers[key] = values[0]  // <-- ONLY KEEPS FIRST VALUE
}
```

Same bug in `internal/client/serve.go:219-221`.

**Impact:** `Cookie`, `Set-Cookie`, and other multi-value headers are corrupted.

### 7. Hardcoded Domain in Public URL

**File:** `internal/host/grpc_server.go:193`

```go
publicURL := fmt.Sprintf("https://%s.tunn.to", tunnelID)  // <-- HARDCODED
```

Should use config domain, not hardcoded "tunn.to".

---

## Dead Code

### 8. ProxyResponse Handler (Legacy)

**File:** `internal/host/grpc_server.go:250-256`

```go
case *pb.TunnelMessage_ProxyResponse:
    // Client acknowledging a proxy request
    common.LogInfo("proxy response received", ...)
```

This handles a legacy message type. The actual HTTP forwarding uses `HttpRequest`/`HttpResponse`.

### 9. handleProxyRequest (Legacy)

**File:** `internal/client/serve.go:271-291`

```go
func (s *ServeClient) handleProxyRequest(stream ..., req *pb.ProxyRequest) {
    // For now, just acknowledge the request
    // This legacy handler is for the old ProxyRequest message type
```

Just sends an ack. Does nothing useful.

---

## Code Smell / Verbose AI Patterns

### 10. Emoji in Output

**File:** `internal/client/serve.go:123`

```go
fmt.Printf("\U0001F517 %s \u2192 %s\n", regResp.PublicUrl, s.TargetURL)
```

Should remove emoji unless user explicitly requests it.

### 11. Excessive INFO Logging

**File:** `internal/host/proxy.go:324`

```go
common.LogInfo("routing to gRPC", "path", r.URL.Path, "content-type", contentType)
```

Every gRPC request logs at INFO. Will spam logs in production.

**File:** `internal/host/webproxy.go:133`

```go
common.LogInfo("public mode - skipping auth", "tunnel_id", tunnelID)
```

Logged for EVERY request in public mode.

### 12. Duplicate LogAuthTransport

**File:** `internal/common/logging.go:81-114`
**File:** `internal/common/auth.go:11-30`

Two nearly identical `*AuthTransport` types. Should consolidate.

---

## Test Coverage: Pathetic

### Current Tests

| File | What It Tests | Quality |
|------|---------------|---------|
| `serve_test.go:TestServeClientBasic` | Struct fields exist | Useless |
| `serve_test.go:TestHandleProxyRequest` | **Deprecated** handler | Wrong |
| `serve_test.go:TestSendHealthChecks` | Health check sending | OK |
| `grpc_server_test.go` | Registration flow | Decent |
| `proxy_test.go` | HTTP routing | Decent |
| `auth_test.go` | Auth handlers | Decent |

### Missing Tests (Critical)

- [ ] `handleHttpRequest` - THE CORE TUNNELING FUNCTIONALITY
- [ ] `handleUdpPacket` - UDP forwarding
- [ ] `proxyHTTPOverGRPC` - Request/response correlation
- [ ] Multi-value header handling
- [ ] Allow-list enforcement
- [ ] Timeout handling
- [ ] Error conditions
- [ ] Concurrent request handling
- [ ] Reconnection logic (doesn't exist!)

---

## Missing Features

### 13. No Reconnection Logic

Client dies if connection drops. No exponential backoff. No retry. Process just exits.

**File:** `internal/client/serve.go:133-172` - `processMessages` returns error on disconnect, `Run` returns, main exits.

---

## Fix Priority

### P0 - Security (Deferred - OAuth feature not core value prop)

1. [ ] Fix `validateToken` to actually validate tokens
2. [ ] Fix `exchangeCodeForToken` to parse token response
3. [ ] Fix `getJWTSigningKey` to use config/env
4. [x] Remove token logging from debug output - **FIXED 2025-01-17**
5. [ ] Add JWT signature validation to `ExtractEmailFromJWT` or document trust boundary

*Note: OAuth login portal is a nice-to-have. Core value prop is HTTP/2+3 tunneling with TLS termination.*

### P1 - Bugs

6. [x] Fix multi-value header handling (join with comma or preserve array) - **FIXED 2025-01-17**
7. [x] Use config domain in public URL generation - **FIXED 2025-01-17**

### P2 - Dead Code Removal

8. [x] Remove `ProxyResponse` handler in grpc_server.go - **FIXED 2025-01-17**
9. [x] Remove `handleProxyRequest` in serve.go - **FIXED 2025-01-17**
10. [ ] Remove `ProxyRequest`/`ProxyResponse` from proto (breaking change, defer)

### P3 - Code Quality

11. [x] Remove emoji from output - **FIXED 2025-01-17**
12. [x] Reduce INFO logging to DEBUG where appropriate - **FIXED 2025-01-17**
13. [x] Consolidate duplicate AuthTransport types - **FIXED 2025-01-17** (removed unused one from auth.go)

### P4 - Test Suite

14. [x] Add `handleHttpRequest` tests - **ADDED 2025-01-17**
15. [x] Add `proxyHTTPOverGRPC` tests - **ADDED 2025-01-17**
16. [x] Add multi-header tests - **ADDED 2025-01-17**
17. [x] Add allow-list enforcement tests - **ADDED 2025-01-17**
18. [x] Add timeout tests - **ADDED 2025-01-17**
19. [x] Add concurrent request tests - **ADDED 2025-01-17**
20. [x] Add error handling tests - **ADDED 2025-01-17**

### P5 - Features

21. [x] Implement reconnection with exponential backoff - **ADDED 2025-01-17**

---

## Files Audited

| File | Lines | Status |
|------|-------|--------|
| `internal/host/proxy.go` | 380 | Has issues |
| `internal/host/grpc_server.go` | 335 | Has issues |
| `internal/host/webproxy.go` | 276 | Has issues |
| `internal/host/auth.go` | 294 | CRITICAL issues |
| `internal/host/udpproxy.go` | 217 | Not audited |
| `internal/client/serve.go` | 403 | Has issues |
| `internal/client/login.go` | 220 | Not audited |
| `internal/client/connect.go` | 208 | Not audited |
| `internal/common/auth.go` | 78 | Has issues |
| `internal/common/logging.go` | 115 | Has issues |
| `internal/common/utils.go` | 19 | Clean |
| `main.go` | 327 | Clean |

---

## Summary

The architecture is sound. The gRPC control plane works. HTTP/3 works. The data plane works.

**2025-01-17 Update:**
- Fixed multi-value header bug (core HTTP functionality)
- Removed dead code (legacy ProxyRequest/ProxyResponse handlers)
- Removed emoji from output
- Fixed excessive INFO logging (changed to DEBUG for per-request logs)
- Added core tunneling tests: handleHttpRequest, multi-headers, concurrent requests, error handling

**Remaining:**
- P0 (OAuth security) deferred - not core value prop, will address when fleshing out sharing feature
- P2: Remove proto messages (breaking change - defer)
