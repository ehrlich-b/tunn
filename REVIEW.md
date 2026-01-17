# Code Review: tunn Audit Summary

**Review Date:** 2025-01-17
**Status:** Core tunneling ready. OAuth needs work for Google login.

---

## Launch Blockers

**Core tunneling:** Ready to ship.

**OAuth (if you want `tunn login` + Google-protected browser portal):**

| Issue | File | Problem |
|-------|------|---------|
| `exchangeCodeForToken` | `auth.go:104` | Returns auth code as token, doesn't parse Google response |
| `validateToken` | `auth.go:132` | Returns hardcoded `user@example.com`, ignores actual user |
| `getJWTSigningKey` | `auth.go:281` | Returns `TODO_CONFIGURE_JWT_SECRET` in prod |

**Workaround:** Launch with `PUBLIC_MODE=true` to bypass auth entirely. Tunnels work, but no Google login protection.

See [TODO.md](TODO.md) for full checklist.

---

## What's Working

The architecture is sound. The gRPC control plane works. HTTP/3 works. The data plane works.

- HTTP/HTTPS tunneling over gRPC (bidirectional streaming)
- Multi-value HTTP headers handled correctly (joined with ", " per RFC)
- Concurrent request handling
- Automatic reconnection with exponential backoff
- UDP tunneling support
- Per-tunnel email allow-lists
- Public mode for headless testing
- TLS termination at proxy
- All tests passing

---

## Post-Launch Cleanup

### ExtractEmailFromJWT Trust Boundary (Low Priority)

**File:** `internal/common/auth.go:34`

`ExtractEmailFromJWT` parses without signature validation. Comment says "signature already validated by proxy" but it's used in `serve.go:125` where there's no prior validation. Low risk since the JWT comes from the user's own `tunn login` token file.

### Proto Cleanup (Breaking Change)

Legacy `ProxyRequest`/`ProxyResponse` messages remain in `proto/tunnel.proto` but are no longer used. Removing them is a breaking change for any deployed clients, so this is deferred.

---

## Completed Fixes (2025-01-17)

### Bugs Fixed

- **Multi-value headers:** Changed `headers[key] = values[0]` to `strings.Join(values, ", ")` in both webproxy.go and serve.go
- **Hardcoded domain:** `grpc_server.go` now uses config domain for public URL generation

### Dead Code Removed

- Removed `ProxyResponse` handler in grpc_server.go
- Removed `handleProxyRequest` in serve.go
- Removed legacy h2rev2 dependency and all related code

### Code Quality

- Removed emoji from output
- Changed per-request INFO logs to DEBUG level
- Consolidated duplicate AuthTransport types
- Removed token logging from auth middleware

### Test Coverage Added

**Client tests (`serve_test.go`):**
- `TestHandleHttpRequest` - core HTTP forwarding
- `TestHandleHttpRequestMultiValueHeaders` - Set-Cookie handling
- `TestHandleHttpRequestError` - connection failures
- `TestHandleHttpRequestConcurrent` - 10 parallel requests
- `TestHandleHttpRequestTimeout` - HTTP timeout handling
- `TestProcessMessagesHttpRequest` - message routing
- `TestHandleUdpPacket` - UDP forwarding with echo
- `TestReconnectionDefaults` - default backoff settings
- `TestReconnectionCustomSettings` - custom backoff
- `TestReconnectionContextCancellation` - graceful shutdown
- `TestExponentialBackoffCap` - backoff ceiling

**Proxy tests (`webproxy_test.go`):**
- `TestProxyHTTPOverGRPC` - full request/response cycle
- `TestProxyHTTPOverGRPCSendError` - stream failures
- `TestAllowListCheck` - email access control
- `TestProxyHTTPOverGRPCMultiValueHeaders` - Accept header handling
- `TestHandleWebProxyTunnelNotFound` - 503 for missing tunnels

### Features Added

- **Reconnection:** Exponential backoff from 1s to 30s (configurable)
- **HTTP Timeout:** Configurable timeout for local target requests

---

## Test Status

```
$ make test
ok      github.com/ehrlich-b/tunn/internal/client
ok      github.com/ehrlich-b/tunn/internal/common
ok      github.com/ehrlich-b/tunn/internal/config
ok      github.com/ehrlich-b/tunn/internal/host
ok      github.com/ehrlich-b/tunn/internal/mockoidc
```

All tests pass. Race detection passes (`make test-race`).

---

## Files Audited

| File | Status |
|------|--------|
| `internal/host/proxy.go` | Clean |
| `internal/host/grpc_server.go` | Clean |
| `internal/host/webproxy.go` | Clean |
| `internal/host/auth.go` | OAuth deferred |
| `internal/host/udpproxy.go` | Clean |
| `internal/client/serve.go` | Clean |
| `internal/client/login.go` | Clean |
| `internal/client/connect.go` | Clean |
| `internal/common/auth.go` | JWT validation deferred |
| `internal/common/logging.go` | Clean |
| `main.go` | Clean |
