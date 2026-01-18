# Code Review: tunn Audit Summary

**Review Date:** 2025-01-17
**Reviewers:** Claude Code (internal), Third-party review (codex)
**Status:** Pre-release fixes required

---

## Executive Summary

The codebase architecture is sound with clean separation, proper concurrency patterns, and good test coverage. However, a third-party review identified several security issues that must be fixed before launch. These are fixable - no architectural rewrites needed.

**Pre-Release Blockers:** 6 issues (see below)

**Production Requirements (after fixes):**
1. Create GitHub OAuth App → set `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`
2. Set `JWT_SECRET` to a cryptographically random string
3. Set `NODE_SECRET` for multi-node deployments
4. Deploy to Fly.io with TLS certificates

---

## Pre-Release Fixes Required

### P0 - Security (Must Fix)

#### 1. JWT Not Validated on Tunnel Registration

**File:** `internal/host/grpc_server.go:194`

When a client registers a tunnel with a JWT, the server uses `ExtractEmailFromJWT()` which explicitly does NOT validate the signature. Anyone can forge a JWT payload claiming any email.

```go
// Current (INSECURE):
creatorEmail = common.ExtractEmailFromJWT(regClient.AuthToken) // No signature check!

// Required: Validate signature with getJWTSigningKey()
```

**Impact:** Attacker can impersonate any email, bypass allow-lists, claim reserved subdomains.
**Fix:** Validate JWT signature in `EstablishTunnel()` using the same `getJWTSigningKey()` used in `CheckJWT()`.

#### 2. Magic Link Session Key Mismatch

**File:** `internal/host/magiclink.go:113`

Magic link verification stores `"email"` in session, but all other code reads `"user_email"`.

```go
// magiclink.go (WRONG):
p.sessionManager.Put(r.Context(), "email", email)

// auth.go, webproxy.go expect (CORRECT):
p.sessionManager.GetString(r.Context(), "user_email")
```

**Impact:** Magic link users appear unauthenticated - can't access protected tunnels.
**Fix:** Change `"email"` to `"user_email"` in magiclink.go.

#### 3. Logging Secrets

**File:** `internal/host/grpc_server.go:176`

The tunnel key (a secret) is logged in error messages:

```go
common.LogError("invalid tunnel key", "tunnel_id", tunnelID, "provided_key", regClient.TunnelKey)
```

**Impact:** Secrets exposed in logs.
**Fix:** Remove `provided_key` from log output.

#### 4. JWT_SECRET Falls Back to Weak Default

**File:** `internal/host/auth.go:541`

If `JWT_SECRET` is not configured, the code logs an error but returns a hardcoded fallback key instead of failing.

```go
common.LogError("JWT_SECRET not configured")
return []byte("unconfigured-jwt-secret")  // DANGEROUS
```

**Impact:** In prod without JWT_SECRET, all JWTs are signed with a known key.
**Fix:** Panic or fail startup in non-dev mode if JWT_SECRET is missing.

#### 5. Internal gRPC Uses InsecureSkipVerify

**File:** `internal/host/proxy.go:165`

Node-to-node gRPC disables TLS verification entirely. This allows MITM to intercept node secrets.

```go
// Current (INSECURE):
tls.Config{InsecureSkipVerify: true}

// Required: Proper TLS verification
```

**Impact:** On any network, attacker can MITM internal traffic and harvest node secret.
**Fix:**
- tunn.to (Fly.io): Use real Let's Encrypt certs, verify against system CA pool
- Self-hosters: Add `TUNN_CA_CERT` env var to specify custom CA chain for internal TLS

Note: We're NOT doing mTLS (mutual TLS with client certs) - just proper server cert verification.

### P1 - Documentation

#### 6. README Says "Google" but Code Uses GitHub

**File:** `README.md` lines 27-28, 37

README says "Login with Google" but the actual auth is GitHub OAuth.

**Fix:** Replace "Google" with "GitHub" in README.

---

## Post-Release Improvements

### Security Hardening

| Issue | Description | Priority |
|-------|-------------|----------|
| Constant-time comparisons | Use `subtle.ConstantTimeCompare` for secrets | Low |
| SMTP TLS | Explicitly configure TLS for SMTP (currently relies on STARTTLS) | Low |

### Code Quality

| Issue | Description | Priority |
|-------|-------------|----------|
| Cache TTL | Remote tunnel cache has no TTL - stale if tunnel moves nodes | Medium |
| Extract HTML templates | Large inline HTML in webproxy.go is hard to maintain | Low |
| More reserved subdomains | Add "root", "admin", "support" to reserved list | Low |
| RandID error handling | `RandID()` panics if crypto/rand fails - consider returning error | Low |

### Test Gaps

| Test | Description |
|------|-------------|
| Forged JWT registration | Test that unsigned/wrongly-signed JWT is rejected on tunnel registration |
| Magic link E2E | Test magic link → session → tunnel access with allow-list |

---

## Known Limitations (Accepted)

### ExtractEmailFromJWT in Client

**File:** `internal/client/serve.go:125`

The client uses `ExtractEmailFromJWT` for local display only (showing logged-in user). The JWT came from the user's own `~/.tunn/token` file. This is safe - users can only "spoof" to themselves.

### Dev JWT Secret

**File:** `internal/config/config.go:109`

Dev mode uses `"dev-jwt-secret-do-not-use-in-prod"`. This is intentional - production requires `JWT_SECRET` env var.

---

## What's Working Well

### Architecture
- Clean separation: proxy (host), client, common, config
- gRPC bidirectional streaming for efficient tunneling
- HTTP/2 + HTTP/3 support
- Stateless core - no database required for basic tunneling
- Email bucket identity model is elegant

### Security Controls
- CSRF protection on OAuth (state parameter with crypto/rand)
- JWT signature verification in CheckJWT middleware
- Session cookies: Secure, SameSite=Lax, HttpOnly
- Node-to-node: shared secret + IP blacklisting
- Token file permissions: 0600

### Concurrency
- Proper mutex usage (RWMutex where appropriate)
- Channel-based response routing for HTTP-over-gRPC
- Background cleanup goroutines

### Testing
- Good coverage for core paths
- Race detection passes
- Edge cases: expired tokens, wrong signatures, domain wildcards

---

## Previously Fixed (2025-01-17)

These issues were identified and fixed:

- ✅ HTTP client timeouts added to GitHub API calls
- ✅ JSON encode error handling added
- ✅ Dead code branch removed in `getCallbackURL()`

---

## Test Results

```
$ make test
ok      github.com/ehrlich-b/tunn/internal/client
ok      github.com/ehrlich-b/tunn/internal/common
ok      github.com/ehrlich-b/tunn/internal/config
ok      github.com/ehrlich-b/tunn/internal/host
ok      github.com/ehrlich-b/tunn/internal/mockoidc

$ make test-race
All tests pass. Race detection clean.
```

---

## Conclusion

The code quality is good - clean architecture, proper concurrency, solid test coverage. The security issues identified are implementation bugs, not design flaws. They're straightforward to fix:

1. Add JWT signature validation to `EstablishTunnel()`
2. Fix session key `"email"` → `"user_email"`
3. Remove secret from log message
4. Fail startup if `JWT_SECRET` missing in prod
5. Remove `InsecureSkipVerify`, add `TUNN_CA_CERT` for self-hosters
6. Update README (Google → GitHub)

After these fixes, the code is production-ready.
