# Code Review: tunn V1 Architecture & gRPC Migration

**Review Date:** 2025-11-16
**Commits Reviewed:** `b68df5e` through `714af2d` (5 commits)
**Review Scope:** Architecture, gRPC implementation, authentication flows, security, code quality

## Executive Summary

The tunn project is undergoing a significant architectural evolution from a POC using `h2rev2` to a production-ready V1 architecture based on gRPC. The migration represents a substantial improvement in architectural sophistication, with well-designed dual auth flows (browser sessions and JWT tokens) and a solid foundation for horizontal scaling via inter-node communication.

**Overall Grade: B+**

**Strengths:**
- Clean, well-structured gRPC control plane architecture
- Thoughtful separation of browser and CLI auth flows
- Comprehensive configuration management with dev/prod modes
- Strong foundation for horizontal scaling
- Good test coverage for critical components

**Critical Issues:**
- **SECURITY**: Hardcoded secrets and incomplete token validation (CRITICAL)
- **INCOMPLETE**: Data plane proxying not implemented - control plane exists but no actual traffic forwarding
- **SECURITY**: Missing authentication on tunnel registration endpoint
- **ARCHITECTURE**: go_package path inconsistency in protobuf definitions

---

## 1. Architecture Review

### 1.1 Overall Design

The V1 architecture follows a clean separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                     tunn Proxy Server                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ HTTP/2 (TCP) │  │ HTTP/3 (QUIC)│  │ Internal gRPC│      │
│  │   :8443      │  │    :8443     │  │   :50051     │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│  ┌──────┴──────────────────┴──────────────────┴───────┐     │
│  │  Router: gRPC vs HTTPS (Content-Type based)        │     │
│  └──────┬──────────────────────────────────────────────┘    │
│         │                                                    │
│  ┌──────┴──────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  TunnelService  │  │ SessionMgr   │  │ InternalSvc  │   │
│  │  (gRPC control) │  │ (Web auth)   │  │ (Node probe) │   │
│  └─────────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────┘
         ▲                      ▲                      ▲
         │ gRPC stream          │ HTTPS                │ gRPC
         │                      │                      │
    ┌────┴─────┐         ┌─────┴─────┐         ┌─────┴─────┐
    │   tunn   │         │  Browser  │         │  Other    │
    │   serve  │         │   Client  │         │  Nodes    │
    └──────────┘         └───────────┘         └───────────┘
```

**Strengths:**
- **Dual protocol support**: HTTP/2 and HTTP/3 listeners provide modern protocol support
- **Content-type routing**: Elegant separation of gRPC and HTTPS traffic on single port
- **Inter-node communication**: Well-designed internal gRPC service for distributed operation
- **Clear separation**: Control plane (gRPC) vs data plane (HTTP proxy) is architecturally sound

**Concerns:**
- **Data plane missing**: Control plane is implemented but actual traffic forwarding is stubbed (proxy.go:100-107, webproxy.go:100-107)
- **Session cookie domain**: Setting `Cookie.Domain = "." + domain` may not work as expected for localhost testing (proxy.go:101)

### 1.2 gRPC Control Plane Design

The gRPC-based control plane (`proto/tunnel.proto`) is well-designed:

**Excellent Design Choices:**
- Bidirectional streaming for persistent connections
- Message envelope pattern (`TunnelMessage`) allows extensibility
- Health check protocol for keepalive
- Clear separation of registration, proxy requests, and health checks

**Issues:**

1. **CRITICAL - Protobuf Package Inconsistency** (tunnel.proto:5 vs internal.proto:5):
   ```protobuf
   // tunnel.proto
   option go_package = "github.com/behrlich/tunn/pkg/proto/tunnelv1";

   // internal.proto
   option go_package = "github.com/ehrlich-b/tunn/pkg/proto/internalv1";
   ```
   Note: `behrlich` vs `ehrlich-b`. This will cause import issues and confusion.

2. **Missing Authentication** on `EstablishTunnel` RPC:
   - `RegisterClient.auth_token` (tunnel.proto:38) is sent but never validated
   - Any client can register a tunnel with any ID
   - **Risk**: Tunnel ID hijacking, unauthorized access

3. **Race Condition** in tunnel registration (grpc_server.go:64-81):
   ```go
   s.mu.Lock()
   if _, exists := s.tunnels[tunnelID]; exists {
       s.mu.Unlock()
       // Sends response AFTER unlocking - other goroutine could register same ID
       stream.Send(respMsg)
       return fmt.Errorf("tunnel ID %s already registered", tunnelID)
   }
   ```
   The unlock happens before sending the error response, creating a small race window.

### 1.3 Authentication Flows

The dual auth approach is architecturally sound:

**Browser Flow (Session-based):**
- Uses `alexedwards/scs` for secure sessions ✓
- CSRF protection via state parameter ✓
- Cookie scoping to subdomain ✓
- Redirect-based flow is standard ✓

**CLI Flow (JWT-based):**
- OAuth Device Flow for CLI authentication ✓
- Token storage in `~/.tunn/token` with 0600 permissions ✓
- Bearer token in Authorization header ✓

**Critical Security Issues:**

1. **CRITICAL - Mock Token Validation** (auth.go:126-138):
   ```go
   func (p *ProxyServer) validateToken(token string) (map[string]string, error) {
       // In V1 with mock OIDC, we'll just return a mock user
       // In production, validate JWT signature and extract claims
       return map[string]string{
           "email": "user@example.com",
       }, nil
   }
   ```
   This accepts ANY token in production. Complete security bypass.

2. **CRITICAL - Hardcoded JWT Secret** (auth.go:292):
   ```go
   return []byte("TODO_CONFIGURE_JWT_SECRET")
   ```
   Production JWT validation uses hardcoded key. Any attacker can forge tokens.

3. **CRITICAL - Insecure Token Exchange** (auth.go:126):
   ```go
   return code, nil  // Just returns the auth code as the token!
   ```
   The authorization code is returned as the access token without any validation.

4. **SECURITY - No Token Expiry Validation**:
   - JWT validation doesn't check `exp` claim
   - Session lifetime is set but no explicit refresh mechanism documented

---

## 2. Code Quality Analysis

### 2.1 Structure and Organization

**Excellent:**
- Clean package structure: `internal/{client,host,config,common,mockoidc}`
- Separation of concerns between client and host
- Proto-generated code isolated in `pkg/proto/`
- Comprehensive Makefile with proper build targets

**Good:**
- Consistent error handling patterns
- Context propagation throughout
- Signal handling for graceful shutdown

**Needs Improvement:**
- Some files are getting large (proxy.go is 377 lines, should split routing/TLS/server logic)
- Mock OIDC mixed into production code (proxy.go:135-145) - should be conditional import

### 2.2 Error Handling

**Strengths:**
- Consistent use of `fmt.Errorf` with `%w` for error wrapping
- Errors logged before returning
- Graceful degradation in health checks

**Weaknesses:**
- Some errors are logged but not returned (grpc_server.go:150)
- Inconsistent error response patterns (some use HTTP errors, some return gRPC errors)

### 2.3 Concurrency and Thread Safety

**Good Practices:**
- Proper use of `sync.RWMutex` for tunnel map (grpc_server.go:17)
- Channel-based shutdown signaling (main.go:59-65)
- Context cancellation propagation

**Issues:**
- **Race condition** in tunnel registration (mentioned above)
- **Cache synchronization** (proxy.go:33-36, 55-57) - RLock/Lock pattern is correct but cache invalidation strategy is missing

### 2.4 Testing

Test coverage appears comprehensive:

```
internal/client/serve_test.go      - gRPC client tests ✓
internal/config/config_test.go     - Config loading tests ✓
internal/host/auth_test.go         - Auth handlers (NEW) ✓
internal/host/grpc_server_test.go  - gRPC server tests ✓
internal/host/proxy_test.go        - Proxy routing tests ✓
```

**Recommendations:**
1. Add integration tests for full auth flows
2. Add tests for concurrent tunnel registration
3. Add tests for inter-node communication
4. Run `make test-coverage` and aim for >80% coverage

---

## 3. Security Analysis

### 3.1 Critical Vulnerabilities (MUST FIX)

| Severity | Issue | Location | Impact |
|----------|-------|----------|--------|
| CRITICAL | Mock token validation in production | auth.go:132-138 | Complete auth bypass |
| CRITICAL | Hardcoded JWT secret | auth.go:292 | Token forgery |
| CRITICAL | No tunnel auth validation | grpc_server.go:37-136 | Tunnel hijacking |
| HIGH | Insecure token exchange | auth.go:126 | Auth code can be reused as token |
| HIGH | Missing JWT expiry validation | auth.go:235-278 | Expired tokens accepted |

### 3.2 Security Best Practices - Missing

1. **Rate Limiting**: No rate limiting on any endpoint
2. **Input Validation**: Tunnel IDs not validated (could contain path traversal, etc.)
3. **TLS Configuration**:
   - `InsecureSkipVerify: true` in dev is expected (config.go:88)
   - But it's also used in client connections (serve.go:30), which could leak to production
4. **Secrets Management**: All secrets in config/env vars, no secret rotation mechanism
5. **Audit Logging**: No audit trail of authentication events or tunnel creation

### 3.3 Recommendations (Priority Order)

1. **IMMEDIATE**: Implement proper OIDC token validation using JWKS
2. **IMMEDIATE**: Add tunnel auth token validation in `EstablishTunnel`
3. **IMMEDIATE**: Move JWT secret to environment variable, fail hard if not set in prod
4. **HIGH**: Implement JWT expiry validation
5. **HIGH**: Add rate limiting to auth endpoints
6. **MEDIUM**: Implement audit logging for security events
7. **MEDIUM**: Add input validation for tunnel IDs (regex: `^[a-z0-9-]{3,32}$`)

---

## 4. Implementation Status

### 4.1 Completed (Phases 0-3)

✅ **Phase 0: Project Setup**
- Protobuf definitions created
- gRPC code generation working
- Mock OIDC server implemented
- Dependencies vendored

✅ **Phase 1: Proxy Server**
- Dual-listener architecture (HTTP/2 + HTTP/3)
- gRPC server implementation
- HTTPS/gRPC routing
- Dev/prod configuration

✅ **Phase 2: Serve Client**
- gRPC client with bidirectional streaming
- Registration flow
- Health check loop (30s interval)
- Signal handling

✅ **Phase 3: Inter-Node Communication**
- Internal gRPC service defined
- `FindTunnel` RPC implemented
- Node discovery via config
- Sequential probing logic
- mTLS for internal communication

✅ **Phase 4: Browser Auth Flow**
- Session manager integration
- OIDC login/callback handlers
- `CheckAuth` middleware
- Web proxy routing

✅ **Phase 5: CLI Auth (Partial)**
- ✅ Device flow in `tunn login` command
- ✅ JWT middleware implemented
- ❌ UDP-over-H2 handler NOT implemented
- ❌ `tunn connect` command NOT implemented
- ❌ UDP proxy logic NOT implemented

### 4.2 Incomplete / Stubbed

1. **Data Plane Proxying** (webproxy.go:100-107):
   ```go
   // TODO: Implement actual data plane proxying
   // For now, show a placeholder
   w.WriteHeader(http.StatusOK)
   fmt.Fprintf(w, "tunn v1 - tunnel connected locally\n")
   ```
   The entire point of the system - actual traffic forwarding - is not implemented.

2. **ProxyRequest Handling** (serve.go:136-149):
   ```go
   // For now, just acknowledge the request
   // In Phase 3, this will actually establish a data connection
   ```
   Client acknowledges proxy requests but doesn't actually forward traffic.

3. **UDP Tunneling** (Phase 5):
   - No `/udp-tunnel/{id}` handler
   - No `tunn connect` command
   - No UDP framing implementation

4. **Production OIDC Integration**:
   - Google OIDC endpoints hardcoded but not tested
   - JWKS fetching not implemented
   - Token refresh not implemented

### 4.3 TODO Discrepancies

The TODO.md marks some items as complete that are actually incomplete:

- TODO.md:42 marks "Connect Web Proxy" as unchecked but with a note - correct ✓
- TODO.md:48-51 marks Phase 5 items as unchecked - correct ✓

However, the implementation is actually in a good intermediate state, not "broken" - just incomplete.

---

## 5. Recent Commits Analysis

### Commit: `714af2d` - Device Flow Implementation

**Changes:**
- Added `internal/client/login.go` (219 lines)
- Refactored `main.go` to support `login` mode

**Quality:** Excellent
- Clean OAuth device flow implementation
- Proper error handling and polling logic
- Secure token storage (0600 permissions)
- Good user experience (shows both URL and code)

**Issues:**
- Device code polling interval defaults to 5s if not provided (login.go:111) - should respect server's recommendation

### Commit: `69d4afd` - Browser Auth Flow

**Changes:**
- Added `internal/host/auth.go` (294 lines)
- Added `internal/host/webproxy.go` (144 lines)
- Session manager integration

**Quality:** Good
- Clean separation of auth handlers
- CSRF protection via state parameter
- Proper session management

**Issues:**
- All the security issues mentioned above
- Mock token validation is a placeholder

### Commit: `1c778f4` - Main Wiring

**Changes:**
- Wired `ProxyServer` and `ServeClient` to `main.go`
- Signal handling for graceful shutdown

**Quality:** Excellent
- Clean separation of modes
- Proper context cancellation
- Good error messages

### Commit: `b473c7a` - Config & Mock OIDC

**Changes:**
- Added comprehensive config package
- Dev/prod environment separation
- Mock OIDC server

**Quality:** Excellent
- Well-structured config management
- Clear environment separation
- Testable configuration

**Suggestion:**
- Consider using a config file (YAML/TOML) in addition to env vars for complex deployments

### Commit: `b68df5e` - gRPC Serve Client

**Changes:**
- Implemented `ServeClient` with bidirectional streaming
- Health check sender goroutine
- Message processing loop

**Quality:** Excellent
- Clean gRPC client implementation
- Proper goroutine management
- Good separation of concerns

---

## 6. gRPC Architecture Assessment

### 6.1 Protocol Design

The gRPC control plane design is **solid and production-ready** with minor fixes:

**Strengths:**
1. **Bidirectional streaming**: Excellent choice for persistent tunnel connections
2. **Message envelope pattern**: `TunnelMessage` with `oneof` allows future extension without breaking changes
3. **Explicit acknowledgments**: `RegisterResponse` and `ProxyResponse` provide clear feedback
4. **Health check protocol**: Simple and effective keepalive mechanism

**Recommended Improvements:**

1. **Add connection metadata** for auth:
   ```protobuf
   // In tunnel.proto, use gRPC metadata instead of auth_token in message
   // This allows for standard auth interceptors
   ```

2. **Add stream management messages**:
   ```protobuf
   message StreamClosed {
     string reason = 1;
   }
   ```

3. **Add metrics/telemetry messages**:
   ```protobuf
   message TunnelMetrics {
     int64 bytes_sent = 1;
     int64 bytes_received = 2;
     int64 connections_active = 3;
   }
   ```

### 6.2 Internal gRPC Design

The inter-node communication design is **excellent**:

**Strengths:**
1. mTLS for node-to-node security ✓
2. Simple request/response pattern for `FindTunnel` ✓
3. Cache-then-probe pattern reduces latency ✓

**Issues:**
1. **No cache invalidation**: When a tunnel disconnects, cache is not updated (proxy.go:84-89)
2. **No timeout on inter-node calls**: Could hang indefinitely (webproxy.go:46)
3. **Sequential probing**: Could be slow with many nodes (webproxy.go:44-62)

**Recommendations:**
1. Add cache TTL and invalidation on tunnel disconnect
2. Add timeouts to inter-node gRPC calls (5s recommended)
3. Consider parallel probing with `sync.WaitGroup` when node count > 3

### 6.3 Migration from h2rev2

The migration from `h2rev2` to gRPC is **well-executed**:

**Good decisions:**
1. Kept old client code (`client.go`) during transition
2. Created new `ServeClient` alongside old code
3. Proto-first design ensures clear contracts

**Remaining work:**
1. Remove old `h2rev2` code once migration is complete
2. Update README.md to reflect new architecture
3. Ensure no lingering dependencies on `h2rev2`

---

## 7. Configuration & Deployment

### 7.1 Configuration Management

The config package (config.go) is **well-designed**:

**Strengths:**
- Clear dev/prod separation
- Sensible defaults
- Environment variable overrides
- Type-safe config struct

**Recommendations:**
1. Add config validation at startup:
   ```go
   func (c *Config) Validate() error {
       if c.IsProd() && c.SkipVerify {
           return fmt.Errorf("SkipVerify must be false in production")
       }
       // ... more validations
   }
   ```

2. Add config documentation:
   ```go
   // ServerAddr is the address of the tunn proxy server
   // Format: "host:port" (e.g., "tunn.to:443")
   // Environment variable: SERVER_ADDR
   ServerAddr string
   ```

### 7.2 Local Testing Setup

The local testing strategy is **excellent**:

1. nip.io for wildcard DNS ✓
2. Mock OIDC for offline testing ✓
3. Self-signed certs with dev flag ✓

**Missing:**
- `test-local.sh` script mentioned in TODO.md (Phase 6)
- Documentation of local testing procedure

---

## 8. Recommendations

### 8.1 Immediate Actions (Before Production)

1. **CRITICAL**: Fix all security vulnerabilities listed in Section 3.1
2. **CRITICAL**: Implement actual data plane proxying (the core functionality)
3. **HIGH**: Add authentication to tunnel registration
4. **HIGH**: Fix protobuf go_package path consistency
5. **MEDIUM**: Add comprehensive integration tests
6. **MEDIUM**: Document the architecture in README.md

### 8.2 Short-term Improvements (Next Sprint)

1. Implement Phase 5 UDP tunneling
2. Add cache invalidation for tunnel discovery
3. Add timeouts to all network operations
4. Implement rate limiting
5. Add audit logging
6. Create E2E test script

### 8.3 Long-term Architecture

1. **Data Plane Considerations**:
   - Current design proxies all traffic through the proxy server
   - Consider direct client-to-client tunneling with proxy as signaling server
   - This would reduce latency and bandwidth costs

2. **Scaling Considerations**:
   - Current node discovery via static config won't scale
   - Consider service mesh (Consul, Kubernetes) for node discovery
   - Consider distributed cache (Redis) for tunnel location

3. **Observability**:
   - Add OpenTelemetry tracing
   - Add Prometheus metrics
   - Add structured logging with trace IDs

4. **Reliability**:
   - Add circuit breakers for inter-node communication
   - Add retry logic with exponential backoff
   - Add health checks beyond simple ping/pong

---

## 9. Conclusion

The tunn V1 architecture represents a **significant improvement** over the POC. The gRPC-based control plane is well-designed, the dual auth flows are thoughtfully implemented, and the foundation for horizontal scaling is solid.

However, there are **critical security issues** that must be addressed before any production use, and the **data plane is not yet implemented**, which means the system cannot actually proxy traffic despite having a sophisticated control plane.

### Next Steps (Priority Order)

1. ✅ Fix security vulnerabilities (auth.go, grpc_server.go)
2. ✅ Implement data plane proxying (webproxy.go, serve.go)
3. ✅ Fix protobuf package paths
4. ✅ Add integration tests
5. ✅ Update documentation
6. ⏸ Complete Phase 5 (UDP tunneling)
7. ⏸ Production OIDC integration
8. ⏸ E2E testing script

**Overall Assessment:** Strong architectural foundation with excellent gRPC design, but critical security and implementation gaps prevent production readiness. With focused effort on the identified issues, this could be production-ready within 2-3 weeks.

---

## Appendix A: Files Reviewed

### Core Implementation
- `proto/tunnel.proto` - Main gRPC service definition
- `proto/internal.proto` - Inter-node communication
- `internal/host/grpc_server.go` - Tunnel service implementation
- `internal/host/proxy.go` - Main proxy server
- `internal/host/webproxy.go` - Web request handler
- `internal/host/auth.go` - Authentication handlers
- `internal/host/internal_server.go` - Inter-node service
- `internal/client/serve.go` - Tunnel client
- `internal/client/login.go` - Device flow client
- `internal/config/config.go` - Configuration management
- `main.go` - Entry point and mode routing

### Build & Infrastructure
- `Makefile` - Build system
- `CLAUDE.md` - Architecture documentation
- `TODO.md` - Implementation roadmap
- `README.md` - User documentation

### Testing
- Multiple `*_test.go` files across packages
