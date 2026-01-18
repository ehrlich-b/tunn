# tunn.to Code Review
*Generated: 2026-01-18 19:27:54 UTC*
*Reviewer: Codex (GPT-5)*

## Executive Summary
The codebase is well-structured and shows thoughtful security intent (email normalization, session handling, allow‑lists, and constant‑time comparisons). The tunnel control plane is clear, and key trust boundaries are called out explicitly. However, there are several security‑critical gaps that can lead to unauthorized internal‑mesh access, replayable magic‑link logins in multi‑node deployments, and reliability hazards under load.

Most of the critical risk comes from multi‑node operation and concurrency correctness: internal gRPC authentication can be effectively disabled if discovery uses Fly DNS without a node secret, UDP forwarding uses non‑thread‑safe stream sends, and a closed‑channel race can panic the server. There are also availability risks from missing server timeouts and unbounded request buffering. These issues should be addressed before production deployment.

Recommendation: **Do not deploy to production until Critical and High issues below are fixed**. After fixes, add targeted tests for replay prevention across nodes, gRPC stream concurrency, and timeout/slowloris resistance.

## Critical Issues (MUST FIX)
- **Internal mesh auth can be bypassed when using Fly DNS discovery without a node secret.** The guard only enforces `TUNN_NODE_SECRET` when `TUNN_NODE_ADDRESSES` is set, leaving multi‑node Fly deployments potentially using an empty secret. An attacker with internal reach could call internal gRPC methods. (`internal/host/proxy.go:94`, `internal/host/proxy.go:159`)
- **UDP forwarding uses non‑thread‑safe gRPC stream sends.** `ForwardUdpPacket` writes directly to `conn.Stream.Send` without the mutex used elsewhere, which can corrupt the stream or interleave frames under concurrent traffic. This can crash or misroute messages. (`internal/host/internal_server.go:114`)
- **UDP response channel close race can panic the server.** `ForwardUdpPacket` closes `respChan` while the tunnel receive loop can still send into it, causing a `send on closed channel` panic. (`internal/host/internal_server.go:96`, `internal/host/grpc_server.go:510`)
- **Magic‑link replay protection is per‑node only.** Used‑token JTIs are tracked in memory; in multi‑node mode the same token can be reused on a different node within its lifetime, enabling replayed logins. (`internal/host/magiclink.go:17`, `internal/host/magiclink.go:224`)

## High Priority Issues
- **No HTTP server timeouts → slowloris risk.** The HTTP/2 and HTTP/3 servers omit Read/Write/Idle timeouts, allowing clients to hold connections indefinitely and exhaust resources. (`internal/host/proxy.go:552`, `internal/host/proxy.go:581`)
- **Node probing uses `context.Background()` without timeout.** A slow or wedged node can hang visitor requests while `FindTunnel` blocks, degrading availability under failure. (`internal/host/webproxy.go:92`)
- **Body size limits can silently truncate requests/responses.** `io.LimitReader` + `io.ReadAll` reads up to the limit but does not detect overflow; oversized bodies are truncated and still forwarded, risking data corruption and unexpected behavior. (`internal/host/webproxy.go:212`, `internal/client/serve.go:292`)
- **Unbounded in‑memory buffering of full HTTP bodies.** Every request/response is fully buffered (up to 100MB each) with no global backpressure; concurrent requests can exhaust memory. (`internal/host/webproxy.go:212`, `internal/client/serve.go:292`)

## Medium Priority Issues
- **Magic‑link endpoint lacks rate limiting / abuse controls.** `/auth/magic` can be spammed to send unlimited emails to arbitrary addresses. Consider per‑IP/email throttling and abuse protection. (`internal/host/magiclink.go:56`)
- **Cross‑node tunnel count enforcement is not wired.** `Storage.RegisterTunnel` exists but is not used in tunnel registration; limits are per‑node only, which undermines stated cross‑node limits and can be abused in multi‑node deployments. (`internal/host/grpc_server.go:409`, `internal/storage/storage.go:41`)
- **Install script is duplicated in code and file.** `install.sh` is embedded in `proxy.go`; divergence risks unreviewed behavior and update drift. (Operational risk.) (`internal/host/proxy.go:688`, `install.sh:1`)

## Low Priority / Suggestions
- **Tunnel key comparison is not constant‑time.** If you treat the tunnel key as a secret, compare with `subtle.ConstantTimeCompare`. (`internal/host/grpc_server.go:269`)
- **Proto `go_package` mismatch.** `proto/tunnel.proto` references `github.com/behrlich/tunn` while the module is `github.com/ehrlich-b/tunn`. This can cause import confusion in generated code. (`proto/tunnel.proto:5`, `go.mod:1`)
- **Documentation env var names are inconsistent with code.** Docs reference `LOGIN_NODE`/`NODE_ADDRESSES` instead of `TUNN_LOGIN_NODE`/`TUNN_NODE_ADDRESSES`. (`docs/login-node-architecture.md:34`, `internal/config/config.go:235`)
- **Rate‑limiting docs describe config knobs not implemented.** `MAX_TUNNELS`, `RATE_LIMIT_MBPS`, etc. are not present in config. (`docs/rate-limiting-design.md:9`, `internal/host/grpc_server.go:101`)

## Security Audit Trail
✓ [internal/common/auth.go:21] Constant‑time token compare for auth middleware
  WHY IT'S PROBABLY FINE: Prevents timing side‑channel on bearer token validation.
  WHAT COULD GO WRONG: Token reuse or leakage elsewhere still compromises auth.
  VERIFIED BY: Read `AuthMiddleware` comparison logic and use of `subtle.ConstantTimeCompare`.

✓ [internal/common/utils.go:23] Email normalization with Unicode NFKC + lowercase
  WHY IT'S PROBABLY FINE: Mitigates case and basic homograph variants for allow‑lists.
  WHAT COULD GO WRONG: Some providers treat local‑part case‑sensitive; normalization may be too aggressive for edge cases.
  VERIFIED BY: Checked `NormalizeEmail` implementation and usage in allow‑list checks.

✓ [internal/host/auth.go:26] `return_to` is sanitized to relative paths only
  WHY IT'S PROBABLY FINE: Blocks open redirects to external domains.
  WHAT COULD GO WRONG: Encoded or unusual path forms may still need additional hardening.
  VERIFIED BY: Reviewed `sanitizeReturnTo` logic for `://`, `//`, and leading `/`.

✓ [internal/host/webproxy.go:220] Platform cookies stripped before proxying to tunnels
  WHY IT'S PROBABLY FINE: Prevents tunnel owners from receiving `tunn_session` cookies.
  WHAT COULD GO WRONG: New platform cookies added later may not be included in the blocklist.
  VERIFIED BY: Reviewed `platformCookies` map and `stripPlatformCookies` usage.

✓ [internal/host/grpc_server.go:203] Tunnel ID validated as RFC‑1123 DNS label
  WHY IT'S PROBABLY FINE: Prevents subdomain injection and invalid hostnames.
  WHAT COULD GO WRONG: Internationalized domain labels (IDNs) are disallowed; ensure this is intended.
  VERIFIED BY: Inspected `isValidDNSLabel` and its use in registration.

✓ [internal/host/grpc_server.go:218] Reserved subdomains blocked
  WHY IT'S PROBABLY FINE: Reduces phishing/squatting risk for common infra and brand names.
  WHAT COULD GO WRONG: List maintenance drift; new phishing targets may appear.
  VERIFIED BY: Checked `reservedSubdomains` map and validation path.

✓ [internal/host/grpc_server.go:299] Creator email derived from validated JWT
  WHY IT'S PROBABLY FINE: Prevents clients from forging `creator_email` during registration.
  WHAT COULD GO WRONG: JWT validation depends on correct secret configuration; misconfig could accept invalid tokens.
  VERIFIED BY: Followed `validateJWTAndExtractEmail` call and confirmed `creator_email` is ignored.

✓ [internal/host/proxy.go:173] Session cookies set with `Secure` and `SameSite=Lax`
  WHY IT'S PROBABLY FINE: Mitigates session leakage over HTTP and basic CSRF.
  WHAT COULD GO WRONG: `Domain` scoping to a broad apex can expose cookies to all subdomains; compromise of any subdomain increases risk.
  VERIFIED BY: Reviewed `scs.SessionManager` cookie settings and domain assignment.

## Files Reviewed
- [x] renew-certs.sh
- [x] TESTING.md
- [x] test-udp-local.sh
- [x] CONTRIBUTING.md
- [x] Makefile
- [x] docker-compose.test.yml
- [x] REVIEW.md
- [x] go.mod
- [x] docs/login-node-architecture.md
- [x] docs/udp-relay-design.md
- [x] docs/rate-limiting-design.md
- [x] GEMINI.md
- [x] proto/tunnel.proto
- [x] proto/internal.proto
- [x] pkg/proto/internalv1/internal_grpc.pb.go
- [x] pkg/proto/internalv1/internal.pb.go
- [x] README.md
- [x] main.go
- [x] TODO.md
- [x] test-local.sh
- [x] test/web/index.html
- [x] pkg/proto/tunnelv1/tunnel.pb.go
- [x] pkg/proto/tunnelv1/tunnel_grpc.pb.go
- [x] test-headless.sh
- [x] install.sh
- [x] V1.1-SUMMARY.md
- [x] fly.toml.dist
- [x] integration_test_framework.md
- [x] CLAUDE.md
- [x] Dockerfile
- [x] test/web/api/test.json
- [x] setup-certs.sh
- [x] go.sum
- [x] scripts/gen-test-certs.sh
- [x] internal/deps/deps.go
- [x] scripts/integration-tests/smoke-test.sh
- [x] scripts/integration-tests/auth-flow-test.sh
- [x] internal/client/login_test.go
- [x] internal/client/serve_test.go
- [x] internal/client/serve.go
- [x] internal/client/login.go
- [x] scripts/integration-tests/device-login-test.sh
- [x] internal/storage/proxy.go
- [x] internal/storage/storage.go
- [x] internal/storage/local.go
- [x] scripts/integration-tests/multi-node-test.sh
- [x] internal/store/device_codes.go
- [x] scripts/integration-tests/magic-link-test.sh
- [x] internal/config/config.go
- [x] scripts/integration-tests/run-all.sh
- [x] internal/store/db.go
- [x] internal/store/users.go
- [x] internal/store/store_test.go
- [x] internal/store/accounts.go
- [x] internal/config/config_test.go
- [x] internal/mockoidc/server.go
- [x] internal/common/logging_test.go
- [x] internal/mockoidc/server_test.go
- [x] internal/host/templates.go
- [x] internal/host/auth_test.go
- [x] internal/common/auth.go
- [x] internal/host/embed.go
- [x] internal/host/webproxy_test.go
- [x] internal/host/auth.go
- [x] internal/common/auth_test.go
- [x] internal/host/internal_server.go
- [x] internal/common/logging.go
- [x] internal/host/login_node_db.go
- [x] internal/host/proxy_test.go
- [x] internal/host/proxy.go
- [x] internal/host/email.go
- [x] internal/host/templates/privacy.html
- [x] internal/host/stripe_test.go
- [x] internal/host/grpc_server.go
- [x] internal/host/magiclink.go
- [x] internal/host/usage_buffer.go
- [x] internal/host/internal_server_test.go
- [x] internal/host/usage_buffer_test.go
- [x] internal/host/webproxy.go
- [x] internal/host/device.go
- [x] internal/common/utils_test.go
- [x] internal/common/utils.go
- [x] internal/host/grpc_server_test.go
- [x] internal/host/stripe.go
- [x] internal/host/templates/terms.html
- [x] internal/host/templates/homepage.html
- [x] internal/host/templates/account.html
