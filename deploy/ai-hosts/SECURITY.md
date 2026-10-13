# Security review

Reviewed against this checkout's code, without hosted calls, SSH, real credentials,
or deployment. This is a proposed supervised connectivity setup, not a claim of
live acceptance on forge, rig, or tunn.to.

## Fixes and prerequisites before rollout

| Finding | Result / gate |
| --- | --- |
| Real `tunn_auth` JWT cookie was forwarded to tunnel targets | Fixed: strip it and `tunn_session`; preserve application cookies. Regression exercises a cookie-authenticated request. |
| Cookie authentication could bypass bearer stripping | Fixed: always strip `Tunn-Authorization`, and independently strip recognized tunn credentials in `Authorization`; preserve unrelated upstream auth. Tests cover account JWT, endpoint token, and upstream auth. |
| Malformed Authorization header entered relay error logs | Fixed: log request path without the header. Regression captures logs and rejects credential leakage. |
| Login ignored `TUNN_CONFIG_DIR`; overwrite preserved permissive file modes and followed destination symlinks | Fixed: account login and endpoint storage share the same isolated directory; account saves replace atomically with mode 0600 and secure the directory to 0700. Tests cover existing 0644 files, relative paths, symlinks, and temporary-file cleanup. |
| CLI's unset `TUNN_ENV` selects dev and disables relay certificate verification | Kit explicitly forces prod and clears inherited tunn settings, including `.env` secret fallback. Every direct login/connect/rotate example sets prod. A general secure-default change remains outside this kit. |
| Complete test suite requires sockets unavailable in this execution environment | **Release gate remains open**: rerun `make vet test test-ai-hosts` in a socket-capable checkout before deploying either client or relay. Tests were not skipped or weakened. |
| No proof that the hosted relay contains compatible protocol/lifecycle/security fixes | Bryan must verify/deploy the correct relay himself, then the coordinator runs the two-phase canary. Offline tests do not establish hosted acceptance. |

The fixed relay leaks require deploying the patched **relay**, not just the
host/Mac clients. This kit performs no production mutation.

## Limits to fix before unattended use

1. **Publisher login lasts 24 hours without refresh.** The token issuer's
   [device login](../../internal/host/device.go) sets that expiry. Running tunnels
   authenticate at registration, so an already connected publisher may continue
   after expiry but fail its next reconnect. Add a revocable machine credential
   or refresh lifecycle before relying on unattended recovery. For this canary,
   Bryan relogins and restarts within the test window; the local health check
   reports expiry. Existing processes do not reload the account JWT.
2. **Every new TCP/MCP publisher process replaces its capability.** See
   [publisher startup](../../main.go) and
   [endpoint token storage](../../internal/client/endpoint_token.go). A relay-only
   reconnect reuses the file; a supervisor/service/WSL restart generates a new
   token. Add an explicit safe reuse/rotation lifecycle before automatic restarts
   can recover consumers without a secure token-copy step. The kit preserves
   this behavior and the canary demands refreshed files after restarts.
3. **Capabilities have no expiry, consumer identity, or per-consumer revocation.**
   Each token grants access to the whole endpoint, not one SSH user, command,
   tool, or session. Multiple consumers share one token. Rotation replaces one
   digest and revokes new uses of the old capability; already open SSH/TCP
   connections and forwarded MCP work can continue. Add expiring grants and
   active-session revocation if those guarantees are needed. Stop the publisher
   to disconnect existing streams immediately. Rotation does not revoke creator
   account JWT/cookie access, which is an independent allowed authentication path.
4. **Ingress auth attempts have no endpoint/IP request-rate limiter.** Bandwidth
   and concurrent connection bounds limit authenticated traffic; they do not
   bound unauthenticated request floods or repeated SSH authentication attempts.
   Add an admission limiter before wider sharing. Strong 256-bit capability
   entropy makes guessing impractical, but cannot prevent denial of service.
5. **Tool filtering is not a complete MCP authorization policy.** The
   [bridge](../../internal/mcpbridge/bridge.go) filters `tools/list` and rejects
   disallowed `tools/call` before reaching the child. It does not scope resources,
   prompts, allowed arguments, files, sessions, or destructive effects of an
   allowed tool. Review the full wingthing surface locally, including resources
   and prompts, before using an account with authority over the AI host. Use a
   restricted OS user and narrowly reviewed tools. Add broader method/argument
   policy if wingthing exposes sensitive non-tool operations.

These are meaningful reliability/authorization changes, not small patches to
silently make in a deployment kit. The canary is suitable only for Bryan's
explicitly supervised evaluation while they remain unresolved.

## Trust and authentication

- **Publishing:** a signed account JWT authenticates tunnel creation at the
  [relay control plane](../../internal/host/grpc_server.go). The relay derives
  identity from its validated token. The public tunnel-creation key is not a
  visitor credential. This kit uses neither master client secrets nor public mode.
- **SSH/MCP consumption:** a random 32-byte capability authenticates HTTPS
  requests to its one active endpoint. Registration sends only its SHA-256
  digest; comparisons are constant-time. A consumer's HTTPS request sends the
  plaintext bearer to the relay, so the relay can observe it. Exact creator
  identity via valid account JWT/cookie is also accepted; the token is an
  additional capability rather than the only authentication path.
- **SSH:** tunn wraps an ordinary SSH byte stream in HTTP/2 CONNECT. SSH still
  authenticates its own user and encrypts payloads end to end. Pin the host key,
  use keys and a restricted Linux account, disable password/root login according
  to Bryan's host policy, and leave agent forwarding off. The local sshd sees
  loopback connections; source-IP SSH throttles therefore do not identify each
  remote visitor. A stolen endpoint token alone does not supply an SSH key.
- **MCP and dashboard:** relay TLS termination exposes requests/responses to the
  relay operator. MCP has no equivalent SSH encryption layer. Anyone with the
  endpoint token gets the reviewed MCP surface, which may control the host.
  Dashboard requests require a verified allowed email (creator also allowed);
  no endpoint capability is generated for ordinary `serve`. An account JWT is
  broad and should be used only locally for dashboard canary checks. Browser
  cookies are signed, Secure/HttpOnly, and scoped to the relay domain.
- **Transport:** the kit uses verified TLS to tunn.to, no `--insecure`, no public
  raw port, and loopback consumer listeners. It refuses redirects in automated
  HTTP probes so credentials cannot be replayed to another destination.
  HTTP dashboard upstream traffic stays on host loopback. Do not expose the
  local stdio bridge or dashboard directly on a public interface.
- **Local credentials:** publisher JWTs and endpoint capabilities are distinct
  mode-0600 files under per-host mode-0700 credential directories. Mac consumers
  receive only endpoint capabilities; the dashboard test uses a separate Mac
  login. Never put token plaintext in argv, git, chat, or captured stdout. A
  malicious process running as the same OS user can read these files; permissions
  protect other users, not a compromised host account.

## Bounds, availability, and logs

The [limits](../../internal/host/limits.go) specify 10 GB/month and 200 Mbps on
Free, 500 GB/month and 500 Mbps on Pro, with ten seconds of bandwidth burst.
[Concurrent tunnels](../../internal/storage/storage.go) are 5/25; each endpoint
permits at most [100 streaming connections](../../internal/common/protocol.go).
The HTTP bridge limits MCP messages to 4 MiB and requests to a 25-second work
window, serializes child work, and rejects browser `Origin` headers. The canary
does not stress these limits or run a potentially destructive tool. Quota checks
occur when admitting requests, and long-lived streams are metered on close;
do not treat the monthly quota as a strict active-session cutoff.

The CLI reconnects after a relay loss with exponential backoff. Publisher
process failures use the supervisor's bounded retry rate, while login failures
stop and require Bryan's intervention. WSL sleep/shutdown is an availability
boundary. Health is diagnostic, not a repair loop.

Host logs contain process events and bounded child errors, with mode-0600
rotation. Generic redaction is defense in depth; arbitrary wingthing stderr can
still reveal application secrets. Review logs locally before sharing them.
Relay logs can contain emails, endpoint IDs, request paths, and auth/usage events;
paths can contain sensitive identifiers. This patch removes a known raw-header
leak but does not establish a relay retention policy or full audit trail. Set
retention/access controls as part of Bryan's relay operation. No inspector is
enabled, and neither health nor canary prints credential or response contents.
