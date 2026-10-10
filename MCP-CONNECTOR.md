# MCP connector audit

Offline audit against the Streamable HTTP and OAuth authorization contracts
described in the brief. No network or hosted-client verification was performed.

| Contract | Baseline | Evidence and gap |
| --- | --- | --- |
| Streamable HTTP POST | Have | `internal/mcpbridge/bridge.go:ServeHTTP`, `handlePOST` handle requests, notifications and JSON responses. `writeMCPResponse` emits finite SSE responses. |
| Optional standalone GET/SSE | Have | `Bridge.ServeHTTP` returns 405 for GET, which is the permitted unsupported-stream response. No unsolicited stream or resumability is implemented. |
| Session IDs | Partial | `validSession` / `ensureSessionID` use one global session, prevent a second legacy client from initializing, and DELETE does not invalidate it. Modern requests in `modern.go:validateProtocolRequest` are sessionless. |
| OAuth 2.1 authorization code with PKCE | Missing | `internal/host/auth.go:getAuthFromTunnelBearer` accepts tunn account and endpoint tokens; GitHub login is upstream identity authentication, not an MCP authorization server. |
| RFC 8414 authorization server metadata | Missing | `internal/host/proxy.go:createHandler` has no OAuth metadata route. |
| RFC 9728 protected resource metadata | Missing | `internal/host/webproxy.go:proxyToLocal` returns a bare bearer challenge without `resource_metadata`. |
| RFC 7591 dynamic client registration | Missing | No remote MCP client registry or registration endpoint exists. |
| Audience-bound access tokens | Partial | `internal/host/metering.go:grantBearer` and `internal/metering/store.go:Resolve` bind manual grants to owner + tunnel. MCP OAuth does not issue them or validate the resource parameter. Account JWTs are broader credentials. |
| Email login + explicit MCP consent | Partial | `internal/host/magiclink.go` implements one-use email login. Its return path is `/account`; no client/tunnel consent exists. |
| Connected-client listing + revocation | Partial | The existing metering API lists/revokes manual grants. No OAuth client identity or consent management exists. |
| Metering + audit | Have | `internal/host/metering.go:ingressMeter` records admission, byte charges and completion in the durable ledger, including rejected requests. |
| CLI connector URL | Partial | `main.go:runMCP` and `internal/client/serve.go` publish `/mcp`, but describe manual token use and require `--` for stdio commands. |

## Implemented contract

| Contract | Now | Implementation |
| --- | --- | --- |
| Streamable HTTP POST and optional GET/SSE | Have | Existing JSON/finite SSE responses are retained; unsupported standalone GET returns 405. `internal/mcpbridge/bridge.go:ServeHTTP`, `writeMCPResponse`. |
| Legacy session lifecycle | Have | Each initialize receives a fresh random ID, with bounded one-hour lifetime and DELETE invalidation. A second client can initialize while the child remains initialized. `internal/mcpbridge/bridge.go:setNewSession`, `deleteSession`; `modern.go:writeCachedInitialize`. |
| OAuth authorization code + PKCE | Have | Public clients use mandatory S256, exact redirects, five-minute one-use codes and explicit, one-use browser consent. `internal/host/mcp_oauth.go:handleMCPAuthorize`, `handleMCPConsent`, `handleMCPToken`; durable state in `mcp_oauth_store.go`. |
| RFC 8414 discovery | Have | `/.well-known/oauth-authorization-server` advertises the canonical issuer, endpoints, code grant, `none` client auth, S256 and `mcp` scope. `mcp_oauth.go:handleMCPOAuth`. |
| RFC 9728 discovery | Have | Both `/.well-known/oauth-protected-resource/mcp` and the origin-root fallback identify the exact resource and authorization server. Unauthorized/invalid-token requests return a `resource_metadata` bearer challenge. `mcp_oauth.go:handleMCPResourceMetadata`, `mcpChallenge`; `webproxy.go:proxyToLocal`. |
| RFC 7591 DCR | Have | `/oauth/register` persists public client metadata and exact HTTPS/loopback HTTP redirects, with size/count caps. `mcp_oauth.go:handleMCPRegistration`. Confidential clients and registration-management APIs are outside this implementation. |
| Audience-bound access tokens | Have | One-hour opaque tokens are stored only as SHA-256 digests in the existing grant ledger. Both OAuth requests require the same exact resource; ingress checks owner + tunnel, `/mcp`, expiry and revocation before forwarding. `mcp_oauth.go:handleMCPToken`, `webproxy.go:proxyToLocal`, `metering.go:grantBearer`. Tokens cannot manage accounts or clients. |
| Existing email login + consent | Have | Signed email links preserve the authorization return path; verified allow-listed users or the owner must explicitly consent on the platform origin with session-bound CSRF. `auth.go:handleLogin`, `magiclink.go:generateMagicLinkTokenForReturnTo`, `handleMagicLinkVerify`, `mcp_oauth.go:handleMCPConsent`. |
| Owner list/disconnect | Have | `/account/mcp` and owner-bearer `/api/mcp/clients` list grants with client names. Disconnect revokes all current grants and pending codes/consent forms for that client on that tunnel. `mcp_oauth.go:handleMCPClients`. |
| Metering + audit | Have | OAuth ingress has `mcp_oauth` auth method and grant ID, uses existing atomic admission/byte charging, and records rejections. `webproxy.go:proxyToLocal`, `metering.go:ingressMeter`. |
| CLI + guide | Have | `tunn mcp <command…>` and explicit delimiters work; the successful registration prints the connector URL and browser-consent instructions. `mcp_cli.go`, `main.go:runMCP`, `internal/client/serve.go`; [guide](docs/mcp-connectors.md). |

OAuth registrations and pending browser state live on the login node. Peer
nodes forward OAuth HTTP requests there, obtain live ownership via the extended
authenticated `FindTunnel` RPC (`proto/internal.proto`, `internal_server.go`),
and validate issued credentials via existing remote metering. Older peers without
ownership metadata fail consent closed.

Limitations: stdio application state remains shared across transport sessions;
there is no standalone SSE, resumption, client-side sampling/elicitation, refresh
token, client-ID metadata-document support, or per-client child isolation. These
are outside the authorization-code/DCR connector contract requested here.

## Verification

`go vet ./...` passed. The in-process end-to-end test in
`internal/host/mcp_oauth_test.go:TestMCPOAuthConnectorEndToEnd` passes with a real
stdio subprocess and relay/tunnel messages: discovery → DCR → email login →
consent → PKCE code/token → initialize → tools/list → tools/call. Its assertions
include credential stripping, grant audit identity, admission counts and byte
metering. Negative tests cover resource/client/redirect/verifier binding, code
reuse, missing PKCE, token expiry, revoked clients, pending-code/consent
revocation, CSRF, denied consent replay and unapproved email access. CLI and
session lifecycle regressions pass without socket listeners.

`go test ./...` was attempted unchanged. It is blocked by `bind: operation not
permitted` in `internal/client` (first failure: inspector loopback server),
`internal/host` (host-mode loopback fixture), and `internal/mcpbridge` (all socket
bridge fixtures). The remaining packages pass. Coordinator rerun with loopback
available, from this checkout:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./...
```

No network access, hosted connector check, deployment or push was performed.
