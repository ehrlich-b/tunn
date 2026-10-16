# MCP connector contract

## Implemented contract

| Contract | Now | Implementation |
| --- | --- | --- |
| Streamable HTTP POST and optional GET/SSE | Have | Existing JSON/finite SSE responses are retained; unsupported standalone GET returns 405. `internal/mcpbridge/bridge.go:ServeHTTP`, `writeMCPResponse`. |
| Legacy session lifecycle | Have | Each initialize receives a fresh random ID, with bounded one-hour lifetime and DELETE invalidation. A second client can initialize while the child remains initialized. `internal/mcpbridge/bridge.go:setNewSession`, `deleteSession`; `modern.go:writeCachedInitialize`. |
| OAuth authorization code + PKCE | Have | Public clients use mandatory S256, exact redirects, five-minute one-use codes and explicit, one-use browser consent. `internal/host/mcp_oauth.go:handleMCPAuthorize`, `handleMCPConsent`, `handleMCPToken`; durable state in `mcp_oauth_store.go`. |
| RFC 8414 discovery | Have | `/.well-known/oauth-authorization-server` advertises the canonical issuer, endpoints, code grant, `none` client auth, S256 and `mcp` scope. `mcp_oauth.go:handleMCPOAuth`. |
| RFC 9728 discovery | Have | Both `/.well-known/oauth-protected-resource/mcp` and the origin-root fallback identify the exact resource and authorization server. Unauthorized/invalid-token requests return a `resource_metadata` bearer challenge. `mcp_oauth.go:handleMCPResourceMetadata`, `mcpChallenge`; `webproxy.go:proxyToLocal`. |
| RFC 7591 DCR | Have | `/oauth/register` persists public client metadata and exact HTTPS/loopback HTTP redirects, with size/count caps and a bounded peer rate limiter that ignores spoofed public forwarding headers. `mcp_oauth.go:handleMCPRegistration`, `mcp_oauth_store.go:allowRegistration`. Confidential clients and registration-management APIs are outside this implementation. |
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
are outside the authorization-code/DCR connector contract described here.
