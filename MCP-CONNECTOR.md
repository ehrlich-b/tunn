# MCP connector contract

## Implemented contract

| Contract | Now | Implementation |
| --- | --- | --- |
| Streamable HTTP POST and optional GET/SSE | Have | Existing JSON/finite SSE responses are retained; unsupported standalone GET returns 405. `internal/mcpbridge/bridge.go:ServeHTTP`, `writeMCPResponse`. |
| Legacy session lifecycle | Have | Each initialize receives a fresh random ID, with bounded one-hour lifetime and DELETE invalidation. A second client can initialize while the child remains initialized. `internal/mcpbridge/bridge.go:setNewSession`, `deleteSession`; `modern.go:writeCachedInitialize`. |
| OAuth authorization code + PKCE | Have | Public clients use mandatory S256, exact redirects, five-minute one-use codes and explicit, one-use browser consent. `internal/host/mcp_oauth.go:handleMCPAuthorize`, `handleMCPConsent`, `handleMCPToken`; durable state in `mcp_oauth_store.go`. |
| RFC 8414 discovery | Have | `/.well-known/oauth-authorization-server` advertises the canonical issuer, endpoints, code and refresh grants, `none` client auth, S256 and `mcp` scope. `mcp_oauth.go:handleMCPOAuth`. |
| RFC 9728 discovery | Have | Both `/.well-known/oauth-protected-resource/mcp` and the origin-root fallback identify the exact resource and authorization server. Unauthorized/invalid-token requests return a `resource_metadata` bearer challenge. `mcp_oauth.go:handleMCPResourceMetadata`, `mcpChallenge`; `webproxy.go:proxyToLocal`. |
| RFC 7591 DCR | Have | `/oauth/register` persists public client metadata and exact HTTPS/loopback HTTP redirects, with size/count caps and a bounded peer rate limiter that ignores spoofed public forwarding headers. `mcp_oauth.go:handleMCPRegistration`, `mcp_oauth_store.go:allowRegistration`. Confidential clients and registration-management APIs are outside this implementation. |
| Audience-bound access tokens | Have | One-hour opaque tokens are stored only as SHA-256 digests in the existing grant ledger. Both OAuth requests require the same exact resource; ingress checks owner + tunnel, `/mcp`, expiry and revocation before forwarding. `mcp_oauth.go:handleMCPToken`, `webproxy.go:proxyToLocal`, `metering.go:grantBearer`. Tokens cannot manage accounts or clients. |
| Existing email login + consent | Have | Signed email links preserve the authorization return path; verified allow-listed users or the owner must explicitly consent on the platform origin with session-bound CSRF. `auth.go:handleLogin`, `magiclink.go:generateMagicLinkTokenForReturnTo`, `handleMagicLinkVerify`, `mcp_oauth.go:handleMCPConsent`. |
| Owner list/disconnect | Have | `/account/mcp` and owner-bearer `/api/mcp/clients` list grants with client names. Disconnect revokes all current grants, refresh descendants and pending codes/consent forms for that client on that tunnel. `mcp_oauth.go:handleMCPClients`. |
| Metering + audit | Have | OAuth ingress has `mcp_oauth` auth method and grant ID, uses existing atomic admission/byte charging, and records rejections. `webproxy.go:proxyToLocal`, `metering.go:ingressMeter`. |
| CLI + guide | Have | `tunn mcp <command…>` and explicit delimiters work; the successful registration prints the connector URL and browser-consent instructions. `mcp_cli.go`, `main.go:runMCP`, `internal/client/serve.go`; [guide](docs/mcp-connectors.md). |

OAuth registrations and pending browser state live on the login node. Peer
nodes forward OAuth HTTP requests there, obtain live ownership via the extended
authenticated `FindTunnel` RPC (`proto/internal.proto`, `internal_server.go`),
and validate issued credentials via existing remote metering. Older peers without
ownership metadata fail consent closed.

Limitations: stdio application state remains shared across transport sessions;
there is no standalone SSE, resumption, client-side sampling/elicitation, client-ID metadata-document support, or per-client child isolation. These
are outside the authorization-code/DCR connector contract described here.

## Refresh and revocation

Public clients may register `grant_types: ["authorization_code", "refresh_token"]`
(in either order). Omitting `grant_types` enables both. An explicit
`["authorization_code"]` registration remains supported and receives only an
access token. Existing registrations that saved only `authorization_code` keep
that setting and need a new registration to obtain refresh tokens. Discovery
advertises both grants; no client secret or HTTP client
authentication is accepted. S256 and exact redirect/resource binding remain
mandatory for the authorization-code exchange.

After browser consent, `/oauth/token` returns a one-hour opaque `access_token`
and, for refresh-enabled clients, a `refresh_token`. Refresh uses a form-encoded
POST with `grant_type=refresh_token`, the registered `client_id`, the current
`refresh_token`, and the same exact `resource` URI. Scope may be omitted or `mcp`.
A successful exchange returns a new access token and a new refresh token. Replace
the saved refresh token atomically; every refresh token is single use. The
absolute refresh lifetime ends 30 days after consent and never slides on rotation.
After expiry or terminal rejection, reconnect through explicit browser consent.

Replay detection is strict: reuse of a retained, rotated refresh token deletes
the entire family and revokes its access tokens, including credentials returned
to the winning request in a concurrent rotation. There is no retry grace period.
A lost response can therefore require new consent. Clients must serialize refresh
requests. Up to 1,024 digests per family are retained, including the current one;
the oldest spent digest is pruned as rotation continues. A replay older than that
window is rejected without invalidating the family. There is no 127-rotation
ceiling. Storage permits at most 64 live families per owner and 10,000 globally;
expired entries are reclaimed when consent or refresh families are created.
Each successful rotation revokes the family's previous access grant, leaving
at most one live access grant per family. The superseded ledger row remains for
in-flight requests to receive a normal revocation denial. Failure to create or
commit the replacement preserves the current access grant and leaves the refresh
token unused. Expired or revoked OAuth access-token rows without unfinished
requests are reclaimed before issuing another access token. Rows still needed
for in-flight revocation or expiry checks count toward grant capacity until all
their requests finish; a later issuance then reclaims them. Rapid or hourly
rotation with completed requests does not accumulate spent access grants.
Pending and approved authorization records are also bounded (128 per owner,
10,000 globally), with a 30-day maximum retention. These are OAuth storage bounds.

Consent binds the immutable owner and person account IDs, registered client,
canonical resource URI and immutable resource generation. The login authority
checks those bindings and current person permissions on issuance and rotation;
resource nodes validate the same consent through the shared grant ledger. An
unavailable authority issues no credentials and admits no authenticated call.
A name transfer or changed generation cannot revive an earlier consent, code,
access token or refresh family, even if a previous owner later reclaims the name.
Only SHA-256 digests of credential secrets are persisted; raw credentials must
not be logged or sent to the publisher.

Owner disconnect at `/account/mcp` or `DELETE /api/mcp/clients?tunnel=...&client_id=...`
revokes the client's pending forms, codes, all access tokens and every refresh
family on that owner's endpoint. The management page and `GET /api/mcp/clients`
list approved, unexpired consents independently of access-token cleanup, so a
dormant client retains its Disconnect control. Consent entries report the consent
expiry in `expires_at`; `grant_id` is empty when no live access grant remains.
MCP person access uses the publisher's current `--allow` list, including verified
email aliases and domain entries; the owner always retains access. Restarting the
publisher with a person removed revokes that person's consents, pending forms,
codes, access tokens and refresh families across clients. Adding the person back
requires new consent and cannot revive those credentials. MCP invitations are
not stored as web-sharing permissions and do not grant access to a private HTTP
app later published on the same name. `DELETE /api/sharing/<endpoint>` also
revokes that person's existing MCP credentials across clients and linked email
aliases; remove the person from `--allow` to prevent new consent. Revoking a
mapped access grant through the existing grant API revokes
its originating consent and all its descendants. Each authority revocation is
transactional; an acknowledged revocation cannot race issuance into leaving a
usable descendant. New consent is required after disconnect or consent revocation.

Pre-refresh access grants retain their original one-hour expiry; they cannot
acquire refresh credentials. Because old credentials lack person bindings,
person revocation conservatively revokes all unbound OAuth state on that endpoint. Clients may continue
to use authorization code plus PKCE without implementing refresh. Real hosted MCP
client compatibility remains REQUIRED-UNRUN; local process tests do not establish
compatibility with a hosted connector.
