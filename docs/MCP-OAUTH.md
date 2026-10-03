# Bounded MCP OAuth for hosted clients

OAuth is disabled by default. This opt-in relay feature supplies the discovery
and owner-consent contract for manually pre-registered public clients. No live
relay configuration or hosted application registration was changed during this
implementation.

## Configuration

Set `TUNN_MCP_OAUTH_CLIENTS_FILE` to an explicit JSON file and optionally set
`TUNN_MCP_OAUTH_ISSUER` to the canonical HTTPS apex origin. Its hostname must
match `TUNN_DOMAIN`; it has no path, query or fragment. The default issuer is
`https://<TUNN_DOMAIN>`. Configure the same client file, issuer and owner signing
key on all participating relay nodes. Existing cluster node authentication
still applies; an unset node secret denies all internal database RPCs, while a
single-node relay uses local storage directly.

Example client-file shape (illustrative values, no registration performed):

```json
{
  "clients": [
    {
      "client_id": "tunn-build-chatgpt",
      "name": "ChatGPT build investigation",
      "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"]
    },
    {
      "client_id": "tunn-build-claude",
      "name": "Claude build investigation",
      "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]
    }
  ]
}
```

Copy the callback actually displayed in the application's connection setup;
the ChatGPT callback above depends on advertised issuer identification. Configure
the matching public client ID there and token endpoint authentication `none`.
The actual account UI's acceptance of an empty secret remains to be observed.
See [hosted application acceptance](HOSTED-MCP-ACCEPTANCE.md) for primary sources
and the exact local-versus-hosted evidence boundary.

Before creating a hosted connection, run `tunn mcp check --issuer <approved-apex>
<HTTPS-endpoint>/mcp` with options before the URL. Failed JSON reports lead with
the recovery action for the failed check; `ready:true` exposes the application
setup notes. A separate issuer must be explicitly named before it is fetched.
Passing discovery does not establish owner login or either registered client.

Client files allow at most 16 clients, four exact HTTPS callbacks per client,
256-byte IDs and 113-byte names. Unknown fields, duplicate IDs, callback
fragments/userinfo and reserved callback parameters are rejected. There are no
client secrets, dynamic registrations, client-metadata URL fetches, JWKS fetches
or refresh tokens.

## Owner and client flow

1. An unauthenticated private `/mcp` request returns 401 and a Bearer
   `resource_metadata` challenge. Both protected-resource well-known paths
   identify the canonical full `/mcp` URL and the single configured issuer.
   Metadata is served only for an active account-owned HTTP/MCP endpoint.
2. The client uses authorization code plus S256 PKCE, with exact client ID,
   callback, resource and `mcp:access` scope. The owner signs in using the
   existing browser login, reviews the named client, endpoint, expiry and
   allowance, then explicitly allows or cancels. A signed five-minute consent
   ticket and host-only Strict SameSite CSRF cookie bind the POST to that owner.
3. Consent creates a hashed, one-use authorization code, without issuing an
   access grant. The token endpoint atomically consumes the correctly bound
   code and creates an existing private-tool grant. Wrong bindings do not
   consume the code; a concurrent replay cannot create another grant.
4. The returned opaque bearer expires 30 minutes after the consent page was
   created and allows 100 HTTP admissions. Protocol initialization and discovery
   consume slots alongside tool calls. List it with `tunn grant list <endpoint>`
   and revoke its ID with `tunn grant revoke <id>` using the owner's saved login.

Every authorization callback carries the configured `iss`, including errors.
Token responses are noncacheable and contain the bearer once. The database
stores only code/consent/access-token hashes. Codes persist across a database
reopen; owner merges and replacement endpoint ownership are checked centrally.
Transient storage failures return 503 and do not forward. Token exchange is
not automatically retried after an ambiguous failure: the owner can inspect
and revoke a possible orphan grant before starting a fresh sign-in.

The authorization code binds the exact full resource URI. The resulting grant
retains the established **logical owner and endpoint audience**, and ingress
enforces literal `/mcp`. It does not persist an issuer/domain/port audience;
do not share this database across distinct configured authorities while assuming
their grants are origin-isolated. `mcp:access` permits that route; it does not
constrain individual tool names, arguments or arbitrary upstream MCP sessions.

Expired/revoked bearers return 401 with resource discovery when OAuth is enabled,
with their original accounting denial reason. Explicit credentials never fall
back to an owner cookie. Exhaustion remains 429. No refresh or `offline_access`
is advertised, so clients must authorize again after expiry; hosted behavior
at that boundary remains unverified.

## Local verification

`make test-mcp-oauth` runs race-enabled parser, consent, storage, RPC, discovery
and read-only checker coverage. `make test-mcp-oauth-workflow` additionally uses
the pinned Python SDK prepared by the existing build-investigation fixture.
The ordinary suite includes the Go workflow.

The workflow performs synthetic owner consent and PKCE through actual local
TLS relays, then uses official Go and Python MCP clients for seven useful tool
calls and six cited paths. It verifies separate owner usage, one-client
revocation and publisher reconnect. This is a manual OAuth protocol harness
followed by SDK calls; it does not exercise a hosted application's OAuth client
or a browser's SameSite implementation. See
[recorded local evidence](HOSTED-MCP-EVIDENCE.md).
