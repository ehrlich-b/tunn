# Connect a local MCP server

Follow the canonical [Claude.ai and ChatGPT journey](https://tunn.to/mcp-to-claude)
for publishing, diagnostic checks and hosted setup. Start with the harmless echo
example; real hosted-client acceptance remains REQUIRED-UNRUN.

```sh
tunn login
tunn mcp --tools echo -- python3 examples/mcp/echo.py
tunn connector-check --oauth --expect-tools echo --call-tool echo \
  --arguments '{"message":"hello"}' --deny-tool hidden_echo <printed-Connector-URL>
```

Keep the publisher running. The default `connector-check <URL>` checks discovery
without OAuth registration. `--oauth` registers a diagnostic public client and
prints a consent URL for a loopback callback; run it on the desktop where you
open the link. Tokens are held in memory. `--expect-tools` asserts the exact
exposed set; calls and denial probes are explicit and must be harmless.
`--json` emits the final report; consent instructions go to stderr.

`--tools` applies to stdio only. HTTP upstreams enforce their own permissions.
The stdio call timeout is 25 seconds, with a 27-second forwarding timeout.
For longer work, return a job ID. Prices and quotas come from [pricing](https://tunn.to/pricing)
and `tunn usage`; name protection depends on the plan and available reservations.

Visit `https://<relay-domain>/account/mcp` to see connected clients and disconnect
one on a particular tunnel. Disconnect revokes its access tokens, refresh token
families, pending authorization codes and consent forms on that tunnel. New
access needs fresh approval. Access tokens expire after one hour. Clients with
refresh enabled also receive a refresh token with an absolute lifetime ending
30 days after consent; rotation never extends that deadline. Every refresh token
is single use: a successful refresh returns a new access token and refresh token
and immediately invalidates the previous access token. Save the new refresh token
atomically and serialize refresh requests.

Replay detection is strict: reuse of a retained, rotated refresh token revokes
the whole family, including tokens returned to a concurrent winning request.
There is no retry grace period, so a lost response can require fresh consent.
The last 1,024 digests are retained; older replays are rejected without revoking
the current family. After the 30-day deadline, connect again with browser consent.

To remove a person, restart the publisher with that person removed from `--allow`.
MCP checks the live list, including verified email aliases and domain entries;
the owner always retains access. Removing a person revokes their consents, codes,
access tokens and refresh families across clients. Adding them back requires new
consent. MCP invitations do not become web-sharing permissions for a private
HTTP app later published on the same name.
Rotating the publisher's manual endpoint token does not revoke OAuth grants.

Owner automation can use a tunn owner bearer with:

```text
GET /api/mcp/clients?tunnel=my-tools
DELETE /api/mcp/clients?tunnel=my-tools&client_id=<registered-client-id>
```

Clients discover RFC 9728 metadata from the unauthenticated `/mcp` bearer
challenge, then RFC 8414 metadata on the platform origin. Registration supports
RFC 7591 public clients (`token_endpoint_auth_method: none`), exact HTTPS or
loopback HTTP redirect URIs, and authorization-code grants with mandatory S256
PKCE. New registrations enable `authorization_code` and `refresh_token` by
default. Explicit code-only registrations and previously saved code-only clients
continue without refresh; register a new client to enable it. Refresh uses a
form-encoded POST to `/oauth/token` with `grant_type=refresh_token`, `client_id`,
the current `refresh_token` and the same exact `resource`; scope may be omitted or
`mcp`. Include the exact connector URL as `resource` in both authorization and
token requests. Request scope `mcp`. The token permits this tunnel's exposed MCP
capabilities only at `/mcp`; it does not grant tunn account or management access.
Registration is capped at five requests per five minutes per verified peer;
HTTP 429 includes `Retry-After`. Client registrations, codes and consent forms
have bounded storage capacity.

Each call uses the existing ingress ledger, with a grant ID and `mcp_oauth`
authentication method. `tunn usage my-tools` exports usage and request decisions.
The stdio adapter serializes calls to a single child. Legacy clients have
separate expiring HTTP session IDs, but the child's application state is shared.
Standalone GET/SSE is optional and returns 405; finite SSE POST responses work.
Client-side sampling/elicitation, stream resumption and per-client child process
isolation are not implemented.

Self-hosted relays need an authenticated login node, durable SQLite, a configured
JWT signing key and email login (or another existing login provider). Peer nodes
forward OAuth requests to the login node and verify grants through shared
metering; all peers must include the MCP ownership fields in `FindTunnel`.
This change requires deployment before a hosted connector can use it.
