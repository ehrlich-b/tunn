# Connect a local MCP server

Give an AI agent scoped, revocable, audited access to your private MCP server.
The agent needs a remote MCP connector; it does not need tunn installed.

```sh
tunn login
tunn mcp --name my-tools npx -y @modelcontextprotocol/server-filesystem .
```

Copy the printed **Connector URL** into your client's remote MCP connector
settings. In the browser, sign in with tunn's existing email link or configured
identity provider, then approve “Allow <client> to use <tunnel> tools?” Keep the
publisher running. Connector availability and UI depend on the client's plan
and supported features; this implementation has not been tested against live
Claude.ai or ChatGPT.

Use `--tools read_file,list_directory` before the command to restrict the stdio
server's tools. `--allow colleague@example.com` lets that verified user consent
to a connector too. An explicit `--` before the child command is also supported.
An existing HTTP MCP server can be published with
`tunn mcp --name my-tools http://127.0.0.1:3000/mcp`.

Visit `https://<relay-domain>/account/mcp` to see connected clients and disconnect
one on a particular tunnel. Disconnect invalidates its current tokens, pending
authorization codes and pending consent forms on that tunnel. New access needs
fresh approval. Tokens expire after one hour; there are no refresh tokens.
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
PKCE. Include the exact connector URL as `resource` in both authorization and
token requests. Request scope `mcp`. The token permits this tunnel's exposed MCP
capabilities only at `/mcp`; it does not grant tunn account or management access.

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
