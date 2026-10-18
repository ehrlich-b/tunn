---
name: tunn
description: Share a local HTTP app or MCP server through an authenticated HTTPS endpoint.
---

# tunn

Use when a local app needs phone access, a client preview, a callback endpoint,
or an MCP connection from another machine. Keep the app and tunn running.

## Install and login

```sh
curl -fsSL https://tunn.to/install.sh | sh
tunn login
```

First login needs human approval at the printed device URL. Give the person the
code and URL. Subsequent publishers use saved renewable credentials without
stdin. Use the same OS user and `TUNN_CONFIG_DIR` for login and publishing.
Never print credential files. Exit 78 requires a new login.

## Publish

```sh
tunn 3000
tunn 3000 --allow=alex@example.com,sam@example.com
```

These are alternatives. Default access is owner-only. The second also allows
Alex and Sam after browser sign-in with those exact emails. Send the printed
HTTPS URL. `tunn 3000 --json` emits a `route` event with the actual `url`.
Manage web invitations at https://tunn.to/account/sharing. Select the tunnel and
remove the person to revoke access. Web grants persist across reconnects; a
shorter startup allowlist does not revoke them.

Only for a callback that cannot authenticate, with provider signature checks:

```sh
tunn 3000 --public
```

That exposes the whole tunnel to anyone with the URL. Keep private app tunnels
private.

## MCP

For an existing HTTP MCP server:

```sh
tunn mcp --name work-tools --allow=alex@example.com http://127.0.0.1:3000/mcp
```

Or download and publish the stdio example:

```sh
curl -fsSL https://tunn.to/dl/examples/mcp/echo.py -o echo.py
tunn mcp --name work-tools --allow=alex@example.com -- python3 echo.py
```

Use one publisher for a name. Copy its printed Connector URL into the AI client.
Private MCP supports OAuth for allowed accounts and an endpoint bearer token.
Do not expose that token. Check the example, replacing the URL if different:

```sh
tunn connector-check --oauth --expect-tools echo --call-tool echo --arguments '{"message":"hello"}' https://work-tools.tunn.to/mcp
```

Expect exit 0, `PASS: OAuth consent, initialize and tools/list ["echo"]`,
`PASS: exact tool allow-list` and `PASS: harmless allowed tool call`.
OAuth needs browser approval. Do not claim every AI client is verified.

## Verify

- Signed-out browser requires sign-in; an allowed email loads the app.
- An unlisted signed-in account receives 403.
- After removing a web invitation, that recipient receives 403. Stopping the publisher stops
  app access. For MCP, remove the email from `--allow` and restart; disconnect
  OAuth clients at `/account/mcp`.
- Check phone reloads and live updates over mobile data. Preserve app-level
  tokens, origin rules and pairing.
- TLS ends at the relay, which can read traffic. Sign-out everywhere invalidates
  browser sessions, not CLI credentials or endpoint tokens.

[Full commands and trust boundary](https://tunn.to/agents).
