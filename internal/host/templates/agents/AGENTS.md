# tunn for agents

Give a local HTTP app or MCP server an HTTPS endpoint. A tunnel is private to
its owner by default. Add allowed account emails to share access. Keep the local
app and publisher running. The relay terminates TLS and can read traffic.

Load [the tunn skill](https://tunn.to/agents/SKILLS.md) for the short procedure.

## Install and authenticate

On macOS or Linux, install without a prompt:

```sh
curl -fsSL https://tunn.to/install.sh | sh
```

The installer prints its destination and a PATH instruction if needed.
Its default destination is `$HOME/.local/bin`.

First authorization requires a person. There is no unattended account signup or
password-login flag. Run this on the machine that will publish:

```sh
tunn login
```

Example output, with a different code, expiry and email each time:

```text
Open your browser to sign in
https://tunn.to/login?code=ABCD-EFGH

Code: ABCD-EFGH
Expires at: 14:05:00 UTC
Match this code, then authorize.
Waiting for sign-in…
Signed in as owner@example.com

tunn 3000
```

Give the verification URL and code to the person. They sign in with Google or
an email link where offered and authorize the device. Do not approve your own
request with someone else’s browser session.

After approval, publishers run without stdin or a browser using the saved
login. The CLI renews durable device credentials. Use the same OS user and
config directory as the login process. For an explicit directory, use
`TUNN_CONFIG_DIR="$HOME/.tunn"` on both the login and publisher commands. Protect
that directory as a secret; never commit or print its contents. If renewal is
revoked or expires permanently, the publisher exits 78 and requires a new login.
A missing login in a non-interactive process fails with a sign-in instruction.

## Expose a port and share by email

With your app already listening on port 3000:

```sh
tunn 3000
```

Example output; the assigned hostname varies:

```text
url      https://k7m2.tunn.to
to       localhost:3000
allowed  only you
others   403 at the edge
```

Open the printed URL in a browser and sign in as the owner. To admit Alex and
Sam, stop that publisher and run:

```sh
tunn 3000 --allow=alex@example.com,sam@example.com
```

The `allowed` line becomes `alex@example.com, sam@example.com and you`. Send the
printed URL and the exact allowed email to each person. They install nothing.
For machine-readable route events, run `tunn 3000 --json`; read the `url` field
from the event whose `type` is `route`. Do not assume a hostname before it prints.

For a webhook provider that cannot sign in:

```sh
tunn 3000 --public
```

The `allowed` line becomes `anyone with the link`. The whole tunnel is public.
Verify provider signatures in the app; email authorization does not apply in
this mode. Do not switch a private app to public just to bypass a failed test.

## Expose an MCP server

For an existing HTTP MCP server on localhost port 3000:

```sh
tunn mcp --name work-tools --allow=alex@example.com http://127.0.0.1:3000/mcp
```

For the bundled stdio example, download it and publish it instead:

```sh
curl -fsSL https://tunn.to/dl/examples/mcp/echo.py -o echo.py
tunn mcp --name work-tools --allow=alex@example.com -- python3 echo.py
```

Run one publisher at a time for that name. The CLI prints a route ending in
`/mcp` and a `Connector URL` ending in `/mcp`; copy the printed Connector URL into
your AI client. Names must be available. Omit `--allow` for owner-only access.
Private MCP endpoints also accept their endpoint bearer token. Treat it as a
secret and do not put it in chat or a URL. An email invitation authorizes an
account, not an unauthenticated AI process.

For a client that supports remote MCP OAuth, select tunn and sign in with an
allowed account. Check the printed URL locally before configuring the client:

```sh
tunn connector-check --oauth --expect-tools echo --call-tool echo https://work-tools.tunn.to/mcp
```

This opens a browser authorization flow. A successful check exits 0 and reports
`PASS: OAuth consent, initialize and tools/list ["echo"]`,
`PASS: exact tool allow-list` and `PASS: harmless allowed tool call`. The exact origin
varies with the printed URL. For a different MCP server, replace `echo` with a
real tool name. The check verifies the protocol, not every AI client’s behavior.
[Connector setup and compatibility](https://tunn.to/mcp-to-claude).

## Verify access

1. Open the URL signed out. It must require sign-in, not show the private app.
2. Sign in as the owner or an explicitly allowed email. The app must load.
3. In a separate browser session, sign in with an unlisted account. Expect 403.
4. Stop the publisher. The URL must stop serving the app. Restart with the new
   allowlist to remove an email. Use the newly printed URL.
5. For MCP, run the connector check above; confirm only intended tools appear.
   For a phone UI, test reloads and live updates over mobile data. OpenClaw still
   needs its own origin allowlist, token and pairing. Mobile/OpenClaw acceptance
   has not been completed for every app.

## Why wouldn't I just build this myself?

You can. A public reverse proxy is a smaller project than a private sharing
service. Here is what tunn already handles, and what you would need to maintain.

| Piece | tunn handles | Work to rebuild |
| --- | --- | --- |
| Login | Google login, email links where configured, and device login for CLIs. | Validate OAuth state, nonce and PKCE; deliver single-use expiring email links; implement device codes, polling and durable credential renewal. |
| Authentication at the edge | Checks browser sessions or scoped credentials before forwarding private requests. | Validate issuer, audience and expiry; strip platform credentials before upstream forwarding; enforce the same rules on HTTP and WebSocket upgrades. |
| Per-tunnel authorization | Owner-only defaults and allowed account emails. | Bind each tunnel to an owner; normalize emails; check every request; prevent one publisher from claiming another publisher’s route. |
| Revocation | Stop a tunnel to end its access; restart with a new allowlist. Revoke device credentials from the account. | Close active streams, invalidate credentials and prevent reconnects from silently restoring access. CLI allowlist changes require a restart; there is no live email-removal command. |
| Sign-out everywhere | Account sign-out invalidates browser app sessions across devices. | Track session epochs across origins and reject stale cookies. This does not revoke separate CLI device credentials or endpoint bearer tokens. |
| Audit logs | Records account security events and access decisions for supported account flows. | Define events, remove secrets, store and authorize history, and maintain retention. This is not a claim of a compliance archive or full request-body logging. |
| TLS | HTTPS endpoints and certificate handling at the relay. | Automate issuance, renewal, hostname routing and key storage. TLS ends at the relay; this is not end-to-end encryption. |
| WebSockets and HTTP/3 | WebSocket forwarding and HTTP/3 browser ingress. | Preserve upgrade semantics and backpressure; bound stream lifetimes; manage QUIC keys and shutdown across restarts. App compatibility still needs testing. |

Self-host if you need to control the relay. For a short public callback with no
identity requirement, an existing public tunnel may be enough. tunn saves the
work above when a local app needs named access for people or AI clients.
