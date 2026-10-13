# Local MCP to Claude.ai

From this checkout, install the CLI (`make build`) or use the approved release
installer. Run a harmless echo server first:

```bash
tunn login
tunn mcp --tools echo -- python3 examples/mcp/echo.py
```

The terminal prints a Connector URL ending in `/mcp`. Keep it running. MCP is
private by default. The example returns only the text you provide and has no
network, filesystem or credential access.

In Claude.ai, add that URL as a custom connector, choose automatic OAuth client
registration if prompted, sign in to tunn and approve access to the named
endpoint. Enable it in a conversation and ask for echo with `message=hello`.
[Current Claude instructions](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
(fetched 2026-10-11). Do not select published-client identity for this preview:
tunn supports dynamic registration, not that newer identity mechanism.

For your own stdio server:

```bash
tunn mcp --name work-tools -- ./my-mcp-server
# Exact allowed tools, stdio only:
tunn mcp --tools status,search -- ./my-mcp-server
```

For an already running Streamable HTTP server:

```bash
tunn mcp --name work-tools http://127.0.0.1:3000/custom-mcp-path
```

tunn remaps its public `/mcp` path to the supplied upstream path. HTTP servers
manage their own tool permissions. Revoke a client's access at `/account/mcp`.
The bridge's local call timeout is 27 seconds; long jobs should return a job ID.

Free automatically attempts to reserve one published name; Pro attempts up to ten, including
random names. Choose names before publishing. Once slots are full, further
names remain temporary. Unreserved names can be reused while available but are not
protected while offline; contact support for reservation changes.

On a failed connection, check the printed path, running process, cloud network
reachability, OAuth registration choice and owner/allow-list email. Initial 401
with resource metadata is normal on a private MCP endpoint. 429 owner-budget
reasons mean quota exhaustion; `tunn usage` shows the account totals. Don't use
`--public` as a workaround for failed OAuth.

The same URL can be configured through ChatGPT's current custom-MCP plugin
flow; follow [official OpenAI instructions](https://developers.openai.com/plugins/build/app-quickstart)
(fetched 2026-10-11). Local protocol acceptance is tested. Hosted Claude.ai and
ChatGPT acceptance must still be recorded by the coordinator before launch;
this document does not claim an authenticated hosted-client test happened.
