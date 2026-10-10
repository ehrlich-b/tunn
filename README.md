# tunn

Share localhost like a Google Doc.

```bash
tunn 8080
```

```
https://abc123.tunn.to → localhost:8080
```

Share with specific people:

```bash
tunn 8080 --allow=alice@gmail.com,bob@company.com
```

Visitors log in with GitHub or a magic link. If they're on your list, they're in. Otherwise, access denied.

## Install

```bash
curl -fsSL https://tunn.to/install.sh | sh
```

Or build from source: `make build`

## Usage

```bash
tunn login                    # One-time GitHub auth
tunn 8080                     # Expose localhost:8080
tunn 3000 --allow=@company.com  # Allow entire domain
tunn 8080 -id=myapp           # Custom URL (myapp.tunn.to)
```

### Local request inspector

Add `--inspect` when debugging an HTTP endpoint or webhook handler:

```bash
tunn 8080 --inspect
```

The CLI prints a loopback viewer URL. It shows the last 50 forwarded requests,
their status, timing, and byte counts. Select a request to inspect its headers
and body, then replay it directly to the configured target after changing
your handler. Only complete bodies up to 64 KiB can be replayed. Captures stay
in the local process and disappear when tunn stops; they may contain webhook
secrets or personal data. Replay creates a new delivery, so use a test endpoint
or an idempotent handler when the action has side effects. Provider signatures
with timestamps may expire before replay.

### Metered consumer grants

Give each consumer of a private HTTP endpoint a separate token and budget:

```bash
tunn serve --id=api --allow=owner@example.com 8080
tunn grant create api --for=agent@example.com --expires=1h \
  --rate=60 --monthly-requests=1000 --monthly-bytes=1000000
tunn grant list api
tunn usage --tunnel api --since 24h
tunn usage # current month across all your tunnels, including owner byte totals
tunn grant revoke api <grant-id>
```

Create prints the consumer token once; only its digest reaches the relay.
Consumers send `Tunn-Authorization: Bearer <token>`. Request/byte exhaustion
returns `429`; expiry and revocation return `403`. The durable ledger records
caller usage and rejected ingress decisions across buffered and streamed HTTP.
Optional shared monthly owner caps support an entry tier of about $12/year;
per-user request and byte totals let us check that target against Fly.io costs.
See [the usage contract](docs/METERING.md) for units, retention, streaming limit
trailers, local/self-hosted CLI options, and the boundary between metering and
billable usage.

### Remote MCP preview

Expose a local stdio MCP server as a remote Streamable HTTP endpoint:

```bash
tunn login
tunn mcp --name work-tools -- docker mcp gateway run --profile work
```

For stdio servers, enforce an exact tool allow-list locally. Disallowed tools
are removed from discovery and rejected before their arguments reach the child:

```bash
tunn mcp --name files --tools read_file,list_directory -- ./filesystem-mcp
```

If the local server already speaks Streamable HTTP, point `tunn mcp` at it
directly. Its local path is mapped to the stable public `/mcp` path:

```bash
tunn mcp --name work-tools http://127.0.0.1:3000/internal/mcp
```

The endpoint is `https://work-tools.tunn.to/mcp`. MCP endpoints are private
unless you explicitly pass `--public`. Each run creates a random,
endpoint-scoped token in `~/.tunn/endpoints/work-tools.token`; only its SHA-256
digest is sent to the relay. Retrieve it later with `tunn token work-tools` and
configure the remote client to send it as either:

```text
Tunn-Authorization: Bearer <endpoint-token> # preserves upstream Authorization
Authorization: Bearer <endpoint-token>      # for clients with fixed auth fields
```

Rotate a running endpoint without restarting it:

```bash
tunn token --rotate work-tools
```

The token file is replaced atomically; the publisher sends the relay only the
new digest, normally within one second. The old token is revoked when that
update arrives.

Endpoint tokens default to `~/.tunn/endpoints`. Containers, CI jobs, and other
isolated runtimes can set `TUNN_CONFIG_DIR` to an absolute directory; tokens
will be created in its mode-0700 `endpoints` child and remain mode 0600.

The stdio adapter accepts MCP 2026-07-28 sessionless Streamable HTTP clients:
`server/discover`, tool listing and calls, per-request metadata, and the
standard method/name headers. It initializes an older stdio child once and
also retains legacy HTTP session compatibility through MCP 2025-11-25. It
supports finite SSE responses and a 25-second request window covering queueing,
child initialization, pipe writes, and the response wait after validation.
Canceled queued requests do not reach the child. The adapter returns HTTP 504
and 502 for timeouts and child-process failures with the caller's JSON-RPC ID.
If publisher shutdown disconnects the relay first, it returns a transport 502;
subsequent requests see an offline 503. Late replies
cannot satisfy a later request that reuses the same caller ID. Already forwarded
work may continue in the child after caller cancellation; a partial pipe write
terminates the child to avoid reusing a corrupted stream. Modern
`subscriptions/listen`, multi round-trip requests, concurrent child calls,
and server-to-client requests are not yet supported by this adapter.
Already-networked HTTP MCP servers are forwarded without MCP translation and
use the chunked data path, so their response bodies and SSE streams are not
buffered or capped at 30 seconds.

### Raw TCP preview

Publish a database, SSH daemon, game server, device, or any other TCP service:

```bash
# On the machine that can reach the private service
tunn tcp --name database 127.0.0.1:5432
```

On a consuming machine, store the endpoint token in a mode-0600 file and open
a loopback port for ordinary applications:

```bash
tunn connect --listen 127.0.0.1:15432 --token-file ./database.token database
psql -h 127.0.0.1 -p 15432
```

If both commands run as the same user on one machine, `tunn connect database`
automatically uses `~/.tunn/endpoints/database.token`. Explicit remote URLs
never auto-load a local token. TCP is carried as full-duplex, chunked bytes over
authenticated HTTP/2 CONNECT and preserves half-close; it does not allocate a
public raw port, so the consuming side currently needs the tunn CLI.

The same byte path can publish a Unix-domain socket while keeping its path
private to the publishing machine:

```bash
tunn unix --name docker /var/run/docker.sock
tunn connect --listen 127.0.0.1:12375 --token-file ./docker.token docker
```

For an HTTP-speaking socket, use the HTTP adapter and access the resulting
private HTTPS endpoint directly. Public mode is intentionally disabled here:

```bash
tunn unix --as http --name docker-api /var/run/docker.sock
```

See [the product roadmap](docs/PRODUCT-ROADMAP.md) for the HTTP, webhook, MCP,
and metering sequence; [the 2.0 design](docs/DESIGN-2.0.md) for architecture;
and [the commercial thesis](docs/COMMERCIAL-THESIS.md) for the buyer and payment
test.

## Self-Host

Run your own tunn server:

```bash
tunn -mode=host -domain=tunnel.yourcompany.com
```

See `tunn -mode=host -help` for configuration options.

## How It Works

Your laptop connects to tunn.to over a persistent tunnel. When someone visits your tunnel URL, the request is forwarded to your localhost.

- TLS terminated at tunn.to (or your server)
- HTTP/2 and HTTP/3 listeners; the Fly configuration exposes TCP and UDP 443
- Email-based access control

## Development

```bash
make build    # Build the binary
make test     # Run tests
make test-metering-contract # Durable usage/grant and forwarding contract (no sockets)
make integration-test-metering # Local TLS relay/publisher/CLI grant lifecycle
make test-mcp # Run the focused stdio/Streamable HTTP bridge tests
make integration-test-ai # TLS relay; private MCP/TCP, rotation, concurrency, reconnect
make check    # Full pre-commit check (format, tidy, test with race detection)
```

See `CLAUDE.md` for architecture details and contribution guidelines.

## License

MIT
