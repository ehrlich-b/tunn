# tunn

Give local MCP tools and webhook handlers a public HTTPS URL.

```bash
tunn login
tunn http 8080                      # Public webhook/dev endpoint
tunn mcp -- ./my-mcp-server         # Private MCP endpoint with OAuth consent
```

Copy the printed `/mcp` URL to your cloud client's connector settings. Keep your
local process running. [Connect to Claude.ai](docs/guides/mcp-to-claude.md),
[compare with ngrok](https://tunn.to/ngrok-alternative), or see
[pricing](https://tunn.to/pricing). Hosted pages describe this release after the
coordinator deploys it; the local guides work from this checkout now.

Free: 3 concurrent tunnels, 100,000 admissions and 1 GB metered transfer per UTC
month across your account. Proposed Pro: $6/month or $60/year, 10 tunnels,
1,000,000 admissions, 50 GB and 4 reserved names. No automatic overage charges.
Checkout opens only after billing acceptance; launch activation is reviewed by
an operator. Existing subscriptions are not repriced by this change.

Share a local app privately with `tunn 8080 --allow=alice@example.com`. Visitors
sign in with GitHub or an email link. For webhook callbacks, keep the endpoint
public and validate the sender's signatures in your application.
The [SSH API](docs/ssh-api.md) also supports OpenSSH publication and forwarding.

## Install

For the versioned source-checkout install, upgrade and recovery path, use the
[install guide](docs/install-recovery.md). Its fixture gate is
`bash scripts/verify-install-recovery.sh --fixtures`; actual native activation
remains a separate owner-run acceptance gate. The legacy downloader below does
not retain that path's checked artifact history or recovery journal.

```bash
curl -fsSL https://tunn.to/install.sh | sh
```

Or build from source: `make build`

Source and release builds use production configuration and verify relay TLS
certificates by default. For local development, use `tunn --dev ...` (before the
subcommand) or `TUNN_ENV=dev`; set `TUNN_SERVER_ADDR=localhost:8443` for a local
relay. Development mode explicitly permits self-signed relay certificates.

## Usage

```bash
tunn login                    # One-time GitHub auth
tunn 8080                     # Expose localhost:8080
tunn 3000 --allow=@company.com  # Allow entire domain
tunn 8080 -id=myapp           # Custom URL (myapp.tunn.to)
```

Login codes last ten minutes. The CLI prints the expiry clock time with its
time zone and automatically requests a new code while you are still waiting.
Use the newest link and code. If login has stopped, run `tunn login` again.

Login and all HTTP/2 relay connections honor `HTTPS_PROXY`, `HTTP_PROXY`, and
`NO_PROXY`, with `ALL_PROXY` as a fallback; lowercase names also work. HTTP and
HTTPS CONNECT proxies and SOCKS5 proxies are supported. Relay DNS can be resolved
by the proxy. The CLI uses TCP HTTPS/HTTP/2, so a proxy-only network needs no
QUIC/UDP access. HTTP/3 is for visitor web traffic; ordinary proxies cannot carry
it, and visitors must fall back to the relay's TCP HTTPS listener.

HTTP uploads have a **100 MiB (104,857,600-byte)** request-body limit. Larger
uploads return **413** naming the limit. Known oversized lengths are rejected at
the edge before forwarding; streamed bodies are checked as they arrive. Streamed
downloads have no fixed body-size cap; legacy buffered responses retain a 100 MiB
cap. Account bandwidth and grant limits still apply.

### WebSockets

HTTP tunnels also carry WebSocket upgrades and full-duplex text, binary,
ping/pong, and close frames. Use the same HTTPS URL with `wss://` in a client;
the relay and publisher must both support `websocket-v1`. Browser upgrades use
the same email allow-list session cookie as HTTP, so sign in on the tunnel's
HTTPS page first.

```bash
tunn 18789 --allow=you@example.com
tunn 8080 --allow=you@example.com --ws-idle-timeout=10m --ws-keepalive=30s
```

Defaults: five minutes without received traffic, pings every 30 seconds on
both legs, eight MiB per message, and 100 concurrent streaming connections per
tunnel (shared with HTTP streams). `--ws-idle-timeout=0` and `--ws-keepalive=0`
disable the respective timers. `--ws-max-message-size` sets a limit in bytes
across all fragments, in both directions. Compression/extensions are not
negotiated. Standard HTTP/1.1 upgrades are supported; HTTP/2 and HTTP/3 extended
CONNECT WebSockets are not implemented.

Native clients can opt into an endpoint token while browsers retain email login:

```bash
tunn 8080 --id=myapp --allow=you@example.com --bearer
tunn token myapp
tunn token --rotate myapp
```

Send `Tunn-Authorization: Bearer <endpoint-token>` on HTTP requests and the
WebSocket handshake. This preserves the application's `Authorization` header.
`Authorization: Bearer <endpoint-token>` also works when the client has only
one auth field; that tunn credential is consumed before forwarding. Tokens
use the same private files and digest-only registration as MCP. Rotation
revokes the old token, normally within one second, and disconnects WebSockets
opened with it; existing cookie-authenticated sockets remain connected. Token
access is off unless `--bearer` is passed. An ordinary tunnel without `--allow`
is still public.

For applications that authenticate through HTTP headers,
`--require-upstream-auth` rejects HTTP and WebSocket requests that lack an
application `Authorization` header after tunn authentication is stripped. The
application must validate the credential. OpenClaw browsers authenticate in a
WebSocket message, so keep gateway token/password auth enabled instead of using
that header guard. See the [OpenClaw guide draft](docs/guides/openclaw.md) and
[forwarded-header contract](docs/how-it-works.md#websocket-upgrades).

### Embed in Go

Import `github.com/ehrlich-b/tunn/sdk` to publish an existing `http.Handler` or
HTTP origin with context cancellation, bounded reconnects, lifecycle events and
concurrent-safe Close. It reuses the CLI publisher and relay authentication.
See the [Go SDK API and lifecycle](docs/go-sdk.md) and the runnable
[handler](examples/sdk-handler/main.go) and [origin](examples/sdk-origin/main.go)
examples. Full loopback acceptance is required before SDK release.

### Local request inspector

Add `--inspect` when debugging an HTTP endpoint or webhook handler:

```bash
tunn 8080 --inspect
```

The CLI prints a secret-protected loopback viewer URL with the last 50 completed
requests, correlation IDs, status, terminal reasons, timing and byte counts.
Headers and query values are redacted; request bodies are omitted by default.
Add `--inspect-body` to explicitly retain local HTTP bodies up to 64 KiB.
Captured application data can still contain secrets and disappears when tunn
stops. Replay is a deliberate action against the original configured target:
reconstruct redacted or missing fields explicitly, then review the visible
result. Incomplete/truncated requests and SSE/WebSocket/CONNECT streams cannot
be replayed. Replay can repeat side effects; use a test or idempotent handler.
See the [debugging journey and limitations](docs/inspection.md).

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
Optional shared monthly owner caps impose tighter account limits. The proposed
$12/year entry tier is deferred; see [pricing economics](PRICING.md).
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
unless you explicitly pass `--public`. Paste the printed connector URL into
your AI client's remote MCP settings, sign in to tunn, and approve access to
this tunnel. The client discovers OAuth, registers dynamically and exchanges
a PKCE authorization code for a one-hour token. Owners can list and disconnect
clients at `/account/mcp`. See [the connector guide](docs/mcp-connectors.md).

For clients configured manually, each run also creates a random,
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

For supervised SSH, wingthing MCP, and private dashboard access on forge and
rig, see the [AI host deployment kit](deploy/ai-hosts/README.md), including its
security prerequisites and two-phase restart canary.

## Self-Host

### Persistent machine endpoints (preview)

Host mode reads `~/.config/tunn/host.yaml` and keeps private named HTTP, TCP,
Unix, and MCP endpoints connected under a per-user service:

```bash
tunn service install
tunn service status
tunn hosts
tunn service uninstall
tunn openclaw --name home-openclaw  # setup scaffold; requires WebSocket support
```

This preview requires a standalone authenticated relay with
`TUNN_HOST_MODE=true`; it is disabled by default. See
[host mode](docs/host-mode.md) for configuration, stable-name ownership,
macOS/Linux/Windows/WSL startup, health, logs, and local tests.

### Run a relay

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
make test-dogfood # Defaults, proxy login/control, uploads and device-code regressions
make test-dogfood-memory # Same regression assertions without socket binds
make test-metering-contract # Durable usage/grant and forwarding contract (no sockets)
make integration-test-metering # Local TLS relay/publisher/CLI grant lifecycle
make test-mcp # Run the focused stdio/Streamable HTTP bridge tests
make test-ai-hosts # Offline deployment-kit unit and shell syntax checks
make test-websocket # Local TLS relay, auth, headers, rotation, 100 sockets
make test-websocket-memory # Same WebSocket stack over net.Pipe; no socket binds
make test-sdk-contract # Go SDK lifecycle, external consumer and required loopback parity
make integration-test-ai # TLS relay; private MCP/TCP, rotation, concurrency, reconnect
make check    # Full pre-commit check (format, tidy, test with race detection)
```

See `CLAUDE.md` for architecture details and contribution guidelines.

## License

MIT

An approved full license text is not present in this checkout. License packaging
and redistribution rights remain unresolved; the local install rehearsal does
not change ownership or supply a replacement license.

### Account cutoffs and custom domains

All account traffic shares hard monthly request and byte allowances across HTTP,
WebSockets, TCP CONNECT and MCP. See [metering](docs/METERING.md) for the counting
contract and owner usage view. Pro accounts can attach customer DNS names with
automatic HTTPS:

```bash
tunn domain add work.example.com --tunnel work
# Set work.example.com's CNAME to the returned cname_target, then:
tunn domain verify work.example.com
tunn serve --name work 8080
tunn domain list
```

See [custom domains and Fly setup](docs/CUSTOM-DOMAINS.md) for ownership,
renewal, credentials and the required operator configuration.
