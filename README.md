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

The stdio adapter currently supports one session, Streamable HTTP POST, legacy
MCP initialization through 2025-11-25, finite SSE responses, and a 25-second
call window. Standalone event streams and server-to-client requests are not yet
supported by the stdio adapter. Already-networked HTTP MCP servers use the new
chunked data path, so their response bodies and SSE streams are not buffered or
capped at 30 seconds.

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

See [the 2.0 design](docs/DESIGN-2.0.md) for the product direction, security
requirements, implemented connection kernel, and remaining “tunnel anything”
roadmap.

## Self-Host

Run your own tunn server:

```bash
tunn -mode=host -domain=tunnel.yourcompany.com
```

See `tunn -mode=host -help` for configuration options.

## How It Works

Your laptop connects to tunn.to over a persistent tunnel. When someone visits your tunnel URL, the request is forwarded to your localhost.

- TLS terminated at tunn.to (or your server)
- HTTP/2 and HTTP/3 support
- Email-based access control

## Development

```bash
make build    # Build the binary
make test     # Run tests
make test-mcp # Run the focused stdio/Streamable HTTP bridge tests
make check    # Full pre-commit check (format, tidy, test with race detection)
```

See `CLAUDE.md` for architecture details and contribution guidelines.

## License

MIT
