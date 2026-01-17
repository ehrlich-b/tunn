# tunn

Reverse tunnel that exposes your localhost to the internet. Share access with specific people using their email addresses.

## Quick Start

```bash
# Login with Google
tunn login

# Expose localhost:8000 to the internet (private to you)
tunn serve -to localhost:8000

# Share with specific people
tunn serve -to localhost:8000 --allow alice@gmail.com,bob@company.com
```

Output:
```
https://abc123.tunn.to -> localhost:8000
Accessible by: you@gmail.com, alice@gmail.com, bob@company.com
```

Visitors to `abc123.tunn.to` are prompted to log in with Google. If their email is on the allow list, they get through. Otherwise, access denied.

## Building

```bash
make build
./bin/tunn --help
```

## How It Works

```
Browser -> HTTPS -> tunn.to proxy -> gRPC tunnel -> tunn serve -> localhost
```

The proxy terminates TLS and forwards HTTP requests over a persistent gRPC stream to your `tunn serve` client. The client makes the request to your local server and streams the response back.

Supports HTTP/2 and HTTP/3 (QUIC).

## Local Development

Uses nip.io for wildcard DNS on localhost:

```bash
# Terminal 1: Start the proxy
./bin/tunn -mode=host -env=dev

# Terminal 2: Start a tunnel
./bin/tunn -mode=client -to=localhost:8000 -env=dev

# Terminal 3: Make a request
curl -k https://<tunnel-id>.tunn.local.127.0.0.1.nip.io:8443/
```

Dev mode uses self-signed certs and a mock OIDC provider.

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `WELL_KNOWN_KEY` | Key for tunnel creation auth | `tunn-free-v1-2025` |
| `PUBLIC_MODE` | Disable auth (for testing) | `false` |
| `DOMAIN` | Base domain for tunnels | `tunn.to` |

## Architecture

- **Proxy nodes**: Stateless Go servers on Fly.io, full mesh for tunnel discovery
- **Control plane**: gRPC bidirectional streaming
- **Data plane**: HTTP-over-gRPC with request/response correlation
- **Auth**: Google OAuth, email allow-lists per tunnel

See [CLAUDE.md](CLAUDE.md) for the full architecture doc.

## Status

Core tunneling works. Auth is placeholder (mock OIDC). See [TODO.md](TODO.md) for remaining work.
