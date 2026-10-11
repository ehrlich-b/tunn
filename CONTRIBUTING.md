# Contributing to tunn

## Building

```bash
make build          # Build the binary
make test           # Run tests
make test-race      # Run tests with race detection
make proto          # Regenerate protobuf code
make check          # Full pre-commit check (fmt, tidy, test-race)
```

Always use `make` commands - never run `go` commands directly.

## Local Development

tunn uses [nip.io](https://nip.io) for wildcard DNS on localhost. This allows testing subdomain routing without modifying /etc/hosts.

### Terminal 1: Start the proxy

```bash
export TUNN_CLIENT_SECRET=dev-token
export TUNN_ENV=dev
./bin/tunn -mode=host
```

### Terminal 2: Start a tunnel

```bash
export TUNN_ENV=dev
export TUNN_SECRET=dev-token
export TUNN_SERVER_ADDR=localhost:8443
./bin/tunn 8080
```

### Terminal 3: Make a request

```bash
curl -k https://<tunnel-id>.tunn.local.127.0.0.1.nip.io:8443/
```

Source builds default to production configuration and verify relay TLS. Local
development must explicitly set `TUNN_ENV=dev` or use the global `--dev` flag
before the subcommand. Dev mode automatically:

- Uses self-signed certificates
- Starts a mock OIDC provider on :9000
- Uses nip.io domains for subdomain routing

## Environment Variables

### Client

| Variable | Description | Default |
|----------|-------------|---------|
| `TUNN_ENV` | `dev` or `prod` | `prod` |
| `TUNN_WELL_KNOWN_KEY` | Tunnel creation key | `tunn-free-v1-2025` |

### Server (host mode)

| Variable | Description | Default |
|----------|-------------|---------|
| `TUNN_CLIENT_SECRET` | Self-hosted client secret | (optional) |
| `TUNN_ENV` | `dev` or `prod` | `prod` |
| `TUNN_DOMAIN` | Base domain | `tunn.to` |
| `TUNN_PUBLIC_MODE` | Disable auth | `false` |

## Architecture

See [CLAUDE.md](CLAUDE.md) for the full architecture document.

```
┌─────────────────────────────────────────────────────────────┐
│                        tunn.to                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Proxy Nodes (HTTP/2 + HTTP/3)                       │   │
│  │  - TLS termination                                   │   │
│  │  - gRPC control plane                                │   │
│  │  - Full mesh inter-node sync                         │   │
│  └────────┬─────────────────────────────────────────────┘   │
│           │ gRPC bidirectional stream                        │
└───────────┼─────────────────────────────────────────────────┘
            │
    ┌───────┴───────┐
    │   tunn 8080   │  Your laptop
    └───────────────┘
```

### Key Components

- **Proxy** (`internal/host/`): Terminates TLS, routes requests to tunnels
- **Client** (`internal/client/`): Establishes tunnel, forwards to localhost
- **Proto** (`pkg/proto/`): gRPC definitions for control and data plane

### Data Flow

1. Client connects to proxy via gRPC bidirectional stream
2. Client sends `RegisterClient` with tunnel ID and allowed emails
3. Browser requests `https://<tunnel>.tunn.to`
4. Proxy sends `HttpRequest` message to client over gRPC
5. Client makes HTTP request to localhost
6. Client sends `HttpResponse` message back to proxy
7. Proxy returns response to browser

## Testing

```bash
make test           # Unit tests
make test-race      # With race detection
make test-coverage  # Generate coverage report

# E2E tests (requires running proxy)
./test-headless.sh
```

## Code Quality

```bash
make fmt            # Format code
make tidy           # Tidy dependencies
make verify         # Quick pre-commit (fmt + test)
make check          # Full pre-commit (fmt + tidy + test-race)
```
