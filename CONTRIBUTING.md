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
export TOKEN=dev-token
export ENV=dev
./bin/tunn -mode=host
```

### Terminal 2: Start a tunnel

```bash
export ENV=dev
export WELL_KNOWN_KEY=tunn-free-v1-2025
./bin/tunn 8080
```

### Terminal 3: Make a request

```bash
curl -k https://<tunnel-id>.tunn.local.127.0.0.1.nip.io:8443/
```

Dev mode automatically:
- Uses self-signed certificates
- Starts a mock OIDC provider on :9000
- Uses nip.io domains for subdomain routing

## Environment Variables

### Client

| Variable | Description | Default |
|----------|-------------|---------|
| `ENV` | `dev` or `prod` | `prod` |
| `WELL_KNOWN_KEY` | Tunnel creation key | `tunn-free-v1-2025` |

### Server (host mode)

| Variable | Description | Default |
|----------|-------------|---------|
| `TOKEN` | Server auth token | (required) |
| `ENV` | `dev` or `prod` | `prod` |
| `DOMAIN` | Base domain | `tunn.to` |
| `PUBLIC_MODE` | Disable auth | `false` |

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
