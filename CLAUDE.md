# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`tunn` is an HTTP/HTTPS tunneling service that creates secure tunnels to expose local services publicly. It's built in Go and uses HTTP/2 reverse proxy technology via the `h2rev2` library. The system consists of two modes:

- **Host mode**: Runs on a server (e.g., Fly.io) and accepts tunnel connections
- **Client mode**: Runs locally and creates tunnels to expose local services

## Common Commands

### Building
```bash
make build          # Build binary for current OS to ./bin/tunn
make build-all      # Build for Linux, macOS, and Windows
make clean          # Remove build artifacts
```

### Development
```bash
make dev            # Run in development mode (client mode)
go run main.go      # Run directly with go
```

### Testing
```bash
go test ./...       # Run all tests (currently no tests exist)
go fmt ./...        # Format code
go mod tidy         # Clean up dependencies
```

### Docker & Deployment
```bash
make docker         # Build Docker image
make docker-run     # Run Docker container locally
make fly-deploy     # Deploy to Fly.io
make fly-logs       # View Fly.io logs
```

### Certificate Management
```bash
make cert-setup     # Set up SSL certificates
make cert-renew     # Renew SSL certificates
```

## Architecture

### Core Components

1. **Main executable** (`main.go`): Single binary that runs in either host or client mode
2. **Host mode**: Listens on port 443 with TLS, handles reverse proxy connections
3. **Client mode**: Connects to host and creates tunnels for local services

### Key Features

- **Authentication**: Bearer token-based auth via `TOKEN` environment variable
- **TLS termination**: Host mode handles SSL/TLS certificates
- **HTTP/2 support**: Uses HTTP/2 for reverse proxy connections
- **Subdomain routing**: Routes `<id>.tunn.to` to appropriate tunnel client

### Dependencies

- `github.com/aojea/h2rev2`: HTTP/2 reverse proxy library
- `golang.org/x/net`: Extended networking support
- Standard Go libraries for HTTP, TLS, crypto

## Configuration

### Environment Variables
- `TOKEN`: Required authentication token for tunnel connections

### Command Line Flags
- `-mode`: "host" or "client" (default: "client")
- `-to`: Target URL for client mode (default: "http://127.0.0.1:8000")
- `-id`: Tunnel ID for client mode (blank = random)
- `-domain`: Public domain (default: "tunn.to")

### Example Usage

Client mode (typical usage):
```bash
TOKEN=your_secret_token ./bin/tunn -to http://127.0.0.1:8000
```

Host mode (server deployment):
```bash
TOKEN=your_secret_token ./bin/tunn -mode host
```

## Development Notes

- Go version: 1.23.0+ required
- No test files currently exist in the codebase
- Uses standard Go project layout
- TLS certificates expected in `/app/certs/` for host mode
- Extensive logging for debugging auth and proxy operations