# CLAUDE.md: tunn V1 Architecture Blueprint

This document outlines the robust, production-ready V1 architecture for `tunn`, designed for deployment on Fly.io and full local testability.

## Core Philosophy

`tunn` is a unified platform for creating secure reverse tunnels. It is built on a single, powerful core technology but exposes two distinct access patterns tailored to different use cases: a stateful **Browser Flow** for web apps and a stateless **CLI Flow** for programmatic access to raw TCP/UDP ports.

## Technical Architecture

### 1. The `tunn` Proxy (Central Server)

The Proxy is the heart of the system. It is a single Go application that runs multiple services.

*   **Listeners:** The application will listen on two internal ports, with Fly.io's edge routing public `443/tcp` and `443/udp` traffic accordingly.
    *   **HTTP/3 Server:** Using `quic-go`, it terminates QUIC connections for modern browser clients.
    *   **HTTP/2 Server:** Terminates standard TLS (TCP) connections. This single listener will serve both gRPC and standard HTTPS traffic by routing requests based on their `Content-Type` header.
*   **Authentication:** A unified middleware chain inspects incoming requests.
    *   If a `tunn_session` cookie is present, it's handled by the **Session Service**.
    *   If an `Authorization: Bearer` header is present, it's handled by the **JWT Service**.
    *   If neither is present, the user is directed to an authentication entry point (either a web login page or instructions for CLI login).
*   **Control Plane:** The connection with the `tunn serve` clients is managed via a **gRPC** bidirectional stream over HTTP/2. This replaces the PoC's `h2rev2` library with a production-grade, multiplexed transport for managing tunnels.

### 2. The `tunn` Server Client ("Sharer")

The `tunn serve` command.

*   **Transport:** It establishes a single, persistent gRPC bidirectional stream to the Proxy's control plane endpoint.
*   **Multiplexing:** All communication, including health checks and the creation of new forwarding connections, is multiplexed over this single gRPC connection. When the Proxy needs to forward a public request, it will instruct the client over the gRPC stream to establish a new data stream.

### 3. The `tunn` Client Client ("Accessor")

The `tunn login` and `tunn connect` commands.

*   **Authentication:** `tunn login` uses the OAuth 2.0 Device Authorization Grant to get a JWT for the user, which is stored locally.
*   **UDP Transport:** `tunn connect` establishes a UDP tunnel by making a special `POST` request over **HTTP/2 (on TCP/443)**. This connection is then hijacked to become a raw, bidirectional stream. UDP datagrams are framed with a simple length prefix and sent over this stream, ensuring maximum compatibility with restrictive firewalls.

### Local End-to-End Testing Strategy

The entire system is designed to be testable on a local machine.

1.  **Mock OIDC Provider:** A lightweight, built-in server will simulate the Google login and device flows, allowing for offline authentication testing.
2.  **Wildcard DNS:** Using a service like `nip.io` (e.g., `*.tunn.local.127.0.0.1.nip.io`) allows for testing subdomain routing on `localhost`.
3.  **Self-Signed Certificates:** A local CA and self-signed certs will be used to enable TLS for local testing.

## Auth Flow 1: Browser (HTTP, Stateful)

*   **Mechanism:** Secure session cookies (`alexedwards/scs`).
*   **Sequence:** User visits a `tunn` URL -> Proxy sees no cookie -> Redirect to Google Login (or mock OIDC provider) -> On success, Proxy sets a session cookie for `.tunn.to` -> User is redirected back and can now access the web app.

## Auth Flow 2: CLI (UDP, Stateless)

*   **Mechanism:** JWT Bearer Tokens (`golang-jwt/jwt`).
*   **Sequence (`login`):** User runs `tunn login` -> Gets a code and URL -> Authenticates in browser -> CLI polls and receives a JWT.
*   **Sequence (`connect`):** User runs `tunn connect` -> Client makes an HTTP/2 `POST` request with the JWT -> Connection is hijacked into a bidirectional stream -> Local UDP packets are proxied over this stream.

## Technology Choices

*   **Control Plane:** **gRPC** (over HTTP/2) for robust, multiplexed communication between server and sharer.
*   **Web Sessions:** `github.com/alexedwards/scs/v2` for stateful browser authentication.
*   **JWTs:** `github.com/golang-jwt/jwt/v4` for stateless CLI authentication.
*   **HTTP/3:** `github.com/quic-go/quic-go` for the modern web listener.
*   **Protobuf:** `google.golang.org/protobuf` for defining the gRPC API.

## Build and Test Commands

**CRITICAL: Always use `make` for building and testing. Never run `go` commands directly.**

This project uses a comprehensive Makefile to ensure consistent builds and tests across all environments. Direct use of `go build`, `go test`, or other `go` commands is prohibited.

### Essential Commands

**Building:**
- `make build` - Build the binary for the current OS
- `make proto` - Regenerate protobuf/gRPC code (run after modifying `.proto` files)
- `make clean` - Remove all build artifacts

**Testing:**
- `make test` - Run all tests (use this by default)
- `make test-race` - Run tests with race detection (use before commits)
- `make test-coverage` - Generate HTML coverage report

**Code Quality:**
- `make fmt` - Format all Go code
- `make tidy` - Tidy Go module dependencies
- `make verify` - Format and test (quick pre-commit check)
- `make check` - Comprehensive check: format, tidy, and test with race detection (thorough pre-commit)

**Common Workflows:**
- Before committing: `make check`
- After modifying proto files: `make proto && make test`
- Quick iteration: `make build && ./bin/tunn`
- Full verification: `make clean && make check && make build`

### Why Make Only?

1. **Consistency:** Ensures all developers and CI/CD use identical build flags and test configurations
2. **Protobuf Generation:** The `make proto` target handles code generation and file organization correctly
3. **Future-Proofing:** As the build process becomes more complex (e.g., embedding assets, multi-stage builds), the Makefile will handle it transparently
4. **Discoverability:** `make help` shows all available commands

**Exception:** You may use `go mod` commands directly for dependency management when needed, but prefer `make tidy`.
