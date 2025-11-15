# TODO.md: V1 Implementation Plan

This checklist details the steps to build the robust, production-ready V1 of `tunn`, incorporating gRPC, dual auth flows, and a comprehensive testing strategy.

**Important:** Always use `make` for building and testing. See CLAUDE.md for details.

## Phase 0: Project Setup & Prototyping ✅

- [x] **Define Protobuf API:** Create the `.proto` file for the gRPC control plane. Define the `TunnelService` with a bidirectional `EstablishTunnel` RPC. Define messages for client registration, proxy instructions, and health checks.
- [x] **Generate gRPC Code:** Generate the Go client and server code from the `.proto` file.
- [x] **Vendor Dependencies:** Remove `h2rev2` (will be removed when code is refactored). Add `google.golang.org/grpc`, `google.golang.org/protobuf`, `github.com/quic-go/quic-go`, `github.com/golang-jwt/jwt/v4`, and `github.com/alexedwards/scs/v2`.
- [x] **Create Mock OIDC Server:** Build a simple, test-only HTTP server that implements the minimal OIDC and Device Flow endpoints needed for local testing.

## Phase 1: The New `tunn` Proxy ✅

- [x] **Implement Dual-Listener Server:** Structure the main `host` application to launch two goroutines: one for the HTTP/3 (QUIC) server and one for the HTTP/2 (TCP) server.
- [x] **Implement gRPC Server:** Create the gRPC server and implement the `EstablishTunnel` method. Accepts connections, handles registration, health checks, and maintains active tunnel connections.
- [x] **Implement HTTPS/gRPC Router:** On the HTTP/2 listener, created a router that examines `Content-Type` header to route between gRPC and HTTPS traffic.
- [x] **Add Local Testing Config:** Created config package with dev/prod environments. Dev mode uses nip.io domains, local certs, and automatically starts mock OIDC server on :9000.

## Phase 2: The New `tunn serve` ("Sharer") ✅

- [x] **Refactor `serve` Command:** Created new gRPC-based ServeClient in `internal/client/serve.go` (legacy h2rev2 code remains in `client.go` for now).
- [x] **Implement gRPC Client:** ServeClient establishes bidirectional stream to proxy's `TunnelService` and sends `RegisterClient` message.
- [x] **Implement Control Loop:** Client processes incoming messages (ProxyRequest, HealthCheckResponse) and sends periodic health checks every 30 seconds.

## Phase 3: Browser Auth Flow (Web) ✅

- [x] **Integrate Session Manager:** Initialize and add the `scs.SessionManager` middleware to the web request handler chain.
- [x] **Implement Web Auth Handlers:** Create the `/auth/login` and `/auth/callback` handlers that use the (mock) OIDC service to authenticate a user.
- [x] **Implement `CheckAuth` Middleware:** Create the middleware to check for a valid session cookie on incoming web requests to subdomains.
- [x] **Connect Web Proxy:** When an authenticated web request arrives, the proxy handler will find the appropriate `Server Client` via the gRPC control plane. Full data plane proxying will be implemented in a future phase.

## Phase 4: CLI Auth & UDP Tunneling

- [ ] **Implement Device Flow (`tunn login`):** Create the `tunn login` command that performs the OAuth Device Authorization Grant against the (mock) OIDC provider to retrieve and save a JWT.
- [ ] **Implement `CheckJWT` Middleware:** Create middleware to validate JWTs on incoming API requests.
- [ ] **Implement UDP-over-H2 Handler:** Create the `/udp-tunnel/{id}` handler, protected by the `CheckJWT` middleware. This handler will hijack the HTTP/2 connection to create a raw bidirectional stream.
- [ ] **Implement `tunn connect` Command:** Create the `connect` command. It will load the JWT, start a local UDP listener, and make the authenticated `POST` request to the `/udp-tunnel/` endpoint.
- [ ] **Implement UDP Proxy Logic:** Implement the logic in both the `connect` command and the proxy handler to frame UDP packets (length-prefix) and proxy them over the hijacked HTTP/2 stream.

## Phase 5: Final Integration & Docs

- [ ] **Write E2E Test Script:** Create a shell script (`test-local.sh`) that automates the full local testing process: starts the proxy, starts a sharer, runs `tunn login`, and runs `tunn connect`.
- [ ] **Update `README.md`:** Thoroughly document the architecture, the two auth flows, and the local testing procedure.
- [ ] **Secure Configuration:** Ensure all secrets (OIDC client secret, JWT signing key) are loaded from environment variables and never hardcoded.
