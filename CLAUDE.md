# tunn Architecture

This document explains how tunn works under the hood.

## Overview

tunn is a reverse tunnel that exposes your localhost to the internet with Google Doc-style sharing. The system has two components:

1. **Proxy Server** - Runs on Fly.io at tunn.to, terminates TLS, routes requests
2. **Client** - Runs on your laptop, forwards requests to localhost

```
Browser                     Proxy (tunn.to)                    Your Laptop
   |                             |                                  |
   |  GET abc123.tunn.to/api     |                                  |
   |---------------------------->|                                  |
   |                             |  gRPC: HttpRequest               |
   |                             |--------------------------------->|
   |                             |                                  | GET localhost:8080/api
   |                             |                                  |-----.
   |                             |                                  |<----'
   |                             |  gRPC: HttpResponse              |
   |                             |<---------------------------------|
   |  200 OK + body              |                                  |
   |<----------------------------|                                  |
```

## Protocol

All communication between client and proxy uses a **single gRPC bidirectional stream**. This gives us:

- Multiplexing (many HTTP requests over one connection)
- Automatic reconnection
- Binary efficiency (protobuf)
- Works through corporate firewalls (looks like HTTPS)

### Message Types

```protobuf
// Client -> Server: Register this tunnel
message RegisterClient {
  string tunnel_id = 1;           // "myapp" -> myapp.tunn.to
  string target_url = 2;          // "http://localhost:8080"
  repeated string allowed_emails = 3;  // ["alice@gmail.com"]
  string tunnel_key = 4;          // Authorization key
}

// Server -> Client: Forward this HTTP request
message HttpRequest {
  string connection_id = 1;       // Correlates request/response
  string method = 2;
  string path = 3;
  map<string, string> headers = 4;
  bytes body = 5;
}

// Client -> Server: Here's the HTTP response
message HttpResponse {
  string connection_id = 1;
  int32 status_code = 2;
  map<string, string> headers = 3;
  bytes body = 4;
}
```

## Authentication

tunn supports three auth methods:

### 1. GitHub OAuth (tunn.to users)

```
tunn login
```

Uses OAuth 2.0 Device Code flow:
1. CLI requests a device code from server
2. CLI opens browser to `tunn.to/login?device_code=ABC123`
3. User clicks "Login with GitHub"
4. Server authorizes the device code
5. CLI polls and receives a JWT, saves to `~/.tunn/token`

### 2. Magic Link (email-only users)

For users without GitHub, the login page offers email authentication:
1. User enters email
2. Server sends a magic link JWT via SMTP
3. User clicks link, gets session cookie

### 3. Client Secret (self-hosters)

```bash
tunn 8080 --secret=mysecretkey
```

Self-hosted servers can set `CLIENT_SECRET` env var. Clients authenticate by passing the secret.

## Access Control

Tunnels are private by default. Only the creator can access them.

```bash
# Share with specific people
tunn 8080 --allow alice@gmail.com,bob@company.com

# Share with entire domain
tunn 8080 --allow @company.com
```

**Email Bucket Model**: An account is a collection of verified emails. If Alice has both `alice@gmail.com` and `alice@company.com` verified (via GitHub OAuth), and a tunnel allows `alice@company.com`, she can access it while logged in with either email.

## Multi-Node Architecture

tunn.to runs multiple proxy nodes on Fly.io for availability. Each node:

- Maintains its own set of connected tunnels
- Discovers other nodes via Fly.io internal DNS
- Routes requests to the correct node

```
+---------------------------------------------------------------+
|                         Fly.io                                |
|                                                               |
|  +-----------+    +-----------+    +-----------+              |
|  |   Node 1  |<-->|   Node 2  |<-->|   Node 3  |              |
|  |  tunnels: |    |  tunnels: |    |  tunnels: |              |
|  |  - abc123 |    |  - xyz789 |    |  - foo456 |              |
|  +-----------+    +-----------+    +-----------+              |
|        ^                ^                ^                    |
|        | gRPC           | gRPC           | gRPC               |
|  +-----+-----+    +-----+-----+    +-----+-----+              |
|  |   Client  |    |   Client  |    |   Client  |              |
|  +-----------+    +-----------+    +-----------+              |
+---------------------------------------------------------------+
```

When a request arrives for `abc123.tunn.to` at Node 2:
1. Node 2 checks local tunnels - not found
2. Node 2 asks Node 1 and Node 3 via internal gRPC
3. Node 1 responds "I have it"
4. Node 2 proxies the request to Node 1
5. Node 1 forwards to the client

### Login Node

One node is designated the **login node** (`LOGIN_NODE=true`). It owns the SQLite database for:

- Device codes
- Accounts and email buckets
- Usage tracking
- Magic link replay protection

Other nodes proxy DB operations to the login node via gRPC.

## Rate Limiting

|                     | Free    | Pro     |
|---------------------|---------|---------|
| Monthly bandwidth   | 1 GB    | 50 GB   |
| Concurrent tunnels  | 3       | 10      |
| Per-tunnel rate     | 200 Mbps| 500 Mbps|

Note: Per-tunnel rates allow 10 seconds of burst before limiting kicks in.

Rate limits apply to the **tunnel creator**, not visitors. If your public tunnel gets hammered, it counts against your quota.

## Self-Hosting

tunn is fully self-hostable:

```bash
tunn -mode=host -domain=tunnel.company.com
```

Single-node deployments need:
- `LOGIN_NODE=true`
- `CLIENT_SECRET=your-secret` (or users.yaml for per-user tokens)
- TLS certificates
- No external dependencies (SQLite is embedded)

## Code Structure

```
internal/
  client/
    serve.go      # ServeClient - establishes tunnel, forwards HTTP
    login.go      # LoginClient - device code OAuth flow
  host/
    proxy.go      # ProxyServer - HTTP/2+3 listeners, TLS, routing
    grpc_server.go # TunnelServer - gRPC control plane
    webproxy.go   # HTTP request forwarding, allow-list checks
    auth.go       # GitHub OAuth, sessions
    device.go     # Device code endpoints
    magiclink.go  # Magic link email auth
  storage/
    local.go      # LocalStorage - SQLite (login node)
    proxy.go      # ProxyStorage - gRPC to login node
  store/
    db.go         # SQLite schema
    accounts.go   # Account/email bucket operations
```

## Build Commands

```bash
make build    # Build binary
make test     # Run tests
make check    # Full pre-commit (fmt, tidy, test with race detection)
make proto    # Regenerate protobuf code
```

Always use `make` - never run `go` commands directly.
