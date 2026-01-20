# How the Reverse Tunnel Works

This document explains the technical details of how tunn tunnels HTTP traffic from the internet to your localhost.

## The Problem

Your laptop is behind NAT. The internet can't reach `localhost:8080`. You need a public URL that routes to your local server.

## The Solution

tunn maintains a persistent outbound connection from your laptop to the proxy server. When traffic arrives at the proxy, it sends it down this connection to your laptop, which forwards it to localhost and sends the response back.

```
Internet                    Proxy (tunn.to)                      Your Laptop
    |                            |                                    |
    | 1. GET abc123.tunn.to      |                                    |
    |--------------------------->|                                    |
    |                            | 2. gRPC HttpRequest                |
    |                            |----------------------------------->|
    |                            |                                    | 3. GET localhost:8080
    |                            |                                    |--------.
    |                            |                                    |<-------'
    |                            | 4. gRPC HttpResponse               |
    |                            |<-----------------------------------|
    | 5. 200 OK                  |                                    |
    |<---------------------------|                                    |
```

## Why gRPC?

The tunnel uses a single gRPC bidirectional stream for all communication. This design provides:

1. **NAT traversal** - Your laptop initiates the connection, so no inbound ports needed
2. **Multiplexing** - Many HTTP requests flow over one connection concurrently
3. **Binary efficiency** - Protobuf encoding is compact
4. **Corporate firewall friendly** - Looks like normal HTTPS traffic (port 443)
5. **Automatic reconnection** - gRPC handles connection drops gracefully

## Protocol Messages

Three message types flow over the gRPC stream:

### RegisterClient (client -> server)

Sent once when the tunnel starts. Tells the proxy what subdomain you want and who can access it.

```protobuf
message RegisterClient {
  string tunnel_id = 1;           // "myapp" -> myapp.tunn.to
  string target_url = 2;          // "http://localhost:8080"
  repeated string allowed_emails = 3;  // ["alice@gmail.com", "@company.com"]
  string tunnel_key = 4;          // Authorization to create tunnels
  string auth_token = 5;          // JWT proving who you are
}
```

### HttpRequest (server -> client)

Sent when an HTTP request arrives at your tunnel URL. Contains the full request.

```protobuf
message HttpRequest {
  string connection_id = 1;       // Links request to response
  string method = 2;              // "GET", "POST", etc.
  string path = 3;                // "/api/users?page=1"
  map<string, string> headers = 4;
  bytes body = 5;                 // Request body (max 100 MB)
}
```

### HttpResponse (client -> server)

Sent after making the local HTTP request. Contains the full response.

```protobuf
message HttpResponse {
  string connection_id = 1;       // Matches the request
  int32 status_code = 2;          // 200, 404, etc.
  map<string, string> headers = 3;
  bytes body = 4;                 // Response body (max 100 MB)
}
```

## HTTP/2 vs HTTP/3

The proxy listens on both protocols:

| Protocol | Transport | Port | Used For |
|----------|-----------|------|----------|
| HTTP/2   | TCP       | 8443 | gRPC tunnel + web traffic |
| HTTP/3   | QUIC/UDP  | 8443 | Web traffic only |

**gRPC always uses HTTP/2** because it requires TCP's reliable ordered delivery.

**Browser traffic** can use either. Modern browsers (Chrome, Firefox, Safari) will use HTTP/3 if available because QUIC provides:
- Faster connection establishment (0-RTT)
- Better performance on lossy networks
- No head-of-line blocking

The server advertises HTTP/3 support via the `Alt-Svc` header. Browsers that support it will switch automatically.

## Request Lifecycle

Here's exactly what happens when someone visits `https://abc123.tunn.to/api`:

### 1. DNS Resolution
Browser resolves `abc123.tunn.to` -> proxy's IP (via Fly.io anycast)

### 2. TLS Handshake
Browser establishes TLS connection. Proxy terminates TLS with wildcard cert for `*.tunn.to`.

### 3. HTTP Request Arrives
```
GET /api HTTP/2
Host: abc123.tunn.to
Cookie: tunn_session=xxx
```

### 4. Tunnel Lookup
Proxy extracts `abc123` from the Host header. Looks up in local tunnel map.

### 5. Authentication Check
If not in `PUBLIC_MODE`:
- Check for valid session cookie
- If no session, redirect to `/auth/login?return_to=/api`
- If session exists, verify user's email is in tunnel's allow-list

### 6. Rate Limit Check
Check creator's quota hasn't been exceeded (1 GB/month free, 50 GB/month pro).

### 7. Forward via gRPC
Create `HttpRequest` message, generate unique `connection_id`, send to client.

### 8. Client Receives Request
Client's `processMessages` loop receives the HttpRequest. Spawns goroutine (limited to 100 concurrent).

### 9. Local HTTP Request
Client makes actual HTTP request to `localhost:8080/api`.

### 10. Response Flows Back
Client wraps response in `HttpResponse` message, sends via gRPC.

### 11. Proxy Delivers Response
Proxy matches `connection_id`, writes headers and body to original HTTP response.

## Concurrency

The system handles concurrent requests at multiple levels:

**Proxy side:**
- Each HTTP request gets a unique `connection_id`
- A response channel is created and stored in `pendingRequests` map
- When gRPC response arrives, it's routed to the correct channel

**Client side:**
- Incoming HttpRequests spawn goroutines
- Semaphore limits concurrent handlers (default: 100)
- Thread-safe stream wrapper ensures gRPC sends don't interleave

## Reconnection

If the connection drops, the client automatically reconnects with exponential backoff:

1. Initial delay: 1 second
2. Double each attempt
3. Cap at 30 seconds
4. Repeat until context canceled

During reconnection, the tunnel is offline. In-flight requests timeout (30 seconds).

## Security Considerations

**Platform cookies are stripped**: The proxy removes `tunn_session` cookies before forwarding to your localhost. Tunnel owners never see visitor session tokens.

**Body size limits**: Both request and response bodies are limited to 100 MB to prevent memory exhaustion.

**Rate limiting**: Per-tunnel bandwidth limiting via token bucket algorithm. Prevents a single tunnel from consuming all resources.

**Reserved subdomains**: ~50 common phishing targets (google, paypal, etc.) are blocked to prevent abuse.
