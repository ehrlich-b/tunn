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
  bytes body = 5;                 // Request body (max 100 MiB)
}
```

### HttpResponse (client -> server)

Sent after making the local HTTP request. Contains the full response.

```protobuf
message HttpResponse {
  string connection_id = 1;       // Matches the request
  int32 status_code = 2;          // 200, 404, etc.
  map<string, string> headers = 3;
  bytes body = 4;                 // Legacy buffered response (max 100 MiB)
}
```

## HTTP/2 vs HTTP/3

Upgraded peers additionally negotiate chunked HTTP and WebSocket adapters on
the gRPC stream. OPEN carries request headers, ACCEPT carries response headers,
and DATA carries bounded chunks instead of a complete body. The buffered
messages above remain the compatibility path for older publishers.

The proxy listens on both protocols:

| Protocol | Transport | Port | Used For |
|----------|-----------|------|----------|
| HTTP/2   | TCP       | 8443 | gRPC tunnel + web traffic |
| HTTP/3   | QUIC/UDP  | 8443 | Web traffic only |

The current gRPC tunnel implementation uses HTTP/2. Public web requests can
use HTTP/2 or HTTP/3 at the relay, then traverse the existing gRPC tunnel.

Login, owner APIs and HTTP/2 control connections honor standard proxy environment
variables, including `ALL_PROXY` fallback and `NO_PROXY` exclusions. The CLI
always uses TCP HTTPS/HTTP/2 and does not try QUIC on proxy-only networks.
Ordinary HTTP CONNECT and SOCKS5 proxies do not carry HTTP/3 UDP traffic; visitor
clients must fall back to the TCP HTTPS listener when QUIC is unavailable.

**Browser traffic** can use either when UDP reaches the relay. QUIC can avoid
transport-level head-of-line blocking between HTTP/3 streams.

The TCP HTTPS listener advertises the UDP listener through `Alt-Svc`. The Fly
deployment also needs its UDP 443 service and a dedicated IPv4 address;
HTTP/3 reachability has not yet been checked against a live deployment.

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
Cookie: tunn_auth=xxx
```

### 4. Tunnel Lookup
Proxy extracts `abc123` from the Host header. Looks up in local tunnel map.

### 5. Authentication Check
If not in `PUBLIC_MODE`:
- Check for valid session cookie
- If no session, redirect to `/auth/login?return_to=/api`
- If session exists, verify user's email is in tunnel's allow-list

### 6. Rate Limit Check
Check creator's quota hasn't been exceeded (10 GB/month free, 500 GB/month pro).

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

**Platform cookies are stripped**: The proxy removes `tunn_auth` and legacy `tunn_session` cookies before forwarding to your localhost. Tunnel owners never see visitor session tokens.

**Body size limits**: HTTP requests are limited to 100 MiB (104,857,600 bytes).
Known oversized uploads are rejected at the edge before forwarding. Unknown-length
uploads are checked while streaming; final response headers wait for validation
so an early origin response cannot hide an oversized upload. Rejection returns
HTTP 413 with the limit and `Tunn-Limit-Reason: request_body_too_large`.
Streamed responses, including SSE and large downloads, have no fixed body-size
cap. The legacy buffered response path retains its 100 MiB cap. Bandwidth and
grant budgets apply to both paths. Raw TCP CONNECT streams use those budgets
rather than the HTTP upload cap.

**Rate limiting**: Per-tunnel bandwidth limiting via token bucket algorithm. Prevents a single tunnel from consuming all resources.

**Reserved subdomains**: ~50 common phishing targets (google, paypal, etc.) are blocked to prevent abuse.

## Per-caller usage and HTTP grants

The publisher relay makes one durable ingress decision per HTTP request in the
login node's SQLite ledger. Other relays use its authenticated internal Metering
RPC service. Counters group by tunnel/endpoint name, normalized email or token/
grant ID (or anonymous), and UTC admission month. Authentication and budget
rejections have audit events too; neither bodies nor headers enter this ledger.

`tunn grant create` issues an expiring per-consumer bearer credential with
minute-rate and monthly request/body-byte budgets. The relay checks known body
sizes before forwarding and reserves bytes as unknown-length bodies stream.
Limits return `429`; expired/revoked grants return `403`. A stream that already
sent headers ends with a limit-reason trailer instead of a replacement status.
Short writes reconcile reserved bytes, while interrupted reservations remain
conservative and are labeled after restart. Account bandwidth quotas still
apply, using the creator's account ID and one account update per metered call.

`tunn grant list [<endpoint>]` returns owner-scoped grant metadata without
credentials. `tunn usage [--tunnel NAME] [--since DURATION]` exports retained
audit events and caller rollups, plus owner totals across the selected tunnels.
Without `--since`, it uses durable current-month counters; duration reports
flag potentially missing audit events. Optional login-node settings
`TUNN_OWNER_MONTHLY_REQUESTS` and `TUNN_OWNER_MONTHLY_BYTES` enforce shared HTTP
caps per account UUID across all verified owner emails, callers, and tunnels. These controls support Bryan's
about-$12/year entry-tier target and per-user Fly.io egress cost checks.
See [the v1 usage contract](METERING.md) for exact units, hard
retention/capacity bounds, owner API authentication, and local test commands.
These are operational usage counters; commercial billing still requires failure
and routing reconciliation.

## WebSocket upgrades

A `GET` with `Connection: Upgrade`, `Upgrade: websocket`, a version-13 key,
and HTTP/1.1 follows the ordinary tunnel lookup, authentication, allow-list,
and quota checks. A private tunnel returns 401 for an unauthenticated upgrade
and 403 for a session outside its email allow-list. The visitor first signs in
using the HTTPS page; the browser sends that cookie on its subsequent same-site
WebSocket handshake. No upgrade reaches the local application before auth.

The publisher forwards the handshake to its configured target over HTTP/1.1,
including HTTPS and HTTP-over-Unix targets. It validates the response's 101,
Upgrade, Connection, accept key, and selected subprotocol. Only then does the
relay write 101 and hijack the public connection. Non-101 upstream rejections
remain HTTP responses. Frames already buffered beside the handshake are kept.
Both relay and publisher must be upgraded; older publishers get an explicit
501 instead of the buffered HTTP fallback for WebSockets.

The local application sees:

| Header | Value |
| --- | --- |
| `Host` | Original public tunnel authority, including a port if supplied |
| `Origin` | Original client origin, unchanged; the application validates it |
| `X-Forwarded-Host` | Original public tunnel authority |
| `X-Forwarded-Proto` | Scheme observed at TLS termination: `https` for WSS |
| `X-Forwarded-For` | Network peer IP observed by the ingress relay |
| `Authorization` | Application credential, unless used to authenticate tunn |
| `Cookie` | Application cookies with `tunn_auth` and legacy `tunn_session` removed |

This contract applies to streamed and legacy HTTP too. Caller-supplied
`Forwarded` and `X-Forwarded-*` values are replaced to prevent spoofing.
Cluster hops preserve the first relay's peer/scheme only with an HMAC verified
using `NodeSecret`; the signature and internal headers never reach the app.
If a separate load balancer connects to tunn, the peer is that load balancer,
not a claimed address from its headers. Don't base application identity on
these headers or turn on trusted-proxy auth without an independent trust
configuration.

Frames retain their original masking, message boundaries, subprotocol, and
ping/pong/close payloads. Fragmented messages count toward the configurable
eight-MiB default in each direction. Exceeding it closes with 1009; framing
violations close with 1002. Text UTF-8 and application semantics remain the
endpoint's responsibility. Extensions (including permessage-deflate) are not
negotiated, so compressed payloads cannot bypass the limit.

The publisher streams frames using a 32-KiB scratch buffer. Both directions
have bounded transport queues and apply backpressure rather than buffering
whole messages. All logical streams still share one gRPC transport, so a
slow socket can delay other connections; independent flow-controlled data
streams remain future work. Socket writes have a 30-second stall deadline.
The 100-stream limit is shared by HTTP and WebSockets. Close replies get up to
five seconds; disconnect, publisher shutdown, and token revocation clean up
both connections. Hijacked sockets clear the HTTP server's request deadlines.

By default, five minutes without received bytes closes with 1001. The
publisher sends pings every 30 seconds to both peers; received pong and other
traffic refresh idle time, but generated pings alone do not. Set
`--ws-idle-timeout`, `--ws-keepalive` (zero disables either), and
`--ws-max-message-size` on the publisher. A ping may wait for a frame boundary.
Network interruption still requires the application to reconnect. The local
HTTP inspector does not capture or replay upgraded frame traffic.

`--bearer` generates an endpoint-scoped token for native HTTP/WebSocket clients
and retains browser email auth. Prefer `Tunn-Authorization` so upstream
`Authorization` stays intact. Neither token nor platform cookie reaches the
local app. `tunn token --rotate NAME` revokes the old token for new HTTP requests
and upgrades when its digest update arrives (normally within one second), and
closes WebSockets authenticated with it. Existing ordinary HTTP requests may
finish. Stopping the publisher revokes remote reachability altogether.

`--require-upstream-auth` requires the application `Authorization` header on
HTTP requests and upgrades after tunn's credentials have been removed. It does
not validate credentials or inspect authentication inside WebSocket messages.
Keep application auth enabled even behind an email allow-list. Only ordinary
HTTP/1.1 WebSocket upgrades are supported, not RFC 8441/9220 extended CONNECT.
