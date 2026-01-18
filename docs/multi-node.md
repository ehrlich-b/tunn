# Multi-Node Architecture

tunn supports running multiple proxy nodes for high availability and geographic distribution. This document explains how nodes discover each other and route requests to the correct tunnel.

## Overview

```
                              Load Balancer
                                   |
                +------------------+------------------+
                |                  |                  |
           +---------+        +---------+        +---------+
           | Node 1  |<------>| Node 2  |<------>| Node 3  |
           | login   |        |         |        |         |
           | SQLite  |        | (proxy) |        | (proxy) |
           +---------+        +---------+        +---------+
                ^                  ^                  ^
                |                  |                  |
           [Client A]         [Client B]         [Client C]
           tunnel: foo        tunnel: bar        tunnel: baz
```

Key concepts:
- Each client connects to **one node** (whichever is closest/available)
- Web requests can arrive at **any node** (via load balancer)
- Nodes communicate via **internal gRPC** to find tunnels on other nodes
- One node is the **login node** that owns the SQLite database

## Node Discovery

Nodes find each other through two mechanisms:

### 1. Fly.io DNS (Automatic)

On Fly.io, nodes discover peers via internal DNS:

```go
// Fly.io sets FLY_APP_NAME automatically
dnsName := os.Getenv("FLY_APP_NAME") + ".internal"  // e.g., "tunn.internal"
ips, _ := net.LookupIP(dnsName)  // Returns all node IPs
```

This returns IPv6 addresses for all machines in the app. Each node filters out its own IP and connects to the others.

### 2. Static Configuration (Self-Hosted)

For self-hosted deployments, configure node addresses explicitly:

```bash
# On each node
export TUNN_NODE_ADDRESSES=node1.internal:50051,node2.internal:50051,node3.internal:50051
```

Each node connects to all addresses except itself.

## Request Routing

When a request arrives for `foo.tunn.to`, the receiving node must find which node hosts that tunnel.

### Step 1: Check Local

```go
if tunnel, exists := localTunnels["foo"]; exists {
    // Tunnel is on this node, proxy directly
    proxyToLocal(tunnel, request)
    return
}
```

### Step 2: Check Cache

```go
if nodeAddr, cached := tunnelCache["foo"]; cached {
    // We know which node has it, proxy there
    proxyToNode(nodeAddr, request)
    return
}
```

### Step 3: Probe Other Nodes

```go
for _, client := range nodeClients {
    resp, err := client.FindTunnel(ctx, &FindTunnelRequest{TunnelId: "foo"})
    if resp.Found {
        // Cache the result
        tunnelCache["foo"] = resp.NodeAddress
        // Proxy to that node
        proxyToNode(resp.NodeAddress, request)
        return
    }
}
```

### Step 4: Not Found

```go
http.Error(w, "Tunnel not found or offline", 503)
```

## Performance

**Complexity:**
- Local lookup: O(1) - hash map
- Cache hit: O(1) - hash map
- Cache miss: O(n) - probes all nodes, then caches result

For most requests, routing is O(1). Only the first request for a tunnel on another node incurs the O(n) probe cost.

**Cache Limitations:**

The current implementation has no cache invalidation. If a tunnel disconnects from Node A and reconnects to Node B:
1. Cache still points to Node A
2. Request goes to Node A
3. Node A returns 503 (tunnel not found)
4. Browser sees error

This is acceptable for the 1-4 node scale tunn targets. For larger deployments, you'd want cache TTL or invalidation broadcasts.

## The FindTunnel RPC

Internal service that each node exposes:

```protobuf
service InternalService {
  rpc FindTunnel(FindTunnelRequest) returns (FindTunnelResponse);
  rpc GetNodeInfo(NodeInfoRequest) returns (NodeInfoResponse);
}

message FindTunnelRequest {
  string tunnel_id = 1;
}

message FindTunnelResponse {
  bool found = 1;
  string node_address = 2;  // Public HTTPS address to proxy to
}
```

When a node receives `FindTunnel("foo")`, it checks its local tunnel map and returns whether it has that tunnel.

## Cross-Node Proxying

Once we know which node has the tunnel, we proxy the HTTP request there:

```go
func proxyToNode(nodeAddr string, r *http.Request) {
    target := "https://" + nodeAddr
    proxy := httputil.NewSingleHostReverseProxy(target)

    // CRITICAL: Preserve original Host header
    // Remote node needs "foo.tunn.to" to extract tunnel ID
    proxy.Director = func(req *http.Request) {
        originalHost := req.Host
        defaultDirector(req)
        req.Host = originalHost  // Restore original
    }

    proxy.ServeHTTP(w, r)
}
```

The remote node receives the request, extracts the tunnel ID from the Host header, and handles it as a local request.

## Login Node

One node is special: the **login node**. It owns the SQLite database and handles:

- Device code storage (for CLI login)
- Account management
- Usage tracking
- Magic link replay protection

### Determining the Login Node

```go
func IsLoginNode() bool {
    // Self-hosted: explicit env var
    if os.Getenv("TUNN_LOGIN_NODE") == "true" {
        return true
    }
    // Fly.io: process group name
    if os.Getenv("FLY_PROCESS_GROUP") == "login" {
        return true
    }
    return false
}
```

### Login Node Discovery

Non-login nodes discover the login node by probing:

```go
func findLoginNode() {
    for addr, client := range nodeClients {
        resp, _ := client.GetNodeInfo(ctx, &NodeInfoRequest{})
        if resp.IsLoginNode {
            loginNodeClient = client
            return
        }
    }
}
```

### Database Proxying

Non-login nodes proxy database operations to the login node via gRPC:

```go
// On non-login node
func CreateDeviceCode() {
    return loginNodeClient.CreateDeviceCode(ctx, &CreateDeviceCodeRequest{...})
}

// On login node
func CreateDeviceCode() {
    return db.CreateDeviceCode(...)  // Direct SQLite access
}
```

This is implemented via the `LoginNodeDBService` gRPC service.

## Node-to-Node Authentication

All internal gRPC calls are authenticated with a shared secret:

```bash
export TUNN_NODE_SECRET=your-secret-here
```

This secret is passed as gRPC metadata and verified on the receiving node.

**IMPORTANT:** Multi-node mode **requires** `TUNN_NODE_SECRET` to be set. The server will refuse to start without it.

## Fly.io Configuration

Example `fly.toml` for a multi-node setup:

```toml
app = "tunn"
primary_region = "iad"

[processes]
  login = "./tunn -mode=host"
  proxy = "./tunn -mode=host"

[[vm]]
  size = "shared-cpu-1x"
  memory = "256mb"
  processes = ["login"]
  count = 1

[[vm]]
  size = "shared-cpu-1x"
  memory = "256mb"
  processes = ["proxy"]
  count = 2  # Scale as needed

[env]
  TUNN_ENV = "prod"
  TUNN_DOMAIN = "tunn.to"
```

Fly.io automatically sets:
- `FLY_APP_NAME` - Used for DNS discovery
- `FLY_PROCESS_GROUP` - "login" or "proxy", determines if login node

## Self-Hosted Multi-Node

For self-hosted multi-node:

**Node 1 (login node):**
```bash
export TUNN_LOGIN_NODE=true
export TUNN_NODE_SECRET=shared-secret
export TUNN_NODE_ADDRESSES=node2.internal:50051,node3.internal:50051
export TUNN_PUBLIC_ADDR=node1.example.com:443
./tunn -mode=host
```

**Node 2:**
```bash
export TUNN_NODE_SECRET=shared-secret
export TUNN_NODE_ADDRESSES=node1.internal:50051,node3.internal:50051
export TUNN_PUBLIC_ADDR=node2.example.com:443
./tunn -mode=host
```

**Node 3:**
```bash
export TUNN_NODE_SECRET=shared-secret
export TUNN_NODE_ADDRESSES=node1.internal:50051,node2.internal:50051
export TUNN_PUBLIC_ADDR=node3.example.com:443
./tunn -mode=host
```

## Graceful Degradation

Non-login nodes implement graceful degradation if the login node is unreachable:

- **Usage tracking:** Buffered locally, flushed when connection restored
- **Quota checks:** Cached for 30 seconds, allows traffic during brief outages
- **New device codes:** Fail (users can retry when login node is back)

This ensures tunnels keep working even if the login node has brief downtime.

## Tunnel Limits

Tunnel limits are enforced across the cluster:

- When a client registers a tunnel, the node checks with the login node
- Login node tracks all active tunnels per account
- If account is at limit (3 free, 10 pro), registration is denied
- When tunnel disconnects, count is decremented

This prevents users from exceeding limits by connecting to different nodes.
