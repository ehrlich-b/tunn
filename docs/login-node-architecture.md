# Login Node Architecture

## Overview

One node in the cluster is the **login node**. It owns the SQLite database and handles all auth/account operations. Other nodes discover it and proxy DB operations to it.

**Self-hosting first:** Works with static config. Fly.io DNS is just one discovery method.

## The Design

```
┌─────────────────────────────────────────────────────────────────┐
│                         Cluster                                 │
│                                                                 │
│  ┌─────────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Login Node    │    │    Node     │    │    Node     │     │
│  │                 │◄───│             │◄───│             │     │
│  │  SQLite         │    │  stateless  │    │  stateless  │     │
│  │  Litestream ────┼──► S3 (backup)   │    │             │     │
│  │                 │    │             │    │             │     │
│  │  LOGIN_NODE=true│    │  discovers  │    │  discovers  │     │
│  └─────────────────┘    │  login node │    │  login node │     │
│         ▲               └─────────────┘    └─────────────┘     │
│         │                     │                  │              │
│         └─────────────────────┴──────────────────┘              │
│                    gRPC: "are you the login node?"              │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

### How Login Node is Determined

```go
func IsLoginNode() bool {
    // Self-host: explicit env var
    if os.Getenv("LOGIN_NODE") == "true" {
        return true
    }
    // Fly.io: process group name
    if os.Getenv("FLY_PROCESS_GROUP") == "login" {
        return true
    }
    return false
}
```

Two ways to be a login node:
1. **Self-host:** Set `LOGIN_NODE=true`
2. **Fly.io:** Be in the `login` process group (Fly sets `FLY_PROCESS_GROUP` automatically)

### Self-Hosted

```bash
# On the login node
LOGIN_NODE=true

# On all nodes (for discovery)
NODE_ADDRESSES=10.0.0.1:50051,10.0.0.2:50051,10.0.0.3:50051
```

### Single Node (Simplest)

```bash
LOGIN_NODE=true
# No NODE_ADDRESSES needed - it's alone
```

### Future: Postgres

```bash
# All nodes can be login nodes (Postgres handles concurrency)
LOGIN_NODE=true
DATABASE_URL=postgres://user:pass@host/db
```

---

## Discovery Protocol

### Step 1: Enumerate Peers

```go
func (n *Node) discoverPeers() []string {
    // Option A: Static config
    if addrs := os.Getenv("NODE_ADDRESSES"); addrs != "" {
        return strings.Split(addrs, ",")
    }

    // Option B: Fly.io DNS
    if appName := os.Getenv("FLY_APP_NAME"); appName != "" {
        ips, _ := net.LookupIP(appName + ".internal")
        return ipsToAddrs(ips, 50051)
    }

    // Option C: Single node
    return nil
}
```

### Step 2: Find Login Node

```go
func (n *Node) findLoginNode() (*grpc.ClientConn, error) {
    // Am I the login node?
    if os.Getenv("LOGIN_NODE") == "true" {
        return nil, nil  // I am the login node, no need to connect
    }

    peers := n.discoverPeers()
    for _, addr := range peers {
        conn, err := grpc.Dial(addr, ...)
        if err != nil {
            continue
        }

        // Ask: "are you the login node?"
        resp, err := pb.NewNodeClient(conn).GetNodeInfo(ctx, &pb.NodeInfoRequest{})
        if err != nil {
            conn.Close()
            continue
        }

        if resp.IsLoginNode {
            return conn, nil  // Found it
        }
        conn.Close()
    }

    return nil, errors.New("no login node found")
}
```

### Step 3: Periodic Re-Discovery

```go
func (n *Node) discoveryLoop() {
    ticker := time.NewTicker(30 * time.Second)
    for range ticker.C {
        if n.loginNodeConn == nil || !n.loginNodeConn.IsHealthy() {
            conn, err := n.findLoginNode()
            if err != nil {
                log.Warn("login node not found, operating in degraded mode")
                continue
            }
            n.loginNodeConn = conn
        }
    }
}
```

---

## gRPC Interface

Add to existing node proto:

```protobuf
// Node identification
message NodeInfoRequest {}
message NodeInfoResponse {
  bool is_login_node = 1;
  string node_id = 2;
}

// Login node services (only login node implements these)
service LoginNodeDB {
  // Node info
  rpc GetNodeInfo(NodeInfoRequest) returns (NodeInfoResponse);

  // Usage tracking
  rpc RecordUsage(RecordUsageRequest) returns (RecordUsageResponse);
  rpc GetMonthlyUsage(GetUsageRequest) returns (GetUsageResponse);

  // Auth / Device codes
  rpc CreateDeviceCode(CreateDeviceCodeRequest) returns (DeviceCode);
  rpc GetDeviceCode(GetDeviceCodeRequest) returns (DeviceCode);
  rpc AuthorizeDeviceCode(AuthorizeRequest) returns (AuthorizeResponse);

  // Accounts
  rpc GetAccount(GetAccountRequest) returns (Account);
  rpc GetAccountByEmail(GetAccountByEmailRequest) returns (Account);
  rpc CreateOrUpdateAccount(AccountRequest) returns (Account);

  // Active tunnels (cross-node count)
  rpc RegisterTunnel(RegisterTunnelRequest) returns (RegisterTunnelResponse);
  rpc UnregisterTunnel(UnregisterTunnelRequest) returns (Empty);
  rpc GetTunnelCount(GetTunnelCountRequest) returns (TunnelCountResponse);
}
```

---

## What Needs the Login Node?

| Operation | Needs Login Node? | If Login Node Down |
|-----------|-------------------|-------------------|
| Tunnel proxying | No | **Works** |
| Rate limit (bandwidth) | Write | Buffer locally, flush later |
| Rate limit (quota check) | Read | Use stale cache, fail open |
| New login (`/auth/*`) | Write | **503 Service Unavailable** |
| Existing sessions | No | **Works** (JWT verified locally) |
| Account lookup | Read | Use cache, fail open if miss |
| Active tunnel count | Write | Per-node count only |
| Device code flow | Write | **503 Service Unavailable** |
| Stripe webhooks | Write | **503** (Stripe retries) |

**Key insight:** Only new auth flows fail. Existing tunnels and sessions keep working.

---

## Graceful Degradation

### Usage Recording

```go
func (n *Node) RecordUsage(accountID string, bytes int64) {
    if n.IsLoginNode() {
        // Direct write to SQLite
        n.store.RecordUsage(accountID, bytes)
        return
    }

    if n.loginNodeConn != nil && n.loginNodeConn.IsHealthy() {
        // Proxy to login node
        _, err := n.loginNodeClient.RecordUsage(ctx, &pb.RecordUsageRequest{
            AccountId: accountID,
            Bytes:     bytes,
        })
        if err == nil {
            return
        }
    }

    // Login node unavailable - buffer locally
    n.usageBuffer.Add(accountID, bytes)
}
```

### Usage Buffer

```go
type UsageBuffer struct {
    mu      sync.Mutex
    pending map[string]int64  // accountID -> bytes
}

func (b *UsageBuffer) Add(accountID string, bytes int64) {
    b.mu.Lock()
    b.pending[accountID] += bytes
    b.mu.Unlock()
}

// Called when login node becomes available
func (b *UsageBuffer) Flush(client pb.LoginNodeDBClient) {
    b.mu.Lock()
    toFlush := b.pending
    b.pending = make(map[string]int64)
    b.mu.Unlock()

    for accountID, bytes := range toFlush {
        client.RecordUsage(ctx, &pb.RecordUsageRequest{
            AccountId: accountID,
            Bytes:     bytes,
        })
    }
}
```

### Auth Endpoints

```go
func (p *ProxyServer) handleLogin(w http.ResponseWriter, r *http.Request) {
    if !p.node.IsLoginNode() && !p.node.LoginNodeAvailable() {
        http.Error(w, "Login temporarily unavailable", http.StatusServiceUnavailable)
        return
    }
    // ... normal login flow (proxied if not login node)
}
```

### Quota Checks

```go
func (n *Node) CheckQuota(accountID string, plan string) bool {
    quota := getQuotaBytes(plan)

    // Try to get fresh data
    if n.IsLoginNode() {
        usage, _ := n.store.GetMonthlyUsage(accountID)
        return usage < quota
    }

    if n.loginNodeConn != nil {
        resp, err := n.loginNodeClient.GetMonthlyUsage(ctx, &pb.GetUsageRequest{
            AccountId: accountID,
        })
        if err == nil {
            n.usageCache.Set(accountID, resp.Bytes, 30*time.Second)
            return resp.Bytes < quota
        }
    }

    // Fall back to cache
    if cached, ok := n.usageCache.Get(accountID); ok {
        return cached < quota
    }

    // No data available - fail open (allow traffic)
    return true
}
```

---

## Login Node Lifecycle

### Startup

```go
func (n *Node) Start() {
    if os.Getenv("LOGIN_NODE") == "true" {
        // Initialize SQLite
        n.store = store.NewSQLiteStore("/data/tunn.db")

        // Start Litestream (if configured)
        if url := os.Getenv("LITESTREAM_REPLICA_URL"); url != "" {
            n.startLitestream(url)
        }

        n.isLoginNode = true
    }

    // Start peer discovery (even login node discovers peers for mesh)
    go n.discoveryLoop()

    // Start usage flush loop (non-login nodes)
    if !n.isLoginNode {
        go n.usageFlushLoop()
    }
}
```

### Login Node Replacement

If the login node machine dies:

1. **Restore from Litestream:**
   ```bash
   litestream restore -o /data/tunn.db s3://bucket/tunn.db
   ```

2. **Start new machine with LOGIN_NODE=true**

3. **Other nodes auto-discover** via next discovery cycle

**Data loss:** Buffered usage in other nodes (if they also crashed). DB state from last Litestream snapshot.

---

## Self-Host Scenarios

### Scenario 1: Single Node (Most Common)

```bash
LOGIN_NODE=true
# That's it - one machine does everything
```

### Scenario 2: Two Nodes (Basic HA)

```bash
# Node A (login node)
LOGIN_NODE=true
NODE_ADDRESSES=nodeA:50051,nodeB:50051

# Node B (proxy)
NODE_ADDRESSES=nodeA:50051,nodeB:50051
```

If Node A dies, Node B keeps proxying existing tunnels. New logins fail until Node A recovers.

### Scenario 3: No Auth (Simplest)

```bash
CLIENT_SECRET=mysecret
# No LOGIN_NODE needed - auth is just secret comparison
# No SQLite needed
```

---

## tunn.to Scenario (Fly.io + SQLite)

With SQLite, exactly ONE machine can be the login node (single writer). Fly process groups make this declarative.

### fly.toml

```toml
app = "tunn"

[build]
  builder = "paketobuildpacks/builder:base"

[env]
  FLY_APP_NAME = "tunn"
  LITESTREAM_REPLICA_URL = "s3://tigris-tunn/tunn.db"

# Volume only attached to "login" process
[mounts]
  source = "tunn_data"
  destination = "/data"
  processes = ["login"]

# Two process groups: login (1 instance) and proxy (scale freely)
[processes]
  login = "./tunn --mode=host"
  proxy = "./tunn --mode=host"

[[services]]
  processes = ["login", "proxy"]  # Both handle HTTP
  internal_port = 8443
  protocol = "tcp"
  # ... rest of service config
```

### Deploy & Scale

```bash
# Create volume (once)
fly volumes create tunn_data --size 1 --region ord

# Deploy
fly deploy

# Scale: 1 login node (has volume), N proxy nodes (stateless)
fly scale count login=1 proxy=3
```

**That's it.** No post-deploy commands. No manual env vars.

- Fly sets `FLY_PROCESS_GROUP=login` on login machines
- Fly sets `FLY_PROCESS_GROUP=proxy` on proxy machines
- `IsLoginNode()` checks `FLY_PROCESS_GROUP == "login"`
- Volume automatically attached only to login process

### Scaling

```bash
fly scale count login=1 proxy=10   # 1 login, 10 proxies
fly scale count login=1 proxy=1    # 1 login, 1 proxy (minimal)
fly scale count login=1 proxy=0    # Just login node (cheapest)
```

Login is always exactly 1. Proxy scales freely.

### Login Node Replacement

If the login machine dies, Fly restarts it automatically with the same volume.

If volume is corrupted:

```bash
# 1. Destroy old volume
fly volumes destroy tunn_data

# 2. Create new volume
fly volumes create tunn_data --size 1 --region ord

# 3. Restore from Litestream
fly ssh console -s -C "litestream restore -o /data/tunn.db s3://tigris-tunn/tunn.db"

# 4. Redeploy (attaches volume to new login machine)
fly deploy
```

---

## Implementation Checklist

### Phase 1: Login Node Basics
- [ ] Add `LOGIN_NODE` env var check
- [ ] Conditional SQLite init (only on login node)
- [ ] Add `IsLoginNode()` helper
- [ ] Add `GetNodeInfo` RPC

### Phase 2: Discovery
- [ ] Implement `discoverPeers()` (static + Fly DNS)
- [ ] Implement `findLoginNode()` loop
- [ ] Add `LoginNodeAvailable()` helper

### Phase 3: DB Proxy RPCs
- [ ] Add `LoginNodeDB` service to proto
- [ ] Implement on login node (SQLite calls)
- [ ] Implement on other nodes (proxy calls)

### Phase 4: Graceful Degradation
- [ ] Add `UsageBuffer` for offline accumulation
- [ ] Add usage flush loop
- [ ] Add 503 responses for auth when login node down
- [ ] Add quota cache with stale fallback

### Phase 5: Litestream
- [ ] Add Litestream config
- [ ] Document restore procedure

---

## Files to Modify

1. `proto/internal.proto` - Add `LoginNodeDB` service, `NodeInfoResponse`
2. `internal/host/proxy.go` - Login node detection, discovery
3. `internal/host/login_node.go` (new) - `LoginNodeDB` service impl
4. `internal/host/usage_buffer.go` (new) - Buffering logic
5. `internal/store/db.go` - Conditional init
6. `litestream.yml` - Backup config (login node only)

---

## Summary

### Login Node Detection

```go
func IsLoginNode() bool {
    // Self-host: explicit env var
    if os.Getenv("LOGIN_NODE") == "true" {
        return true
    }
    // Fly.io: process group name
    if os.Getenv("FLY_PROCESS_GROUP") == "login" {
        return true
    }
    return false
}
```

| Environment | How | Config |
|-------------|-----|--------|
| Self-host | Env var | `LOGIN_NODE=true` |
| Fly.io | Process group | `FLY_PROCESS_GROUP=login` (automatic) |
| Postgres | All nodes | `LOGIN_NODE=true` on all |

### Discovery

| Config | How Peers Found |
|--------|-----------------|
| `NODE_ADDRESSES=...` | Static list (self-host) |
| `FLY_APP_NAME=...` | DNS lookup (Fly.io) |
| Neither | Single node, no discovery |

### Degradation

| Scenario | Auth | Tunnels |
|----------|------|---------|
| Login node healthy | Works | Works |
| Login node down | **503** | Works |
| Login node replaced | Works (after discovery) | Works |

### Fly.io One-Liner

```bash
fly scale count login=1 proxy=N
```

Login node has volume, proxy nodes are stateless. All defined in fly.toml.
