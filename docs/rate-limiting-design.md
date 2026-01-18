# Rate Limiting Design

Limits for tunnels, bandwidth, and monthly quota. Self-host first: works without SQLite.

## Limits Overview

| Limit | Free | Pro | Config | Advertised |
|-------|------|-----|--------|------------|
| Concurrent tunnels | 3 | 10 | `MAX_TUNNELS` | Yes |
| Bandwidth per tunnel | 100 Mbps | 250 Mbps | `RATE_LIMIT_MBPS` | No |
| Monthly quota | 100 MB | 50 GB | `MONTHLY_QUOTA_MB` | Vaguely |
| Flush threshold | 20 MB | 20 MB | `FLUSH_THRESHOLD_MB` | No |

**Self-hosters:** All limits configurable. Without SQLite, monthly quota is disabled.

**Comparison to ngrok free tier:**
- ngrok: 3 tunnels, 1 GB/month, 20k requests, complex credit system
- tunn free: 3 tunnels, 100 MB/month, simple pricing

---

## Why These Numbers?

Limits are engineered to cap worst-case overage before cutoff.

### The Overage Problem

When a user hits quota, there's a window before they get cut off:
- **Single node:** Up to 20 MB per tunnel (threshold flush + local cache update)
- **Multi-node:** Up to 30 seconds of bandwidth (quota cache refresh interval)

### Working Backwards from Acceptable Overage

**Free tier: Max overage < 1 GiB ($0.02 at Fly's $0.02/GB)**
```
3 tunnels × X Mbps × 30 sec < 1 GiB
X < 1024 MB × 8 bits / (3 × 30 sec) ≈ 91 Mbps
```
→ **100 Mbps** per tunnel = ~1.1 GiB worst case = $0.02

**Pro tier: Max overage < 10 GiB ($0.20)**
```
10 tunnels × Y Mbps × 30 sec < 10 GiB
Y < 10240 MB × 8 bits / (10 × 30 sec) ≈ 273 Mbps
```
→ **250 Mbps** per tunnel = ~9.3 GiB worst case = $0.19

### Cost Analysis

| Scenario | Tunnels | Bandwidth | Max Overage | Cost | Acceptable? |
|----------|---------|-----------|-------------|------|-------------|
| Free abuser | 3 | 100 Mbps | 1.1 GiB | $0.02 | Yes - 10x quota but 2 cents |
| Pro abuser | 10 | 250 Mbps | 9.3 GiB | $0.19 | Yes - they paid $4/mo |

**Key insight:** Abusers get cut off for the rest of the month. A free user costs us $0.02 once, then they're done. Not worth over-engineering to prevent.

### The Story

- **100 Mbps (free):** Typical home fiber upload speed. Reasonable for local dev server.
- **250 Mbps (pro):** Faster for staging/demo servers. Still won't saturate data center links.
- **20 MB threshold:** Forces flush before accumulating too much. Limits single-node overage to 60-200 MB.
- **30 sec refresh:** Cross-node consistency. Rare edge case for multi-node overage.

---

## Self-Host vs Hosted

### Without SQLite (typical self-host)

- **Rate limit:** Works (token bucket is in-memory)
- **Concurrent tunnels:** Per-node only (no cross-node coordination)
- **Monthly quota:** Disabled (no persistence)

### With SQLite (tunn.to or persistent self-host)

- **Rate limit:** Same (token bucket)
- **Concurrent tunnels:** Cross-node via SQLite
- **Monthly quota:** Full tracking with persistence

```go
type LimitConfig struct {
    MaxTunnels      int     // Per-node if no SQLite, global with SQLite
    RateLimitMbps   int     // Mbps per tunnel
    MonthlyQuotaMB  int     // 0 = disabled, requires SQLite
    HasSQLite       bool    // Determines behavior
}
```

---

## 1. Concurrent Tunnel Limit

**Default:** 10 tunnels
**Config:** `MAX_TUNNELS=10`

### Without SQLite (per-node)

Simple in-memory counter:

```go
type TunnelServer struct {
    mu           sync.Mutex
    tunnelCount  map[string]int  // accountID -> count on this node
    maxTunnels   int
}

func (s *TunnelServer) canAddTunnel(accountID string) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.tunnelCount[accountID] < s.maxTunnels
}
```

**Limitation:** User could open 10 tunnels on each of 4 nodes = 40 total. Acceptable for self-host.

### With SQLite (cross-node)

Track active tunnels in SQLite:

```sql
CREATE TABLE active_tunnels (
    tunnel_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    connected_at TEXT NOT NULL,
    last_heartbeat TEXT NOT NULL
);

CREATE INDEX idx_active_tunnels_account ON active_tunnels(account_id);
```

**On connect:**
```sql
-- Atomic check-and-insert
INSERT INTO active_tunnels (tunnel_id, account_id, node_id, connected_at, last_heartbeat)
SELECT ?, ?, ?, datetime('now'), datetime('now')
WHERE (SELECT COUNT(*) FROM active_tunnels WHERE account_id = ?) < ?
```
Returns 0 rows affected if at limit.

**On disconnect:**
```sql
DELETE FROM active_tunnels WHERE tunnel_id = ?
```

**Heartbeat (every 60s):**
```sql
UPDATE active_tunnels SET last_heartbeat = datetime('now') WHERE tunnel_id = ?
```

**Cleanup stale (every 5 min):**
```sql
DELETE FROM active_tunnels WHERE last_heartbeat < datetime('now', '-5 minutes')
```

---

## 2. Bandwidth Rate Limit (Per-Tunnel)

**Default:** 100 Mbps
**Config:** `RATE_LIMIT_MBPS=100`

Uses `golang.org/x/time/rate` token bucket. Always in-memory, no SQLite needed.

### Conversion

```go
// Mbps to bytes/sec
func mbpsToBytesPerSec(mbps int) int {
    return mbps * 1_000_000 / 8  // 100 Mbps = 12.5 MB/s
}
```

### Implementation

```go
import "golang.org/x/time/rate"

type TunnelConnection struct {
    // ... existing fields ...
    rateLimiter *rate.Limiter
}

func NewTunnelConnection(rateLimitMbps int) *TunnelConnection {
    bytesPerSec := mbpsToBytesPerSec(rateLimitMbps)

    return &TunnelConnection{
        // Rate = bytes/sec, Burst = 1 second worth
        rateLimiter: rate.NewLimiter(rate.Limit(bytesPerSec), bytesPerSec),
    }
}
```

### Enforcement

```go
func (t *TunnelConnection) CheckRateLimit(bytes int) bool {
    return t.rateLimiter.AllowN(time.Now(), bytes)
}

// In webproxy.go
if !tunnel.CheckRateLimit(len(responseBody)) {
    http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
    return
}
```

---

## 3. Monthly Quota (Optional, Requires SQLite)

**Default:** Disabled (0)
**Config:** `MONTHLY_QUOTA_MB=100` (for 100 MB limit)

Only enabled when:
1. `MONTHLY_QUOTA_MB > 0`
2. SQLite is configured

### Schema

```sql
CREATE TABLE account_usage (
    account_id TEXT NOT NULL,
    tunnel_id TEXT NOT NULL,
    bucket_time TEXT NOT NULL,
    bytes_used INTEGER NOT NULL,
    PRIMARY KEY (account_id, tunnel_id, bucket_time)
);

CREATE INDEX idx_account_usage_month ON account_usage(account_id, bucket_time);
```

### In-Memory Accumulator

Each tunnel tracks bytes, flushes on threshold OR interval:

```go
const (
    flushInterval  = 10 * time.Minute
    flushThreshold = 20 * 1024 * 1024  // 20 MB - flush immediately if exceeded
)

type TunnelConnection struct {
    bytesSinceFlush int64
    lastFlush       time.Time
    accountID       string
    tunnelID        string
}

func (t *TunnelConnection) RecordBytes(n int64, store *UsageStore) {
    newTotal := atomic.AddInt64(&t.bytesSinceFlush, n)

    // Threshold flush: if accumulated > 20 MB, flush immediately
    if newTotal >= flushThreshold && store != nil {
        t.FlushUsage(store)
    }
}

func (t *TunnelConnection) FlushUsage(store *UsageStore) {
    bytes := atomic.SwapInt64(&t.bytesSinceFlush, 0)
    if bytes == 0 {
        return
    }

    bucketTime := time.Now().UTC().Truncate(10 * time.Minute).Format(time.RFC3339)
    store.AddUsage(t.accountID, t.tunnelID, bucketTime, bytes)
    t.lastFlush = time.Now()
}
```

### Flush Triggers

1. **Threshold (20 MB):** Immediate flush when accumulated bytes exceed threshold
2. **Interval (10 min):** Background goroutine flushes all tunnels
3. **Disconnect:** Flush remaining bytes

```go
func (t *TunnelConnection) Close() {
    if usageStore != nil {
        t.FlushUsage(usageStore)
    }
    // ... cleanup
}
```

### Read vs Write Cadence

- **Read (quota refresh):** Every 30 seconds - keeps cached monthly totals fresh
- **Write (flush):** Every 10 minutes OR immediately on 20 MB threshold

This handles both:
- Normal usage: infrequent writes (every 10 min)
- Heavy usage: immediate writes when blasting bandwidth

### Write to SQLite

```sql
INSERT INTO account_usage (account_id, tunnel_id, bucket_time, bytes_used)
VALUES (?, ?, ?, ?)
ON CONFLICT (account_id, tunnel_id, bucket_time)
DO UPDATE SET bytes_used = bytes_used + excluded.bytes_used
```

### Read Monthly Total

Every 10 minutes, refresh cached totals:

```go
func (s *UsageStore) GetMonthlyUsage() map[string]int64 {
    monthStart := time.Now().UTC().Format("2006-01") + "-01T00:00:00Z"

    rows, _ := s.db.Query(`
        SELECT account_id, SUM(bytes_used)
        FROM account_usage
        WHERE bucket_time >= ?
        GROUP BY account_id
    `, monthStart)

    result := make(map[string]int64)
    for rows.Next() {
        var accountID string
        var total int64
        rows.Scan(&accountID, &total)
        result[accountID] = total
    }
    return result
}
```

### Quota Check

```go
type UsageTracker struct {
    mu           sync.RWMutex
    monthlyUsage map[string]int64  // cached from SQLite
    pending      map[string]int64  // unflushed bytes per account
    quotaBytes   int64             // 0 = disabled
    store        *UsageStore       // nil if no SQLite
}

func (t *UsageTracker) HasQuota(accountID string, additionalBytes int64) bool {
    if t.quotaBytes == 0 || t.store == nil {
        return true  // Quota disabled
    }

    t.mu.RLock()
    used := t.monthlyUsage[accountID] + t.pending[accountID]
    t.mu.RUnlock()

    return (used + additionalBytes) < t.quotaBytes
}
```

### Nightly Rollup

Compact previous day's 10-min buckets into daily rollup:

```go
func (s *UsageStore) RollupYesterday() {
    yesterday := time.Now().UTC().AddDate(0, 0, -1)
    dayStart := yesterday.Format("2006-01-02") + "T00:00:00Z"
    dayEnd := time.Now().UTC().Format("2006-01-02") + "T00:00:00Z"

    // Get accounts with usage yesterday
    rows, _ := s.db.Query(`
        SELECT DISTINCT account_id FROM account_usage
        WHERE bucket_time >= ? AND bucket_time < ?
    `, dayStart, dayEnd)

    for rows.Next() {
        var accountID string
        rows.Scan(&accountID)

        // Sum and delete in transaction
        tx, _ := s.db.Begin()

        var total int64
        tx.QueryRow(`
            SELECT COALESCE(SUM(bytes_used), 0) FROM account_usage
            WHERE account_id = ? AND bucket_time >= ? AND bucket_time < ?
        `, accountID, dayStart, dayEnd).Scan(&total)

        tx.Exec(`
            DELETE FROM account_usage
            WHERE account_id = ? AND bucket_time >= ? AND bucket_time < ?
        `, accountID, dayStart, dayEnd)

        tx.Exec(`
            INSERT INTO account_usage (account_id, tunnel_id, bucket_time, bytes_used)
            VALUES (?, 'rollup', ?, ?)
        `, accountID, dayStart, total)

        tx.Commit()
    }
}
```

---

## Configuration

```bash
# All deployments (self-host defaults)
MAX_TUNNELS=10              # Max concurrent tunnels
RATE_LIMIT_MBPS=250         # Bandwidth limit per tunnel
FLUSH_THRESHOLD_MB=20       # Flush to DB when accumulated bytes exceed this
MONTHLY_QUOTA_MB=0          # 0 = disabled (default for self-host)
```

**tunn.to production:**
```bash
# Free tier
MAX_TUNNELS_FREE=3
RATE_LIMIT_MBPS_FREE=100    # 100 Mbps = ~1 GiB max overage
MONTHLY_QUOTA_MB_FREE=100   # 100 MB/month

# Pro tier
MAX_TUNNELS_PRO=10
RATE_LIMIT_MBPS_PRO=250     # 250 Mbps = ~9 GiB max overage
MONTHLY_QUOTA_MB_PRO=51200  # 50 GB/month

# Shared
FLUSH_THRESHOLD_MB=20
QUOTA_REFRESH_SEC=30        # How often to refresh cached quotas
```

**Self-host (generous defaults):**
```bash
MAX_TUNNELS=100
RATE_LIMIT_MBPS=1000        # 1 Gbps
MONTHLY_QUOTA_MB=0          # Disabled - no SQLite needed
```

### What We Advertise

| Limit | Advertise? | Free | Pro |
|-------|------------|------|-----|
| Concurrent tunnels | Yes | 3 | 10 |
| Monthly quota | Vaguely | "Limited" | "50 GB" |
| Bandwidth rate limit | No | - | - |

### Why Different Rate Limits for Free vs Pro?

Not about user experience - about limiting our exposure to abuse:
- Free user maxing out 3 tunnels @ 100 Mbps for 30 sec = 1.1 GiB overage ($0.02)
- Pro user maxing out 10 tunnels @ 250 Mbps for 30 sec = 9.3 GiB overage ($0.19)

Both acceptable. Pro users paid $4/mo so we can absorb more.

---

## Enforcement Points

### 1. Tunnel Connect (grpc_server.go)

```go
func (s *TunnelServer) RegisterClient(stream) {
    // Check concurrent tunnel limit
    if !s.canAddTunnel(accountID) {
        return status.Error(codes.ResourceExhausted, "Too many tunnels")
    }

    // Register (SQLite if available, otherwise in-memory)
    s.registerTunnel(tunnelID, accountID)

    // Create rate limiter
    tunnel.rateLimiter = newRateLimiter(s.config.RateLimitMbps)
}
```

### 2. HTTP Proxy (webproxy.go)

```go
func proxyHTTPOverGRPC(tunnel, req) {
    requestSize := len(requestBody)

    // Check monthly quota (if enabled)
    if !usageTracker.HasQuota(tunnel.AccountID, int64(requestSize)) {
        http.Error(w, "Monthly quota exceeded", http.StatusTooManyRequests)
        return
    }

    // ... proxy request, get response ...

    responseSize := len(responseBody)
    totalSize := requestSize + responseSize

    // Check rate limit
    if !tunnel.CheckRateLimit(totalSize) {
        http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
        return
    }

    // Record usage (for monthly quota)
    tunnel.RecordBytes(int64(totalSize))

    // Write response
    w.Write(responseBody)
}
```

### 3. Tunnel Disconnect

```go
func (t *TunnelConnection) Close() {
    // Flush usage before removing
    if usageStore != nil {
        t.FlushUsage(usageStore)
    }

    // Remove from active tunnels
    tunnelServer.removeTunnel(t.tunnelID, t.accountID)
}
```

---

## Files to Create/Modify

1. `internal/store/db.go` - Add schemas (only if SQLite enabled)
2. `internal/store/usage.go` (new) - `UsageStore` for SQLite operations
3. `internal/host/limits.go` (new) - `LimitConfig`, `UsageTracker`
4. `internal/host/grpc_server.go` - Tunnel count check/tracking
5. `internal/host/tunnel.go` - Add rate limiter, usage accumulator
6. `internal/host/webproxy.go` - Enforce limits
7. `internal/host/proxy.go` - Initialize limits from config

---

## Summary

| Feature | Without SQLite | With SQLite |
|---------|---------------|-------------|
| Rate limit | Works | Works |
| Tunnel count | Per-node | Cross-node |
| Monthly quota | Disabled | Full tracking |

Self-hosters get rate limits and per-node tunnel counts out of the box. Monthly quota is a tunn.to feature requiring SQLite persistence.
