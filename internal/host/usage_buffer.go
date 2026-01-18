package host

import (
	"context"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
)

// UsageBuffer accumulates usage data when the login node is unavailable.
// Non-login nodes buffer usage locally and flush to the login node when it reconnects.
type UsageBuffer struct {
	mu      sync.Mutex
	pending map[string]int64 // accountID -> bytes
}

// NewUsageBuffer creates a new usage buffer.
func NewUsageBuffer() *UsageBuffer {
	return &UsageBuffer{
		pending: make(map[string]int64),
	}
}

// Add accumulates usage for an account.
func (b *UsageBuffer) Add(accountID string, bytes int64) {
	b.mu.Lock()
	b.pending[accountID] += bytes
	b.mu.Unlock()
}

// Flush sends all pending usage to the storage and clears the buffer.
// Returns the number of accounts flushed and any error encountered.
func (b *UsageBuffer) Flush(ctx context.Context, store storage.Storage) (int, error) {
	b.mu.Lock()
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return 0, nil
	}

	// Copy and clear pending
	toFlush := b.pending
	b.pending = make(map[string]int64)
	b.mu.Unlock()

	// Flush each account
	var firstErr error
	flushed := 0
	for accountID, bytes := range toFlush {
		if err := store.RecordUsage(ctx, accountID, bytes); err != nil {
			// Put failed entries back in the buffer
			b.mu.Lock()
			b.pending[accountID] += bytes
			b.mu.Unlock()

			if firstErr == nil {
				firstErr = err
			}
			common.LogError("failed to flush usage", "account_id", accountID, "bytes", bytes, "error", err)
		} else {
			flushed++
			common.LogDebug("flushed usage", "account_id", accountID, "bytes", bytes)
		}
	}

	return flushed, firstErr
}

// Len returns the number of accounts with pending usage.
func (b *UsageBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// QuotaCache caches monthly usage with stale fallback.
// When login node is unavailable, returns stale cached values rather than failing.
type QuotaCache struct {
	mu      sync.RWMutex
	entries map[string]*quotaCacheEntry
	ttl     time.Duration
}

type quotaCacheEntry struct {
	bytes     int64
	fetchedAt time.Time
}

// NewQuotaCache creates a new quota cache with the given TTL.
func NewQuotaCache(ttl time.Duration) *QuotaCache {
	return &QuotaCache{
		entries: make(map[string]*quotaCacheEntry),
		ttl:     ttl,
	}
}

// Get returns cached usage for an account.
// Returns (bytes, true) if found, (0, false) if not cached.
func (c *QuotaCache) Get(accountID string) (int64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[accountID]
	if !ok {
		return 0, false
	}
	return entry.bytes, true
}

// Set stores usage for an account.
func (c *QuotaCache) Set(accountID string, bytes int64) {
	c.mu.Lock()
	c.entries[accountID] = &quotaCacheEntry{
		bytes:     bytes,
		fetchedAt: time.Now(),
	}
	c.mu.Unlock()
}

// IsFresh returns true if the cached value is within TTL.
func (c *QuotaCache) IsFresh(accountID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[accountID]
	if !ok {
		return false
	}
	return time.Since(entry.fetchedAt) < c.ttl
}

// Cleanup removes entries older than maxAge.
func (c *QuotaCache) Cleanup(maxAge time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for id, entry := range c.entries {
		if entry.fetchedAt.Before(cutoff) {
			delete(c.entries, id)
			removed++
		}
	}
	return removed
}
