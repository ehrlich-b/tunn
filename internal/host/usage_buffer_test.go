package host

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
)

func TestUsageBuffer_AddAndLen(t *testing.T) {
	buf := NewUsageBuffer()

	if buf.Len() != 0 {
		t.Errorf("new buffer should have len 0, got %d", buf.Len())
	}

	buf.Add("account1", 100)
	buf.Add("account2", 200)
	buf.Add("account1", 50) // Should accumulate

	if buf.Len() != 2 {
		t.Errorf("expected 2 accounts, got %d", buf.Len())
	}
}

type mockStorage struct {
	usage    map[string]int64
	failNext bool
}

func (m *mockStorage) RecordUsage(ctx context.Context, accountID string, bytes int64) error {
	if m.failNext {
		return errors.New("storage unavailable")
	}
	if m.usage == nil {
		m.usage = make(map[string]int64)
	}
	m.usage[accountID] += bytes
	return nil
}

func (m *mockStorage) GetMonthlyUsage(ctx context.Context, accountID string) (int64, error) {
	return m.usage[accountID], nil
}

// Implement remaining Storage interface methods (not used in tests)
func (m *mockStorage) Available() bool { return true }
func (m *mockStorage) CreateDeviceCode(ctx context.Context) (*storage.DeviceCode, error) {
	return nil, nil
}
func (m *mockStorage) GetDeviceCode(ctx context.Context, code string) (*storage.DeviceCode, error) {
	return nil, nil
}
func (m *mockStorage) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*storage.DeviceCode, error) {
	return nil, nil
}
func (m *mockStorage) AuthorizeDeviceCode(ctx context.Context, code, email string) (bool, error) {
	return false, nil
}
func (m *mockStorage) GetAccount(ctx context.Context, accountID string) (*storage.Account, error) {
	return nil, nil
}
func (m *mockStorage) GetAccountByEmail(ctx context.Context, email string) (*storage.Account, error) {
	return nil, nil
}
func (m *mockStorage) FindOrCreateByEmails(ctx context.Context, emails []string, verifiedVia string) (*storage.Account, error) {
	return nil, nil
}
func (m *mockStorage) GetEmailBucket(ctx context.Context, email string) ([]string, error) {
	return nil, nil
}
func (m *mockStorage) UpdatePlan(ctx context.Context, accountID, plan string) error { return nil }
func (m *mockStorage) RegisterTunnel(ctx context.Context, tunnelID, accountID, nodeAddress string) (*storage.TunnelRegistration, error) {
	return nil, nil
}
func (m *mockStorage) UnregisterTunnel(ctx context.Context, tunnelID string) error { return nil }
func (m *mockStorage) GetTunnelCount(ctx context.Context, accountID string) (int32, error) {
	return 0, nil
}

func TestUsageBuffer_Flush(t *testing.T) {
	buf := NewUsageBuffer()
	store := &mockStorage{}

	buf.Add("account1", 100)
	buf.Add("account2", 200)
	buf.Add("account1", 50)

	flushed, err := buf.Flush(context.Background(), store)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if flushed != 2 {
		t.Errorf("expected 2 accounts flushed, got %d", flushed)
	}
	if buf.Len() != 0 {
		t.Errorf("buffer should be empty after flush, got %d", buf.Len())
	}

	if store.usage["account1"] != 150 {
		t.Errorf("expected account1 usage 150, got %d", store.usage["account1"])
	}
	if store.usage["account2"] != 200 {
		t.Errorf("expected account2 usage 200, got %d", store.usage["account2"])
	}
}

func TestUsageBuffer_FlushWithFailure(t *testing.T) {
	buf := NewUsageBuffer()
	store := &mockStorage{failNext: true}

	buf.Add("account1", 100)

	flushed, err := buf.Flush(context.Background(), store)
	if err == nil {
		t.Error("expected error on failed flush")
	}
	if flushed != 0 {
		t.Errorf("expected 0 accounts flushed, got %d", flushed)
	}
	if buf.Len() != 1 {
		t.Errorf("failed items should be put back in buffer, got len %d", buf.Len())
	}
}

func TestQuotaCache_GetSet(t *testing.T) {
	cache := NewQuotaCache(1 * time.Second)

	_, ok := cache.Get("account1")
	if ok {
		t.Error("expected miss for non-existent account")
	}

	cache.Set("account1", 12345)
	bytes, ok := cache.Get("account1")
	if !ok {
		t.Error("expected hit after set")
	}
	if bytes != 12345 {
		t.Errorf("expected 12345, got %d", bytes)
	}
}

func TestQuotaCache_IsFresh(t *testing.T) {
	cache := NewQuotaCache(100 * time.Millisecond)

	if cache.IsFresh("account1") {
		t.Error("non-existent account should not be fresh")
	}

	cache.Set("account1", 100)
	if !cache.IsFresh("account1") {
		t.Error("newly set account should be fresh")
	}

	time.Sleep(150 * time.Millisecond)
	if cache.IsFresh("account1") {
		t.Error("expired account should not be fresh")
	}
}

func TestQuotaCache_Cleanup(t *testing.T) {
	cache := NewQuotaCache(50 * time.Millisecond)

	cache.Set("account1", 100)
	cache.Set("account2", 200)

	time.Sleep(100 * time.Millisecond)

	cache.Set("account3", 300) // Fresh entry

	removed := cache.Cleanup(50 * time.Millisecond)
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}

	_, ok := cache.Get("account1")
	if ok {
		t.Error("account1 should have been cleaned up")
	}

	_, ok = cache.Get("account3")
	if !ok {
		t.Error("account3 should still exist")
	}
}
