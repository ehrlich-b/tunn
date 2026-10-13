package storage_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

func storageAccountsFixture(t *testing.T) (*storage.LocalStorage, *store.AccountStore) {
	t.Helper()
	db, err := store.OpenLocal(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT OR IGNORE INTO ops_fixture VALUES(1,'disposable-local')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return storage.NewLocalStorage(db), store.NewAccountStore(db)
}

func TestAccountQuotasConcurrentPublisherRegistrations(t *testing.T) {
	for _, plan := range []string{"free", "pro"} {
		t.Run(plan, func(t *testing.T) {
			local, accounts := storageAccountsFixture(t)
			account, err := accounts.FindOrCreateByEmails([]string{"owner@example.invalid"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			if err := accounts.UpdatePlan(account.ID, plan); err != nil {
				t.Fatal(err)
			}
			limit := storage.FreeTunnelLimit
			if plan == "pro" {
				limit = storage.ProTunnelLimit
			}
			const attempts = storage.ProTunnelLimit + 5
			start := make(chan struct{})
			results := make(chan *storage.TunnelRegistration, attempts)
			var wg sync.WaitGroup
			for i := 0; i < attempts; i++ {
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					<-start
					out, err := local.RegisterTunnel(context.Background(), fmt.Sprintf("api-%d", n), account.ID, "fixture-node")
					if err != nil {
						t.Errorf("registration: %v", err)
						return
					}
					results <- out
				}(i)
			}
			close(start)
			wg.Wait()
			close(results)
			allowed := 0
			for out := range results {
				if out.Allowed {
					allowed++
				} else if out.Reason != "tunnel limit reached" {
					t.Errorf("unexpected denial: %v", out)
				}
				if out.MaxAllowed != int32(limit) || out.CurrentCount > int32(limit) {
					t.Errorf("invalid quota snapshot: %v", out)
				}
			}
			if count, err := local.GetTunnelCount(context.Background(), account.ID); err != nil || count != int32(limit) || allowed != limit {
				t.Fatalf("allowed=%d count=%d want=%d error=%v", allowed, count, limit, err)
			}
		})
	}
}

func TestAccountQuotasLiveMergeAndDowngradeKeepRegistrations(t *testing.T) {
	local, accounts := storageAccountsFixture(t)
	ctx := context.Background()
	first, err := accounts.FindOrCreateByEmails([]string{"first@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	second, err := accounts.FindOrCreateByEmails([]string{"second@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []*store.Account{first, second} {
		for i := 0; i < 3; i++ {
			out, err := local.RegisterTunnel(ctx, fmt.Sprintf("api-%s-%d", account.PrimaryEmail[:5], i), account.ID, "fixture-node")
			if err != nil || !out.Allowed {
				t.Fatalf("registration=%v error=%v", out, err)
			}
		}
	}
	merged, err := accounts.FindOrCreateByEmails([]string{first.PrimaryEmail, second.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first.ID, second.ID, merged.ID} {
		if count, err := local.GetTunnelCount(ctx, id); err != nil || count != 6 {
			t.Fatalf("alias count=%d error=%v", count, err)
		}
		if out, err := local.RegisterTunnel(ctx, "free-denied", id, "fixture-node"); err != nil || out.Allowed || out.Reason != "tunnel limit reached" {
			t.Fatalf("merge bypassed quota: %v %v", out, err)
		}
	}
	if err := accounts.UpdatePlan(first.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if out, err := local.RegisterTunnel(ctx, "upgraded", second.ID, "fixture-node"); err != nil || !out.Allowed || out.CurrentCount != 7 || out.MaxAllowed != int32(storage.ProTunnelLimit) {
		t.Fatalf("upgrade=%v error=%v", out, err)
	}
	if err := accounts.UpdatePlan(second.ID, "free"); err != nil {
		t.Fatal(err)
	}
	if out, err := local.RegisterTunnel(ctx, "downgrade-denied", first.ID, "fixture-node"); err != nil || out.Allowed || out.CurrentCount != 7 || out.MaxAllowed != int32(storage.FreeTunnelLimit) {
		t.Fatalf("downgrade=%v error=%v", out, err)
	}
	for _, name := range []string{"upgraded", "api-first-0", "api-secon-0"} {
		if err := local.UnregisterTunnel(ctx, name); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := local.RegisterTunnel(ctx, "replacement", merged.ID, "fixture-node"); err != nil || !out.Allowed || out.CurrentCount != 5 {
		t.Fatalf("released quota=%v error=%v", out, err)
	}
}

func TestAccountQuotaDenialDoesNotClaimPaidName(t *testing.T) {
	local, accounts := storageAccountsFixture(t)
	ctx := context.Background()
	a, err := accounts.FindOrCreateByEmails([]string{"paid@example.invalid"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpdatePlan(a.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < storage.ProTunnelLimit; i++ {
		out, err := local.RegisterTunnel(ctx, fmt.Sprintf("active-%d", i), a.ID, "fixture-node")
		if err != nil || !out.Allowed {
			t.Fatalf("registration=%v error=%v", out, err)
		}
	}
	// Release one durable claim while retaining its active publisher.
	if err := accounts.ReleaseSubdomain(a.ID, "active-0"); err != nil {
		t.Fatal(err)
	}
	if out, err := local.RegisterTunnel(ctx, "denied-service", a.ID, "fixture-node"); err != nil || out.Allowed || out.Reason != "tunnel limit reached" {
		t.Fatalf("quota denial=%v error=%v", out, err)
	}
	if owner, err := accounts.GetSubdomainOwner("denied-service"); err != nil || owner != "" {
		t.Fatalf("denied publisher claimed name: owner=%s error=%v", owner, err)
	}
}
