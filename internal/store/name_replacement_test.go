package store_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
)

func TestSalesNameOwnership(t *testing.T) {
	for _, plan := range []string{"free", "pro"} {
		t.Run(plan, func(t *testing.T) {
			accounts := store.NewAccountStore(accountCorrectnessDB(t))
			a, err := accounts.FindOrCreateByEmails([]string{"owner@example.invalid"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if err = accounts.UpdatePlan(a.ID, plan); err != nil {
				t.Fatal(err)
			}
			limit := store.ReservedSubdomainLimit(plan)
			for i := 0; i < limit; i++ {
				if err = accounts.ReserveSubdomain(a.ID, fmt.Sprintf("preview-%d", i)); err != nil {
					t.Fatal(err)
				}
			}
			if err = accounts.ReserveSubdomain(a.ID, "one-too-many"); err == nil {
				t.Fatal("allowance bypassed")
			}
			names, err := accounts.GetReservedSubdomains(a.ID)
			if err != nil || len(names) != limit {
				t.Fatal(names, err)
			}
			t.Logf("%s allows %d, rejects %d", plan, limit, limit+1)
		})
	}
}

func TestSalesNameReplacement(t *testing.T) {
	for _, plan := range []string{"free", "pro"} {
		t.Run(plan, func(t *testing.T) {
			db := accountCorrectnessDB(t)
			accounts := store.NewAccountStore(db)
			ctx := context.Background()
			a, err := accounts.FindOrCreateByEmails([]string{"owner@example.invalid"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			b, err := accounts.FindOrCreateByEmails([]string{"other@example.invalid"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if err = accounts.UpdatePlan(a.ID, plan); err != nil {
				t.Fatal(err)
			}
			mustReserve := func(id, name string) {
				t.Helper()
				if err := accounts.ReserveSubdomain(id, name); err != nil {
					t.Fatal(err)
				}
			}
			mustReserve(a.ID, "old-preview")
			mustReserve(b.ID, "occupied-preview")
			for i := 1; i < store.ReservedSubdomainLimit(plan); i++ {
				mustReserve(a.ID, fmt.Sprintf("extra-%d", i))
			}
			originalSurvives := func() {
				t.Helper()
				owner, err := accounts.GetSubdomainOwner("old-preview")
				if err != nil || owner != a.ID {
					t.Fatalf("original lost: %s %v", owner, err)
				}
			}
			for _, tc := range []struct{ id, new string }{{b.ID, "stolen-preview"}, {a.ID, "occupied-preview"}, {a.ID, "old-preview"}} {
				if err = accounts.ReplaceSubdomain(ctx, tc.id, "old-preview", tc.new); err == nil {
					t.Fatal("failed swap succeeded", tc)
				}
				originalSurvives()
			}
			if _, err = db.Exec(`CREATE TRIGGER fail_name BEFORE INSERT ON reserved_subdomains WHEN NEW.subdomain='failed-preview' BEGIN SELECT RAISE(ABORT,'injected write failure'); END`); err != nil {
				t.Fatal(err)
			}
			if err = accounts.ReplaceSubdomain(ctx, a.ID, "old-preview", "failed-preview"); err == nil {
				t.Fatal("write failure accepted")
			}
			originalSurvives()
			if err = accounts.ReplaceSubdomain(ctx, a.ID, "old-preview", "new-preview"); err != nil {
				t.Fatal(err)
			}
			if owner, err := accounts.GetSubdomainOwner("new-preview"); err != nil || owner != a.ID {
				t.Fatal(owner, err)
			}
			if owner, err := accounts.GetSubdomainOwner("old-preview"); err != nil || owner != "" {
				t.Fatal(owner, err)
			}
			if err = accounts.ReserveSubdomain(a.ID, "overflow"); err == nil {
				t.Fatal("swap increased allowance")
			}
			if err = accounts.ReleaseSubdomain(b.ID, "occupied-preview"); err != nil {
				t.Fatal(err)
			}
			mustReserve(b.ID, "old-preview")
		})
	}
}

func TestSalesNameReplacementSimultaneousClaims(t *testing.T) {
	db := accountCorrectnessDB(t)
	accounts := store.NewAccountStore(db)
	ctx := context.Background()
	var ids []string
	for i := 0; i < 2; i++ {
		a, err := accounts.FindOrCreateByEmails([]string{fmt.Sprintf("owner-%d@example.invalid", i)}, "test")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, a.ID)
		if err = accounts.ReserveSubdomain(a.ID, fmt.Sprintf("old-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make([]error, 2)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = accounts.ReplaceSubdomain(ctx, ids[i], fmt.Sprintf("old-%d", i), "shared-preview")
		}(i)
	}
	close(start)
	wg.Wait()
	wins := 0
	for i, err := range results {
		if err == nil {
			wins++
		} else {
			owner, e := accounts.GetSubdomainOwner(fmt.Sprintf("old-%d", i))
			if e != nil || owner != ids[i] {
				t.Fatal("loser lost original", owner, e)
			}
		}
	}
	if wins != 1 {
		t.Fatal("expected one claim", results)
	}
}
