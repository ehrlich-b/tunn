package store_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
)

func TestAccountsReservationRetryAtCapacity(t *testing.T) {
	accounts := store.NewAccountStore(accountCorrectnessDB(t))
	account, err := accounts.FindOrCreateByEmails([]string{"paid@example.invalid"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpdatePlan(account.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < store.MaxReservedSubdomains; i++ {
		if err := accounts.ReserveSubdomain(account.ID, fmt.Sprintf("service-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := accounts.ReserveSubdomain(account.ID, " SERVICE-0 "); err != nil {
		t.Fatalf("retry for an already-owned name failed at capacity: %v", err)
	}
	if err := accounts.ReserveSubdomain(account.ID, "overflow-service"); err == nil {
		t.Fatal("overflow reservation accepted")
	}
	if err := accounts.ReleaseSubdomain(account.ID, "service-0"); err != nil {
		t.Fatal(err)
	}
	if err := accounts.ReserveSubdomain(account.ID, "replacement"); err != nil {
		t.Fatal(err)
	}
	names, err := accounts.GetReservedSubdomains(account.ID)
	if err != nil || len(names) != store.MaxReservedSubdomains {
		t.Fatalf("names=%v err=%v", names, err)
	}
}

func TestAccountsConcurrentReservationsHonorPlanLimit(t *testing.T) {
	for _, plan := range []string{"free", "pro"} {
		t.Run(plan, func(t *testing.T) {
			accounts := store.NewAccountStore(accountCorrectnessDB(t))
			account, err := accounts.FindOrCreateByEmails([]string{"paid@example.invalid"}, "github")
			if err != nil {
				t.Fatal(err)
			}
			if err := accounts.UpdatePlan(account.ID, plan); err != nil {
				t.Fatal(err)
			}
			limit := store.ReservedSubdomainLimit(plan)
			const attempts = store.MaxReservedSubdomains + 2
			start := make(chan struct{})
			results := make(chan bool, attempts)
			var wg sync.WaitGroup
			for i := 0; i < attempts; i++ {
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					<-start
					results <- accounts.ReserveSubdomain(account.ID, fmt.Sprintf("service-%d", n)) == nil
				}(i)
			}
			close(start)
			wg.Wait()
			close(results)
			winners := 0
			for ok := range results {
				if ok {
					winners++
				}
			}
			names, err := accounts.GetReservedSubdomains(account.ID)
			if err != nil {
				t.Fatal(err)
			}
			if winners != limit || len(names) != limit {
				t.Fatalf("concurrent reservations exceeded allowance: accepted=%d stored=%d want=%d", winners, len(names), limit)
			}
		})
	}
}
