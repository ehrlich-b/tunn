package store

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestAccountEmailConcurrentLinkCannotMergeOrSteal(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := NewAccountStore(db)
	first, err := s.FindOrCreateByEmails([]string{"first@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.FindOrCreateByEmails([]string{"second@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{first.ID, second.ID} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			_, err := s.MutateAccountEmail(context.Background(), id, "shared@example.com", "link")
			results <- err
		}(id)
	}
	close(start)
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrEmailOwned) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal(successes, conflicts)
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM accounts").Scan(&count); err != nil || count != 2 {
		t.Fatal("accounts merged", count, err)
	}
	for _, id := range []string{first.ID, second.ID} {
		a, err := s.GetByID(id)
		if err != nil || a.ID != id {
			t.Fatal(a, err)
		}
	}
}

func TestAccountEmailPrimaryRemoveRaceKeepsVerifiedPrimary(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := NewAccountStore(db)
	a, err := s.FindOrCreateByEmails([]string{"primary@example.com", "alias@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, action := range []string{"primary", "remove"} {
		wg.Add(1)
		go func(action string) {
			defer wg.Done()
			<-start
			_, err := s.MutateAccountEmail(context.Background(), a.ID, "alias@example.com", action)
			results <- err
		}(action)
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrPrimaryEmail) && !errors.Is(err, ErrEmailNotLinked) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatal("expected one serialized action to win", successes)
	}
	current, err := s.GetByID(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range current.Emails {
		if e.Email == current.PrimaryEmail {
			return
		}
	}
	t.Fatal("primary no longer belongs to account", current)
}
