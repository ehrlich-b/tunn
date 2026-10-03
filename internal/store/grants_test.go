package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func grantFixture(t *testing.T) (*sql.DB, *GrantStore, *Account) {
	t.Helper()
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	acc, err := NewAccountStore(db).FindOrCreateByEmails([]string{"owner@grant.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	return db, NewGrantStore(db), acc
}

func createTestGrant(t *testing.T, s *GrantStore, accountID, endpointID string, limit int64) (*Grant, string) {
	t.Helper()
	g, token, err := s.Create(context.Background(), GrantCreate{AccountID: accountID, EndpointID: endpointID, Label: "investigator", ExpiresAt: time.Now().Add(time.Hour), RequestLimit: limit})
	if err != nil {
		t.Fatal(err)
	}
	return g, token
}

func checkAdmission(t *testing.T, s *GrantStore, q GrantAdmissionRequest, reason string, status int) *GrantAdmission {
	t.Helper()
	a, err := s.Admit(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if a.Reason != reason || a.Status != status || a.Allowed != (status == 200) {
		t.Fatalf("admission=%+v want %s/%d", a, reason, status)
	}
	return a
}

func TestGrantLifecycleIsolationAndReplay(t *testing.T) {
	db, s, acc := grantFixture(t)
	ctx := context.Background()
	g, token := createTestGrant(t, s, acc.ID, "build", 2)
	other, otherToken := createTestGrant(t, s, acc.ID, "build", 3)
	third, err := NewAccountStore(db).FindOrCreateByEmails([]string{"other@grant.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	// No raw bearer credential appears in persisted columns or metadata JSON.
	var digest string
	if err := db.QueryRow(`SELECT token_digest FROM endpoint_grants WHERE id=?`, g.ID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if digest == token || digest != grantDigest(token) || len(digest) != 64 {
		t.Fatal("credential stored incorrectly")
	}
	meta, err := json.Marshal(g)
	if err != nil || strings.Contains(string(meta), token) || strings.Contains(string(meta), digest) {
		t.Fatal("credential leaked from metadata")
	}
	q := GrantAdmissionRequest{AccountID: acc.ID, EndpointID: "build", Token: token, RequestID: "one"}
	checkAdmission(t, s, q, "grant", 200)
	checkAdmission(t, s, q, "grant", 200) // Ambiguous ACK retry consumes once.
	q.RequestID = "two"
	checkAdmission(t, s, q, "grant", 200)
	q.RequestID = "three"
	checkAdmission(t, s, q, "grant_exhausted", 429)
	q.RequestID = "one"
	checkAdmission(t, s, q, "grant", 200) // Existing reservation survives exhaustion.
	q.Token = otherToken
	checkAdmission(t, s, q, "grant_invalid", 401) // Cannot share another grant's reservation.
	q.RequestID = "other"
	checkAdmission(t, s, q, "grant", 200)
	q.AccountID = third.ID
	checkAdmission(t, s, q, "grant_invalid", 401)
	q.AccountID = acc.ID
	q.EndpointID = "somewhere-else"
	checkAdmission(t, s, q, "grant_invalid", 401)
	q.EndpointID = "build"
	q.Token = GrantTokenPrefix + strings.Repeat("x", 43)
	checkAdmission(t, s, q, "grant_invalid", 401)
	q.Token = "malformed"
	checkAdmission(t, s, q, "grant_invalid", 401)
	listed, err := s.List(ctx, third.ID, "")
	if err != nil || len(listed) != 0 {
		t.Fatalf("owner metadata leaked: %+v %v", listed, err)
	}
	found, err := s.Revoke(ctx, third.ID, g.ID)
	if err != nil || found {
		t.Fatalf("cross-owner revoke: %v %v", found, err)
	}
	for i := 0; i < 2; i++ {
		found, err = s.Revoke(ctx, acc.ID, g.ID)
		if err != nil || !found {
			t.Fatalf("revoke: %v %v", found, err)
		}
	}
	q.Token, q.RequestID = token, "one"
	checkAdmission(t, s, q, "grant_revoked", 403)
	q.Token, q.RequestID = otherToken, "other-two"
	checkAdmission(t, s, q, "grant", 200) // Independent consumer remains usable.
	listed, err = s.List(ctx, acc.ID, "build")
	if err != nil || len(listed) != 2 {
		t.Fatalf("grants: %+v %v", listed, err)
	}
	for _, record := range listed {
		if record.Used != 2 || record.Revoked != (record.ID == g.ID) {
			t.Fatalf("metadata=%+v other=%s", record, other.ID)
		}
	}
	listed, err = s.List(ctx, acc.ID, "absent")
	if err != nil || len(listed) != 0 {
		t.Fatal("endpoint filter failed")
	}
}

func TestGrantExpiryCancellationAndAtomicRollback(t *testing.T) {
	db, s, acc := grantFixture(t)
	g, token := createTestGrant(t, s, acc.ID, "build", 2)
	q := GrantAdmissionRequest{AccountID: acc.ID, EndpointID: "build", Token: token, RequestID: "canceled"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := s.Admit(ctx, q); err == nil || out != nil {
		t.Fatalf("canceled request admitted: %+v %v", out, err)
	}
	// Admission and allowance must roll back together if persistence fails.
	if _, err := db.Exec(`CREATE TRIGGER fail_grant_admission BEFORE INSERT ON grant_admissions BEGIN SELECT RAISE(ABORT,'synthetic'); END`); err != nil {
		t.Fatal(err)
	}
	if out, err := s.Admit(context.Background(), q); err == nil || out != nil {
		t.Fatalf("partial admission=%+v %v", out, err)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_grant_admission`); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(context.Background(), acc.ID, "")
	if err != nil || list[0].Used != 0 {
		t.Fatalf("partial charge=%+v %v", list, err)
	}
	checkAdmission(t, s, q, "grant", 200)
	if _, err := db.Exec(`UPDATE endpoint_grants SET expires_at=? WHERE id=?`, time.Now().Add(-time.Second).UnixMilli(), g.ID); err != nil {
		t.Fatal(err)
	}
	// Expiry dominates retry reservations as well as new requests.
	checkAdmission(t, s, q, "grant_expired", 403)
	q.RequestID = "new"
	checkAdmission(t, s, q, "grant_expired", 403)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := s.Admit(context.Background(), q); err == nil || out != nil {
		t.Fatalf("closed DB admitted=%+v %v", out, err)
	}
}

func TestGrantAtomicAdmissionAcrossConnectionsAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(8)
	acc, err := NewAccountStore(db).FindOrCreateByEmails([]string{"concurrent@grant.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	s := NewGrantStore(db)
	g, token := createTestGrant(t, s, acc.ID, "build", 7)
	var wg sync.WaitGroup
	results := make(chan *GrantAdmission, 40)
	errors := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Multiple stores and SQLite connections share no process mutex.
			out, err := NewGrantStore(db).Admit(context.Background(), GrantAdmissionRequest{AccountID: acc.ID, EndpointID: "build", Token: token, RequestID: fmt.Sprintf("request-%d", i)})
			if err != nil {
				errors <- err
				return
			}
			results <- out
		}(i)
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	allowed, denied := 0, 0
	for out := range results {
		if out.Allowed {
			allowed++
		} else if out.Reason == "grant_exhausted" {
			denied++
		} else {
			t.Fatalf("unexpected denial=%+v", out)
		}
	}
	if allowed != 7 || denied != 33 {
		t.Fatalf("concurrent admissions=%d denied=%d", allowed, denied)
	}
	// A live exhausted grant must retain both its allowance and its successful
	// retry reservation when the authority restarts after an ambiguous reply.
	live, liveToken := createTestGrant(t, s, acc.ID, "build", 1)
	checkAdmission(t, s, GrantAdmissionRequest{AccountID: acc.ID, EndpointID: "build", Token: liveToken, RequestID: "ambiguous-reply"}, "grant", 200)
	if _, err := s.Revoke(context.Background(), acc.ID, g.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s = NewGrantStore(db)
	list, err := s.List(context.Background(), acc.ID, "")
	if err != nil || len(list) != 2 {
		t.Fatalf("restart lost state=%+v %v", list, err)
	}
	for _, record := range list {
		if record.ID == g.ID && (record.Used != 7 || !record.Revoked) {
			t.Fatalf("restart lost revoked grant: %+v", record)
		}
		if record.ID == live.ID && (record.Used != 1 || record.Revoked) {
			t.Fatalf("restart lost exhausted grant: %+v", record)
		}
	}
	checkAdmission(t, s, GrantAdmissionRequest{AccountID: acc.ID, EndpointID: "build", Token: token, RequestID: "restarted"}, "grant_revoked", 403)
	checkAdmission(t, s, GrantAdmissionRequest{AccountID: acc.ID, EndpointID: "build", Token: liveToken, RequestID: "new-after-restart"}, "grant_exhausted", 429)
	checkAdmission(t, s, GrantAdmissionRequest{AccountID: acc.ID, EndpointID: "build", Token: liveToken, RequestID: "ambiguous-reply"}, "grant", 200)
}

func TestGrantMergedOwnershipAndValidation(t *testing.T) {
	db, s, old := grantFixture(t)
	accounts := NewAccountStore(db)
	newOwner, err := accounts.FindOrCreateByEmails([]string{"new@grant.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpdatePlan(newOwner.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	g, token := createTestGrant(t, s, old.ID, "build", 4)
	merged, err := accounts.FindOrCreateByEmails([]string{old.PrimaryEmail, newOwner.PrimaryEmail}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if merged.ID != newOwner.ID {
		t.Fatal("merge fixture chose unexpected owner")
	}
	for _, id := range []string{old.ID, newOwner.ID} {
		out, err := s.List(context.Background(), id, "")
		if err != nil || len(out) != 1 || out[0].AccountID != merged.ID {
			t.Fatalf("merged metadata=%+v %v", out, err)
		}
		checkAdmission(t, s, GrantAdmissionRequest{AccountID: id, EndpointID: "build", Token: token, RequestID: id}, "grant", 200)
	}
	_, _ = createTestGrant(t, s, old.ID, "build", 1) // Cached registration owner remains valid.
	last, err := accounts.FindOrCreateByEmails([]string{"last@grant.test"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpdatePlan(newOwner.ID, "free"); err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpdatePlan(last.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	merged, err = accounts.FindOrCreateByEmails([]string{old.PrimaryEmail, last.PrimaryEmail}, "github")
	if err != nil || merged.ID != last.ID {
		t.Fatalf("nested merge failed: %+v %v", merged, err)
	}
	for _, id := range []string{old.ID, newOwner.ID, last.ID} {
		out, err := s.List(context.Background(), id, "")
		if err != nil || len(out) != 2 || out[0].AccountID != last.ID || out[1].AccountID != last.ID {
			t.Fatalf("nested merge metadata=%+v %v", out, err)
		}
		checkAdmission(t, s, GrantAdmissionRequest{AccountID: id, EndpointID: "build", Token: token, RequestID: "nested-merge-retry"}, "grant", 200)
	}
	found, err := s.Revoke(context.Background(), last.ID, g.ID)
	if err != nil || !found {
		t.Fatalf("merged owner revoke=%v %v", found, err)
	}
	base := GrantCreate{AccountID: merged.ID, EndpointID: "build", Label: "client", ExpiresAt: time.Now().Add(time.Hour), RequestLimit: 1}
	for _, mutate := range []func(*GrantCreate){
		func(q *GrantCreate) { q.AccountID = "" }, func(q *GrantCreate) { q.EndpointID = "" }, func(q *GrantCreate) { q.RequestLimit = 0 }, func(q *GrantCreate) { q.RequestLimit = MaxGrantRequests + 1 }, func(q *GrantCreate) { q.Label = "bad\nlabel" }, func(q *GrantCreate) { q.ExpiresAt = time.Now().Add(-time.Minute) }, func(q *GrantCreate) { q.ExpiresAt = time.Now().Add(MaxGrantLifetime + time.Hour) },
	} {
		q := base
		mutate(&q)
		if _, token, err := s.Create(context.Background(), q); !errors.Is(err, ErrInvalidGrant) || token != "" {
			t.Fatalf("invalid accepted=%+v tokenExists=%v err=%v", q, token != "", err)
		}
	}
	base.AccountID = "nonexistent"
	if _, token, err := s.Create(context.Background(), base); !errors.Is(err, ErrGrantNotOwned) || token != "" {
		t.Fatal("unknown owner acquired grant")
	}
}
