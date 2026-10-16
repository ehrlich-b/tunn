package domains

import (
	"context"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"testing"
	"time"
)

// These tests assert safe behavior and deliberately fail when the review finding reproduces.
func TestReviewUnverifiedWildcardCannotSquatNamespace(t *testing.T) {
	r, _, _ := domainFixture(t, nil)
	ctx := context.Background()
	attacker := addDomain(t, r, "*.example.com", "attacker", "two")
	if attacker.State != "pending" {
		t.Fatal(attacker.State)
	}
	// No attacker DNS record, TXT proof, verification, or ACME request is made.
	now := r.now().Add(365 * 24 * time.Hour)
	r.now = func() time.Time { return now }
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: "*.apps.example.com", Tunnel: "dashboard", Owner: "one"}); err != nil {
		t.Fatalf("unverified ancestor still blocks rightful owner after one year: %v", err)
	}
}

func TestReviewReservationLossCancelsInflightCertificate(t *testing.T) {
	r, _, d := wildcardFixture(t)
	ctx := context.Background()
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	r.issuer = issuerFunc(func(ctx context.Context, name string, present PresentChallenge) ([]byte, []byte, error) {
		cleanup, err := present(ctx, "review-token", "review-proof")
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		// Model a legitimate release/reassignment while a slow ACME order runs.
		accounts := store.NewAccountStore(r.db)
		if err := accounts.ReleaseSubdomain("one", "dashboard"); err != nil {
			t.Fatal(err)
		}
		if err := accounts.ReserveSubdomain("two", "dashboard"); err != nil {
			t.Fatal(err)
		}
		if response, err := r.Challenge(ctx, &pb.ChallengeRequest{Name: name, Token: "review-token"}); err == nil {
			t.Logf("HTTP-01 still serves challenge after reservation reassignment: %q", response.Body)
		}
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	pair, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.example.com"})
	if err == nil && len(pair.KeyPem) > 0 {
		_, nextErr := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.example.com"})
		t.Fatalf("authority returned certificate/key to requesting relay after reservation moved; subsequent lookup correctly denies: %v", nextErr)
	}
}

func TestReviewWildcardTXTChangeDuringIssuance(t *testing.T) {
	r, dns, d := wildcardFixture(t)
	ctx := context.Background()
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	r.issuer = issuerFunc(func(_ context.Context, name string, _ PresentChallenge) ([]byte, []byte, error) {
		dns.txt = nil
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	if _, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.example.com"}); err == nil {
		t.Fatal("lost TXT proof still published certificate")
	}
	var count int
	if err := r.db.QueryRow(`SELECT count(*) FROM wildcard_certificates`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stored keys after TXT loss: count=%d err=%v", count, err)
	}
}

func TestReviewConcreteVerifyMustRecordIssuanceAttempt(t *testing.T) {
	r, dns, _ := domainFixture(t, nil)
	ctx := context.Background()
	d := addDomain(t, r, "concrete.example.com", "concrete", "one")
	dns.records[d.Name] = d.CnameTarget
	calls := 0
	r.issuer = issuerFunc(func(_ context.Context, name string, _ PresentChallenge) ([]byte, []byte, error) {
		calls++
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	var attempts int
	err := r.db.QueryRow(`SELECT count(*) FROM domain_issue_attempts`).Scan(&attempts)
	if calls == 1 && (err != nil || attempts == 0) {
		t.Fatalf("concrete Verify reaches issuer without durable attempt accounting (calls=%d, attempts=%d, query_error=%v)", calls, attempts, err)
	}
}
