package domains

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestR3PendingClaimProofReclaim(t *testing.T) {
	for _, tc := range []struct{ incumbent, contender string }{
		{"*.example.com", "*.apps.example.com"},
		{"*.apps.example.com", "dashboard.apps.example.com"},
		{"work.example.com", "work.example.com"},
	} {
		t.Run(tc.incumbent+"/"+tc.contender, func(t *testing.T) {
			r, dns, _ := domainFixture(t, nil)
			ctx := context.Background()
			attacker := addDomain(t, r, tc.incumbent, "attacker", "two")
			request := &pb.Domain{Name: tc.contender, Tunnel: "dashboard", Owner: "one"}
			_, err := r.Add(ctx, request)
			if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "prove ownership") {
				t.Fatalf("no competing proof request: %v", err)
			}
			var target string
			if err := r.db.QueryRow(`SELECT target FROM domain_reclaim_requests WHERE name=? AND owner='one'`, tc.contender).Scan(&target); err != nil {
				t.Fatal(err)
			}
			if target == attacker.CnameTarget {
				t.Fatal("reclaim reused attacker's proof")
			}
			if _, err := r.Add(ctx, request); status.Code(err) != codes.AlreadyExists {
				t.Fatalf("unproved request replaced incumbent: %v", err)
			}
			dns.records[tc.contender] = target
			reclaimed, err := r.Add(ctx, request)
			if err != nil || reclaimed.Owner != "one" || reclaimed.CnameTarget != target {
				t.Fatalf("proof did not reclaim: %v %v", reclaimed, err)
			}
			if _, err := r.Verify(ctx, attacker); status.Code(err) != codes.NotFound {
				t.Fatalf("stale claim survived: %v", err)
			}
			if _, err := r.Add(ctx, &pb.Domain{Name: tc.incumbent, Tunnel: "other", Owner: "two"}); status.Code(err) != codes.AlreadyExists {
				t.Fatalf("verified ownership not protected: %v", err)
			}
		})
	}
}

func TestR3PendingClaimExpiryAndFreshProof(t *testing.T) {
	r, dns, _ := domainFixture(t, nil)
	ctx := context.Background()
	attacker := addDomain(t, r, "work.example.com", "attacker", "two")
	if _, err := r.Verify(ctx, attacker); status.Code(err) != codes.FailedPrecondition {
		t.Fatal(err)
	}
	request := &pb.Domain{Name: attacker.Name, Tunnel: "dashboard", Owner: "one"}
	if _, err := r.Add(ctx, request); status.Code(err) != codes.AlreadyExists {
		t.Fatal(err)
	}
	var oldTarget string
	if err := r.db.QueryRow(`SELECT target FROM domain_reclaim_requests`).Scan(&oldTarget); err != nil {
		t.Fatal(err)
	}
	now := r.now().Add(25 * time.Hour)
	r.now = func() time.Time { return now }
	reopened, err := New(r.db, r.base, fixtureKey, dns, nil)
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = r.now
	replacement := addDomain(t, reopened, request.Name, request.Tunnel, request.Owner)
	if replacement.CnameTarget == oldTarget || replacement.CnameTarget == attacker.CnameTarget {
		t.Fatal("expired proof reused")
	}
	dns.records[replacement.Name] = oldTarget
	if _, err := reopened.Verify(ctx, replacement); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale reclaim proof admitted: %v", err)
	}
}

func TestR3VerifiedClaimSurvivesLeaseLoss(t *testing.T) {
	r, dns, d := wildcardFixture(t)
	ctx := context.Background()
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	dns.txt = nil
	now := r.now().Add(25 * time.Hour)
	r.now = func() time.Time { return now }
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: "*.example.com", Tunnel: "second", Owner: "two"}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("lost lease surrendered verified owner: %v", err)
	}
}

func TestR3ConcreteCertificateReuseAndRenewalAccounting(t *testing.T) {
	r, dns, _ := domainFixture(t, nil)
	ctx := context.Background()
	d := addDomain(t, r, "work.example.com", "site", "one")
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
	original, err := r.Certificate(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := r.Verify(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	cached, err := r.Certificate(ctx, d)
	if err != nil || !bytes.Equal(original.CertificatePem, cached.CertificatePem) || !bytes.Equal(original.KeyPem, cached.KeyPem) {
		t.Fatalf("valid cert not reused: %v", err)
	}
	if calls != 1 {
		t.Fatalf("fresh verify issued %d times", calls)
	}
	var attempts int
	if err := r.db.QueryRow(`SELECT count(*) FROM domain_issue_attempts`).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("initial accounting=%d %v", attempts, err)
	}
	now := r.now().Add(61 * 24 * time.Hour)
	r.now = func() time.Time { return now }
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("renewal calls=%d", calls)
	}
	if err := r.db.QueryRow(`SELECT count(*) FROM domain_issue_attempts WHERE name=? AND at=?`, d.Name, now.Unix()).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("renewal not recorded: %d %v", attempts, err)
	}
}

func TestR3ConcreteFailureBackoffSurvivesRestart(t *testing.T) {
	r, dns, _ := domainFixture(t, nil)
	ctx := context.Background()
	d := addDomain(t, r, "work.example.com", "site", "one")
	dns.records[d.Name] = d.CnameTarget
	calls := 0
	issuer := issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
		calls++
		return nil, nil, fmt.Errorf("local issuer failure")
	})
	r.issuer = issuer
	if _, err := r.Verify(ctx, d); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
	restarted, err := New(r.db, r.base, fixtureKey, dns, issuer)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = r.now
	if _, err := restarted.Verify(ctx, d); status.Code(err) != codes.ResourceExhausted || calls != 1 {
		t.Fatalf("failed attempt backoff=%v calls=%d", err, calls)
	}
	var attempts int
	if err := r.db.QueryRow(`SELECT count(*) FROM domain_issue_attempts`).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("failed attempt accounting=%d %v", attempts, err)
	}
	now := r.now().Add(time.Minute)
	restarted.now = func() time.Time { return now }
	if _, err := restarted.Verify(ctx, d); status.Code(err) != codes.Unavailable || calls != 2 {
		t.Fatalf("retry after delay=%v calls=%d", err, calls)
	}
}

func TestR3ConcreteSpentBudget(t *testing.T) {
	for _, tc := range []struct {
		owner string
		count int
	}{{"one", 10}, {"two", 100}} {
		t.Run(tc.owner, func(t *testing.T) {
			r, dns, _ := domainFixture(t, nil)
			ctx := context.Background()
			d := addDomain(t, r, "work.example.com", "site", "one")
			dns.records[d.Name] = d.CnameTarget
			for i := 0; i < tc.count; i++ {
				if _, err := r.db.Exec(`INSERT INTO domain_issue_attempts VALUES(?,?,?)`, tc.owner, "other.example.com", r.now().Unix()); err != nil {
					t.Fatal(err)
				}
			}
			r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
				t.Fatal("spent budget reached issuer")
				return nil, nil, nil
			})
			for i := 0; i < 2; i++ {
				if _, err := r.Verify(ctx, d); status.Code(err) != codes.ResourceExhausted {
					t.Fatalf("budget error=%v", err)
				}
			}
		})
	}
}

func TestR3ConcreteFailureConsumesWildcardBudget(t *testing.T) {
	r, dns, parent := wildcardFixture(t)
	ctx := context.Background()
	if _, err := r.Verify(ctx, parent); err != nil {
		t.Fatal(err)
	}
	concrete := addDomain(t, r, "work.example.com", "dashboard", "one")
	dns.records[concrete.Name] = concrete.CnameTarget
	for i := 0; i < 9; i++ {
		if _, err := r.db.Exec(`INSERT INTO domain_issue_attempts VALUES('one','other.example.com',?)`, r.now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
		calls++
		return nil, nil, fmt.Errorf("local failure")
	})
	if _, err := r.Verify(ctx, concrete); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
	if _, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.example.com"}); status.Code(err) != codes.ResourceExhausted || calls != 1 {
		t.Fatalf("separate wildcard budget: %v calls=%d", err, calls)
	}
}

func TestR3WildcardReservationRevokesOrder(t *testing.T) {
	for _, reassign := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("reassign=%v/failure=%v", reassign, fail), func(t *testing.T) {
				r, _, parent := wildcardFixture(t)
				ctx := context.Background()
				if _, err := r.Verify(ctx, parent); err != nil {
					t.Fatal(err)
				}
				in := &pb.Domain{Name: "dashboard.apps.example.com"}
				if fail {
					r.issuer = issuerFunc(func(_ context.Context, name string, _ PresentChallenge) ([]byte, []byte, error) {
						cert, key := fakeCert(t, name, r.now())
						return cert, key, nil
					})
					if _, err := r.Certificate(ctx, in); err != nil {
						t.Fatal(err)
					}
					now := r.now().Add(61 * 24 * time.Hour)
					r.now = func() time.Time { return now }
					if _, err := r.Verify(ctx, parent); err != nil {
						t.Fatal(err)
					}
				}
				r.issuer = issuerFunc(func(ctx context.Context, name string, present PresentChallenge) ([]byte, []byte, error) {
					cleanup, err := present(ctx, "token", "proof")
					if err != nil {
						t.Fatal(err)
					}
					defer cleanup()
					if _, err := r.Challenge(ctx, &pb.ChallengeRequest{Name: name, Token: "token"}); err != nil {
						t.Fatalf("authorized challenge denied: %v", err)
					}
					accounts := store.NewAccountStore(r.db)
					if err := accounts.ReleaseSubdomain("one", "dashboard"); err != nil {
						t.Fatal(err)
					}
					if reassign {
						if err := accounts.ReserveSubdomain("two", "dashboard"); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := r.Challenge(ctx, &pb.ChallengeRequest{Name: name, Token: "token"}); status.Code(err) != codes.NotFound {
						t.Fatalf("revoked challenge still served: %v", err)
					}
					if _, err := present(ctx, "late-token", "late-proof"); err == nil {
						t.Fatal("revoked order published challenge")
					}
					if fail {
						return nil, nil, fmt.Errorf("failed renewal")
					}
					cert, key := fakeCert(t, name, r.now())
					return cert, key, nil
				})
				if pair, err := r.Certificate(ctx, in); err == nil || pair != nil {
					t.Fatalf("revoked order returned key: %v %v", pair, err)
				}
				if !fail {
					var count int
					if err := r.db.QueryRow(`SELECT count(*) FROM wildcard_certificates`).Scan(&count); err != nil || count != 0 {
						t.Fatalf("revoked order stored key: %d %v", count, err)
					}
				}
			})
		}
	}
}

func TestR3PendingProofRequestCapacity(t *testing.T) {
	r, _, _ := domainFixture(t, nil)
	ctx := context.Background()
	addDomain(t, r, "*.example.com", "attacker", "two")
	for _, name := range []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"} {
		_, err := r.Add(ctx, &pb.Domain{Name: name, Tunnel: "site", Owner: "one"})
		if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "prove ownership") {
			t.Fatal(err)
		}
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: "unrelated.other.com", Tunnel: "site", Owner: "one"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("proof requests not counted against normal claims: %v", err)
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: "fifth.example.com", Tunnel: "site", Owner: "one"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("proof request bound ignored: %v", err)
	}
}

func TestR3LegacyClaimExpiryMigration(t *testing.T) {
	r, dns, _ := domainFixture(t, nil)
	ctx := context.Background()
	if _, err := r.db.Exec(`DROP TABLE custom_domains;
 CREATE TABLE custom_domains(name TEXT PRIMARY KEY,owner TEXT NOT NULL,tunnel TEXT NOT NULL,target TEXT UNIQUE NOT NULL,state TEXT NOT NULL DEFAULT 'pending',verified_until INTEGER NOT NULL DEFAULT 0,certificate BLOB NOT NULL DEFAULT '',key BLOB NOT NULL DEFAULT '',not_after INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '');
 INSERT INTO custom_domains(name,owner,tunnel,target,state) VALUES('*.pending.example.com','two','','pending.relay.test','pending'),('*.ready.example.com','two','','ready.relay.test','ready'),('*.failed.example.com','two','','failed.relay.test','dns_verification_failed');`); err != nil {
		t.Fatal(err)
	}
	migrated, err := New(r.db, r.base, fixtureKey, dns, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := migrated.now().Add(25 * time.Hour)
	migrated.now = func() time.Time { return now }
	if err := migrated.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"*.pending.example.com", "*.failed.example.com"} {
		if _, err := migrated.read(ctx, name); err == nil {
			t.Fatalf("legacy unverified claim retained: %s", name)
		}
	}
	if _, err := migrated.Add(ctx, &pb.Domain{Name: "app.ready.example.com", Tunnel: "site", Owner: "one"}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("legacy verified owner lost protection: %v", err)
	}
}
