package domains

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type wildcardDNS struct {
	*fakeDNS
	txt []string
}

func (d *wildcardDNS) LookupTXT(context.Context, string) ([]string, error) { return d.txt, d.err }
func wildcardFixture(t *testing.T) (*Registry, *wildcardDNS, *pb.Domain) {
	r, dns, db := domainFixture(t, nil)
	if err := store.NewAccountStore(db).ReserveSubdomain("one", "dashboard"); err != nil {
		t.Fatal(err)
	}
	wd := &wildcardDNS{fakeDNS: dns}
	r.dns = wd
	d := addDomain(t, r, "*.apps.ehrlich.dev", "dashboard", "one")
	wd.txt = []string{d.CnameTarget}
	return r, wd, d
}
func TestWildcardOwnershipRoutingAndAbuseGuards(t *testing.T) {
	r, dns, d := wildcardFixture(t)
	ctx := context.Background()
	var calls atomic.Int32
	r.issuer = issuerFunc(func(ctx context.Context, name string, p PresentChallenge) ([]byte, []byte, error) {
		calls.Add(1)
		cleanup, err := p(ctx, "token", "proof")
		if err != nil {
			return nil, nil, err
		}
		defer cleanup()
		if response, err := r.Challenge(ctx, &pb.ChallengeRequest{Name: name, Token: "token"}); err != nil || response.Body != "proof" {
			t.Fatalf("challenge=%v %v", response, err)
		}
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	dns.txt = nil
	dns.records[d.Name] = "relay.test"
	if _, err := r.Verify(ctx, d); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("generic CNAME accepted: %v", err)
	}
	if _, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"}); err == nil {
		t.Fatal("unverified domain issued")
	}
	dns.txt = []string{d.CnameTarget}
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("wildcard verification ordered a wildcard certificate")
	}
	for _, name := range []string{"evil.test", "apps.ehrlich.dev", "a.b.apps.ehrlich.dev", "random.apps.ehrlich.dev", "www.apps.ehrlich.dev", "*.apps.ehrlich.dev"} {
		if _, err := r.Certificate(ctx, &pb.Domain{Name: name}); err == nil {
			t.Fatalf("accepted arbitrary SNI %s", name)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("abusive SNI created an order")
	}
	for _, name := range []string{"dashboard.apps.ehrlich.dev", "*.nested.apps.ehrlich.dev", "*.ehrlich.dev"} {
		if _, err := r.Add(ctx, &pb.Domain{Name: name, Tunnel: "second", Owner: "two"}); status.Code(err) != codes.AlreadyExists {
			t.Fatalf("overlap %s: %v", name, err)
		}
	}
	route, err := r.Route(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"})
	if err != nil || route.Tunnel != "dashboard" || route.Owner != "one" {
		t.Fatalf("route=%v %v", route, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent orders=%d", calls.Load())
	}
	pair, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"})
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := r.db.QueryRow(`SELECT key FROM wildcard_certificates`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("PRIVATE KEY")) || bytes.Equal(sealed, pair.KeyPem) {
		t.Fatal("stored plaintext key")
	}
	reopened, err := New(r.db, r.base, fixtureKey, dns, nil)
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = r.now
	if cached, err := reopened.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"}); err != nil || !bytes.Equal(cached.CertificatePem, pair.CertificatePem) {
		t.Fatalf("restart lost cert: %v", err)
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: d.Name, Tunnel: "reports", Owner: "one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: d.Name, Tunnel: "dashboard", Owner: "two"}); err == nil {
		t.Fatal("other owner acquired app")
	}
	dns.txt = nil
	dns.err = fmt.Errorf("DNS down")
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"}); err == nil {
		t.Fatal("DNS failure retained certificate admission")
	}
}
func TestWildcardFailuresRateLimitRenewalAndDeletion(t *testing.T) {
	r, _, d := wildcardFixture(t)
	ctx := context.Background()
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	var calls int
	r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
		calls++
		return nil, nil, fmt.Errorf("issuance fails")
	})
	in := &pb.Domain{Name: "dashboard.apps.ehrlich.dev"}
	if _, err := r.Certificate(ctx, in); status.Code(err) != codes.Unavailable {
		t.Fatal(err)
	}
	if _, err := r.Certificate(ctx, in); status.Code(err) != codes.ResourceExhausted || calls != 1 {
		t.Fatalf("no backoff: %v %d", err, calls)
	}
	now := r.now().Add(2 * time.Minute)
	r.now = func() time.Time { return now }
	r.issuer = issuerFunc(func(_ context.Context, name string, _ PresentChallenge) ([]byte, []byte, error) {
		calls++
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	if _, err := r.Certificate(ctx, in); err != nil {
		t.Fatal(err)
	}
	now = now.Add(61 * 24 * time.Hour)
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("renewal orders=%d", calls)
	}
	if _, err := r.Delete(ctx, d); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Certificate(ctx, in); err == nil {
		t.Fatal("deleted wildcard admitted certificate")
	}
	replacement := addDomain(t, r, d.Name, "second", "two")
	if _, err := r.Verify(ctx, replacement); err == nil {
		t.Fatal("old proof transferred ownership")
	}
}

func TestWildcardPersistentOwnerAndGlobalIssuanceLimits(t *testing.T) {
	for _, tc := range []struct {
		owner string
		count int
	}{{"one", 10}, {"another-owner", 100}} {
		t.Run(tc.owner, func(t *testing.T) {
			r, _, d := wildcardFixture(t)
			ctx := context.Background()
			if _, err := r.Verify(ctx, d); err != nil {
				t.Fatal(err)
			}
			r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
				t.Fatal("rate-limited request reached ACME")
				return nil, nil, nil
			})
			for i := 0; i < tc.count; i++ {
				if _, err := r.db.Exec(`INSERT INTO domain_issue_attempts(owner,name,at) VALUES(?,?,?)`, tc.owner, fmt.Sprintf("past-%d", i), r.now().Add(-2*time.Minute).Unix()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"}); status.Code(err) != codes.ResourceExhausted {
				t.Fatalf("limit ignored: %v", err)
			}
		})
	}
}
func TestWildcardInflightDeletionCannotResurrectCertificate(t *testing.T) {
	r, _, d := wildcardFixture(t)
	ctx := context.Background()
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	r.issuer = issuerFunc(func(ctx context.Context, name string, p PresentChallenge) ([]byte, []byte, error) {
		if _, err := r.Delete(ctx, d); err != nil {
			t.Fatal(err)
		}
		if _, err := p(ctx, "token", "proof"); err == nil {
			t.Fatal("deleted claim presented challenge")
		}
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	if _, err := r.Certificate(ctx, &pb.Domain{Name: "dashboard.apps.ehrlich.dev"}); err == nil {
		t.Fatal("deleted claim published certificate")
	}
	var count int
	r.db.QueryRow(`SELECT count(*) FROM wildcard_certificates`).Scan(&count)
	if count != 0 {
		t.Fatal("deleted claim retained key")
	}
}

func TestWildcardRenewalBackoffKeepsValidCertificate(t *testing.T) {
	r, dns, d := wildcardFixture(t)
	ctx := context.Background()
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	r.issuer = issuerFunc(func(_ context.Context, name string, _ PresentChallenge) ([]byte, []byte, error) {
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	in := &pb.Domain{Name: "dashboard.apps.ehrlich.dev"}
	original, err := r.Certificate(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	now := r.now().Add(61 * 24 * time.Hour)
	r.now = func() time.Time { return now }
	r.issuer = issuerFunc(func(context.Context, string, PresentChallenge) ([]byte, []byte, error) {
		return nil, nil, fmt.Errorf("CA unavailable")
	})
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		cached, err := r.Certificate(ctx, in)
		if err != nil || !bytes.Equal(cached.CertificatePem, original.CertificatePem) {
			t.Fatalf("backoff discarded valid certificate: %v", err)
		}
	}
	dns.txt = nil
	dns.err = fmt.Errorf("DNS down")
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Certificate(ctx, in); err == nil {
		t.Fatal("fallback bypassed DNS proof")
	}
}
