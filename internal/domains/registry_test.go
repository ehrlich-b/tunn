package domains

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var fixtureKey = []byte("01234567890123456789012345678901")

type fakeDNS struct {
	records map[string]string
	err     error
}

func (d *fakeDNS) LookupCNAME(ctx context.Context, name string) (string, error) {
	if d.err != nil {
		return "", d.err
	}
	return d.records[name], nil
}

type issuerFunc func(context.Context, string, PresentChallenge) ([]byte, []byte, error)

func (f issuerFunc) Issue(ctx context.Context, name string, p PresentChallenge) ([]byte, []byte, error) {
	return f(ctx, name, p)
}
func domainFixture(t *testing.T, issuer Issuer) (*Registry, *fakeDNS, *sql.DB) {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO accounts(id,primary_email,plan,created_at) VALUES('one','one@example.com','pro',1),('two','two@example.com','pro',1),('free','free@example.com','free',1)`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"one", "two"} {
		if err := store.NewAccountStore(db).UpdatePlan(id, "pro"); err != nil {
			t.Fatal(err)
		}
	}
	dns := &fakeDNS{records: map[string]string{}}
	r, err := New(db, "relay.test", fixtureKey, dns, issuer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	return r, dns, db
}
func addDomain(t *testing.T, r *Registry, name, tunnel, owner string) *pb.Domain {
	t.Helper()
	d, err := r.Add(context.Background(), &pb.Domain{Name: name, Tunnel: tunnel, Owner: owner})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func fakeCert(t *testing.T, name string, now time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
func TestDomainClaimsEntitlementsAndReservations(t *testing.T) {
	r, _, db := domainFixture(t, nil)
	ctx := context.Background()
	for _, bad := range []string{"relay.test", "a.relay.test", "*.example.com", "https://work.example.com", "a.example.com:443", "127.0.0.1", "bad_name.example.com", "a..example.com", "foo.123", "日本.example.com"} {
		if _, err := r.Add(ctx, &pb.Domain{Name: bad, Tunnel: "site", Owner: "one"}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("accepted %s: %v", bad, err)
		}
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: "work.example.com", Tunnel: "www", Owner: "one"}); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: "work.example.com", Tunnel: "site", Owner: "free"}); status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
	d := addDomain(t, r, "Work.Example.com.", "site", "one")
	again := addDomain(t, r, d.Name, "site", "one")
	if again.CnameTarget != d.CnameTarget {
		t.Fatal("idempotent add changed DNS target")
	}
	if owner, err := store.NewAccountStore(db).GetSubdomainOwner("site"); err != nil || owner != "one" {
		t.Fatalf("reservation=%s %v", owner, err)
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: d.Name, Tunnel: "second", Owner: "two"}); status.Code(err) != codes.AlreadyExists {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: "other.example.com", Tunnel: "site", Owner: "two"}); status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
	if _, err := r.Verify(ctx, &pb.Domain{Name: d.Name, Owner: "two"}); status.Code(err) != codes.NotFound {
		t.Fatal(err)
	}
	if _, err := r.Delete(ctx, &pb.Domain{Name: d.Name, Owner: "two"}); status.Code(err) != codes.NotFound {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		addDomain(t, r, fmt.Sprintf("d%d.example.com", i), "site", "one")
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: "fifth.example.com", Tunnel: "site", Owner: "one"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatal(err)
	}
	list, err := r.List(ctx, &pb.Owner{Owner: "two"})
	if err != nil || len(list.Domains) != 0 {
		t.Fatalf("%v %v", list, err)
	}
	if _, err := r.Route(ctx, d); err == nil {
		t.Fatal("pending claim routed")
	}
}
func TestDomainConcurrentClaimHasOneOwner(t *testing.T) {
	r, _, _ := domainFixture(t, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for _, owner := range []string{"one", "two"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Add(context.Background(), &pb.Domain{Name: "race.example.com", Tunnel: "site", Owner: owner})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				winners++
			} else if status.Code(err) != codes.AlreadyExists {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatal(winners)
	}
}
func TestDomainDNSLeaseDowngradeRemovalAndTakeover(t *testing.T) {
	r, dns, db := domainFixture(t, nil)
	ctx := context.Background()
	d := addDomain(t, r, "work.example.com", "site", "one")
	r.issuer = issuerFunc(func(_ context.Context, name string, _ PresentChallenge) ([]byte, []byte, error) {
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	if _, err := r.Verify(ctx, d); status.Code(err) != codes.FailedPrecondition {
		t.Fatal(err)
	}
	dns.records[d.Name] = d.CnameTarget
	ready, err := r.Verify(ctx, d)
	if err != nil || ready.State != "ready" {
		t.Fatalf("%v %v", ready, err)
	}
	later := r.now().Add(DNSLease + time.Second)
	original := r.now
	r.now = func() time.Time { return later }
	if _, err := r.Route(ctx, d); err == nil {
		t.Fatal("expired DNS lease routed")
	}
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Route(ctx, d); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE accounts SET plan='free' WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Certificate(ctx, d); err == nil {
		t.Fatal("downgraded owner got certificate")
	}
	if _, err := db.Exec(`UPDATE accounts SET plan='pro' WHERE id='one'`); err != nil {
		t.Fatal(err)
	}
	dns.err = fmt.Errorf("DNS unavailable")
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Route(ctx, d); err == nil {
		t.Fatal("DNS outage kept route alive")
	}
	dns.err = nil
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	// Deleting a claim revokes routing and keys immediately, but preserves the
	// independently reserved stable tunnel name.
	if _, err := r.Delete(ctx, d); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Certificate(ctx, d); status.Code(err) != codes.NotFound {
		t.Fatal(err)
	}
	replacement := addDomain(t, r, d.Name, "second", "two")
	if replacement.CnameTarget == d.CnameTarget {
		t.Fatal("new owner reused old DNS proof")
	}
	if _, err := r.Verify(ctx, replacement); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("stale DNS transferred ownership", err)
	}
	r.now = original
}
func TestDomainReplacementCannotPublishInflightCertificate(t *testing.T) {
	r, dns, _ := domainFixture(t, nil)
	ctx := context.Background()
	d := addDomain(t, r, "work.example.com", "site", "one")
	dns.records[d.Name] = d.CnameTarget
	r.issuer = issuerFunc(func(_ context.Context, name string, present PresentChallenge) ([]byte, []byte, error) {
		if _, err := r.Delete(ctx, d); err != nil {
			t.Fatal(err)
		}
		replacement := addDomain(t, r, name, "second", "two")
		if _, err := present(ctx, "stale-token", "stale-proof"); err == nil {
			t.Fatal("stale order presented challenge")
		}
		dns.records[name] = replacement.CnameTarget
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	if _, err := r.Verify(ctx, d); err == nil {
		t.Fatal("inflight issuance resurrected deleted ownership")
	}
	list, err := r.List(ctx, &pb.Owner{Owner: "two"})
	if err != nil || len(list.Domains) != 1 || list.Domains[0].State != "pending" {
		t.Fatalf("%v %v", list, err)
	}
}
func TestDomainCertificateRejectsWrongSAN(t *testing.T) {
	r, dns, _ := domainFixture(t, nil)
	d := addDomain(t, r, "work.example.com", "site", "one")
	dns.records[d.Name] = d.CnameTarget
	r.issuer = issuerFunc(func(_ context.Context, _ string, _ PresentChallenge) ([]byte, []byte, error) {
		cert, key := fakeCert(t, "wrong.example.com", r.now())
		return cert, key, nil
	})
	if _, err := r.Verify(context.Background(), d); err == nil {
		t.Fatal("wrong certificate accepted")
	}
	if _, err := r.Certificate(context.Background(), d); err == nil {
		t.Fatal("wrong certificate served")
	}
}
