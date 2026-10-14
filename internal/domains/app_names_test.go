package domains

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNamespaceCapacityIndependentOfSharedReservations(t *testing.T) {
	r, dns, db := domainFixture(t, nil)
	ctx := context.Background()
	accounts := store.NewAccountStore(db)
	for i := 0; i < 4; i++ {
		if err := accounts.ReserveSubdomain("one", fmt.Sprintf("existing-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	d := addDomain(t, r, "*.apps.customer.test", "", "one")
	dns.records[d.Name] = d.CnameTarget
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	local := storage.NewLocalStorageWithClock(db, r.now)
	for i := 0; i < 50; i++ {
		label := fmt.Sprintf("app-%d", i)
		out := addDomain(t, r, d.Name, label, "one")
		if out.AppNameLimit != 50 || len(out.AppNames) != i+1 {
			t.Fatalf("name metadata: limit=%d count=%d", out.AppNameLimit, len(out.AppNames))
		}
		route, err := r.Route(ctx, &pb.Domain{Name: label + ".apps.customer.test"})
		if err != nil {
			t.Fatal(err)
		}
		// First 10 publishers fit the unchanged concurrent Pro tunnel cap and must
		// neither auto-reserve their internal IDs nor require a shared slot.
		if i < 10 {
			reg, err := local.RegisterTunnel(ctx, route.Tunnel, "one", "node")
			if err != nil || !reg.Allowed {
				t.Fatalf("publisher %d: %+v %v", i, reg, err)
			}
		}
	}
	if out, err := r.Add(ctx, &pb.Domain{Name: d.Name, Tunnel: "app-51", Owner: "one"}); out != nil || status.Code(err) != codes.ResourceExhausted || !containsMessage(err, "Pro: 50 names") {
		t.Fatalf("51st name: %+v %v", out, err)
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: d.Name, Tunnel: "app-0", Owner: "one"}); err != nil {
		t.Fatalf("idempotent at capacity: %v", err)
	}
	names, err := accounts.GetReservedSubdomains("one")
	if err != nil || len(names) != 4 {
		t.Fatalf("shared reservations changed: %d %v", len(names), err)
	}
	if err := accounts.ReserveSubdomain("one", "fifth-shared"); err == nil {
		t.Fatal("shared reservation cap weakened")
	}
}
func containsMessage(err error, s string) bool { return err != nil && strings.Contains(err.Error(), s) }

func TestNamespaceLabelsAndPublisherAdmissionAreOwnerScoped(t *testing.T) {
	r, dns, db := domainFixture(t, nil)
	ctx := context.Background()
	// The customer's app label is already owned globally by someone else.
	if err := store.NewAccountStore(db).ReserveSubdomain("two", "grafana"); err != nil {
		t.Fatal(err)
	}
	one := addDomain(t, r, "*.apps.one.test", "grafana", "one")
	two := addDomain(t, r, "*.apps.two.test", "grafana", "two")
	for _, d := range []*pb.Domain{one, two} {
		dns.records[d.Name] = d.CnameTarget
		if _, err := r.Verify(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	routeOne, err := r.Route(ctx, &pb.Domain{Name: "grafana.apps.one.test"})
	if err != nil {
		t.Fatal(err)
	}
	routeTwo, err := r.Route(ctx, &pb.Domain{Name: "grafana.apps.two.test"})
	if err != nil {
		t.Fatal(err)
	}
	if routeOne.Tunnel == routeTwo.Tunnel {
		t.Fatal("different namespaces shared a publisher ID")
	}
	if _, err := r.Add(ctx, &pb.Domain{Name: one.Name, Tunnel: "grafana", Owner: "two"}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("cross-account squatting: %v", err)
	}
	if err := store.NewAccountStore(db).ReserveSubdomain("two", routeOne.Tunnel); err == nil {
		t.Fatal("another account squatted on the namespace publisher ID")
	}
	local := storage.NewLocalStorageWithClock(db, r.now)
	if reg, err := local.RegisterTunnel(ctx, routeOne.Tunnel, "two", "node"); err != nil || reg.Allowed {
		t.Fatalf("other account admitted: %+v %v", reg, err)
	}
	for _, route := range []*pb.Domain{routeOne, routeTwo} {
		if reg, err := local.RegisterTunnel(ctx, route.Tunnel, route.Owner, "node"); err != nil || !reg.Allowed {
			t.Fatalf("owner denied: %+v %v", reg, err)
		}
	}
	if names, err := store.NewAccountStore(db).GetReservedSubdomains("one"); err != nil || len(names) != 0 {
		t.Fatalf("scoped publication auto-reserved shared slots: %d %v", len(names), err)
	}
	if _, err := db.Exec(`UPDATE custom_domains SET verified_until=0 WHERE name=?`, one.Name); err != nil {
		t.Fatal(err)
	}
	local.UnregisterTunnel(ctx, routeOne.Tunnel)
	if reg, err := local.RegisterTunnel(ctx, routeOne.Tunnel, "one", "node"); err != nil || reg.Allowed {
		t.Fatalf("expired namespace publisher admitted: %+v %v", reg, err)
	}
}

func TestNamespaceConcurrentLimitAndClaimDeletion(t *testing.T) {
	r, _, db := domainFixture(t, nil)
	d := addDomain(t, r, "*.apps.customer.test", "", "one")
	for i := 0; i < 49; i++ {
		addDomain(t, r, d.Name, fmt.Sprintf("app-%d", i), "one")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	added := 0
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := r.Add(context.Background(), &pb.Domain{Name: d.Name, Tunnel: fmt.Sprintf("race-%d", i), Owner: "one"})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				added++
			} else if status.Code(err) != codes.ResourceExhausted {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if added != 1 {
		t.Fatalf("capacity race admitted %d", added)
	}
	if _, err := r.Delete(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM namespace_app_names`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("orphan names: %d %v", count, err)
	}
	replacement := addDomain(t, r, d.Name, "app-0", "two")
	if replacement.CnameTarget == d.CnameTarget || len(replacement.AppNames) != 1 {
		t.Fatal("replacement inherited old authority or names")
	}
}

func TestNamespaceForwardMigrationPreservesDataAndIsOnceOnly(t *testing.T) {
	r, dns, db := domainFixture(t, nil)
	ctx := context.Background()
	accounts := store.NewAccountStore(db)
	if err := accounts.ReserveSubdomain("one", "legacy"); err != nil {
		t.Fatal(err)
	}
	d := addDomain(t, r, "*.apps.legacy.test", "legacy", "one")
	dns.records[d.Name] = d.CnameTarget
	r.issuer = issuerFunc(func(_ context.Context, name string, _ PresentChallenge) ([]byte, []byte, error) {
		cert, key := fakeCert(t, name, r.now())
		return cert, key, nil
	})
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Certificate(ctx, &pb.Domain{Name: "legacy.apps.legacy.test"}); err != nil {
		t.Fatal(err)
	}
	var sealedBefore []byte
	if err := db.QueryRow(`SELECT key FROM wildcard_certificates`).Scan(&sealedBefore); err != nil {
		t.Fatal(err)
	}
	// Recreate only the pre-change schema; retain actual claims, encrypted cert
	// rows, and global reservation rows as deployed by the previous head.
	if _, err := db.Exec(`DROP TRIGGER namespace_claim_deleted; DROP TRIGGER namespace_claim_replaced; DROP TRIGGER namespace_app_deleted; DROP TABLE namespace_app_names; DELETE FROM domain_settings WHERE name='namespace-app-names-v1';`); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateNamespaceNames(db); err != nil {
		t.Fatal(err)
	}
	var sealedAfter []byte
	if err := db.QueryRow(`SELECT key FROM wildcard_certificates`).Scan(&sealedAfter); err != nil || !bytes.Equal(sealedBefore, sealedAfter) {
		t.Fatal("migration changed encrypted certificate data")
	}
	route, err := r.Route(ctx, &pb.Domain{Name: "legacy.apps.legacy.test"})
	if err != nil || route.Tunnel != "legacy" {
		t.Fatalf("historical publisher changed: %+v %v", route, err)
	}
	if err := accounts.ReserveSubdomain("one", "later-shared"); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateNamespaceNames(db); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Route(ctx, &pb.Domain{Name: "later-shared.apps.legacy.test"}); err == nil {
		t.Fatal("restart repeated legacy backfill")
	}
	if _, err := r.Delete(ctx, d); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"namespace_app_names", "wildcard_certificates", "domain_challenges"} {
		var count int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s retains rows: %d %v", table, count, err)
		}
	}
	if names, err := accounts.GetReservedSubdomains("one"); err != nil || len(names) != 2 {
		t.Fatalf("migration/deletion lost global names: %d %v", len(names), err)
	}
}

func TestNamespaceDeletionDuringIssuanceCannotReturnKeys(t *testing.T) {
	for _, renewal := range []bool{false, true} {
		t.Run(fmt.Sprint(renewal), func(t *testing.T) {
			r, dns, db := domainFixture(t, nil)
			ctx := context.Background()
			d := addDomain(t, r, "*.apps.customer.test", "grafana", "one")
			dns.records[d.Name] = d.CnameTarget
			if _, err := r.Verify(ctx, d); err != nil {
				t.Fatal(err)
			}
			r.issuer = issuerFunc(func(_ context.Context, name string, _ PresentChallenge) ([]byte, []byte, error) {
				cert, key := fakeCert(t, name, r.now())
				return cert, key, nil
			})
			in := &pb.Domain{Name: "grafana.apps.customer.test"}
			if renewal {
				if _, err := r.Certificate(ctx, in); err != nil {
					t.Fatal(err)
				}
				now := r.now().Add(61 * 24 * time.Hour)
				r.now = func() time.Time { return now }
				if _, err := r.Verify(ctx, d); err != nil {
					t.Fatal(err)
				}
			}
			r.issuer = issuerFunc(func(ctx context.Context, name string, p PresentChallenge) ([]byte, []byte, error) {
				cleanup, err := p(ctx, "token", "proof")
				if err != nil {
					t.Fatal(err)
				}
				defer cleanup()
				if _, err := r.Delete(ctx, d); err != nil {
					t.Fatal(err)
				}
				if _, err := r.Challenge(ctx, &pb.ChallengeRequest{Name: name, Token: "token"}); status.Code(err) != codes.NotFound {
					t.Fatalf("deleted authority challenge: %v", err)
				}
				if _, err := p(ctx, "late", "late"); err == nil {
					t.Fatal("stale order published challenge")
				}
				if renewal {
					return nil, nil, fmt.Errorf("fixture renewal failure")
				}
				cert, key := fakeCert(t, name, r.now())
				return cert, key, nil
			})
			if pair, err := r.Certificate(ctx, in); err == nil || pair != nil {
				t.Fatalf("deleted namespace returned certificate keys: err=%v", err)
			}
			var count int
			if err := db.QueryRow(`SELECT count(*) FROM wildcard_certificates`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("orphan keys: %d %v", count, err)
			}
		})
	}
}

func TestNamespaceIDsCannotBeReservedThroughAnyWriterOrAfterDeletion(t *testing.T) {
	r, dns, db := domainFixture(t, nil)
	ctx := context.Background()
	d := addDomain(t, r, "*.apps.customer.test", "grafana", "one")
	id := d.AppNames[0].Tunnel
	dns.records[d.Name] = d.CnameTarget
	if _, err := r.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	hosts, err := store.NewHostStore(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, deleted := range []bool{false, true} {
		if deleted {
			if _, err := r.Delete(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.NewAccountStore(db).ReserveSubdomain("two", id); err == nil {
			t.Fatal("AccountStore claimed internal ID")
		}
		if _, err := r.Add(ctx, &pb.Domain{Name: "unrelated.other.test", Tunnel: id, Owner: "two"}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("exact-domain reservation path: %v", err)
		}
		if err := hosts.Register("two", common.HostManifest{Machine: "other-host", Tunnels: []common.HostEndpointSpec{{Name: id, Kind: "http"}}}); err == nil {
			t.Fatal("host reserved internal ID")
		}
		if _, err := db.Exec(`INSERT INTO reserved_subdomains VALUES(?,'two',1)`, id); err == nil {
			t.Fatal("SQL insert bypassed scoped-ID gate")
		}
		if err := store.NewAccountStore(db).ReserveSubdomain("two", "ordinary"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE reserved_subdomains SET subdomain=? WHERE subdomain='ordinary'`, id); err == nil {
			t.Fatal("SQL update bypassed scoped-ID gate")
		}
		if deleted {
			local := storage.NewLocalStorageWithClock(db, r.now)
			if reg, err := local.RegisterTunnel(ctx, id, "one", "node"); err != nil || reg.Allowed {
				t.Fatalf("revoked internal ID became shared publisher: %+v %v", reg, err)
			}
		}
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM reserved_subdomains WHERE subdomain=?`, id).Scan(&count); err != nil || count != 0 {
		t.Fatal("internal ID consumed shared reservation")
	}
}

func TestNamespaceMigrationPreservesHistoricalGlobalInternalStyleName(t *testing.T) {
	r, _, db := domainFixture(t, nil)
	id := "ns-" + strings.Repeat("a", 48)
	// Model a global name written by an older head before these safety triggers.
	if _, err := db.Exec(`DROP TRIGGER namespace_shared_insert_guard; INSERT INTO reserved_subdomains VALUES(?,'one',1)`, id); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateNamespaceNames(db); err != nil {
		t.Fatal(err)
	}
	if err := store.NewAccountStore(db).ReserveSubdomain("one", id); err != nil {
		t.Fatalf("historical reservation retry failed: %v", err)
	}
	local := storage.NewLocalStorageWithClock(db, r.now)
	if reg, err := local.RegisterTunnel(context.Background(), id, "one", "node"); err != nil || !reg.Allowed {
		t.Fatalf("historical publisher denied: %+v %v", reg, err)
	}
}
