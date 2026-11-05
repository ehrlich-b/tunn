package metering

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"testing"
	"time"
)

func TestR3RepeatedSharingPreservesGlobalGrantCapacity(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	// Reduce only the global capacity, keeping the production transaction logic.
	s.maxGrants = 3
	ctx := context.Background()
	if _, err = s.Sharing(ctx, &pb.SharingRequest{Operation: "register", Owner: "attacker", Endpoint: "attacker", Mode: "private"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err = s.Sharing(ctx, &pb.SharingRequest{Operation: "share", Owner: "attacker", Endpoint: "attacker", Email: "same@example.com", ExpiresAt: time.Now().AddDate(100, 0, 0).UnixMilli()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.CreateGrant(ctx, &pb.Grant{Owner: "victim", Endpoint: "victim", TokenSha256: make([]byte, 32), ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err != nil {
		t.Fatalf("unrelated grant error=%v", err)
	}
	var total int
	if err = db.QueryRow("SELECT count(*) FROM meter_grants").Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("repeated shares plus unrelated grant retained %d rows, want 2", total)
	}
	t.Log("identical shares retained one row; unrelated machine grant admitted")
}

func r3SharingStore(t *testing.T) (*sql.DB, *Store) {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return db, s
}
func r3Share(t *testing.T, s *Store, owner, endpoint, operation, email string) (*pb.SharingResponse, error) {
	t.Helper()
	return s.Sharing(context.Background(), &pb.SharingRequest{Owner: owner, Endpoint: endpoint, Operation: operation, Mode: "private", Email: email, ExpiresAt: s.now().Add(time.Hour).UnixMilli()})
}

func TestR3SharingOwnerAndResourceBoundsProtectUnrelatedOwners(t *testing.T) {
	db, s := r3SharingStore(t)
	s.maxGrants = 6
	s.maxOwnerGrants = 2
	s.maxResourcePeople = 1
	s.maxOwnerResources = 2
	for _, endpoint := range []string{"first", "second"} {
		if _, err := r3Share(t, s, "owner", endpoint, "register", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := r3Share(t, s, "owner", endpoint, "share", "alice@example.com"); err != nil {
			t.Fatal(err)
		}
		if endpoint == "first" {
			if _, err := r3Share(t, s, "owner", "first", "share", "bob@example.com"); err != ErrCapacity {
				t.Fatal("per-resource cap failed before owner cap", err)
			}
		}
	}
	if _, err := r3Share(t, s, "owner", "first", "share", "bob@example.com"); err != ErrCapacity {
		t.Fatal("resource cap bypassed", err)
	}
	if _, err := r3Share(t, s, "owner", "third", "register", ""); err != ErrCapacity {
		t.Fatal("resource inventory cap bypassed", err)
	}
	digest := sha256.Sum256([]byte("owner machine"))
	if _, err := s.CreateGrant(context.Background(), &pb.Grant{Owner: "owner", Endpoint: "machine", TokenSha256: digest[:], ExpiresAt: s.now().Add(time.Hour).UnixMilli()}); err != ErrCapacity {
		t.Fatal("owner cap bypassed via machine grants", err)
	}
	digest = sha256.Sum256([]byte("unrelated machine"))
	if _, err := s.CreateGrant(context.Background(), &pb.Grant{Owner: "unrelated", Endpoint: "machine", TokenSha256: digest[:], ExpiresAt: s.now().Add(time.Hour).UnixMilli()}); err != nil {
		t.Fatal("one owner blocked unrelated machine grant", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM meter_grants`).Scan(&n); err != nil || n != 3 {
		t.Fatal("failed admission changed current grants", n, err)
	}
}

func TestR3SharingRenewalAtGlobalCapacityAndBoundedAudit(t *testing.T) {
	db, s := r3SharingStore(t)
	s.maxGrants = 2
	s.maxSharingAudit = 3
	s.maxOwnerSharingAudit = 2
	ids := map[string]string{}
	for _, owner := range []string{"first", "second"} {
		if _, err := r3Share(t, s, owner, owner, "register", ""); err != nil {
			t.Fatal(err)
		}
		out, err := r3Share(t, s, owner, owner, "share", "alice@example.com")
		if err != nil {
			t.Fatal(err)
		}
		ids[owner] = out.Resources[0].People[0].Id
	}
	for i := 0; i < 3; i++ {
		for _, owner := range []string{"first", "second"} {
			if _, err := r3Share(t, s, owner, owner, "unshare", "alice@example.com"); err != nil {
				t.Fatal(err)
			}
			out, err := r3Share(t, s, owner, owner, "share", "alice@example.com")
			if err != nil {
				t.Fatal("renewal failed at global capacity", err)
			}
			if len(out.Resources[0].People) != 1 || out.Resources[0].People[0].Id != ids[owner] {
				t.Fatal("sharing inserted history into current grants")
			}
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sharing_audit`).Scan(&n); err != nil || n != 3 {
		t.Fatal("global audit bound", n, err)
	}
	for _, owner := range []string{"first", "second"} {
		if err := db.QueryRow(`SELECT count(*) FROM sharing_audit WHERE owner=?`, owner).Scan(&n); err != nil || n > 2 {
			t.Fatal("owner audit bound", owner, n, err)
		}
	}
	if _, err := r3Share(t, s, "first", "first", "share", "new@example.com"); err != ErrCapacity {
		t.Fatal("global cap lost", err)
	}
	if _, err := r3Share(t, s, "first", "first", "unshare", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	out, err := restarted.Sharing(context.Background(), &pb.SharingRequest{Owner: "first", Endpoint: "first", Operation: "register", Mode: "private", InitialEmails: []string{"alice@example.com"}})
	if err != nil || len(out.Resources[0].People) != 1 || !out.Resources[0].People[0].Revoked {
		t.Fatal("restart or audit eviction replayed seed permissions", out, err)
	}
}

func TestR3SharingMutationRateIsOwnerScopedAndDurable(t *testing.T) {
	db, s := r3SharingStore(t)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	s.maxSharingMutations = 4
	if _, err := r3Share(t, s, "owner", "api", "register", ""); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"share", "unshare", "share"} {
		if _, err := r3Share(t, s, "owner", "api", op, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r3Share(t, s, "owner", "api", "share", "alice@example.com"); err != ErrSharingRate {
		t.Fatal("rate cap bypassed", err)
	}
	if _, err := r3Share(t, s, "owner", "api", "get", ""); err != nil {
		t.Fatal("rate cap blocked read", err)
	}
	if _, err := r3Share(t, s, "unrelated", "other", "register", ""); err != nil {
		t.Fatal("rate cap blocked unrelated owner", err)
	}
	restarted, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = s.now
	restarted.maxSharingMutations = 4
	if _, err := r3Share(t, restarted, "owner", "api", "unshare", "alice@example.com"); err != ErrSharingRate {
		t.Fatal("restart reset owner rate", err)
	}
	clock = clock.Add(time.Minute)
	if _, err := r3Share(t, restarted, "owner", "api", "unshare", "alice@example.com"); err != nil {
		t.Fatal("rate window did not expire", err)
	}
}

func TestR3SharingUpgradeCompactsHistoricalRowsWithoutRestoringRevocation(t *testing.T) {
	db, s := r3SharingStore(t)
	out, err := r3Share(t, s, "owner", "api", "register", "")
	if err != nil {
		t.Fatal(err)
	}
	resource := out.Resources[0]
	for i := 0; i < 3; i++ {
		digest := sha256.Sum256([]byte(fmt.Sprint(i)))
		g := &pb.Grant{Id: fmt.Sprint("old-", i), Owner: "owner", Endpoint: resource.Id, Consumer: "person:alice@example.com", TokenSha256: digest[:], ExpiresAt: s.now().AddDate(100, 0, 0).UnixMilli(), Revoked: i == 2}
		data, _ := json.Marshal(g)
		if _, err = db.Exec(`INSERT INTO meter_grants(id,owner,endpoint,digest,expires,data) VALUES(?,?,?,?,?,?)`, g.Id, g.Owner, g.Endpoint, digest[:], g.ExpiresAt, data); err != nil {
			t.Fatal(err)
		}
	}
	restarted, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r3Share(t, restarted, "owner", "api", "get", "")
	if err != nil || len(got.Resources[0].People) != 1 || got.Resources[0].People[0].Id != "old-2" || !got.Resources[0].People[0].Revoked {
		t.Fatal("upgrade lost newest revoked decision", got, err)
	}
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM sharing_audit WHERE action='legacy-history'`).Scan(&n); err != nil || n != 2 {
		t.Fatal("history not moved to audit", n, err)
	}
	if _, err = New(db); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM sharing_audit WHERE action='legacy-history'`).Scan(&n); err != nil || n != 2 {
		t.Fatal("restart duplicated historical decisions", n, err)
	}
}

func TestR3SharingUpgradeRepairsObsoleteResourceOwner(t *testing.T) {
	db, s := r3SharingStore(t)
	accounts := store.NewAccountStore(db)
	first, err := accounts.FindOrCreateByEmails([]string{"first@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	second, err := accounts.FindOrCreateByEmails([]string{"second@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.UpdatePlan(second.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	out, err := r3Share(t, s, first.ID, "api", "register", "")
	if err != nil {
		t.Fatal(err)
	}
	id := out.Resources[0].Id
	if _, err = r3Share(t, s, first.ID, "api", "share", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err = r3Share(t, s, first.ID, "api", "unshare", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	merged, err := accounts.FindOrCreateByEmails([]string{"first@example.com", "second@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	// Emulate the persisted split ownership left by the reviewed release.
	if _, err = db.Exec(`UPDATE web_resources SET owner=? WHERE endpoint='api'`, first.ID); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r3Share(t, restarted, first.ID, "api", "get", "")
	if err != nil || got.Resources[0].Owner != merged.ID || got.Resources[0].Id != id || len(got.Resources[0].People) != 1 || !got.Resources[0].People[0].Revoked {
		t.Fatal("upgrade failed to preserve revoked resource", got, err)
	}
	var old int
	if err = db.QueryRow(`SELECT count(*) FROM sharing_mutation_rate WHERE owner=?`, first.ID).Scan(&old); err != nil || old != 0 {
		t.Fatal("merge left owner rate state", old, err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM sharing_audit WHERE owner=?`, first.ID).Scan(&old); err != nil || old != 0 {
		t.Fatal("merge left owner audit state", old, err)
	}
}

func TestR3SharingMutationRateFollowsMergedOwner(t *testing.T) {
	db, s := r3SharingStore(t)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	accounts := store.NewAccountStore(db)
	s.maxSharingMutations = 4
	owners := make([]string, 2)
	for i, email := range []string{"first@example.com", "second@example.com"} {
		account, err := accounts.FindOrCreateByEmails([]string{email}, "github")
		if err != nil {
			t.Fatal(err)
		}
		owners[i] = account.ID
		endpoint := fmt.Sprint("resource-", i)
		if _, err = r3Share(t, s, account.ID, endpoint, "register", ""); err != nil {
			t.Fatal(err)
		}
		if _, err = r3Share(t, s, account.ID, endpoint, "share", "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := accounts.FindOrCreateByEmails([]string{"first@example.com", "second@example.com"}, "github"); err != nil {
		t.Fatal(err)
	}
	if _, err := r3Share(t, s, owners[0], "resource-0", "share", "alice@example.com"); err != ErrSharingRate {
		t.Fatal("obsolete owner bypassed merged admission rate", err)
	}
}
