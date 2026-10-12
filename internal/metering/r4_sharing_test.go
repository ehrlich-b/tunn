package metering

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

// Upgrade fixture inserts the prior release representation directly.
func TestR4UpgradeRetiresOrphanSharingHistoryAtGlobalCapacity(t *testing.T) {
	db, s := r3SharingStore(t)
	out, err := r3Share(t, s, "prior-owner", "preview", "register", "")
	if err != nil {
		t.Fatal(err)
	}
	oldID := out.Resources[0].Id
	// Exact prior share/revoke/insert representation: repeated decisions, then
	// name ownership changes (also produced by the prior merge/reconnect bug).
	for i := 0; i < 3; i++ {
		digest := sha256.Sum256([]byte(fmt.Sprint("historical-", i)))
		g := &pb.Grant{Id: fmt.Sprint("historical-", i), Owner: "prior-owner", Endpoint: oldID, Consumer: "person:same@example.com", TokenSha256: digest[:], ExpiresAt: time.Now().AddDate(100, 0, 0).UnixMilli(), Revoked: i < 2}
		data, _ := json.Marshal(g)
		if _, err := db.Exec(`INSERT INTO meter_grants(id,owner,endpoint,digest,expires,data) VALUES(?,?,?,?,?,?)`, g.Id, g.Owner, g.Endpoint, digest[:], g.ExpiresAt, data); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`UPDATE web_resources SET owner='new-owner', id='new-generation' WHERE endpoint='preview'`); err != nil {
		t.Fatal(err)
	}
	upgraded, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	upgraded.maxGrants = 3
	var orphaned, audited int
	if err := db.QueryRow(`SELECT count(*) FROM meter_grants g WHERE NOT EXISTS (SELECT 1 FROM web_resources r WHERE r.id=g.endpoint AND r.owner=g.owner)`).Scan(&orphaned); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sharing_audit WHERE action='resource-retired'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("unrelated-machine"))
	_, err = upgraded.CreateGrant(context.Background(), &pb.Grant{Owner: "unrelated", Endpoint: "machine", TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	if orphaned != 0 || audited != 3 || err != nil {
		t.Fatalf("orphans=%d migrated=%d unrelated admission=%v", orphaned, audited, err)
	}
	t.Logf("upgrade retained %d orphan rows; audited=%d; unrelated admission=%v", orphaned, audited, err)
}

// All calls use the fixed implementation, with two rows rather than 256.
func TestR4NameReclaimReleasesOwnerSharingCapacity(t *testing.T) {
	db, s := r3SharingStore(t)
	s.maxOwnerGrants = 2
	ids := map[string]bool{}
	for i := 0; i < 3; i++ {
		out, err := r3Share(t, s, "owner", "preview", "register", "")
		if err != nil {
			t.Fatal(err)
		}
		if ids[out.Resources[0].Id] {
			t.Fatal("generation reused")
		}
		ids[out.Resources[0].Id] = true
		_, err = r3Share(t, s, "owner", "preview", "share", "same@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			if _, err = r3Share(t, s, "other-owner", "preview", "register", ""); err != nil {
				t.Fatal(err)
			}
		}
	}
	var retained int
	if err := db.QueryRow(`SELECT count(*) FROM meter_grants WHERE owner='owner'`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	current, err := r3Share(t, s, "owner", "preview", "get", "")
	if err != nil || retained != 1 || len(current.Resources[0].People) != 1 {
		t.Fatal(retained, current, err)
	}
	restarted, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	restarted.maxOwnerGrants = 2
	if _, err = r3Share(t, restarted, "owner", "preview", "share", "same@example.com"); err != nil {
		t.Fatal("sharing after restart failed", err)
	}
	t.Log("third generation can share before and after restart; obsolete grants no longer count")
}

func TestR4ReplacementRetiresPeopleAndGroupsWithBoundedAudit(t *testing.T) {
	db, s := r3SharingStore(t)
	s.maxSharingAudit, s.maxOwnerSharingAudit = 2, 1
	out, err := r3Share(t, s, "owner", "preview", "register", "")
	if err != nil {
		t.Fatal(err)
	}
	oldID := out.Resources[0].Id
	for _, target := range []string{"alice@example.com", "group:company:engineering"} {
		if _, err := r3Share(t, s, "owner", "preview", "share", target); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r3Share(t, s, "owner", "preview", "unshare", "group:company:engineering"); err != nil {
		t.Fatal(err)
	}
	// A machine grant can have the same endpoint string; consumer namespace, not
	// endpoint alone, determines whether generation retirement applies.
	digest := sha256.Sum256([]byte("independent-machine"))
	machine, err := s.CreateGrant(context.Background(), &pb.Grant{Owner: "owner", Endpoint: oldID, TokenSha256: digest[:], ExpiresAt: s.now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	out, err = r3Share(t, s, "new-owner", "preview", "register", "")
	if err != nil || out.Resources[0].Id == oldID || len(out.Resources[0].People) != 0 {
		t.Fatalf("replacement: %v %v", out, err)
	}
	var n, revoked int
	var target, action string
	if err := db.QueryRow(`SELECT count(*) FROM meter_grants`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("remaining grants=%d %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM meter_grants WHERE id=?`, machine.Id).Scan(&n); err != nil || n != 1 {
		t.Fatalf("machine retired=%d %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sharing_audit`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("unbounded audit=%d %v", n, err)
	}
	if err := db.QueryRow(`SELECT target,action,revoked FROM sharing_audit`).Scan(&target, &action, &revoked); err != nil || target != "group:company:engineering" || action != "resource-retired" || revoked != 1 {
		t.Fatalf("audit lost group/revocation: %s %s %d %v", target, action, revoked, err)
	}
	if _, err := New(db); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM meter_grants WHERE id=?`, machine.Id).Scan(&n); err != nil || n != 1 {
		t.Fatalf("startup retired machine=%d %v", n, err)
	}
}

func TestR4FailedReplacementRollsBackRetirement(t *testing.T) {
	db, s := r3SharingStore(t)
	out, err := r3Share(t, s, "owner", "preview", "register", "")
	if err != nil {
		t.Fatal(err)
	}
	id := out.Resources[0].Id
	if _, err := r3Share(t, s, "owner", "preview", "share", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := r3Share(t, s, "owner", "preview", "unshare", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	var audited int
	if err := db.QueryRow(`SELECT count(*) FROM sharing_audit`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	// Retirement runs before initial sharing; invalid sharing must roll it back.
	if _, err := s.Sharing(context.Background(), &pb.SharingRequest{Operation: "register", Owner: "other", Endpoint: "preview", Mode: "private", InitialEmails: []string{"invalid"}}); err == nil {
		t.Fatal("invalid replacement admitted")
	}
	current, err := r3Share(t, s, "owner", "preview", "get", "")
	if err != nil || current.Resources[0].Id != id || len(current.Resources[0].People) != 1 || !current.Resources[0].People[0].Revoked {
		t.Fatalf("replacement failure lost revoked decision: %v %v", current, err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sharing_audit`).Scan(&n); err != nil || n != audited {
		t.Fatalf("failed replacement wrote audit: %d %v", n, err)
	}
	// Reconnect still cannot replay the revoked seed after the failed replacement.
	current, err = s.Sharing(context.Background(), &pb.SharingRequest{Operation: "register", Owner: "owner", Endpoint: "preview", Mode: "private", InitialEmails: []string{"alice@example.com"}})
	if err != nil || current.Resources[0].Id != id || !current.Resources[0].People[0].Revoked {
		t.Fatalf("seed replayed: %v %v", current, err)
	}
}

func TestR4UpgradeRetiresGroupOwnerMismatchAndKeepsLiveRevocation(t *testing.T) {
	db, s := r3SharingStore(t)
	out, err := r3Share(t, s, "owner", "preview", "register", "")
	if err != nil {
		t.Fatal(err)
	}
	id := out.Resources[0].Id
	// At most three grants: a current revoked person, an obsolete owner group
	// pointing at the same resource ID, and a machine with no web resource.
	if _, err := r3Share(t, s, "owner", "preview", "share", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := r3Share(t, s, "owner", "preview", "unshare", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("orphan-group"))
	g := &pb.Grant{Id: "orphan-group", Owner: "obsolete", Endpoint: id, Consumer: "group:company:engineering", TokenSha256: digest[:], ExpiresAt: s.now().AddDate(100, 0, 0).UnixMilli(), Revoked: true}
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO meter_grants(id,owner,endpoint,digest,expires,data) VALUES(?,?,?,?,?,?)`, g.Id, g.Owner, g.Endpoint, digest[:], g.ExpiresAt, data); err != nil {
		t.Fatal(err)
	}
	digest = sha256.Sum256([]byte("machine-upgrade"))
	machine, err := s.CreateGrant(context.Background(), &pb.Grant{Owner: "machine-owner", Endpoint: "machine", TokenSha256: digest[:], ExpiresAt: s.now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	restart, err := New(db, func(s *Store) { s.maxSharingAudit = 2; s.maxOwnerSharingAudit = 1 })
	if err != nil {
		t.Fatal(err)
	}
	current, err := restart.Sharing(context.Background(), &pb.SharingRequest{Operation: "register", Owner: "owner", Endpoint: "preview", Mode: "private", InitialEmails: []string{"alice@example.com"}})
	if err != nil || current.Resources[0].Id != id || len(current.Resources[0].People) != 1 || !current.Resources[0].People[0].Revoked {
		t.Fatalf("live revocation changed: %v %v", current, err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM meter_grants WHERE id=?`, g.Id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("orphan group=%d %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM meter_grants WHERE id=?`, machine.Id).Scan(&n); err != nil || n != 1 {
		t.Fatalf("lost machine=%d %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sharing_audit`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("audit bound=%d %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sharing_audit WHERE grant_id=? AND target=? AND revoked=1 AND action='resource-retired'`, g.Id, g.Consumer).Scan(&n); err != nil || n != 1 {
		t.Fatalf("group audit=%d %v", n, err)
	}
	if _, err := New(db); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sharing_audit WHERE action='resource-retired'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("duplicate retirement=%d %v", n, err)
	}
}

func TestR4OwnerGrantLimitCannotRaiseHardCap(t *testing.T) {
	db, _ := r3SharingStore(t)
	for _, limit := range []int{-1, 0, MaxOwnerGrants + 1} {
		if _, err := New(db, WithOwnerGrantLimit(limit)); err == nil {
			t.Fatalf("invalid owner limit %d admitted", limit)
		}
	}
}
