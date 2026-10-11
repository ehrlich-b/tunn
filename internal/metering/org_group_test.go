package metering

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestOrgGroupDurabilityRevocationAndResourceIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "group-permissions.db")
	open := func() (*sql.DB, *Store) {
		t.Helper()
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		s, err := New(db)
		if err != nil {
			t.Fatal(err)
		}
		return db, s
	}
	db, s := open()
	ctx := context.Background()
	call := func(op, owner, target string) *pb.WebResource {
		t.Helper()
		out, err := s.Sharing(ctx, &pb.SharingRequest{Operation: op, Owner: owner, Endpoint: "preview", Mode: "private", Email: target, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
		if err != nil {
			t.Fatal(err)
		}
		return out.Resources[0]
	}
	r := call("register", "owner", "")
	for _, target := range []string{"group:company:engineering", "group:other:engineering"} {
		call("share", "owner", target)
	}
	r = call("get", "owner", "")
	if len(r.People) != 2 {
		t.Fatal("group permissions not distinct")
	}
	for _, g := range r.People {
		if g.Consumer == "person:group:company:engineering" || len(g.TokenSha256) != 0 {
			t.Fatal("group became email or secret exposed")
		}
	}
	call("unshare", "owner", "group:company:engineering")
	db.Close()
	db, s = open()
	defer db.Close()
	restored := call("get", "owner", "")
	if restored.Id != r.Id {
		t.Fatal("resource identity lost after restart")
	}
	for _, g := range restored.People {
		if g.Consumer == "group:company:engineering" && !g.Revoked || g.Consumer == "group:other:engineering" && g.Revoked {
			t.Fatal("group revoke crossed orgs or was forgotten")
		}
	}
	for _, target := range []string{"group:company", "group:company:*", "group:company:engineering:extra", "group:company:engineering\n", "group:company:engineering/other"} {
		if _, err := s.Sharing(ctx, &pb.SharingRequest{Operation: "share", Owner: "owner", Endpoint: "preview", Email: target, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err == nil {
			t.Fatalf("invalid group target %q", target)
		}
	}
	if _, err := s.Sharing(ctx, &pb.SharingRequest{Operation: "share", Owner: "stranger", Endpoint: "preview", Email: "group:company:engineering", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err == nil {
		t.Fatal("non-owner shared group")
	}
	reclaimed := call("register", "new-owner", "")
	if reclaimed.Id == r.Id || len(reclaimed.People) != 0 {
		t.Fatal("reclaimed endpoint inherited groups")
	}
}
