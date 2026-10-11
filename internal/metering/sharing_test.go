package metering

import (
	"context"
	"database/sql"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	_ "modernc.org/sqlite"
	"path/filepath"
	"testing"
	"time"
)

func TestWebSharingDurableGenerationAndExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sharing.db")
	open := func() (*sql.DB, *Store) {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		s, err := New(db)
		if err != nil {
			t.Fatal(err)
		}
		return db, s
	}
	db, s := open()
	ctx := context.Background()
	call := func(in *pb.SharingRequest) *pb.WebResource {
		t.Helper()
		out, err := s.Sharing(ctx, in)
		if err != nil || len(out.Resources) != 1 {
			t.Fatalf("%v: %v %v", in, out, err)
		}
		return out.Resources[0]
	}
	r := call(&pb.SharingRequest{Operation: "register", Owner: "owner", Endpoint: "preview", Mode: "private", InitialEmails: []string{" Alice@Example.com ", "@company.example"}})
	if r.Id == "" || len(r.People) != 2 || len(r.People[0].TokenSha256) > 0 {
		t.Fatal(r)
	}
	call(&pb.SharingRequest{Operation: "unshare", Owner: "owner", Endpoint: "preview", Email: "alice@example.com"})
	db.Close()
	db, s = open()
	defer db.Close()
	r2 := call(&pb.SharingRequest{Operation: "register", Owner: "owner", Endpoint: "preview", Mode: "private", InitialEmails: []string{"alice@example.com"}})
	if r2.Id != r.Id {
		t.Fatal("reconnect lost resource identity")
	}
	for _, g := range r2.People {
		if g.Consumer == "person:alice@example.com" && !g.Revoked {
			t.Fatal("restart replayed revoked allow-list")
		}
	}
	r2 = call(&pb.SharingRequest{Operation: "share", Owner: "owner", Endpoint: "preview", Email: "ALICE@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	active := 0
	for _, g := range r2.People {
		if g.Consumer == "person:alice@example.com" && !g.Revoked {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active grants=%d", active)
	}
	for _, in := range []*pb.SharingRequest{
		{Operation: "get", Owner: "stranger", Endpoint: "preview"},
		{Operation: "share", Owner: "stranger", Endpoint: "preview", Email: "evil@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()},
		{Operation: "share", Owner: "owner", Endpoint: "preview", Email: "alice@example.com", ExpiresAt: time.Now().Add(-time.Second).UnixMilli()},
		{Operation: "share", Owner: "owner", Endpoint: "preview", Email: "@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()},
		{Operation: "share", Owner: "owner", Endpoint: "preview", Email: "Alice <alice@example.com>", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()},
		{Operation: "register", Owner: "owner", Endpoint: "bad/name", Mode: "private"},
		{Operation: "register", Owner: "owner", Endpoint: "preview", Mode: "unknown"},
	} {
		if _, err := s.Sharing(ctx, in); err == nil {
			t.Fatalf("accepted %v", in)
		}
	}
	newResource := call(&pb.SharingRequest{Operation: "register", Owner: "new-owner", Endpoint: "preview", Mode: "private"})
	if newResource.Id == r.Id || len(newResource.People) != 0 {
		t.Fatal("name reuse inherited permission")
	}
	if _, err := s.Sharing(ctx, &pb.SharingRequest{Operation: "get", Owner: "owner", Endpoint: "preview", ResourceId: r.Id}); err == nil {
		t.Fatal("old generation retained authority")
	}
	reclaimed := call(&pb.SharingRequest{Operation: "register", Owner: "owner", Endpoint: "preview", Mode: "private"})
	if reclaimed.Id == r.Id || len(reclaimed.People) != 0 {
		t.Fatal("old owner resurrected grants")
	}
	if _, err := s.Sharing(ctx, &pb.SharingRequest{Operation: "register", Owner: "owner", Endpoint: "preview", Mode: "legacy-public"}); err == nil {
		t.Fatal("legacy client silently made a private resource public")
	}
	for _, mode := range []string{"public", "legacy-public"} {
		call(&pb.SharingRequest{Operation: "register", Owner: "owner", Endpoint: mode, Mode: mode})
		if _, err := s.Sharing(ctx, &pb.SharingRequest{Operation: "share", Owner: "owner", Endpoint: mode, Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err == nil {
			t.Fatal("public resource falsely represented as person-only")
		}
	}
}
