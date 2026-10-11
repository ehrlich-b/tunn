package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
)

func TestHostStoreReservations(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()
	accounts := NewAccountStore(db)
	owner, err := accounts.FindOrCreateByEmails([]string{"owner@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	other, err := accounts.FindOrCreateByEmails([]string{"other@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewHostStore(db)
	if err != nil {
		t.Fatal(err)
	}
	m := common.HostManifest{Machine: "gpu-box", Tunnels: []common.HostEndpointSpec{{Name: "gpu-http", Kind: "http"}, {Name: "gpu-ssh", Kind: "tcp"}}}
	if err := s.Register(owner.ID, m); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(owner.ID, m); err != nil {
		t.Fatalf("idempotent registration: %v", err)
	}
	if err := s.CheckEndpoint(owner.ID, "gpu-box", "gpu-ssh", "tcp"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckEndpoint(other.ID, "gpu-box", "gpu-ssh", "tcp"); err == nil {
		t.Fatal("other account admitted")
	}
	if err := s.CheckEndpoint(owner.ID, "gpu-box", "gpu-ssh", "http"); err == nil {
		t.Fatal("adapter mismatch admitted")
	}
	conflict := common.HostManifest{Machine: "other-box", Tunnels: []common.HostEndpointSpec{{Name: "new-name", Kind: "http"}, {Name: "gpu-http", Kind: "http"}}}
	if err := s.Register(other.ID, conflict); err == nil {
		t.Fatal("name stolen")
	}
	if ownerID, err := accounts.GetSubdomainOwner("new-name"); err != nil || ownerID != "" {
		t.Fatal("conflicting manifest was partially committed")
	}
	if err := s.Register(owner.ID, conflict); err == nil {
		t.Fatal("endpoint moved to another machine")
	}
	seen := time.Now().Truncate(time.Second).UTC()
	if err := s.Seen(owner.ID, "gpu-box", "gpu-http", seen); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || len(list[0].Tunnels) != 2 || !list[0].LastSeen.Equal(seen) || !list[0].Tunnels[0].LastSeen.Equal(seen) || list[0].Online {
		t.Fatalf("inventory = %#v", list)
	}
	list, err = s.List(other.ID)
	if err != nil || len(list) != 0 {
		t.Fatalf("account inventory leaked: %v %v", list, err)
	}
}

func TestHostStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	owner, err := NewAccountStore(db).FindOrCreateByEmails([]string{"owner@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE ops_fixture(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO ops_fixture VALUES(1,'disposable-local')`); err != nil {
		t.Fatal(err)
	}
	if err := NewAccountStore(db).UpdatePlan(owner.ID, "pro"); err != nil {
		t.Fatal(err)
	}

	s, err := NewHostStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Register(owner.ID, common.HostManifest{Machine: "gpu-box", Tunnels: []common.HostEndpointSpec{{Name: "gpu-http", Kind: "http"}}}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s, err = NewHostStore(db)
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.List(owner.ID)
	if err != nil || len(list) != 1 || list[0].Online {
		t.Fatalf("persisted inventory = %v %v", list, err)
	}
	if ownerID, err := NewAccountStore(db).GetSubdomainOwner("gpu-http"); err != nil || ownerID != owner.ID {
		t.Fatal("reservation did not survive restart")
	}
}

func TestHostStoreAccountMerge(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer func() { _ = db.Close() }()
	accounts := NewAccountStore(db)
	a, err := accounts.FindOrCreateByEmails([]string{"first@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	b, err := accounts.FindOrCreateByEmails([]string{"second@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.UpdatePlan(a.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	registry, err := NewHostStore(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ account, endpoint string }{{a.ID, "first-api"}, {b.ID, "second-api"}} {
		if err := registry.Register(tc.account, common.HostManifest{Machine: "gpu-box", Tunnels: []common.HostEndpointSpec{{Name: tc.endpoint, Kind: "http"}}}); err != nil {
			t.Fatal(err)
		}
	}
	merged, err := accounts.FindOrCreateByEmails([]string{"first@example.com", "second@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if merged.ID != a.ID {
		t.Fatal("merge discarded Pro identity")
	}
	for _, name := range []string{"first-api", "second-api"} {
		if owner, err := accounts.GetSubdomainOwner(name); err != nil || owner != a.ID {
			t.Fatalf("merged reservation %s: %s %v", name, owner, err)
		}
		if err := registry.CheckEndpoint(a.ID, "gpu-box", name, "http"); err != nil {
			t.Fatal(err)
		}
	}
	list, err := registry.List(a.ID)
	if err != nil || len(list) != 1 || len(list[0].Tunnels) != 2 {
		t.Fatalf("merged inventory = %v %v", list, err)
	}
}
