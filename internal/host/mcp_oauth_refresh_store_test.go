package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"modernc.org/sqlite"
)

var refreshTestBinding = mcpRefreshBinding{
	OwnerID: "11111111-1111-4111-8111-111111111111", PersonID: "22222222-2222-4222-8222-222222222222",
	ClientID: "synthetic-client", Resource: "https://tools.example.test/mcp", Generation: "33333333-3333-4333-8333-333333333333",
}

type refreshLogCapture struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (c *refreshLogCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.Write(p)
}

func (c *refreshLogCapture) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.data.Bytes())
}

func openRefreshTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newRefreshTestStore(t *testing.T, db *sql.DB) *mcpOAuthStore {
	t.Helper()
	s, err := newMCPOAuthStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func refreshFixture(t *testing.T) (*mcpOAuthStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "refresh.db")
	return newRefreshTestStore(t, openRefreshTestDB(t, path)), path
}

func createTestRefresh(t *testing.T, s *mcpOAuthStore, token string) int64 {
	t.Helper()
	id, err := s.createRefreshFamily(context.Background(), refreshTestBinding, sha256.Sum256([]byte(token)), time.Now().Add(time.Hour))
	if err != nil || id <= 0 {
		t.Fatalf("create family: id=%d err=%v", id, err)
	}
	return id
}

func refreshExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func refreshCount(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != want {
		t.Fatalf("%s count=%d want=%d err=%v", table, count, want, err)
	}
}

func TestMCPRefreshFreshUpgradeAndReopen(t *testing.T) {
	for _, upgraded := range []bool{false, true} {
		t.Run(fmt.Sprintf("upgraded=%t", upgraded), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "refresh.db")
			db := openRefreshTestDB(t, path)
			if upgraded {
				// Exact pre-refresh schema, with existing OAuth state to preserve.
				refreshExec(t, db, `CREATE TABLE mcp_oauth_clients(id TEXT PRIMARY KEY,data BLOB NOT NULL);
 CREATE TABLE mcp_oauth_codes(digest BLOB PRIMARY KEY,owner TEXT NOT NULL,endpoint TEXT NOT NULL,client TEXT NOT NULL,expires INTEGER NOT NULL,data BLOB NOT NULL);
 CREATE TABLE mcp_oauth_consents(id TEXT PRIMARY KEY,owner TEXT NOT NULL,endpoint TEXT NOT NULL,client TEXT NOT NULL,expires INTEGER NOT NULL);
 INSERT INTO mcp_oauth_clients VALUES('old-client','{"client_id":"old-client","client_name":"Existing client"}');
 INSERT INTO mcp_oauth_consents VALUES('old-consent','owner','tools','old-client',4102444800);`)
				digest := sha256.Sum256([]byte("old-code"))
				refreshExec(t, db, `INSERT INTO mcp_oauth_codes VALUES(?,?,?,?,?,?)`, digest[:], "owner", "tools", "old-client", 4102444800, []byte(`{"client_id":"old-client","resource":"https://tools.example.test/mcp","code_challenge":"unchanged"}`))
			}
			s := newRefreshTestStore(t, db)
			id := createTestRefresh(t, s, "first")
			first, second, third := sha256.Sum256([]byte("first")), sha256.Sum256([]byte("second")), sha256.Sum256([]byte("third"))
			if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			s = newRefreshTestStore(t, openRefreshTestDB(t, path))
			newRefreshTestStore(t, s.db) // migration is idempotent
			if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, second, third); err != nil {
				t.Fatal(err)
			}
			if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); !errors.Is(err, errMCPRefreshReplay) {
				t.Fatalf("spent digest after reopen: %v", err)
			}
			if upgraded {
				client, err := s.client(t.Context(), "old-client")
				if err != nil || client.Name != "Existing client" {
					t.Fatalf("client changed: %+v %v", client, err)
				}
				refreshCount(t, s.db, "mcp_oauth_consents", 1)
				auth, err := s.takeCode(t.Context(), "old-code", func(a *mcpAuthorization) bool { return a.Challenge == "unchanged" })
				if err != nil || auth.ClientID != "old-client" {
					t.Fatalf("code changed: %+v %v", auth, err)
				}
			}
		})
	}
}

// Exercise the same authority registration used for MCP policy resources, then
// persist its UUID unchanged across transfer, reclaim and a refresh-store reopen.
func TestMCPRefreshRealResourceGeneration(t *testing.T) {
	f := newMCPOAuthFixture(t)
	authority := f.p.meter.(*metering.Store)
	register := func(owner string) string {
		t.Helper()
		out, err := authority.Sharing(t.Context(), &meterpb.SharingRequest{
			Operation: "register", Owner: owner, Endpoint: f.tunnel.TunnelID, Mode: "policy-only",
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Resources) != 1 {
			t.Fatalf("registered resources: %d", len(out.Resources))
		}
		return out.Resources[0].Id
	}
	original := refreshTestBinding
	original.OwnerID, original.PersonID = f.tunnel.AccountID, f.tunnel.AccountID
	original.Generation = register(original.OwnerID)
	if reconnect := register(original.OwnerID); reconnect != original.Generation {
		t.Fatal("same-owner reconnect changed generation")
	}
	s, path := refreshFixture(t)
	first, second, third := sha256.Sum256([]byte("first")), sha256.Sum256([]byte("second")), sha256.Sum256([]byte("third"))
	oldID, err := s.createRefreshFamily(t.Context(), original, first, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.p.storage.FindOrCreateByEmails(t.Context(), []string{"other@example.test"}, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	transferred := original
	transferred.OwnerID = other.ID
	transferred.Generation = register(other.ID)
	current := original
	current.Generation = register(original.OwnerID)
	if original.Generation == transferred.Generation || original.Generation == current.Generation || transferred.Generation == current.Generation {
		t.Fatal("transfer and reclaim must produce distinct resource generations")
	}
	for _, binding := range []mcpRefreshBinding{transferred, current} {
		if err := s.rotateRefresh(t.Context(), oldID, binding, first, second); !errors.Is(err, errMCPRefreshInvalid) {
			t.Fatalf("old credential accepted under replacement binding: %v", err)
		}
		if err := s.revokeRefreshFamily(t.Context(), oldID, binding); err != nil {
			t.Fatal(err)
		}
	}
	newID, err := s.createRefreshFamily(t.Context(), current, first, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	s = newRefreshTestStore(t, openRefreshTestDB(t, path))
	for id, want := range map[int64]string{oldID: original.Generation, newID: current.Generation} {
		var generation, storageType string
		if err := s.db.QueryRow(`SELECT generation,typeof(generation) FROM mcp_oauth_refresh_families WHERE id=?`, id).Scan(&generation, &storageType); err != nil {
			t.Fatal(err)
		}
		if generation != want || storageType != "text" {
			t.Fatalf("generation=%q type=%q, want exact UUID %q as text", generation, storageType, want)
		}
	}
	if err := s.rotateRefresh(t.Context(), oldID, current, first, second); !errors.Is(err, errMCPRefreshInvalid) {
		t.Fatalf("reopen accepted retired generation: %v", err)
	}
	var used int
	if err := s.db.QueryRow(`SELECT used FROM mcp_oauth_refresh_tokens WHERE family=? AND digest=?`, oldID, first[:]).Scan(&used); err != nil || used != 0 {
		t.Fatalf("replacement binding affected original family: used=%d err=%v", used, err)
	}
	if err := s.rotateRefresh(t.Context(), newID, current, first, second); err != nil {
		t.Fatal(err)
	}
	if err := s.revokeRefreshFamily(t.Context(), newID, original); err != nil {
		t.Fatal(err)
	}
	if err := s.rotateRefresh(t.Context(), newID, current, second, third); err != nil {
		t.Fatalf("retired generation revoked replacement family: %v", err)
	}
	if err := s.revokeRefreshFamily(t.Context(), newID, current); err != nil {
		t.Fatal(err)
	}
	if err := s.rotateRefresh(t.Context(), newID, current, third, first); !errors.Is(err, errMCPRefreshInvalid) {
		t.Fatalf("current generation revocation failed: %v", err)
	}
}

func TestMCPRefreshConcurrentRotationAndReplay(t *testing.T) {
	s, path := refreshFixture(t)
	other := newRefreshTestStore(t, openRefreshTestDB(t, path))
	id := createTestRefresh(t, s, "first")
	first := sha256.Sum256([]byte("first"))
	const attempts = 12
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := range attempts {
		wg.Go(func() {
			<-start
			store := s
			if i%2 == 0 {
				store = other
			}
			results <- store.rotateRefresh(t.Context(), id, refreshTestBinding, first, sha256.Sum256(fmt.Appendf(nil, "next-%d", i)))
		})
	}
	close(start)
	wg.Wait()
	close(results)
	wins, replays := 0, 0
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, errMCPRefreshReplay):
			replays++
		case errors.Is(err, errMCPRefreshInvalid):
		default:
			t.Fatalf("unexpected rotation result: %v", err)
		}
	}
	if wins != 1 || replays != 1 {
		t.Fatalf("winners=%d replay invalidations=%d", wins, replays)
	}
	refreshCount(t, s.db, "mcp_oauth_refresh_families", 0)
	refreshCount(t, s.db, "mcp_oauth_refresh_tokens", 0)
	for i := range attempts {
		if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, sha256.Sum256(fmt.Appendf(nil, "next-%d", i)), first); !errors.Is(err, errMCPRefreshInvalid) {
			t.Fatalf("successor survived replay: %v", err)
		}
	}
}

func TestMCPRefreshExactBindings(t *testing.T) {
	s, _ := refreshFixture(t)
	first, second := sha256.Sum256([]byte("first")), sha256.Sum256([]byte("second"))
	mutations := map[string]func(*mcpRefreshBinding){
		"owner":      func(b *mcpRefreshBinding) { b.OwnerID = b.PersonID },
		"person":     func(b *mcpRefreshBinding) { b.PersonID = b.OwnerID },
		"client":     func(b *mcpRefreshBinding) { b.ClientID += "-other" },
		"resource":   func(b *mcpRefreshBinding) { b.Resource += "/" },
		"generation": func(b *mcpRefreshBinding) { b.Generation = "44444444-4444-4444-8444-444444444444" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			id := createTestRefresh(t, s, "first")
			wrong := refreshTestBinding
			mutate(&wrong)
			if err := s.rotateRefresh(t.Context(), id, wrong, first, second); !errors.Is(err, errMCPRefreshInvalid) {
				t.Fatalf("accepted wrong binding: %v", err)
			}
			if err := s.revokeRefreshFamily(t.Context(), id, wrong); err != nil {
				t.Fatal(err)
			}
			if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); err != nil {
				t.Fatalf("wrong binding consumed or revoked family: %v", err)
			}
			// A spent token with the wrong binding must not revoke the family.
			if err := s.rotateRefresh(t.Context(), id, wrong, first, second); !errors.Is(err, errMCPRefreshInvalid) {
				t.Fatal(err)
			}
			if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, second, sha256.Sum256([]byte("third"))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMCPRefreshExpiryCleanupAndRevocation(t *testing.T) {
	for _, mode := range []string{"expiry", "revocation", "replay"} {
		t.Run(mode, func(t *testing.T) {
			s, path := refreshFixture(t)
			id := createTestRefresh(t, s, "first")
			unrelated := createTestRefresh(t, s, "unrelated")
			first, second := sha256.Sum256([]byte("first")), sha256.Sum256([]byte("second"))
			switch mode {
			case "expiry":
				refreshExec(t, s.db, `UPDATE mcp_oauth_refresh_families SET expires=? WHERE id=?`, time.Now().Unix(), id)
				if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); !errors.Is(err, errMCPRefreshInvalid) {
					t.Fatalf("accepted expiry boundary: %v", err)
				}
			case "revocation":
				if err := s.revokeRefreshFamily(t.Context(), id, refreshTestBinding); err != nil {
					t.Fatal(err)
				}
				if err := s.revokeRefreshFamily(t.Context(), id, refreshTestBinding); err != nil {
					t.Fatal(err)
				}
			case "replay":
				if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); err != nil {
					t.Fatal(err)
				}
				if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); !errors.Is(err, errMCPRefreshReplay) {
					t.Fatal(err)
				}
			}
			if err := s.cleanupRefreshFamilies(t.Context()); err != nil {
				t.Fatal(err)
			}
			refreshCount(t, s.db, "mcp_oauth_refresh_families", 1)
			refreshCount(t, s.db, "mcp_oauth_refresh_tokens", 1)
			_ = s.db.Close()
			s = newRefreshTestStore(t, openRefreshTestDB(t, path))
			// Even deliberately reusing a secret gets a different durable family ID.
			newID := createTestRefresh(t, s, "first")
			if newID <= unrelated || newID <= id {
				t.Fatal("family ID was reused")
			}
			if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); !errors.Is(err, errMCPRefreshInvalid) {
				t.Fatalf("cleaned credential resurrected: %v", err)
			}
			if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, second, first); !errors.Is(err, errMCPRefreshInvalid) {
				t.Fatalf("cleaned successor resurrected: %v", err)
			}
			if err := s.rotateRefresh(t.Context(), unrelated, refreshTestBinding, sha256.Sum256([]byte("unrelated")), second); err != nil {
				t.Fatalf("unrelated family affected: %v", err)
			}
		})
	}
}

func TestMCPRefreshBounds(t *testing.T) {
	s, _ := refreshFixture(t)
	digest := sha256.Sum256([]byte("first"))
	for name, mutate := range map[string]func(*mcpRefreshBinding){
		"email owner":             func(b *mcpRefreshBinding) { b.OwnerID = "owner@example.test" },
		"email person":            func(b *mcpRefreshBinding) { b.PersonID = "person@example.test" },
		"nil owner":               func(b *mcpRefreshBinding) { b.OwnerID = "00000000-0000-0000-0000-000000000000" },
		"empty client":            func(b *mcpRefreshBinding) { b.ClientID = "" },
		"large resource":          func(b *mcpRefreshBinding) { b.Resource = strings.Repeat("x", 2049) },
		"missing generation":      func(b *mcpRefreshBinding) { b.Generation = "" },
		"numeric generation":      func(b *mcpRefreshBinding) { b.Generation = "1" },
		"nil generation":          func(b *mcpRefreshBinding) { b.Generation = "00000000-0000-0000-0000-000000000000" },
		"noncanonical generation": func(b *mcpRefreshBinding) { b.Generation = "{33333333-3333-4333-8333-333333333333}" },
	} {
		t.Run(name, func(t *testing.T) {
			binding := refreshTestBinding
			mutate(&binding)
			if _, err := s.createRefreshFamily(t.Context(), binding, digest, time.Now().Add(time.Hour)); !errors.Is(err, errMCPRefreshInvalid) {
				t.Fatalf("accepted invalid binding: %v", err)
			}
		})
	}
	for _, expiry := range []time.Time{time.Now().Add(-time.Second), time.Now().Add(mcpRefreshMaxLifetime + time.Hour)} {
		if _, err := s.createRefreshFamily(t.Context(), refreshTestBinding, digest, expiry); !errors.Is(err, errMCPRefreshInvalid) {
			t.Fatalf("accepted invalid expiry: %v", err)
		}
	}
	id := createTestRefresh(t, s, "first")
	var expiry int64
	if err := s.db.QueryRow(`SELECT expires FROM mcp_oauth_refresh_families WHERE id=?`, id).Scan(&expiry); err != nil {
		t.Fatal(err)
	}
	current := digest
	for i := 1; i < mcpRefreshMaxTokens; i++ {
		next := sha256.Sum256(fmt.Appendf(nil, "token-%d", i))
		if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, current, next); err != nil {
			t.Fatal(err)
		}
		current = next
	}
	if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, current, digest); !errors.Is(err, errMCPRefreshCapacity) {
		t.Fatalf("rotation cap: %v", err)
	}
	refreshCount(t, s.db, "mcp_oauth_refresh_tokens", mcpRefreshMaxTokens)
	var after int64
	if err := s.db.QueryRow(`SELECT expires FROM mcp_oauth_refresh_families WHERE id=?`, id).Scan(&after); err != nil || after != expiry {
		t.Fatalf("rotation extended lifetime: %d != %d: %v", after, expiry, err)
	}
	// Replay evidence is still present at capacity.
	if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, digest, current); !errors.Is(err, errMCPRefreshReplay) {
		t.Fatalf("replay at capacity: %v", err)
	}
	// Populate capacity in one transaction, without 10,000 fsyncs.
	refreshExec(t, s.db, `WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?)
 INSERT INTO mcp_oauth_refresh_families(owner,person,client,resource,generation,expires)
 SELECT ?,?,?,?,?,? FROM n`, mcpRefreshMaxFamilies, refreshTestBinding.OwnerID, refreshTestBinding.PersonID, refreshTestBinding.ClientID, refreshTestBinding.Resource, refreshTestBinding.Generation, time.Now().Add(time.Hour).Unix())
	if _, err := s.createRefreshFamily(t.Context(), refreshTestBinding, digest, time.Now().Add(time.Hour)); !errors.Is(err, errMCPRefreshCapacity) {
		t.Fatalf("family cap: %v", err)
	}
	refreshCount(t, s.db, "mcp_oauth_refresh_families", mcpRefreshMaxFamilies)
	refreshExec(t, s.db, `UPDATE mcp_oauth_refresh_families SET expires=0`)
	createTestRefresh(t, s, "after-cleanup") // creation reclaims expired capacity
	refreshCount(t, s.db, "mcp_oauth_refresh_families", 1)
}

func TestMCPRefreshCancellationAndRollback(t *testing.T) {
	s, _ := refreshFixture(t)
	id := createTestRefresh(t, s, "first")
	first, second := sha256.Sum256([]byte("first")), sha256.Sum256([]byte("second"))
	// Force failure after the old digest has been marked spent.
	refreshExec(t, s.db, `CREATE TRIGGER fail_refresh_insert BEFORE INSERT ON mcp_oauth_refresh_tokens BEGIN SELECT RAISE(ABORT,'synthetic insertion failure'); END`)
	if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); err == nil {
		t.Fatal("failed insertion succeeded")
	}
	if _, err := s.createRefreshFamily(t.Context(), refreshTestBinding, second, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("failed family creation succeeded")
	}
	refreshCount(t, s.db, "mcp_oauth_refresh_families", 1)
	refreshCount(t, s.db, "mcp_oauth_refresh_tokens", 1)
	refreshExec(t, s.db, `DROP TRIGGER fail_refresh_insert`)
	// A duplicate successor must roll back consumption too.
	if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, first); err == nil {
		t.Fatal("rotation to self succeeded")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.rotateRefresh(ctx, id, refreshTestBinding, first, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled rotation: %v", err)
	}
	if err := s.revokeRefreshFamily(ctx, id, refreshTestBinding); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled revocation: %v", err)
	}
	if err := s.cleanupRefreshFamilies(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cleanup: %v", err)
	}
	if _, err := s.createRefreshFamily(ctx, refreshTestBinding, second, time.Now().Add(time.Hour)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled creation: %v", err)
	}
	// Cancel a request actually waiting for the only SQLite connection.
	s.db.SetMaxOpenConns(1)
	holder, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback() }()
	waiting, cancelWaiting := context.WithCancel(t.Context())
	defer cancelWaiting()
	result := make(chan error, 1)
	waitsBefore := s.db.Stats().WaitCount
	go func() { result <- s.rotateRefresh(waiting, id, refreshTestBinding, first, second) }()
	deadline := time.Now().Add(5 * time.Second)
	for s.db.Stats().WaitCount == waitsBefore {
		if time.Now().After(deadline) {
			t.Fatal("rotation did not wait for connection")
		}
		time.Sleep(time.Millisecond)
	}
	cancelWaiting()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting cancellation: %v", err)
	}
	_ = holder.Rollback()
	if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); err != nil {
		t.Fatalf("failure consumed old digest: %v", err)
	}
	// Failure after token deletion must restore the entire family.
	refreshExec(t, s.db, `CREATE TRIGGER fail_refresh_delete BEFORE DELETE ON mcp_oauth_refresh_families BEGIN SELECT RAISE(ABORT,'synthetic deletion failure'); END`)
	if err := s.revokeRefreshFamily(t.Context(), id, refreshTestBinding); err == nil {
		t.Fatal("failed revocation succeeded")
	}
	if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); err == nil || errors.Is(err, errMCPRefreshReplay) {
		t.Fatalf("failed replay invalidation reported as committed: %v", err)
	}
	refreshExec(t, s.db, `DROP TRIGGER fail_refresh_delete`)
	if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, second, sha256.Sum256([]byte("third"))); err != nil {
		t.Fatalf("failed deletion lost successor: %v", err)
	}
}

func TestMCPRefreshMigrationRollback(t *testing.T) {
	db := openRefreshTestDB(t, filepath.Join(t.TempDir(), "refresh.db"))
	// A conflicting object forces a failure partway through the additive DDL.
	refreshExec(t, db, `CREATE VIEW mcp_oauth_refresh_expiry AS SELECT 1`)
	if _, err := newMCPOAuthStore(db); err == nil {
		t.Fatal("conflicting migration succeeded")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='mcp_oauth_refresh_families'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial migration survived: count=%d err=%v", count, err)
	}
	refreshExec(t, db, `DROP VIEW mcp_oauth_refresh_expiry`)
	newRefreshTestStore(t, db)
}

func TestMCPRefreshCancellationInsideTransaction(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// SQLite invokes this trigger after rotation has updated the old digest.
	// Cancellation must roll that update back, even if Exec finishes first.
	function := fmt.Sprintf("cancel_refresh_%d", time.Now().UnixNano())
	if err := sqlite.RegisterScalarFunction(function, 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
		cancel()
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	s, path := refreshFixture(t)
	id := createTestRefresh(t, s, "first")
	first, second := sha256.Sum256([]byte("first")), sha256.Sum256([]byte("second"))
	refreshExec(t, s.db, `CREATE TRIGGER cancel_refresh_insert BEFORE INSERT ON mcp_oauth_refresh_tokens BEGIN SELECT `+function+`(); END`)
	if err := s.rotateRefresh(ctx, id, refreshTestBinding, first, second); err == nil || ctx.Err() != context.Canceled {
		t.Fatalf("cancellation inside transaction: %v (context=%v)", err, ctx.Err())
	}
	// Reopen also checks recovery after database/sql discards a canceled connection.
	_ = s.db.Close()
	deadline := time.Now().Add(5 * time.Second)
	for s.db.Stats().OpenConnections != 0 {
		if time.Now().After(deadline) {
			t.Fatal("canceled connection did not finish closing")
		}
		time.Sleep(time.Millisecond)
	}
	s = newRefreshTestStore(t, openRefreshTestDB(t, path))
	refreshExec(t, s.db, `DROP TRIGGER cancel_refresh_insert`)
	if err := s.rotateRefresh(t.Context(), id, refreshTestBinding, first, second); err != nil {
		t.Fatalf("canceled transaction consumed old digest: %v", err)
	}
}

func TestMCPRefreshDigestOnly(t *testing.T) {
	s, path := refreshFixture(t)
	const sentinel = "SYNTHETIC-REFRESH-SECRET-DO-NOT-PERSIST-7a2f41"
	var logs refreshLogCapture
	oldOutput, oldFlags, oldSlog := log.Writer(), log.Flags(), slog.Default()
	log.SetOutput(&logs)
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer func() { slog.SetDefault(oldSlog); log.SetOutput(oldOutput); log.SetFlags(oldFlags) }()
	id := createTestRefresh(t, s, sentinel)
	digest := sha256.Sum256([]byte(sentinel))
	// Exercise both constraint errors and invalid-credential errors.
	for _, err := range []error{
		s.rotateRefresh(t.Context(), id, refreshTestBinding, digest, digest),
		s.rotateRefresh(t.Context(), id+100, refreshTestBinding, digest, digest),
	} {
		if err == nil || strings.Contains(err.Error(), sentinel) {
			t.Fatal("error missing or includes bearer secret")
		}
	}
	for _, table := range []string{"mcp_oauth_refresh_families", "mcp_oauth_refresh_tokens"} {
		rows, err := s.db.Query("SELECT * FROM " + table)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			for _, value := range values {
				var raw []byte
				if data, ok := value.([]byte); ok {
					raw = data
				} else {
					raw = fmt.Append(nil, value)
				}
				if bytes.Contains(raw, []byte(sentinel)) {
					t.Fatal("bearer secret in row")
				}
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		_ = rows.Close()
	}
	var stored []byte
	if err := s.db.QueryRow(`SELECT digest FROM mcp_oauth_refresh_tokens WHERE family=?`, id).Scan(&stored); err != nil || !bytes.Equal(stored, digest[:]) {
		t.Fatalf("stored digest mismatch: %v", err)
	}
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, path + "-wal", path + "-shm"} {
		data, err := os.ReadFile(file)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(sentinel)) {
			t.Fatal("bearer secret in SQLite file")
		}
	}
	if bytes.Contains(logs.Bytes(), []byte(sentinel)) {
		t.Fatal("bearer secret in logs")
	}
}
