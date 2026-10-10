package storage

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
)

func TestOpsPersistentStorageReadiness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunn.db")
	db, err := store.OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	s := NewLocalStorage(db)
	if err := s.CheckHealth(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.CheckHealth(ctx); err == nil {
		t.Fatal("readiness ignored canceled request")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHealth(context.Background()); err == nil {
		t.Fatal("closed persistent database remained ready")
	}
	db, err = store.OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s = NewLocalStorage(db)
	if err := s.CheckHealth(context.Background()); err != nil {
		t.Fatal("reopened persistent database not ready:", err)
	}
	if _, err := db.Exec("DROP TABLE accounts"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHealth(context.Background()); err == nil {
		t.Fatal("missing account schema remained ready")
	}
}
