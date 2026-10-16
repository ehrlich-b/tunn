package store

import (
	"context"
	"testing"
	"time"
)

func TestInitForTestCommitWaitsForReader(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	writer, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reader, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	readTx, err := reader.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer readTx.Rollback()
	var value string
	if err := readTx.QueryRowContext(ctx, "SELECT value FROM ops_fixture WHERE id=1").Scan(&value); err != nil {
		t.Fatal(err)
	}
	writeTx, err := writer.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writeTx.Rollback()
	if _, err := writeTx.ExecContext(ctx, "UPDATE ops_fixture SET value='committed' WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	// The reader's shared lock must delay COMMIT, then let it succeed.
	committed := make(chan error, 1)
	go func() { committed <- writeTx.Commit() }()
	select {
	case err := <-committed:
		t.Fatalf("COMMIT returned before the reader released its lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := <-committed; err != nil {
		t.Fatalf("COMMIT after releasing reader: %v", err)
	}
	if err := reader.QueryRowContext(ctx, "SELECT value FROM ops_fixture WHERE id=1").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "committed" {
		t.Fatalf("value after COMMIT = %q, want committed", value)
	}
}
