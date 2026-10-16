package store

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"modernc.org/sqlite"
)

var cancellationFunctionID atomic.Uint64

func TestInitForTestSurvivesCanceledQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel from inside SQLite, then keep the statement running until the
	// driver's cancellation goroutine interrupts it. No timing window or sleep
	// is needed to ensure cancellation happens during a native query.
	function := fmt.Sprintf("cancel_test_query_%d", cancellationFunctionID.Add(1))
	if err := sqlite.RegisterScalarFunction(function, 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
		cancel()
		return int64(1), nil
	}); err != nil {
		t.Fatal(err)
	}

	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("INSERT INTO accounts(id,primary_email,created_at) VALUES('fixture','test@example.com',1)"); err != nil {
		t.Fatal(err)
	}

	// Pin the connection so its replacement can be observed explicitly.
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, queryErr := conn.ExecContext(ctx, fmt.Sprintf(`
		WITH RECURSIVE work(n) AS (
			SELECT %s() UNION ALL SELECT n+1 FROM work
		) SELECT sum(n) FROM work`, function))
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(queryErr, context.Canceled) {
		t.Fatalf("query error = %v, want context.Canceled", queryErr)
	}
	if got := db.Stats().OpenConnections; got != 0 {
		t.Fatalf("canceled connection was not discarded: %d open connections", got)
	}
	t.Log("mid-query cancellation discarded the sole SQLite connection")

	var email, marker string
	if err := db.QueryRow("SELECT primary_email FROM accounts WHERE id='fixture'").Scan(&email); err != nil {
		t.Fatalf("schema and fixture after connection replacement: %v", err)
	}
	if email != "test@example.com" {
		t.Fatalf("fixture email = %q", email)
	}
	if err := db.QueryRow("SELECT value FROM ops_fixture WHERE id=1").Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if marker != "disposable-local" {
		t.Fatalf("ops_fixture marker = %q", marker)
	}
}
