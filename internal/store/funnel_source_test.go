package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
)

func TestFunnelSourceMerge(t *testing.T) {
	for _, source := range []string{"alt", "direct", "other"} {
		t.Run(source, func(t *testing.T) {
			db, err := InitForTest()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			accounts := NewAccountStore(db)
			survivor, err := accounts.FindOrCreateByEmailsContext(common.WithFunnelSource(context.Background(), source), []string{"survivor@example.invalid"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			retired, err := accounts.FindOrCreateByEmailsContext(common.WithFunnelSource(context.Background(), "docs"), []string{"retired@example.invalid"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			oldTime := "2026-10-23T00:00:00Z"
			if _, err = db.Exec(`UPDATE funnel_events SET occurred_at=? WHERE account_hash=?`, oldTime, funnelAccountHash(context.Background(), db, retired.ID)); err != nil {
				t.Fatal(err)
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			merged, err := accounts.mergeAccounts(tx, []*Account{survivor, retired})
			if err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			var got, stamp string
			var count int
			err = db.QueryRow(`SELECT count(*),source,occurred_at FROM funnel_events WHERE stage='signup'`).Scan(&count, &got, &stamp)
			if err != nil || count != 1 || got != source || stamp != oldTime || merged.ID != survivor.ID {
				t.Fatalf("merge: count=%d source=%q stamp=%q account=%+v err=%v", count, got, stamp, merged, err)
			}
		})
	}
}

func TestFunnelSourceReport(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	data, err := os.ReadFile("../../testdata/funnel_sources.json")
	if err != nil {
		t.Fatal(err)
	}
	var want []FunnelSourceDay
	if err = json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	for i, row := range want {
		for j := 0; j < row.Count; j++ {
			account := fmt.Sprintf("fixture-%d-%d", i, j)
			RecordFunnel(common.WithFunnelSource(context.Background(), row.Source), db, "signup", account)
			if _, err = db.Exec(`UPDATE funnel_events SET occurred_at=? WHERE account_hash=?`, row.Day+"T12:00:00Z", funnelAccountHash(context.Background(), db, account)); err != nil {
				t.Fatal(err)
			}
		}
	}
	report, err := NewOperationsStore(db, nil).FunnelReport(context.Background(), operationsPrincipal(t, "*"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.SignupSources, want) {
		t.Fatalf("report=%+v want=%+v err=%v", report, want, err)
	}
	if !reflect.DeepEqual(report.Days, []FunnelDay{{Day: "2026-10-23", Stage: "signup", Count: 4}, {Day: "2026-10-24", Stage: "signup", Count: 5}}) {
		t.Fatalf("stage totals changed: %+v", report.Days)
	}
}

func TestFunnelSourceMigration(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE funnel_events(stage TEXT NOT NULL,account_hash TEXT NOT NULL,occurred_at TEXT NOT NULL,PRIMARY KEY(stage,account_hash)); INSERT INTO funnel_events VALUES('signup','legacy-hash','2026-10-23T12:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = initSchema(db); err != nil {
			t.Fatal(err)
		}
	}
	var source, hash, stamp string
	if err = db.QueryRow(`SELECT source,account_hash,occurred_at FROM funnel_events`).Scan(&source, &hash, &stamp); err != nil || source != "other" || hash != "legacy-hash" || stamp != "2026-10-23T12:00:00Z" {
		t.Fatal(source, hash, stamp, err)
	}
	if _, err = db.Exec(`UPDATE funnel_events SET source='https://example.invalid/private'`); err == nil {
		t.Fatal("database accepted a non-token source")
	}
}
