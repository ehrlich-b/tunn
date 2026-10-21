package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// With TUNN_ALERT_UPGRADE_DB this also upgrades a database created by the
// previous release; the normal run checks fresh creation and repeat migration.
func TestTunnelAlertsMigration(t *testing.T) {
	path := os.Getenv("TUNN_ALERT_UPGRADE_DB")
	upgrade := path != ""
	if !upgrade {
		path = filepath.Join(t.TempDir(), "fresh.db")
	}
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = MigrateTunnelAlerts(db); err != nil {
		t.Fatal(err)
	}
	accounts := NewAccountStore(db)
	var account *Account
	if upgrade {
		account, err = accounts.GetByEmail("upgrade@example.invalid")
		if err != nil {
			t.Fatal(err)
		}
		owner, e := accounts.GetSubdomainOwner("upgrade-demo")
		if e != nil || owner != account.ID {
			t.Fatal("upgrade changed reservation", owner, e)
		}
		if account.Plan != "free" {
			t.Fatal("upgrade changed plan", account.Plan)
		}
	} else {
		account, err = accounts.FindOrCreateByEmails([]string{"upgrade@example.invalid"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		if err = accounts.ReserveSubdomain(account.ID, "upgrade-demo"); err != nil {
			t.Fatal(err)
		}
	}
	alerts := NewTunnelAlertStore(db)
	settings, err := alerts.Settings(context.Background(), account.ID, nil)
	if err != nil || settings.Enabled || settings.ThresholdSeconds != 600 || settings.OnGracefulStop {
		t.Fatal(settings, err)
	}
	claimed, err := alerts.Claim(context.Background(), time.Now().Add(24*time.Hour))
	if err != nil || len(claimed) != 0 {
		t.Fatal("never-up reservation alerted", claimed, err)
	}
	settings.Enabled = false
	settings.ThresholdSeconds = 42
	if _, err = alerts.Settings(context.Background(), account.ID, &settings); err != nil {
		t.Fatal(err)
	}
	if err = MigrateTunnelAlerts(db); err != nil {
		t.Fatal(err)
	}
	after, err := alerts.Settings(context.Background(), account.ID, nil)
	if err != nil || after != settings {
		t.Fatal("migration reset preference", after, err)
	}
	t.Logf("fresh=%v upgrade=%v: ownership, plan, defaults, never-up suppression and persisted preferences passed", !upgrade, upgrade)
}

func TestTunnelAlertsDurabilityAndClaims(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.db")
	db, err := OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	accounts := NewAccountStore(db)
	a, err := accounts.FindOrCreateByEmails([]string{"owner@example.invalid"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.ReserveSubdomain(a.ID, "durable-demo"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	alerts := NewTunnelAlertStore(db)
	if _, err = alerts.Settings(ctx, a.ID, &TunnelAlertSettings{Enabled: true, ThresholdSeconds: 600}); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"up", "down"} {
		if err = alerts.Report(ctx, a.ID, "durable-demo", "generation-one", op, "diagnosis", now); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	alerts = NewTunnelAlertStore(db)
	now = now.Add(10 * time.Minute)
	first, err := alerts.Claim(ctx, now)
	if err != nil || len(first) != 1 {
		t.Fatal(first, err)
	}
	second, err := alerts.Claim(ctx, now)
	if err != nil || len(second) != 0 {
		t.Fatal("duplicate claim", second, err)
	}
	// A worker that died after claiming cannot lose the outage notification.
	now = now.Add(time.Hour)
	retry, err := NewTunnelAlertStore(db).Claim(ctx, now)
	if err != nil || len(retry) != 1 || retry[0].Recovery {
		t.Fatal("uncompleted claim lost", retry, err)
	}
	if err = alerts.Delivered(ctx, retry[0]); err != nil {
		t.Fatal(err)
	}
	if err = alerts.Report(ctx, a.ID, "durable-demo", "generation-two", "up", "", now); err != nil {
		t.Fatal(err)
	}
	// A replacement store handle observes the durable hourly rate limit.
	reopened := NewTunnelAlertStore(db)
	claimed, err := reopened.Claim(ctx, now.Add(time.Hour-time.Second))
	if err != nil || len(claimed) != 0 {
		t.Fatal(claimed, err)
	}
	claimed, err = reopened.Claim(ctx, now.Add(time.Hour))
	if err != nil || len(claimed) != 1 || !claimed[0].Recovery {
		t.Fatal(claimed, err)
	}
	// Releasing a name removes its history; a future owner never inherits mail.
	if err = NewAccountStore(db).ReleaseSubdomain(a.ID, "durable-demo"); err != nil {
		t.Fatal(err)
	}
	claimed, err = alerts.Claim(ctx, now.Add(2*time.Hour))
	if err != nil || len(claimed) != 0 {
		t.Fatal(claimed, err)
	}
}

func TestTunnelAlertsDefaultOnlyUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// This is the settings schema shipped before alerts became opt-in.
	_, err = db.Exec(`CREATE TABLE accounts (
 id TEXT PRIMARY KEY, primary_email TEXT NOT NULL,
 plan TEXT NOT NULL DEFAULT 'free', created_at INTEGER NOT NULL);
CREATE TABLE tunnel_alert_settings (
 account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 enabled INTEGER NOT NULL DEFAULT 1,
 threshold_seconds INTEGER NOT NULL DEFAULT 600 CHECK(threshold_seconds BETWEEN 1 AND 604800),
 on_graceful_stop INTEGER NOT NULL DEFAULT 0
);
INSERT INTO accounts VALUES('on','on@example.invalid','free',123),('off','off@example.invalid','free',456),('implicit','implicit@example.invalid','free',789);
INSERT INTO tunnel_alert_settings VALUES('on',1,42,1),('off',0,1200,0);
INSERT INTO tunnel_alert_settings(account_id) VALUES('implicit');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		db, err = OpenLocal(path)
		if err != nil {
			t.Fatal(err)
		}
		alerts := NewTunnelAlertStore(db)
		for id, want := range map[string]TunnelAlertSettings{
			"on":       {Enabled: true, ThresholdSeconds: 42, OnGracefulStop: true},
			"off":      {ThresholdSeconds: 1200},
			"implicit": {Enabled: true, ThresholdSeconds: 600},
		} {
			got, err := alerts.Settings(context.Background(), id, nil)
			if err != nil || got != want {
				t.Fatalf("pass %d: %s changed: %+v want %+v: %v", pass, id, got, want, err)
			}
		}
		var integrity string
		if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
			t.Fatal(integrity, err)
		}
		var writable, before, after int
		if err := db.QueryRow("PRAGMA writable_schema").Scan(&writable); err != nil || writable != 0 {
			t.Fatal("schema editing left enabled", writable, err)
		}
		if err := db.QueryRow("PRAGMA schema_version").Scan(&before); err != nil {
			t.Fatal(err)
		}
		if err := MigrateTunnelAlerts(db); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow("PRAGMA schema_version").Scan(&after); err != nil || before != after {
			t.Fatal("repeat migration changed schema", before, after, err)
		}
		a, err := NewAccountStore(db).FindOrCreateByEmails([]string{"new@example.invalid"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT OR IGNORE INTO tunnel_alert_settings(account_id) VALUES(?)", a.ID); err != nil {
			t.Fatal(err)
		}
		got, err := alerts.Settings(context.Background(), a.ID, nil)
		if err != nil || got.Enabled || got.ThresholdSeconds != 600 || got.OnGracefulStop {
			t.Fatal("column default did not change", got, err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTunnelAlertsNoSettingsSuppressesPendingRecovery(t *testing.T) {
	db, err := InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	accounts := NewAccountStore(db)
	a, err := accounts.FindOrCreateByEmails([]string{"unsaved@example.invalid"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.ReserveSubdomain(a.ID, "unsaved-demo"); err != nil {
		t.Fatal(err)
	}
	alerts := NewTunnelAlertStore(db)
	ctx, now := context.Background(), time.Now().Truncate(time.Second)
	for _, op := range []string{"up", "down"} {
		if err := alerts.Report(ctx, a.ID, "unsaved-demo", "generation", op, "", now); err != nil {
			t.Fatal(err)
		}
	}
	claimed, err := alerts.Claim(ctx, now.Add(24*time.Hour))
	if err != nil || len(claimed) != 0 {
		t.Fatal("unsaved account received offline alert", claimed, err)
	}
	// Model an outage emailed under the previous release's implicit opt-in.
	if _, err := db.Exec("UPDATE tunnel_availability SET online=1,down_sent=1 WHERE tunnel='unsaved-demo'"); err != nil {
		t.Fatal(err)
	}
	claimed, err = alerts.Claim(ctx, now.Add(24*time.Hour))
	if err != nil || len(claimed) != 0 {
		t.Fatal("unsaved account received pending recovery", claimed, err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM tunnel_alert_settings").Scan(&count); err != nil || count != 0 {
		t.Fatal("reading defaults saved a preference", count, err)
	}
}
