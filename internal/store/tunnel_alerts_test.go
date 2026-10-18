package store

import (
	"context"
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
	if err != nil || !settings.Enabled || settings.ThresholdSeconds != 600 || settings.OnGracefulStop {
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
