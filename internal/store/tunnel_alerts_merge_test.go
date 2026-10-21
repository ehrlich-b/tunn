package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestTunnelAlertsAccountMerge(t *testing.T) {
	for _, foreignKeys := range []bool{false, true} {
		t.Run(fmt.Sprintf("foreignKeys=%v", foreignKeys), func(t *testing.T) {
			db, err := OpenLocal(filepath.Join(t.TempDir(), "merge.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			if foreignKeys {
				if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
					t.Fatal(err)
				}
			}
			accounts, alerts := NewAccountStore(db), NewTunnelAlertStore(db)
			ctx, now := context.Background(), time.Now().Truncate(time.Second)
			emails := []string{"first@example.invalid", "second@example.invalid"}
			names := []string{"first-merge", "second-merge"}
			owners := make([]string, 2)
			report := func(owner, name, op string) {
				t.Helper()
				if err := alerts.Report(ctx, owner, name, "generation", op, "lost", now); err != nil {
					t.Fatal(err)
				}
			}
			for i, email := range emails {
				a, err := accounts.FindOrCreateByEmails([]string{email}, "test")
				if err != nil {
					t.Fatal(err)
				}
				owners[i] = a.ID
				if _, err := alerts.Settings(ctx, a.ID, &TunnelAlertSettings{Enabled: true, ThresholdSeconds: 600}); err != nil {
					t.Fatal(err)
				}
				if err := accounts.ReserveSubdomain(a.ID, names[i]); err != nil {
					t.Fatal(err)
				}
				report(a.ID, names[i], "up")
				report(a.ID, names[i], "down")
			}
			// One delivered outage is already consuming the hourly budget at merge time.
			claimed, err := alerts.Claim(ctx, now.Add(600*time.Second))
			if err != nil || len(claimed) != 2 {
				t.Fatal(claimed, err)
			}
			if err := alerts.Delivered(ctx, claimed[0]); err != nil {
				t.Fatal(err)
			}
			merged, err := accounts.FindOrCreateByEmails(emails, "test")
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range claimed {
				var owner, session string
				var downSent, lastEmail int64
				if err := db.QueryRow("SELECT owner,session,down_sent,last_email FROM tunnel_availability WHERE tunnel=?", a.Tunnel).Scan(&owner, &session, &downSent, &lastEmail); err != nil {
					t.Fatal(err)
				}
				wantSent := int64(0)
				if a.Tunnel == claimed[0].Tunnel {
					wantSent = 1
				}
				if owner != merged.ID || session != "generation" || downSent != wantSent || lastEmail != a.Attempt {
					t.Fatalf("lost state: %s %s %d %d", owner, session, downSent, lastEmail)
				}
			}
			pending, err := alerts.Claim(ctx, now.Add(601*time.Second))
			if err != nil || len(pending) != 0 {
				t.Fatal("lost rate budget", pending, err)
			}
			// Delivery already in flight under the absorbed identity still completes.
			if err := alerts.Delivered(ctx, claimed[1]); err != nil {
				t.Fatal(err)
			}
			for i, owner := range owners {
				report(owner, names[i], "heartbeat")
			}
			recovered, err := alerts.Claim(ctx, now.Add(4200*time.Second))
			if err != nil || len(recovered) != 2 {
				t.Fatal("lost recovery", recovered, err)
			}
			for _, a := range recovered {
				if !a.Recovery || a.Owner != merged.ID {
					t.Fatal(a)
				}
				if err := alerts.Delivered(ctx, a); err != nil {
					t.Fatal(err)
				}
			}
			for i, owner := range owners {
				report(owner, names[i], "down")
			}
			outages, err := alerts.Claim(ctx, now.Add(7800*time.Second))
			if err != nil || len(outages) != 2 {
				t.Fatal("old publisher cannot report outage", outages, err)
			}
		})
	}
}

func TestTunnelAlertsMergePreferences(t *testing.T) {
	for _, both := range []bool{false, true} {
		t.Run(fmt.Sprint(both), func(t *testing.T) {
			db, err := OpenLocal(filepath.Join(t.TempDir(), "preferences.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			accounts, alerts := NewAccountStore(db), NewTunnelAlertStore(db)
			ctx := context.Background()
			emails := []string{"first@example.invalid", "second@example.invalid"}
			ids := make([]string, 2)
			for i, email := range emails {
				a, err := accounts.FindOrCreateByEmails([]string{email}, "test")
				if err != nil {
					t.Fatal(err)
				}
				ids[i] = a.ID
			}
			saved := TunnelAlertSettings{Enabled: false, ThresholdSeconds: 1200, OnGracefulStop: true}
			if _, err := alerts.Settings(ctx, ids[0], &saved); err != nil {
				t.Fatal(err)
			}
			if both {
				other := TunnelAlertSettings{Enabled: true, ThresholdSeconds: 42}
				if _, err := alerts.Settings(ctx, ids[1], &other); err != nil {
					t.Fatal(err)
				}
				saved.OnGracefulStop = false
			}
			merged, err := accounts.FindOrCreateByEmails(emails, "test")
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range append(ids, merged.ID) {
				got, err := alerts.Settings(ctx, id, nil)
				if err != nil || got != saved {
					t.Fatal(got, saved, err)
				}
			}
			var count int
			if err := db.QueryRow("SELECT count(*) FROM tunnel_alert_settings").Scan(&count); err != nil || count != 1 {
				t.Fatal(count, err)
			}
		})
	}
}
