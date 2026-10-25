package host

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestLimitsBandwidthOnlyRelay(t *testing.T) {
	for _, plan := range []string{"free", "pro"} {
		for _, streaming := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/streaming=%t", plan, streaming), func(t *testing.T) {
				p, tunnel, _, _ := meteringRelay(t, streaming, "ok")
				db, err := store.InitForTest()
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err := db.Exec(`INSERT INTO accounts(id,primary_email,plan,created_at) VALUES(?,?,?,1)`, tunnel.AccountID, tunnel.CreatorEmail, plan); err != nil {
					t.Fatal(err)
				}
				ledger, err := metering.New(db, metering.WithAccountPlans())
				if err != nil {
					t.Fatal(err)
				}
				p.meter, p.planMeter = ledger, true
				month := time.Now().UTC().Format("2006-01")
				oldLimit := int64(1000000)
				if plan == "pro" {
					oldLimit = 10000000
				}
				if _, err := db.Exec(`INSERT INTO meter_usage(owner,endpoint,caller,month,requests,admitted) VALUES(?,'old','anonymous',?,?,?)`, tunnel.AccountID, month, oldLimit+1, oldLimit+1); err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 2; i++ {
					rec := httptest.NewRecorder()
					p.createHandler().ServeHTTP(rec, relayRequest(relayJWT(t, p, "alice@example.com"), ""))
					if rec.Code != 200 || rec.Body.String() != "ok" {
						t.Fatalf("past old request limit: %d %s", rec.Code, rec.Body)
					}
				}
				out, err := ledger.Export(context.Background(), &meterpb.ExportRequest{Owner: tunnel.AccountID, Month: month})
				if err != nil || out.OwnerUsage.AdmittedRequests != oldLimit+3 || out.OwnerUsage.TotalBytes != 4 {
					t.Fatalf("counting: %v %v", out, err)
				}
				if _, err := db.Exec(`UPDATE meter_usage SET response_bytes=? WHERE owner=? AND endpoint='old'`, GetQuotaBytes(plan)-4, tunnel.AccountID); err != nil {
					t.Fatal(err)
				}
				rec := httptest.NewRecorder()
				p.createHandler().ServeHTTP(rec, relayRequest(relayJWT(t, p, "alice@example.com"), ""))
				if rec.Code != 429 || rec.Header().Get("Tunn-Limit-Reason") != "owner_byte_budget" {
					t.Fatalf("transfer limit: %d %v", rec.Code, rec.Header())
				}
			})
		}
	}
}

func TestLimitsBandwidthOnlyPages(t *testing.T) {
	for _, plan := range []string{"free", "pro"} {
		for _, count := range []int{0, 1, 5, 8, 25} {
			t.Run(fmt.Sprintf("%s/%d", plan, count), func(t *testing.T) {
				db, err := store.InitForTest()
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				local := storage.NewLocalStorage(db)
				a, err := local.FindOrCreateByEmails(context.Background(), []string{"owner+demo@example.com"}, "fixture")
				if err != nil {
					t.Fatal(err)
				}
				if err := store.NewAccountStore(db).UpdatePlan(a.ID, plan); err != nil {
					t.Fatal(err)
				}
				ledger, err := metering.New(db, metering.WithAccountPlans())
				if err != nil {
					t.Fatal(err)
				}
				month := time.Now().UTC().Format("2006-01")
				for i := 0; i < count; i++ {
					if _, err := db.Exec(`INSERT INTO meter_usage(owner,endpoint,caller,month,requests,admitted,response_bytes) VALUES(?,?,'anonymous',?,1250000,1250000,325000000)`, a.ID, fmt.Sprintf("regional-background-worker-%02d", i+1), month); err != nil {
						t.Fatal(err)
					}
				}
				p := &ProxyServer{Domain: "tunn.to", storage: local, meter: ledger, config: &config.Config{Environment: config.EnvProd, Domain: "tunn.to", JWTSecret: "fixture-limits-signing-key"}}
				// An operator abuse ceiling never becomes an advertised plan allowance.
				p.config.OwnerMonthlyRequests = 4000
				for _, path := range []string{"/account", "/pricing"} {
					rec := revenueRequest(t, p, path, path == "/account")
					html := rec.Body.String()
					if rec.Code != 200 || !strings.Contains(html, "unlimited (fair use)") {
						t.Fatalf("%s: %d %s", path, rec.Code, html)
					}
					for _, old := range []string{"of 1M", "of 10M", "1M requests", "10M requests", "4K requests"} {
						if strings.Contains(html, old) {
							t.Fatalf("old request allowance %q on %s", old, path)
						}
					}
					if path == "/account" {
						start := strings.Index(html, `aria-label="Request usage"`)
						if start < 0 {
							t.Fatal("request card missing")
						}
						end := strings.Index(html[start:], `<div class="readings">`)
						if end < 0 {
							t.Fatal("request card missing")
						}
						card := html[start : start+end]
						if !strings.Contains(card, "Requests: unlimited (fair use)") || !strings.Contains(card, formatCount(int64(count)*1250000)+"<small>this month</small>") || strings.Contains(card, "usage-bar") || strings.Contains(card, `class="pct"`) {
							t.Fatal("request card", card)
						}
						if !strings.Contains(html, fmt.Sprintf("of %s</small>", formatBytes(GetQuotaBytes(plan)))) {
							t.Fatal("transfer allowance changed")
						}
					}
					if dir := os.Getenv("TUNN_LIMITS_RENDER_DIR"); dir != "" {
						if err := os.MkdirAll(dir, 0700); err != nil {
							t.Fatal(err)
						}
						name := fmt.Sprintf("%s-%s-%d.html", strings.TrimPrefix(path, "/"), plan, count)
						if err := os.WriteFile(filepath.Join(dir, name), rec.Body.Bytes(), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			})
		}
	}
}
