package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/store"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestAccountMonthlyLimit(t *testing.T) {
	for _, plan := range []string{"free", "pro"} {
		for _, count := range []int{0, 1, 8} {
			for _, usage := range []int64{99, 100, 101} {
				t.Run(fmt.Sprintf("%s/%d/%d", plan, count, usage), func(t *testing.T) {
					f := newWebInspectorFixture(t, 0, 0)
					if err := store.NewAccountStore(f.db).UpdatePlan(f.tunnel.AccountID, plan); err != nil {
						t.Fatal(err)
					}
					f.p.config.OwnerMonthlyBytes = 100
					f.p.meter = onboardingMeter{Backend: f.p.meter, usage: &meterpb.ExportResponse{OwnerUsage: &meterpb.Usage{TotalBytes: usage, AdmittedRequests: 10000001}}}
					delete(f.p.tunnelServer.tunnels, f.tunnel.TunnelID)
					for i := 0; i < count; i++ {
						name := fmt.Sprintf("customer-billing-webhook-staging-service-%d", i)
						f.p.tunnelServer.tunnels[name] = &TunnelConnection{TunnelID: name, TargetURL: "http", AccountID: f.tunnel.AccountID}
					}
					page := f.call("GET", "/account", nil, f.cookie, nil)
					body := page.Body.String()
					if page.Code != 200 {
						t.Fatalf("status %d", page.Code)
					}
					notice := strings.Index(body, `id="monthly-limit"`)
					if (notice >= 0) != (usage >= 100) {
						t.Fatalf("notice at %d for usage %d", notice, usage)
					}
					if notice >= 0 && (notice > strings.Index(body, `id="live-tunnels-title"`) || !strings.Contains(body[notice:], "UTC") || !strings.Contains(body[notice:], "tunn usage")) {
						t.Fatal("notice missing guidance or misplaced")
					}
					if !strings.Contains(body, "Requests: unlimited (fair use)") {
						t.Fatal("unlimited requests missing")
					}
					if usage >= 100 && strings.Contains(body, "Start one with") {
						t.Fatal("encourages starting tunnel while exhausted")
					}
					if usage < 100 && !strings.Contains(body, "Start one with") {
						t.Fatal("missing empty tunnel guidance")
					}
					if dir := os.Getenv("TUNN_MONTHLY_RENDER_DIR"); dir != "" {
						if err := os.MkdirAll(dir, 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%d-%d.html", plan, count, usage)), page.Body.Bytes(), 0600); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func TestAccountMonthlyLimitPlanAndBilling(t *testing.T) {
	for _, plan := range []string{"free", "pro"} {
		for _, delta := range []int64{-1, 0, 1} {
			t.Run(fmt.Sprintf("%s/%d", plan, delta), func(t *testing.T) {
				f := newWebInspectorFixture(t, 0, 0)
				if err := store.NewAccountStore(f.db).UpdatePlan(f.tunnel.AccountID, plan); err != nil {
					t.Fatal(err)
				}
				f.p.meter = onboardingMeter{Backend: f.p.meter, usage: &meterpb.ExportResponse{OwnerUsage: &meterpb.Usage{TotalBytes: GetQuotaBytes(plan) + delta}}}
				body := f.call("GET", "/account?billing=return", nil, f.cookie, nil).Body.String()
				if strings.Contains(body, `id="monthly-limit"`) != (delta >= 0) {
					t.Fatal("plan quota boundary")
				}
				if delta >= 0 && (!strings.Contains(body, "Subscription status") || strings.Contains(body, `<a href="/pricing">Compare plans</a>.</p>`)) {
					t.Fatal("pending guidance")
				}
			})
		}
	}
	t.Run("unavailable usage", func(t *testing.T) {
		f := newWebInspectorFixture(t, 0, 0)
		f.p.meter = nil
		body := f.call("GET", "/account", nil, f.cookie, nil).Body.String()
		if strings.Contains(body, `id="monthly-limit"`) || !strings.Contains(body, "Start one with") {
			t.Fatal("unavailable usage must not imply exhaustion")
		}
	})
	t.Run("checkout unavailable", func(t *testing.T) {
		f := newWebInspectorFixture(t, 0, 0)
		f.p.config.OwnerMonthlyBytes = 100
		f.p.meter = onboardingMeter{Backend: f.p.meter, usage: &meterpb.ExportResponse{OwnerUsage: &meterpb.Usage{TotalBytes: 100}}}
		body := f.call("GET", "/account", nil, f.cookie, nil).Body.String()
		if !strings.Contains(body, `id="monthly-limit"`) || !strings.Contains(body, "Checkout is not available yet") {
			t.Fatal("unavailable billing guidance")
		}
	})
}
