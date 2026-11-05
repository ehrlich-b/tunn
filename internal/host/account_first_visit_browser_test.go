package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestAccountFirstVisitBrowser(t *testing.T) {
	if os.Getenv("TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE") == "" {
		t.Skip("set TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE for browser acceptance")
	}
	f := newWebInspectorFixture(t, 0, 0)
	type snapshot struct {
		HTML           string          `json:"html"`
		Listing        json.RawMessage `json:"listing"`
		Count          int             `json:"count"`
		Plan           string          `json:"plan"`
		UsageAvailable bool            `json:"usageAvailable"`
		Exhausted      bool            `json:"exhausted"`
	}
	snapshots := map[string]snapshot{}
	baseMeter := f.p.meter
	for _, tc := range []struct {
		name, plan  string
		count       int
		exhausted   bool
		priorUsage  bool
		unavailable bool
	}{
		{name: "empty", plan: "free"},
		{name: "prior-usage", plan: "free", priorUsage: true},
		{name: "usage-unavailable", plan: "free", unavailable: true},
		{name: "running", plan: "free", count: 1},
		{name: "over-limit", plan: "free", exhausted: true},
		{name: "busy", plan: "pro", count: 8},
		{name: "plan-limit", plan: "pro", count: storage.ProTunnelLimit},
	} {
		if tc.plan != "free" {
			if err := f.local.UpdatePlan(context.Background(), f.tunnel.AccountID, tc.plan); err != nil {
				t.Fatal(err)
			}
		}
		usage := &meterpb.Usage{}
		if tc.priorUsage {
			usage.TotalBytes, usage.AdmittedRequests = 1024, 1
		}
		if tc.exhausted {
			usage.TotalBytes, usage.AdmittedRequests = GetQuotaBytes(tc.plan)+1, 12500
		}
		export := &meterpb.ExportResponse{OwnerUsage: usage}
		if tc.priorUsage {
			export.Usage = []*meterpb.Usage{{Endpoint: "previous-tunnel", ResponseBytes: 1024, AdmittedRequests: 1}}
		}
		f.p.meter = onboardingMeter{Backend: baseMeter, usage: export}
		if tc.unavailable {
			f.p.meter = nil
		}
		f.p.tunnelServer.tunnels = map[string]*TunnelConnection{}
		for i := 0; i < tc.count; i++ {
			name := fmt.Sprintf("customer-billing-webhook-staging-service-%02d", i+1)
			f.p.tunnelServer.tunnels[name] = &TunnelConnection{TunnelID: name, TargetURL: "http", AccountID: f.tunnel.AccountID, Connected: time.Now().Add(-2 * time.Hour), ClientVersion: "1.2.3", ClientHost: "linux/amd64"}
		}
		page := f.call("GET", "/account", nil, f.cookie, nil)
		listing := f.call("GET", "/api/account/tunnels", nil, f.cookie, nil)
		if page.Code != 200 || listing.Code != 200 {
			t.Fatalf("%s: page %d listing %d", tc.name, page.Code, listing.Code)
		}
		snapshots[tc.name] = snapshot{page.Body.String(), listing.Body.Bytes(), tc.count, tc.plan, !tc.unavailable, tc.exhausted}
	}
	// Capture real authenticated handlers and serve production assets locally.
	handler := f.p.createHandler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "tunn.test"
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	input, err := json.Marshal(snapshots)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "first-visit.json")
	if err := os.WriteFile(file, input, 0600); err != nil {
		t.Fatal(err)
	}
	evidence := os.Getenv("TUNN_FIRST_VISIT_EVIDENCE")
	if evidence == "" {
		evidence = t.TempDir()
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "../../scripts/integration-tests/account-first-visit-browser.cjs", file, server.URL, evidence)
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("first-visit browser acceptance: %v", err)
	}
}
