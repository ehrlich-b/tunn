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
		HTML      string          `json:"html"`
		Listing   json.RawMessage `json:"listing"`
		Count     int             `json:"count"`
		Plan      string          `json:"plan"`
		Exhausted bool            `json:"exhausted"`
	}
	snapshots := map[string]snapshot{}
	for _, tc := range []struct {
		name, plan string
		count      int
		exhausted  bool
	}{
		{"empty", "free", 0, false},
		{"running", "free", 1, false},
		{"over-limit", "free", 0, true},
		{"busy", "pro", 8, false},
		{"plan-limit", "pro", storage.ProTunnelLimit, false},
	} {
		if tc.plan != "free" {
			if err := f.local.UpdatePlan(context.Background(), f.tunnel.AccountID, tc.plan); err != nil {
				t.Fatal(err)
			}
		}
		usage := &meterpb.Usage{}
		if tc.exhausted {
			usage.TotalBytes, usage.AdmittedRequests = GetQuotaBytes(tc.plan)+1, 12500
		}
		f.p.meter = onboardingMeter{Backend: f.p.meter, usage: &meterpb.ExportResponse{OwnerUsage: usage}}
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
		snapshots[tc.name] = snapshot{page.Body.String(), listing.Body.Bytes(), tc.count, tc.plan, tc.exhausted}
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
