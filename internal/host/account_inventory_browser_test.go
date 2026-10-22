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
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
)

func TestAccountInventoryBrowserScreens(t *testing.T) {
	if os.Getenv("TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE") == "" {
		t.Skip("set TUNN_ACCOUNT_TUNNELS_PLAYWRIGHT_MODULE for browser captures")
	}
	f := newWebInspectorFixture(t, 0, 0)
	if err := f.local.UpdatePlan(context.Background(), f.tunnel.AccountID, "pro"); err != nil {
		t.Fatal(err)
	}
	type snapshot struct {
		HTML    string          `json:"html"`
		Listing json.RawMessage `json:"listing"`
		Count   int             `json:"count"`
		Partial bool            `json:"partial"`
	}
	snapshots := map[string]snapshot{}
	for _, count := range []int{0, 1, 8, storage.ProTunnelLimit} {
		for _, partial := range []bool{false, true} {
			f.p.tunnelServer.tunnels = map[string]*TunnelConnection{}
			for i := 0; i < count; i++ {
				name := fmt.Sprintf("customer-analytics-long-running-worker-%02d", i)
				f.p.tunnelServer.tunnels[name] = &TunnelConnection{TunnelID: name, AccountID: f.tunnel.AccountID, Connected: time.Now().Add(-2 * time.Hour), ClientVersion: "1.2.3", ClientHost: "linux/amd64"}
			}
			f.p.nodeClients = nil
			if partial {
				f.p.nodeClients = map[string]internalpb.InternalServiceClient{"offline": unavailableAccountTunnelPeer{}}
			}
			page := f.call("GET", "/account", nil, f.cookie, nil)
			listing := f.call("GET", "/api/account/tunnels", nil, f.cookie, nil)
			if page.Code != 200 || listing.Code != 200 {
				t.Fatalf("snapshot: %d %d", page.Code, listing.Code)
			}
			snapshots[fmt.Sprintf("account-%d-%v", count, partial)] = snapshot{page.Body.String(), listing.Body.Bytes(), count, partial}
		}
	}
	for _, provider := range []string{"google", "github", "email"} {
		f.p.config.GoogleClientID, f.p.config.GoogleClientSecret, f.p.config.GitHubClientID = "", "", ""
		if provider == "google" {
			f.p.config.GoogleClientID, f.p.config.GoogleClientSecret = "fixture-id", "fixture-secret"
		}
		if provider == "github" {
			f.p.config.GitHubClientID = "fixture-id"
		}
		page := f.call("GET", "/auth/login", nil, nil, nil)
		if page.Code != 200 {
			t.Fatal(page.Code)
		}
		snapshots["signin-"+provider] = snapshot{HTML: page.Body.String()}
	}
	// Snapshots use real authenticated handlers; assets retain their production
	// handler. The browser transport is entirely local and never signs in remotely.
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
	file := filepath.Join(t.TempDir(), "snapshots.json")
	if err := os.WriteFile(file, input, 0600); err != nil {
		t.Fatal(err)
	}
	evidence := os.Getenv("TUNN_ACCOUNT_TUNNELS_EVIDENCE")
	if evidence == "" {
		evidence = t.TempDir()
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("node", "../../scripts/integration-tests/account-inventory-screens.cjs", file, server.URL, evidence)
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("browser captures: %v", err)
	}
}
