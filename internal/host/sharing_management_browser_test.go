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

	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

// Capture the actual authenticated handler with realistic ledger volume. The
// browser serves these responses locally, without contacting a live relay.
func TestSharingManagementBrowser(t *testing.T) {
	python := os.Getenv("TUNN_SHARE_BROWSER_PYTHON")
	if python == "" {
		t.Skip("set TUNN_SHARE_BROWSER_PYTHON for layout acceptance")
	}
	evidence := os.Getenv("TUNN_SHARING_EVIDENCE")
	if evidence == "" {
		evidence = t.TempDir()
	}
	if err := os.MkdirAll(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	type snapshot struct {
		Name, HTML      string
		Tunnels, People int
	}
	var snapshots []snapshot
	for _, scenario := range []struct {
		name            string
		tunnels, people int
		selected        bool
		mode            string
	}{
		{"sharing", 8, 5, true, "private"}, {"sharing-list", 8, 5, false, "private"},
		{"sharing-empty", 0, 0, false, "private"}, {"sharing-one", 1, 1, true, "private"},
		{"sharing-plan-limit", storage.ProTunnelLimit, 5, true, "private"},
		{"sharing-people-limit", 8, metering.MaxResourcePeople, true, "private"},
		{"sharing-public", 8, 0, true, "public"},
	} {
		p, tunnel, ledger, _ := meteringRelay(t, false, "hello")
		p.config.PublicAddr = "sharing.test"
		endpoint := "application-preview-for-design-team"
		for i := 0; i < scenario.tunnels; i++ {
			name := endpoint
			if i > 0 {
				name = fmt.Sprintf("regional-background-worker-%02d", i)
			}
			initial := []string{}
			if i == 0 {
				for j := 0; j < scenario.people; j++ {
					initial = append(initial, fmt.Sprintf("person-%02d.long-name@example.com", j+1))
				}
			}
			_, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: name, Mode: scenario.mode, InitialEmails: initial})
			if err != nil {
				t.Fatal(err)
			}
		}
		if scenario.people > 0 {
			_, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: tunnel.AccountID, Endpoint: endpoint, Email: "person-01.long-name@example.com", ExpiresAt: time.Now().Add(7 * 24 * time.Hour).UnixMilli()})
			if err != nil {
				t.Fatal(err)
			}
		}
		if scenario.tunnels > 0 {
			for i, reason := range []string{"authentication_required", "allowlist_denied", "allowed", "unknown_internal_reason"} {
				_, err := ledger.Admit(context.Background(), &mp.Event{RequestId: fmt.Sprintf("%032x", i+1), Owner: tunnel.AccountID, Endpoint: endpoint, Caller: "anonymous", StartedAt: time.Now().UnixMilli(), Reason: reason, Allowed: reason == "allowed"})
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		path := "https://tunn.test/account/sharing"
		if scenario.selected {
			path += "?tunnel=" + endpoint
		}
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, p, "owner@example.com")})
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", scenario.name, w.Code, w.Body)
		}
		snapshots = append(snapshots, snapshot{scenario.name, w.Body.String(), scenario.tunnels, scenario.people})
	}
	input := filepath.Join(evidence, "snapshots.json")
	data, err := json.Marshal(snapshots)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "../../scripts/integration-tests/sharing-management-browser.py", input, evidence)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
}
