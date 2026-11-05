package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

func nameAction(t *testing.T, f *mcpOAuthFixture, c *http.Cookie, old, new, confirm, origin string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "https://tunn.test/account/names", nil)
	r.AddCookie(c)
	csrf, err := f.p.createCSRFToken(r, accountNamesPath)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf_token": {csrf}, "old_name": {old}, "new_name": {new}, "confirm_name": {confirm}}
	r = httptest.NewRequest("POST", "https://tunn.test/account/names", strings.NewReader(form.Encode()))
	r.AddCookie(c)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", origin)
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	return w
}

func TestSalesNameOwnership(t *testing.T) {
	f := newMCPOAuthFixture(t)
	local := f.p.storage.(*storage.LocalStorage)
	ctx := context.Background()
	owner, err := local.GetAccountByEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err = local.AccountStore().ReserveSubdomain(owner.ID, "kept-preview"); err != nil {
		t.Fatal(err)
	}
	registration, err := local.RegisterTunnel(ctx, "temporary-preview", owner.ID, "")
	if err != nil || !registration.Allowed {
		t.Fatal(registration, err)
	}
	c := emailSession(t, f.p, owner.PrimaryEmail)
	page := f.request("GET", "https://tunn.test/account/names", "", "", "", c)
	for _, s := range []string{"kept-preview", "temporary-preview", "Kept · Offline", "Temporary · Connected", "someone else can claim it"} {
		if !strings.Contains(page.Body.String(), s) {
			t.Fatal("missing", s, page.Body)
		}
	}
	if w := f.request("GET", "https://tunn.test/account/names", "", "", "", nil); w.Code != 302 {
		t.Fatal(w.Code)
	}
	other, err := local.FindOrCreateByEmails(ctx, []string{"other@example.invalid"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if w := f.request("GET", "https://tunn.test/account/names", "", "", "", emailSession(t, f.p, other.PrimaryEmail)); strings.Contains(w.Body.String(), "kept-preview") || strings.Contains(w.Body.String(), "temporary-preview") {
		t.Fatal("leaked names")
	}
}

func TestSalesNameReplacement(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprint("edge=", remote), func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			local := f.p.storage.(*storage.LocalStorage)
			ctx := context.Background()
			a, err := local.GetAccountByEmail(ctx, "owner@example.com")
			if err != nil {
				t.Fatal(err)
			}
			if err = local.AccountStore().ReserveSubdomain(a.ID, "old-preview"); err != nil {
				t.Fatal(err)
			}
			other, err := local.FindOrCreateByEmails(ctx, []string{"other@example.invalid"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if err = local.AccountStore().ReserveSubdomain(other.ID, "occupied-preview"); err != nil {
				t.Fatal(err)
			}
			c := emailSession(t, f.p, a.PrimaryEmail)
			otherCookie := emailSession(t, f.p, other.PrimaryEmail)
			fixtureDB := f.p.devices.db
			if remote {
				f.p.config.NodeSecret = "names-local-cluster"
				authority := httptest.NewTLSServer(f.p.createHandler())
				defer authority.Close()
				edge := securityProxy(securityReplicaStorage(t, local))
				edge.config.Insecure = true
				edge.config.NodeSecret = f.p.config.NodeSecret
				edge.loginNodeHTTPAddr = strings.TrimPrefix(authority.URL, "https://")
				f = &mcpOAuthFixture{p: edge}
			}
			check := func(w *httptest.ResponseRecorder, want int) {
				t.Helper()
				if w.Code != want {
					t.Fatal(w.Code, w.Body)
				}
				owner, err := local.AccountStore().GetSubdomainOwner("old-preview")
				if err != nil || owner != a.ID {
					t.Fatal("original lost", owner, err)
				}
			}
			check(nameAction(t, f, c, "old-preview", "new-preview", "wrong", "https://tunn.test"), 409)
			check(nameAction(t, f, otherCookie, "old-preview", "new-preview", "old-preview", "https://tunn.test"), 409)
			check(nameAction(t, f, c, "old-preview", "new-preview", "old-preview", "https://evil.invalid"), 403)
			check(nameAction(t, f, c, "old-preview", "occupied-preview", "old-preview", "https://tunn.test"), 409)
			check(nameAction(t, f, c, "old-preview", "api", "old-preview", "https://tunn.test"), 409)
			check(f.request("POST", "https://tunn.test/account/names", "old_name=old-preview&new_name=new-preview&confirm_name=old-preview", "application/x-www-form-urlencoded", "", c), 403)
			reg, err := local.RegisterTunnel(ctx, "other-active-preview", other.ID, "")
			if err != nil || !reg.Allowed {
				t.Fatal(reg, err)
			}
			check(nameAction(t, f, c, "old-preview", "other-active-preview", "old-preview", "https://tunn.test"), 409)

			for _, name := range []string{"old-preview", "new-preview"} {
				reg, err := local.RegisterTunnel(ctx, name, a.ID, "")
				if err != nil || !reg.Allowed {
					t.Fatal(reg, err)
				}
				check(nameAction(t, f, c, "old-preview", "new-preview", "old-preview", "https://tunn.test"), 409)
				if err = local.UnregisterTunnel(ctx, name); err != nil {
					t.Fatal(err)
				}
			}

			// Fail after the owned delete to prove rollback through the handler and edge.
			if _, err = fixtureDB.Exec(`CREATE TRIGGER fail_name BEFORE INSERT ON reserved_subdomains WHEN NEW.subdomain='failed-preview' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
				t.Fatal(err)
			}
			check(nameAction(t, f, c, "old-preview", "failed-preview", "old-preview", "https://tunn.test"), 409)

			w := nameAction(t, f, c, "old-preview", "new-preview", "old-preview", "https://tunn.test")
			if w.Code != 303 {
				t.Fatal(w.Code, w.Body)
			}
			if owner, err := local.AccountStore().GetSubdomainOwner("new-preview"); err != nil || owner != a.ID {
				t.Fatal(owner, err)
			}
			if err = local.AccountStore().ReserveSubdomain(a.ID, "second-name"); err == nil {
				t.Fatal("Free second reservation succeeded")
			}
		})
	}
}

func TestSalesNameReplacementHostBinding(t *testing.T) {
	f := newMCPOAuthFixture(t)
	local := f.p.storage.(*storage.LocalStorage)
	ctx := context.Background()
	a, err := local.GetAccountByEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err = local.AccountStore().ReserveSubdomain(a.ID, "host-preview"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.NewHostStore(f.p.devices.db); err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.devices.db.Exec(`INSERT INTO host_endpoints VALUES('host-preview',?,'laptop','http',0)`, a.ID); err != nil {
		t.Fatal(err)
	}
	if err = local.ReplaceAccountName(ctx, a.ID, "host-preview", "new-preview"); err == nil {
		t.Fatal("host binding renamed")
	}
	if owner, err := local.AccountStore().GetSubdomainOwner("host-preview"); err != nil || owner != a.ID {
		t.Fatal(owner, err)
	}
}

// Captures actual authenticated responses from disposable local accounts.
func TestSalesNameCapture(t *testing.T) {
	dir := os.Getenv("TUNN_NAMES_CAPTURE_DIR")
	if dir == "" {
		t.Skip("visual capture only")
	}
	type snapshot struct {
		Name, HTML string
		Count      int
	}
	var snapshots []snapshot
	for _, count := range []int{0, 1, 8, 10} {
		f := newMCPOAuthFixture(t)
		local := f.p.storage.(*storage.LocalStorage)
		ctx := context.Background()
		a, err := local.GetAccountByEmail(ctx, "owner@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if count > 1 {
			if err = local.AccountStore().UpdatePlan(a.ID, "pro"); err != nil {
				t.Fatal(err)
			}
		}
		for i := 0; i < count; i++ {
			if err = local.AccountStore().ReserveSubdomain(a.ID, fmt.Sprintf("customer-preview-long-project-name-%02d", i)); err != nil {
				t.Fatal(err)
			}
		}
		if count == 1 {
			if reg, err := local.RegisterTunnel(ctx, "temporary-customer-preview", a.ID, ""); err != nil || !reg.Allowed {
				t.Fatal(reg, err)
			}
		}
		c := emailSession(t, f.p, a.PrimaryEmail)
		w := f.request("GET", "https://tunn.test/account/names", "", "", "", c)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		snapshots = append(snapshots, snapshot{fmt.Sprintf("names-%d", count), w.Body.String(), count})
		if count == 1 {
			w = nameAction(t, f, c, "customer-preview-long-project-name-00", "new-preview", "wrong", "https://tunn.test")
			if w.Code != 409 {
				t.Fatal(w.Code, w.Body)
			}
			snapshots = append(snapshots, snapshot{"names-error", w.Body.String(), count})
		}
	}
	raw, err := json.MarshalIndent(snapshots, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "names-snapshots.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
}
