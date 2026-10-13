package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

func TestReviewCrossAccountDeviceIsolation(t *testing.T) {
	p := durableFixture(t)
	owner := durableLogin(t, p)
	_, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"other@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	cookie := securityCookie(t, p, "other@example.com")
	get := httptest.NewRequest("GET", "https://tunn.test/account/devices", nil)
	get.AddCookie(cookie)
	w := httptest.NewRecorder()
	p.handleDevices(w, get)
	if w.Code != 200 || strings.Contains(w.Body.String(), owner.Device) {
		t.Fatalf("other account listed device: %d", w.Code)
	}
	csrf, err := p.createCSRFToken(get, "/account/devices")
	if err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRequest("POST", "https://tunn.test/account/devices", strings.NewReader(url.Values{"device_id": {owner.Device}, "csrf_token": {csrf}}.Encode()))
	post.AddCookie(cookie)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://tunn.test")
	w = httptest.NewRecorder()
	p.handleDevices(w, post)
	if w.Code != 404 {
		t.Fatalf("other account revoked device: %d", w.Code)
	}
	w, _ = durableRefresh(p, owner.Refresh, strings.Repeat("a", 43))
	if w.Code != 200 {
		t.Fatal("owner device stopped working", w.Code)
	}
	t.Log("cross-account GET hides device; POST with valid other-account CSRF returns 404; owner still refreshes")
}

func TestReviewConcurrentRealClientRefresh(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		p.handleDeviceRefresh(w, r)
	}))
	defer server.Close()
	p.config.PublicAddr = strings.TrimPrefix(server.URL, "https://")
	dir := t.TempDir()
	t.Setenv("TUNN_CONFIG_DIR", dir)
	state := map[string]any{"server": server.URL, "access_token": token.Access, "refresh_token": token.Refresh, "device_id": token.Device, "expires_at": time.Now().Add(-time.Minute)}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var group sync.WaitGroup
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			access, manager, err := client.LoadTunnelToken(context.Background(), p.config.PublicAddr, true)
			if err != nil || access == "" || manager == nil {
				t.Errorf("client refresh: %v", err)
			}
		}()
	}
	close(start)
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent clients sent %d refreshes", calls.Load())
	}
	var revoked int64
	if err := p.devices.db.QueryRow(`SELECT revoked FROM durable_devices WHERE id=?`, token.Device).Scan(&revoked); err != nil || revoked != 0 {
		t.Fatal("family revoked", err, revoked)
	}
	t.Log("two managers sharing one file sent one native TLS refresh to real SQLite; family remains active")
}

func TestReviewConcurrentReplayRevokesFamily(t *testing.T) {
	p := durableFixture(t)
	token := durableLogin(t, p)
	start := make(chan struct{})
	results := make(chan int, 2)
	for _, request := range []string{strings.Repeat("a", 43), strings.Repeat("b", 43)} {
		go func(request string) { <-start; w, _ := durableRefresh(p, token.Refresh, request); results <- w.Code }(request)
	}
	close(start)
	a, b := <-results, <-results
	if !(a == 200 && b == 401 || a == 401 && b == 200) {
		t.Fatalf("concurrent replay statuses %d/%d", a, b)
	}
	var revoked int64
	if err := p.devices.db.QueryRow(`SELECT revoked FROM durable_devices WHERE id=?`, token.Device).Scan(&revoked); err != nil || revoked == 0 {
		t.Fatal("replay did not revoke", err, revoked)
	}
	t.Log("two request IDs using the same secret concurrently yield 200/401 and revoke the family")
}

func TestReviewProductionBaseDatabaseMigration(t *testing.T) {
	fixture := filepath.Join("testdata", "durable-review")
	data, err := os.ReadFile(filepath.Join(fixture, "110485c.db"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tunn.db")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	before := reviewDatabaseSnapshot(t, raw)
	_ = raw.Close()
	db, err := store.OpenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Other release components also install additive tables at store startup.
	initialized := reviewDatabaseSnapshot(t, db)
	p := securityProxy(storage.NewLocalStorage(db))
	p.devices, err = newDeviceCredentialStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = newDeviceCredentialStore(db); err != nil {
		t.Fatal("repeated startup", err)
	}
	after := reviewDatabaseSnapshot(t, db)
	if len(before) != 20 || len(after) != len(initialized)+2 {
		t.Fatalf("migration tables: baseline=%d initialized=%d after=%d, want 20 baseline tables and exactly two new durable tables", len(before), len(initialized), len(after))
	}
	for name, original := range before {
		if !reflect.DeepEqual(original, after[name]) {
			t.Errorf("migration changed baseline table %s", name)
		}
		delete(after, name)
	}
	if _, ok := after["durable_devices"]; !ok {
		t.Error("missing durable_devices")
	}
	if _, ok := after["durable_device_used"]; !ok {
		t.Error("missing durable_device_used")
	}
	data, err = os.ReadFile(filepath.Join(fixture, "110485c-tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	var old map[string]string
	if err = json.Unmarshal(data, &old); err != nil {
		t.Fatal(err)
	}
	if email, err := p.tunnelServer.validatePublisherToken(old["access"]); err != nil || email != "owner@example.com" {
		t.Fatal("existing access rejected", email, err)
	}
	r := httptest.NewRequest("GET", "https://tunn.test/account/devices", nil)
	r.AddCookie(&http.Cookie{Name: authCookieName, Value: old["session"]})
	if email, ok := p.getAuthFromCookie(r); !ok || email != "owner@example.com" {
		t.Fatal("existing browser session rejected")
	}
	w := httptest.NewRecorder()
	p.handleDeviceToken(w, httptest.NewRequest("GET", "https://tunn.test/api/device/token?code=existing-authorized-code", nil))
	var exchange durableTokenFixture
	if err := json.Unmarshal(w.Body.Bytes(), &exchange); err != nil || w.Code != 400 || exchange.Access != "" {
		t.Fatal("outstanding code granted management", w.Code, err)
	}
	t.Log("110485c database reopened; additive migration twice; baseline-minted access/session remain valid; outstanding codes retain publisher scope")
}

// Capture every original schema and row, including opaque blobs, before any
// candidate initialization. Compare again before exercising the legacy login.
func reviewDatabaseSnapshot(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	schemas, err := db.Query(`SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string)
	for schemas.Next() {
		var name, schema string
		if err := schemas.Scan(&name, &schema); err != nil {
			t.Fatal(err)
		}
		result[name] = schema
	}
	if err := schemas.Err(); err != nil {
		t.Fatal(err)
	}
	_ = schemas.Close()
	for name, schema := range result {
		query := `SELECT * FROM "` + strings.ReplaceAll(name, `"`, `""`) + `"`
		if name == "device_codes" {
			query = `SELECT code,user_code,expires_at,authorized,email FROM device_codes`
			schema = strings.ReplaceAll(schema, ", purpose TEXT NOT NULL DEFAULT 'publisher'", "")
			schema = strings.ReplaceAll(schema, ", account_id TEXT NOT NULL DEFAULT ''", "")
		}
		rows, err := db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var contents [][]any
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			contents = append(contents, values)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		_ = rows.Close()
		data, err := json.Marshal(contents)
		if err != nil {
			t.Fatal(err)
		}
		result[name] = schema + "\n" + string(data)
	}
	return result
}

func TestReviewMixedCaseOwnerCanListAndRevokeDevice(t *testing.T) {
	p := durableFixture(t)
	// The GitHub callback passes the verified primary email to setAuthCookie
	// before account storage normalizes the address. Exercise that same path.
	session := httptest.NewRecorder()
	if err := p.setAuthCookie(session, "Owner@Example.COM"); err != nil {
		t.Fatal(err)
	}
	cookie := session.Result().Cookies()[0]
	reviewRawEmail(t, p, cookie.Value, "owner@example.com")
	code, err := p.storage.CreateDeviceCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seed := httptest.NewRequest("GET", "https://tunn.test/login", nil)
	seed.AddCookie(cookie)
	csrf, err := p.createCSRFToken(seed, "/auth/device/authorize")
	if err != nil {
		t.Fatal(err)
	}
	authorize := httptest.NewRequest("POST", "https://tunn.test/auth/device/authorize", strings.NewReader(url.Values{"code": {code.UserCode}, "csrf_token": {csrf}}.Encode()))
	authorize.AddCookie(cookie)
	authorize.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authorize.Header.Set("Origin", "https://tunn.test")
	w := httptest.NewRecorder()
	p.handleDeviceAuthorize(w, authorize)
	if w.Code != 200 {
		t.Fatal("authorization failed", w.Code)
	}
	w = httptest.NewRecorder()
	p.handleDeviceToken(w, httptest.NewRequest("GET", "https://tunn.test/api/device/token?durable=1&code="+url.QueryEscape(code.Code), nil))
	var token durableTokenFixture
	if err := json.Unmarshal(w.Body.Bytes(), &token); err != nil || w.Code != 200 || token.Refresh == "" {
		t.Fatal("exchange failed", w.Code, err)
	}
	reviewRawEmail(t, p, token.Access, "owner@example.com")
	email, _, _, err := parseDeviceToken(token.Access, p.getJWTSigningKey(), time.Now())
	if err != nil || email != "owner@example.com" {
		t.Fatal("issued credential is not usable", email, err)
	}
	var owner string
	if err := p.devices.db.QueryRow(`SELECT email FROM durable_devices WHERE id=?`, token.Device).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != common.NormalizeEmail("Owner@Example.COM") {
		t.Error("new device owner was not stored canonically")
	}
	get := httptest.NewRequest("GET", "https://tunn.test/account/devices", nil)
	get.AddCookie(cookie)
	w = httptest.NewRecorder()
	p.handleDevices(w, get)
	listed := strings.Contains(w.Body.String(), token.Device)
	t.Logf("device stored as %q; canonical account owner@example.com; list status=%d listed=%t", owner, w.Code, listed)
	if w.Code != 200 || !listed {
		t.Error("owner cannot list own mixed-case device")
	}
	csrf, err = p.createCSRFToken(get, "/account/devices")
	if err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRequest("POST", "https://tunn.test/account/devices", strings.NewReader(url.Values{"device_id": {token.Device}, "csrf_token": {csrf}}.Encode()))
	post.AddCookie(cookie)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://tunn.test")
	w = httptest.NewRecorder()
	p.handleDevices(w, post)
	t.Logf("owner revocation with valid CSRF status=%d", w.Code)
	if w.Code != 303 {
		t.Error("owner cannot revoke own mixed-case device")
	}
	w, _ = durableRefresh(p, token.Refresh, strings.Repeat("r", 43))
	t.Logf("refresh after attempted owner revocation status=%d", w.Code)
	if w.Code != 401 {
		t.Error("credential remains renewable after owner tried to revoke it")
	}
}

func TestReviewDeviceCredentialRejectedByManagementRoutes(t *testing.T) {
	for _, principal := range []string{"device-bearer", "device-cookie"} {
		t.Run(principal, func(t *testing.T) {
			f := newProdAuthFixture(t)
			token := durableLogin(t, f.p)
			f.credentials[principal] = token.Access
			for _, route := range prodAuthRoutes {
				if !strings.HasPrefix(route.pattern, "/account") && (!strings.HasPrefix(route.pattern, "/api/") || strings.HasPrefix(route.pattern, "/api/device/")) {
					continue
				}
				t.Run(route.method+" "+route.path, func(t *testing.T) {
					w := f.routeRequest(t, route, principal, "tunn.test")
					if w.Code != route.want[0] {
						t.Fatalf("device credential status %d; anonymous status %d; route %s %s", w.Code, route.want[0], route.method, route.path)
					}
				})
			}
		})
	}
}
