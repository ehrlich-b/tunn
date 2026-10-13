package host

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/identity"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

const appDeviceTestHost = "wing.apps.test"
const appDeviceTestEmail = "owner@example.com"

type appDeviceFixture struct {
	p      *ProxyServer
	tunnel *TunnelConnection
	db     *sql.DB
	ledger *metering.Store
	stream *meteringFixtureStream
	cookie *http.Cookie
}

func newAppDeviceFixture(t *testing.T) *appDeviceFixture {
	t.Helper()
	p, registry, dns := domainProxyFixture(t)
	p.config.PublicAddr = "tunn.test"
	p.config.GitHubClientID = "fixture-id"
	tunnel, _ := p.tunnelServer.GetTunnel("api")
	delete(p.tunnelServer.tunnels, "api")
	tunnel.TunnelID = "wing"
	p.tunnelServer.tunnels["wing"] = tunnel
	tunnel.AllowedEmails = nil
	tunnel.EndpointProtocol = "http"
	d, err := registry.Add(context.Background(), &domainpb.Domain{Name: "*.apps.test", Tunnel: "wing", Owner: tunnel.AccountID})
	if err != nil {
		t.Fatal(err)
	}
	dns.target = d.CnameTarget
	if _, err = registry.Verify(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	// Cancellation may retire a SQLite connection. A file-backed fixture
	// preserves account authority across reconnects, as the relay does.
	db, err := store.OpenLocal(filepath.Join(t.TempDir(), "app-authority.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err = db.Exec(`INSERT INTO accounts(id,primary_email,plan,created_at) VALUES(?,?,'pro',1);`, tunnel.AccountID, appDeviceTestEmail); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO account_emails(email,account_id,verified_via,added_at) VALUES(?,?,'github',1)`, appDeviceTestEmail, tunnel.AccountID); err != nil {
		t.Fatal(err)
	}
	p.storage = storage.NewLocalStorage(db)
	p.appDevices, err = newAppDeviceStore(db)
	if err != nil {
		t.Fatal(err)
	}
	p.appDevices.now = p.currentTime
	ledger := p.meter.(*metering.Store)
	out, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Mode: "private"})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.ResourceID = out.Resources[0].Id
	p.tunnelServer.sharing = ledger
	appKeyFile(t, p)
	cookie := appSessionCookie(t, p, appDeviceTestEmail, "github", true, "")
	return &appDeviceFixture{p, tunnel, db, ledger, tunnel.Stream.(*meteringFixtureStream), cookie}
}

func (f *appDeviceFixture) form(t *testing.T, path string, values url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	if values == nil {
		values = url.Values{}
	}
	if cookie == nil {
		cookie = f.cookie
	}
	r := httptest.NewRequest("POST", "https://tunn.test"+path, nil)
	r.AddCookie(cookie)
	csrf, err := f.p.createCSRFToken(r, appDevicesCSRFAction)
	if err != nil {
		t.Fatal(err)
	}
	values.Set("csrf_token", csrf)
	if values.Get("hostname") == "" {
		values.Set("hostname", appDeviceTestHost)
	}
	r = httptest.NewRequest("POST", "https://tunn.test"+path, strings.NewReader(values.Encode()))
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://tunn.test")
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	return w
}
func (f *appDeviceFixture) json(t *testing.T, path string, in any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://tunn.test"+path, strings.NewReader(string(data)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	return w
}

type appDeviceInvitationResponse struct {
	ID, Invitation string
	Host           string `json:"hostname"`
	QR             string `json:"qr_png"`
	Expires        int64  `json:"expires_at"`
	Authority      string
}

func (f *appDeviceFixture) invite(t *testing.T, cookie *http.Cookie) appDeviceInvitationResponse {
	t.Helper()
	w := f.form(t, "/api/app-devices/invitations", nil, cookie)
	if w.Code != 201 {
		t.Fatalf("invite status=%d", w.Code)
	}
	var out appDeviceInvitationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func (f *appDeviceFixture) claim(t *testing.T, i appDeviceInvitationResponse, verifier string) appInvitation {
	t.Helper()
	challenge := base64.RawURLEncoding.EncodeToString(appDigest(verifier))
	w := f.json(t, "/api/app-devices/claims", map[string]any{"invitation": i.Invitation, "hostname": appDeviceTestHost, "name": "Fixture phone", "code_challenge": challenge, "code_challenge_method": "S256"})
	if w.Code != 201 {
		t.Fatalf("claim status=%d", w.Code)
	}
	var out appInvitation
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func (f *appDeviceFixture) approve(t *testing.T, i appInvitation, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	return f.form(t, "/api/app-devices/claims/"+i.Claim+"/approve", url.Values{"confirmed": {"true"}, "phrase": {i.Phrase}}, cookie)
}
func (f *appDeviceFixture) redeem(t *testing.T, i appInvitation, verifier string, confirmed bool) *httptest.ResponseRecorder {
	t.Helper()
	return f.json(t, "/api/app-devices/claims/"+i.Claim+"/redeem", map[string]any{"code_verifier": verifier, "hostname": appDeviceTestHost, "phrase": i.Phrase, "confirmed": confirmed})
}
func (f *appDeviceFixture) enroll(t *testing.T, cookie *http.Cookie) (appDevice, string) {
	t.Helper()
	i := f.invite(t, cookie)
	verifier, err := randomOAuthValue("")
	if err != nil {
		t.Fatal(err)
	}
	claim := f.claim(t, i, verifier)
	if w := f.approve(t, claim, cookie); w.Code != 200 {
		t.Fatalf("approval status=%d", w.Code)
	}
	w := f.redeem(t, claim, verifier, true)
	if w.Code != 201 {
		t.Fatalf("redeem status=%d", w.Code)
	}
	var out struct {
		Device appDevice
		Secret string `json:"access_token"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Device, out.Secret
}
func appDeviceOpen(p *ProxyServer, host, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://"+host+"/", nil)
	if token != "" {
		r.Header.Set("Tunn-Authorization", "Bearer "+token)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}

func TestAppDeviceEnrollmentAndCredentialMatrix(t *testing.T) {
	f := newAppDeviceFixture(t)
	d, secret := f.enroll(t, nil)
	if d.Account != f.tunnel.AccountID || d.Host != appDeviceTestHost || d.Resource != f.tunnel.ResourceID || d.Expires-d.Created != appDeviceLifetime.Milliseconds() {
		t.Fatal("credential scope/lifetime mismatch")
	}
	appCookie := appSessionCookie(t, f.p, appDeviceTestEmail, "github", true, appDeviceTestHost)
	unshared := appSessionCookie(t, f.p, "stranger@example.com", "magic_link", true, appDeviceTestHost)
	for _, tc := range []struct {
		label, token string
		cookie       *http.Cookie
		want         int
	}{
		{"anonymous", "", nil, 302}, {"owner-browser", "", appCookie, 200}, {"unshared-browser", "", unshared, 403},
		{"device", secret, nil, 200}, {"invalid-over-owner-cookie", "tunn_app_" + strings.Repeat("A", 43), appCookie, 401},
	} {
		t.Run(tc.label, func(t *testing.T) {
			if w := appDeviceOpen(f.p, appDeviceTestHost, tc.token, tc.cookie); w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
		})
	}
	var received map[string]string
	hook := f.stream.hook
	f.stream.hook = func(msg *pb.TunnelMessage) error {
		if r := msg.GetHttpRequest(); r != nil {
			received = r.Headers
		}
		return hook(msg)
	}
	for _, carrier := range []string{"dedicated", "bearer", "basic"} {
		r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
		if carrier == "dedicated" {
			r.Header.Set("Tunn-Authorization", "Bearer "+secret)
			r.Header.Set("Authorization", "Bearer upstream-only")
		}
		if carrier == "bearer" {
			r.Header.Set("Authorization", "Bearer "+secret)
		}
		if carrier == "basic" {
			r.SetBasicAuth("tunn-app", secret)
		}
		r.Header.Set(identity.Header, "forged")
		r.Header.Set(identity.EmailHeader, "forged@example.com")
		r.Header.Set("X-Forwarded-For", "192.0.2.200")
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s=%d", carrier, w.Code)
		}
		for name, value := range received {
			if strings.EqualFold(name, "Tunn-Authorization") || strings.Contains(value, secret) {
				t.Fatal("app credential leaked to backend")
			}
		}
		if carrier == "dedicated" && received["Authorization"] != "Bearer upstream-only" {
			t.Fatal("upstream bearer lost")
		}
		if received[identity.Header] == "forged" || received[identity.EmailHeader] != "owner@example.com" || received["X-Forwarded-For"] == "192.0.2.200" {
			t.Fatal("forged identity reached backend")
		}
	}
	r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
	r.AddCookie(appCookie)
	r.SetBasicAuth("upstream", "password")
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	if w.Code != 200 || received["Authorization"] == "" {
		t.Fatal("upstream Basic lost")
	}
	for _, tc := range []string{"duplicate", "conflict", "malformed", "dedicated-basic", "wrong-basic-password"} {
		r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
		r.AddCookie(appCookie)
		r.Header.Set("Tunn-Authorization", "Bearer "+secret)
		switch tc {
		case "duplicate":
			r.Header.Add("Tunn-Authorization", "Bearer "+secret)
		case "conflict":
			r.Header.Set("Authorization", "Bearer "+secret)
		case "malformed":
			r.Header.Set("Tunn-Authorization", "garbage")
		case "dedicated-basic":
			r.Header.Set("Tunn-Authorization", "Basic garbage")
		case "wrong-basic-password":
			r.Header.Del("Tunn-Authorization")
			r.SetBasicAuth("tunn-app", "bad")
		}
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("ambiguity %s=%d", tc, w.Code)
		}
	}
	for _, path := range []string{"/account", "/api/sharing/api", "/api/device/code", "/api/app-devices"} {
		r := httptest.NewRequest("GET", "https://tunn.test"+path, nil)
		r.Header.Set("Tunn-Authorization", "Bearer "+secret)
		r.AddCookie(f.cookie)
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("app token unlocked management: %s=%d", path, w.Code)
		}
	}
	if w := appDeviceOpen(f.p, "other.apps.test", secret, nil); w.Code != 403 {
		t.Fatalf("sibling scope=%d", w.Code)
	}
	if w := appDeviceOpen(f.p, appDeviceTestHost, "", nil); w.Code != 302 {
		t.Fatal("same NAT opened unpaired device")
	}
	for _, addr := range []string{"192.0.2.1:1234", "198.51.100.2:5678"} {
		r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
		r.RemoteAddr = addr
		r.Header.Set("Tunn-Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("device depended on source IP")
		}
	}
	var stored []byte
	if err := f.db.QueryRow(`SELECT data FROM app_devices WHERE id=?`, d.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), secret) {
		t.Fatal("raw credential stored")
	}
}

func TestAppDeviceInvitationAttacksAndBothConfirmations(t *testing.T) {
	f := newAppDeviceFixture(t)
	i := f.invite(t, nil)
	verifier, _ := randomOAuthValue("")
	claim := f.claim(t, i, verifier)
	if claim.Claim == "" || claim.Host != appDeviceTestHost || claim.Phrase == "" {
		t.Fatal("missing frozen claim display")
	}
	w := f.json(t, "/api/app-devices/claims", map[string]any{"invitation": i.Invitation, "hostname": appDeviceTestHost, "name": "Attacker", "code_challenge": base64.RawURLEncoding.EncodeToString(appDigest("other")), "code_challenge_method": "S256"})
	if w.Code != 400 {
		t.Fatal("second claimant changed frozen claim")
	}
	if w = f.approve(t, claim, appSessionCookie(t, f.p, "stranger@example.com", "github", true, "")); w.Code != 403 {
		t.Fatal("other account approved invitation")
	}
	if w = f.form(t, "/api/app-devices/claims/"+claim.Claim+"/approve", url.Values{"phrase": {"wrong"}, "confirmed": {"true"}}, nil); w.Code != 403 {
		t.Fatal("wrong phrase approved")
	}
	if w = f.form(t, "/api/app-devices/claims/"+claim.Claim+"/approve", url.Values{"phrase": {claim.Phrase}}, nil); w.Code != 403 {
		t.Fatal("missing browser confirmation approved")
	}
	if w = f.redeem(t, claim, verifier, true); w.Code != 202 {
		t.Fatalf("pending status=%d", w.Code)
	}
	if w = f.redeem(t, claim, verifier, true); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("fast polling accepted")
	}
	if w = f.approve(t, claim, nil); w.Code != 200 {
		t.Fatal("approval failed")
	}
	if _, err := f.db.Exec(`UPDATE app_device_invitations SET polled=0 WHERE id=?`, i.ID); err != nil {
		t.Fatal(err)
	}
	if w = f.redeem(t, claim, verifier, false); w.Code != 400 {
		t.Fatal("missing device confirmation issued")
	}
	if _, err := f.db.Exec(`UPDATE app_device_invitations SET polled=0 WHERE id=?`, i.ID); err != nil {
		t.Fatal(err)
	}
	if w = f.redeem(t, claim, strings.Repeat("x", 43), true); w.Code != 400 {
		t.Fatal("wrong verifier issued")
	}
	if _, err := f.db.Exec(`UPDATE app_device_invitations SET polled=0 WHERE id=?`, i.ID); err != nil {
		t.Fatal(err)
	}
	if w = f.redeem(t, claim, verifier, true); w.Code != 201 {
		t.Fatalf("successful redeem=%d", w.Code)
	}
	if w = f.redeem(t, claim, verifier, true); w.Code != 400 {
		t.Fatal("lost-response redemption minted twice")
	}
	var count int
	if err := f.db.QueryRow(`SELECT count(*) FROM app_devices`).Scan(&count); err != nil || count != 1 {
		t.Fatal("unexpected device issuance count", count)
	}
	if _, err := f.db.Exec(`UPDATE app_device_invitations SET expires=0`); err != nil {
		t.Fatal(err)
	}
	if w = f.json(t, "/api/app-devices/claims", map[string]any{"invitation": i.Invitation, "hostname": appDeviceTestHost, "name": "Other", "code_challenge": base64.RawURLEncoding.EncodeToString(appDigest(verifier)), "code_challenge_method": "S256"}); w.Code != 400 {
		t.Fatal("expired QR accepted")
	}
	for _, origin := range []string{"https://evil.test", "https://api.apps.test"} {
		r := httptest.NewRequest("POST", "https://tunn.test/api/app-devices/claims", strings.NewReader(`{}`))
		r.Header.Set("Origin", origin)
		w = httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("untrusted browser origin accepted")
		}
	}
	r := httptest.NewRequest("POST", "https://tunn.test/api/app-devices/invitations", strings.NewReader("hostname="+appDeviceTestHost))
	r.AddCookie(f.cookie)
	r.Header.Set("Origin", "https://tunn.test")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("CSRF-less invitation accepted")
	}
}

func TestAppDeviceSharedAccountLiveAuthorityAndExpiry(t *testing.T) {
	f := newAppDeviceFixture(t)
	shared := appSessionCookie(t, f.p, "shared@example.com", "github", true, "")
	if w := f.form(t, "/api/app-devices/invitations", nil, shared); w.Code != 403 {
		t.Fatal("unshared account enrolled")
	}
	if _, err := f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: f.tunnel.AccountID, Endpoint: f.tunnel.TunnelID, ResourceId: f.tunnel.ResourceID, Email: "shared@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	d, token := f.enroll(t, shared)
	if w := appDeviceOpen(f.p, appDeviceTestHost, token, nil); w.Code != 200 {
		t.Fatal("shared device denied", w.Code)
	}
	if _, err := f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "unshare", Owner: f.tunnel.AccountID, Endpoint: f.tunnel.TunnelID, ResourceId: f.tunnel.ResourceID, Email: "shared@example.com"}); err != nil {
		t.Fatal(err)
	}
	if w := appDeviceOpen(f.p, appDeviceTestHost, token, nil); w.Code != 403 {
		t.Fatal("lost sharing did not return 403", w.Code)
	}
	if w := f.form(t, "/api/app-devices/revoke", url.Values{"device_id": {d.ID}}, shared); w.Code != 200 {
		t.Fatal("guest could not revoke after share removal")
	}
	if w := appDeviceOpen(f.p, appDeviceTestHost, token, appSessionCookie(t, f.p, appDeviceTestEmail, "github", true, appDeviceTestHost)); w.Code != 401 {
		t.Fatal("revoked token fell back to owner cookie")
	}
	d, token = f.enroll(t, nil)
	if _, err := f.db.Exec(`UPDATE app_devices SET expires=? WHERE id=?`, time.Now().Add(-time.Second).UnixMilli(), d.ID); err != nil {
		t.Fatal(err)
	}
	if w := appDeviceOpen(f.p, appDeviceTestHost, token, nil); w.Code != 401 {
		t.Fatal("expired credential accepted")
	}
}

func TestAppDeviceCapacityClaimsValidationAndRates(t *testing.T) {
	t.Run("invitations", func(t *testing.T) {
		f := newAppDeviceFixture(t)
		for n := 0; n < 5; n++ {
			f.invite(t, nil)
		}
		if w := f.form(t, "/api/app-devices/invitations", nil, nil); w.Code != 429 || w.Header().Get("Retry-After") == "" {
			t.Fatal("invitation limit missing")
		}
		var count int
		f.db.QueryRow(`SELECT count(*) FROM app_device_invitations`).Scan(&count)
		if count != 5 {
			t.Fatal("outstanding invitations unbounded")
		}
	})
	t.Run("failed-claims", func(t *testing.T) {
		f := newAppDeviceFixture(t)
		i := f.invite(t, nil)
		for n := 0; n < 10; n++ {
			w := f.json(t, "/api/app-devices/claims", map[string]any{"invitation": i.Invitation, "hostname": "wrong.apps.test", "name": "Device", "code_challenge": strings.Repeat("A", 43), "code_challenge_method": "S256"})
			if w.Code != 400 {
				t.Fatal("claim failure was not counted", n, w.Code)
			}
		}
		w := f.json(t, "/api/app-devices/claims", map[string]any{"invitation": i.Invitation, "hostname": appDeviceTestHost, "name": "Device", "code_challenge": strings.Repeat("A", 43), "code_challenge_method": "S256"})
		if w.Code != 429 {
			t.Fatal("failed-claim limit missing")
		}
	})
	t.Run("validation", func(t *testing.T) {
		f := newAppDeviceFixture(t)
		for n := 0; n < 30; n++ {
			if w := appDeviceOpen(f.p, appDeviceTestHost, "tunn_app_"+strings.Repeat("A", 43), nil); w.Code != 401 {
				t.Fatalf("failure %d=%d", n, w.Code)
			}
		}
		w := appDeviceOpen(f.p, appDeviceTestHost, "tunn_app_"+strings.Repeat("A", 43), nil)
		if w.Code != 429 || w.Header().Get("Retry-After") == "" {
			t.Fatal("validation limit missing")
		}
	})
	t.Run("capacity", func(t *testing.T) {
		f := newAppDeviceFixture(t)
		scope, _, _, err := f.p.appEnrollmentScope(context.Background(), appDeviceTestHost)
		if err != nil {
			t.Fatal(err)
		}
		scope.Account = f.tunnel.AccountID
		scope.Email = appDeviceTestEmail
		for n := 0; n < 20; n++ {
			_, handle, err := f.p.appDevices.invite(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			verifier, _ := randomOAuthValue("")
			i, err := f.p.appDevices.claim(context.Background(), handle, base64.RawURLEncoding.EncodeToString(appDigest(verifier)), "Device", scope.Host)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.p.appDevices.approve(context.Background(), i); err != nil {
				t.Fatal(err)
			}
			if _, _, err = f.p.appDevices.redeem(context.Background(), i.Claim, verifier, scope.Host, i.Phrase, true); err != nil {
				t.Fatal(err)
			}
			if _, err = f.db.Exec(`DELETE FROM app_device_rates WHERE key=?`, appRateKey("invite", scope.Account)); err != nil {
				t.Fatal(err)
			}
		}
		_, handle, err := f.p.appDevices.invite(context.Background(), scope)
		if err != nil {
			t.Fatal(err)
		}
		verifier, _ := randomOAuthValue("")
		i, err := f.p.appDevices.claim(context.Background(), handle, base64.RawURLEncoding.EncodeToString(appDigest(verifier)), "Over cap", scope.Host)
		if err != nil {
			t.Fatal(err)
		}
		f.p.appDevices.approve(context.Background(), i)
		if _, _, err = f.p.appDevices.redeem(context.Background(), i.Claim, verifier, scope.Host, i.Phrase, true); appStatus(err) != 429 {
			t.Fatal("device capacity missing")
		}
	})
}

func TestAppDeviceAtomicRedemptionPersistenceAndRevokeAll(t *testing.T) {
	f := newAppDeviceFixture(t)
	i := f.invite(t, nil)
	verifier, _ := randomOAuthValue("")
	claim := f.claim(t, i, verifier)
	if w := f.approve(t, claim, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	var wg sync.WaitGroup
	var issued atomic.Int64
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := f.p.appDevices.redeem(context.Background(), claim.Claim, verifier, claim.Host, claim.Phrase, true); err == nil {
				issued.Add(1)
			}
		}()
	}
	wg.Wait()
	if issued.Load() != 1 {
		t.Fatal("concurrent redemption count", issued.Load())
	}
	d, token := f.enroll(t, nil)
	if w := f.form(t, "/api/app-devices/revoke-all", nil, nil); w.Code != 200 {
		t.Fatal("revoke-all failed")
	}
	restarted, err := newAppDeviceStore(f.db)
	if err != nil {
		t.Fatal(err)
	}
	f.p.appDevices = restarted
	if w := appDeviceOpen(f.p, appDeviceTestHost, token, nil); w.Code != 401 {
		t.Fatal("restart lost revocation")
	}
	list, err := restarted.list(context.Background(), appDeviceTestHost, d.Account, true)
	if err != nil || len(list) != 2 {
		t.Fatal("device history disappeared")
	}
	for _, device := range list {
		if device.Revoked == 0 {
			t.Fatal("revoke-all left active device")
		}
	}
}

// Test TLS never disables verification. The certificate and private key are
// generated in memory and the client trusts only this disposable fixture.
func appDeviceTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"tunn.test", appDeviceTestHost, "other.apps.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	s.StartTLS()
	t.Cleanup(s.Close)
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	s.Client().Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: appDeviceTestHost}}
	return s
}
