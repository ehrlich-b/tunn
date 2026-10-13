package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/metering"
	internalpb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestAppDeviceExpiredUnconsumedQRAndApprovalAuthorityChanges(t *testing.T) {
	for _, change := range []string{"expiry", "mailbox", "sharing", "resource"} {
		t.Run(change, func(t *testing.T) {
			f := newAppDeviceFixture(t)
			cookie := f.cookie
			if change == "sharing" {
				cookie = appSessionCookie(t, f.p, "guest@example.com", "github", true, "")
				if _, err := f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: f.tunnel.AccountID, Endpoint: f.tunnel.TunnelID, ResourceId: f.tunnel.ResourceID, Email: "guest@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err != nil {
					t.Fatal(err)
				}
			}
			i := f.invite(t, cookie)
			verifier, _ := randomOAuthValue("")
			claim := f.claim(t, i, verifier)
			var err error
			switch change {
			case "expiry":
				_, err = f.db.Exec(`UPDATE app_device_invitations SET expires=0`)
			case "mailbox":
				_, err = f.db.Exec(`DELETE FROM account_emails WHERE email=?`, appDeviceTestEmail)
			case "sharing":
				_, err = f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "unshare", Owner: f.tunnel.AccountID, Endpoint: f.tunnel.TunnelID, ResourceId: f.tunnel.ResourceID, Email: "guest@example.com"})
			case "resource":
				_, err = f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: "other-owner", Endpoint: f.tunnel.TunnelID, Mode: "private"})
			}
			if err != nil {
				t.Fatal(err)
			}
			if w := f.approve(t, claim, cookie); w.Code == 200 {
				t.Fatal("approval survived authority change")
			}
			if w := f.redeem(t, claim, verifier, true); w.Code == 201 {
				t.Fatal("redemption survived authority change")
			}
			if change == "expiry" {
				w := f.json(t, "/api/app-devices/claims", map[string]any{"invitation": i.Invitation, "hostname": appDeviceTestHost, "name": "Phone", "code_challenge": base64.RawURLEncoding.EncodeToString(appDigest(verifier)), "code_challenge_method": "S256"})
				if w.Code != 400 {
					t.Fatal("expired unconsumed QR accepted")
				}
			}
		})
	}
}

func TestAppDeviceDurableDiskExpiryAndRevokeAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app-devices.sqlite")
	open := func() (*sql.DB, *appDeviceStore) {
		t.Helper()
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		s, err := newAppDeviceStore(db)
		if err != nil {
			db.Close()
			t.Fatal(err)
		}
		return db, s
	}
	db, s := open()
	scope := appDevice{Account: "fixture-account", Email: "owner@example.com", Host: appDeviceTestHost, Namespace: "fixture-namespace", Publisher: "fixture-owner", Endpoint: "wing", Resource: "fixture-generation"}
	issue := func() (appDevice, string) {
		t.Helper()
		_, handle, err := s.invite(context.Background(), scope)
		if err != nil {
			t.Fatal(err)
		}
		verifier, _ := randomOAuthValue("")
		i, err := s.claim(context.Background(), handle, base64.RawURLEncoding.EncodeToString(appDigest(verifier)), "Phone", scope.Host)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.approve(context.Background(), i); err != nil {
			t.Fatal(err)
		}
		d, token, err := s.redeem(context.Background(), i.Claim, verifier, scope.Host, i.Phrase, true)
		if err != nil {
			t.Fatal(err)
		}
		return *d, token
	}
	d, token := issue()
	var data []byte
	var digest []byte
	if err := db.QueryRow(`SELECT digest,data FROM app_devices WHERE id=?`, d.ID).Scan(&digest, &data); err != nil {
		t.Fatal(err)
	}
	if len(digest) != 32 || strings.Contains(string(data), token) {
		t.Fatal("digest-only storage violated")
	}
	if _, err := s.revoke(context.Background(), scope.Host, scope.Account, "", true); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, s = open()
	defer db.Close()
	out, err := s.check(context.Background(), &internalpb.AppDeviceCheckRequest{Operation: "resolve", TokenSha256: appDigest(token), Hostname: d.Host, Source: "fixture"})
	if err != nil || out.Status != 401 {
		t.Fatal("disk restart lost revoke-all")
	}
	_, token = issue()
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, s = open()
	defer db.Close()
	s.now = func() time.Time { return time.Now().Add(appDeviceLifetime + time.Minute) }
	out, err = s.check(context.Background(), &internalpb.AppDeviceCheckRequest{Operation: "resolve", TokenSha256: appDigest(token), Hostname: scope.Host, Source: "fixture"})
	if err != nil || out.Status != 401 {
		t.Fatal("disk restart lost expiry")
	}
}

type appDeviceStrictQuota struct{ metering.Backend }

func (b appDeviceStrictQuota) Admit(context.Context, *mp.Event) (*mp.Decision, error) {
	return &mp.Decision{Allowed: false, Status: 429, Reason: "existing_stricter_quota", RetryAfter: 60}, nil
}
func (b appDeviceStrictQuota) Sharing(ctx context.Context, r *mp.SharingRequest) (*mp.SharingResponse, error) {
	return b.Backend.(metering.SharingBackend).Sharing(ctx, r)
}
func TestAppDeviceExistingQuotaAndCarrierBoundaries(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, token := f.enroll(t, nil)
	f.p.meter = appDeviceStrictQuota{f.p.meter}
	var hits atomic.Int64
	hook := f.stream.hook
	f.stream.hook = func(m *pb.TunnelMessage) error {
		if m.GetHttpRequest() != nil {
			hits.Add(1)
		}
		return hook(m)
	}
	if w := appDeviceOpen(f.p, appDeviceTestHost, token, nil); w.Code != 429 || hits.Load() != 0 {
		t.Fatal("app credential bypassed existing quota")
	}
	for _, value := range []string{"Bearer " + token + " extra", "Bearer " + token + ", extra"} {
		r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
		r.Header.Set("Authorization", value)
		r.AddCookie(appSessionCookie(t, f.p, appDeviceTestEmail, "github", true, appDeviceTestHost))
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("malformed app carrier fell back to cookie")
		}
		if headers := f.p.forwardedRequestHeaders(r.Header); headers["Authorization"] != "" {
			t.Fatal("malformed tunn credential could leak to backend")
		}
	}
}

func TestAppDeviceMalformedBasicDoesNotFallBackOrLeak(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, token := f.enroll(t, nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("tunn-app:" + token))
	for _, value := range []string{"Basic " + encoded + "%", "Basic " + encoded + " extra"} {
		r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
		r.Header.Set("Authorization", value)
		r.AddCookie(appSessionCookie(t, f.p, appDeviceTestEmail, "github", true, appDeviceTestHost))
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("malformed app Basic fell back", w.Code)
		}
		if f.p.forwardedRequestHeaders(http.Header{"Authorization": []string{value}})["Authorization"] != "" {
			t.Fatal("malformed Basic credential could reach origin")
		}
	}
}

func TestAppDeviceOwnerAndGuestManagementBoundaries(t *testing.T) {
	f := newAppDeviceFixture(t)
	ownerDevice, _ := f.enroll(t, nil)
	guest := appSessionCookie(t, f.p, "guest@example.com", "github", true, "")
	if _, err := f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: f.tunnel.AccountID, Endpoint: f.tunnel.TunnelID, ResourceId: f.tunnel.ResourceID, Email: "guest@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	guestDevice, guestToken := f.enroll(t, guest)
	if w := f.form(t, "/api/app-devices/revoke", url.Values{"device_id": {ownerDevice.ID}}, guest); w.Code != 404 {
		t.Fatal("guest revoked owner's device")
	}
	r := httptest.NewRequest("GET", "https://tunn.test/api/app-devices?host="+appDeviceTestHost, nil)
	r.AddCookie(guest)
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	var list struct{ Devices []appDevice }
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Devices) != 1 || list.Devices[0].ID != guestDevice.ID {
		t.Fatal("guest device list leaked another account's device")
	}
	if w = f.form(t, "/api/app-devices/revoke", url.Values{"device_id": {guestDevice.ID}}, nil); w.Code != 200 {
		t.Fatal("hostname owner could not revoke delegated device")
	}
	if w = appDeviceOpen(f.p, appDeviceTestHost, guestToken, nil); w.Code != 401 {
		t.Fatal("owner revocation did not revoke guest credential")
	}
}

func (b appDeviceStrictQuota) IPPolicy(ctx context.Context, in *mp.IPPolicyRequest) (*mp.IPPolicy, error) {
	return b.Backend.(metering.IPPolicyBackend).IPPolicy(ctx, in)
}
func (b appDeviceStrictQuota) EndpointPolicy(ctx context.Context, in *mp.EndpointPolicyRequest) (*mp.EndpointPolicyResponse, error) {
	return b.Backend.(metering.PolicyBackend).EndpointPolicy(ctx, in)
}
