package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func appDeviceShareGuest(t *testing.T, f *appDeviceFixture, email string) *http.Cookie {
	t.Helper()
	cookie := appSessionCookie(t, f.p, email, "github", true, "")
	if _, err := f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "share", Owner: f.tunnel.AccountID, Endpoint: f.tunnel.TunnelID, ResourceId: f.tunnel.ResourceID, Email: email, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	return cookie
}

type appDeviceHangingAdmit struct{ metering.Backend }

func (b appDeviceHangingAdmit) Sharing(ctx context.Context, in *mp.SharingRequest) (*mp.SharingResponse, error) {
	return b.Backend.(metering.SharingBackend).Sharing(ctx, in)
}
func (b appDeviceHangingAdmit) Admit(ctx context.Context, in *mp.Event) (*mp.Decision, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestAppDeviceMeterAdmissionUsesSameDeadline(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, token := f.enroll(t, nil)
	f.p.meter = appDeviceHangingAdmit{f.p.meter}
	started := time.Now()
	w := appDeviceOpen(f.p, appDeviceTestHost, token, nil)
	if w.Code != 503 || time.Since(started) > 2500*time.Millisecond {
		t.Fatalf("meter admission=%d elapsed=%s", w.Code, time.Since(started))
	}
}

func TestAppDeviceRejectsMixedPlatformCredentials(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, token := f.enroll(t, nil)
	for _, other := range []string{"tunn_gr_fake", "tunn_ep_fake", "tunn_sk_fake", relayJWT(t, f.p, appDeviceTestEmail)} {
		r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
		r.Header.Set("Tunn-Authorization", "Bearer "+token)
		r.Header.Set("Authorization", "Bearer "+other)
		w := httptest.NewRecorder()
		f.p.createHandler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("mixed app/platform carriers accepted", w.Code)
		}
	}
}

func TestAppDeviceVerifiedMergeKeepsManagementAssertionAndRateScope(t *testing.T) {
	f := newAppDeviceFixture(t)
	cookieA := appDeviceShareGuest(t, f, "merge-a@example.com")
	cookieB := appDeviceShareGuest(t, f, "merge-b@example.com")
	dA, token := f.enroll(t, cookieA)
	dB, _ := f.enroll(t, cookieB)
	pending := f.invite(t, cookieA)
	if err := f.p.storage.UpdatePlan(context.Background(), dB.Account, "pro"); err != nil {
		t.Fatal(err)
	}
	merged, err := f.p.storage.FindOrCreateByEmails(context.Background(), []string{dA.Email, dB.Email}, "github")
	if err != nil || merged.ID != dB.Account {
		t.Fatal("verified merge failed", err)
	}
	var assertion string
	hook := f.stream.hook
	f.stream.hook = func(m *pb.TunnelMessage) error {
		if r := m.GetHttpRequest(); r != nil {
			assertion = r.Headers["X-Tunn-Identity"]
		}
		return hook(m)
	}
	if w := appDeviceOpen(f.p, appDeviceTestHost, token, nil); w.Code != 200 {
		t.Fatal("merged device lost authorized access", w.Code)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["account_id"] != merged.ID || claims["sub"] != merged.ID || claims["email"] != dA.Email {
		t.Fatal("assertion retained retired UUID or rebound mailbox")
	}
	r := httptest.NewRequest("GET", "https://tunn.test/api/app-devices?host="+appDeviceTestHost, nil)
	r.AddCookie(cookieB)
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	var listed struct{ Devices []appDevice }
	if err = json.Unmarshal(w.Body.Bytes(), &listed); err != nil || w.Code != 200 || len(listed.Devices) != 2 {
		t.Fatal("merge orphaned managed devices")
	}
	for _, d := range listed.Devices {
		if d.Account != merged.ID {
			t.Fatal("noncanonical device metadata")
		}
	}
	i, err := f.p.appDevices.invitation(context.Background(), "id", pending.ID)
	if err != nil || i.Account != merged.ID || i.Email != dA.Email {
		t.Fatal("pending invitation not migrated")
	}
	var rate int
	if err = f.db.QueryRow(`SELECT count FROM app_device_rates WHERE key=?`, appRateKey("invite", merged.ID)).Scan(&rate); err != nil || rate != 3 {
		t.Fatal("merge reset enrollment rate", rate, err)
	}
	if _, err = f.db.Exec(`DELETE FROM account_emails WHERE email=?`, dA.Email); err != nil {
		t.Fatal(err)
	}
	if w = appDeviceOpen(f.p, appDeviceTestHost, token, nil); w.Code != 403 {
		t.Fatal("merge stopped enforcing originating mailbox")
	}
	if w = f.form(t, "/api/app-devices/revoke", url.Values{"device_id": {dA.ID}, "scope": {"self"}}, cookieB); w.Code != 200 {
		t.Fatal("merged account could not revoke device", w.Code)
	}
	if w = f.form(t, "/api/app-devices/revoke-all", url.Values{"scope": {"self"}}, cookieB); w.Code != 200 {
		t.Fatal("merged revoke-all failed")
	}
	var active int
	f.db.QueryRow(`SELECT count(*) FROM app_devices WHERE account=? AND revoked=0`, merged.ID).Scan(&active)
	if active != 0 {
		t.Fatal("merge revoke-all missed devices")
	}
	if _, err = f.p.appDevices.invitation(context.Background(), "id", pending.ID); err == nil {
		t.Fatal("merge revoke-all missed pending invitation")
	}
}

func TestAppDeviceOwnerRevokeAllWorksWithPublisherOffline(t *testing.T) {
	f := newAppDeviceFixture(t)
	f.enroll(t, nil)
	guest := appDeviceShareGuest(t, f, "offline-guest@example.com")
	_, token := f.enroll(t, guest)
	pending := f.invite(t, guest)
	f.p.tunnelServer.mu.Lock()
	delete(f.p.tunnelServer.tunnels, f.tunnel.TunnelID)
	f.p.tunnelServer.mu.Unlock()
	w := f.form(t, "/api/app-devices/revoke-all", url.Values{"scope": {"hostname"}}, nil)
	if w.Code != 200 {
		t.Fatal("offline owner revoke-all failed", w.Code)
	}
	f.p.tunnelServer.mu.Lock()
	f.p.tunnelServer.tunnels[f.tunnel.TunnelID] = f.tunnel
	f.p.tunnelServer.mu.Unlock()
	if w = appDeviceOpen(f.p, appDeviceTestHost, token, nil); w.Code != 401 {
		t.Fatal("offline revoke-all missed delegated credential")
	}
	if _, err := f.p.appDevices.invitation(context.Background(), "id", pending.ID); err == nil {
		t.Fatal("offline revoke-all missed delegated invitation")
	}
}

type appDeviceDomainFault struct {
	domains.Backend
	hang       bool
	wrongOwner bool
}

func (b appDeviceDomainFault) Route(ctx context.Context, in *domainpb.Domain) (*domainpb.Domain, error) {
	if b.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	out, err := b.Backend.Route(ctx, in)
	if err == nil && b.wrongOwner {
		out.Owner = "different-owner"
	}
	return out, err
}

type appDeviceAccountFault struct{ storage.Storage }

func (s appDeviceAccountFault) GetAccount(ctx context.Context, id string) (*storage.Account, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestAppDeviceAdmissionDeadlineAndInvalidCredentialPrecedence(t *testing.T) {
	for _, fault := range []string{"domain", "account", "owner"} {
		t.Run(fault, func(t *testing.T) {
			f := newAppDeviceFixture(t)
			d, token := f.enroll(t, nil)
			if fault == "domain" {
				f.p.domains = appDeviceDomainFault{Backend: f.p.domains, hang: true}
			}
			if fault == "account" {
				f.p.storage = appDeviceAccountFault{f.p.storage}
			}
			if fault == "owner" {
				f.p.domains = appDeviceDomainFault{Backend: f.p.domains, wrongOwner: true}
			}
			started := time.Now()
			w := appDeviceOpen(f.p, appDeviceTestHost, token, nil)
			want := 503
			if fault == "owner" {
				want = 403
			}
			if w.Code != want || time.Since(started) > 2500*time.Millisecond {
				t.Fatalf("admission=%d elapsed=%s", w.Code, time.Since(started))
			}
			if _, err := f.p.appDevices.revoke(context.Background(), d.Host, d.Account, d.ID, true); err != nil {
				t.Fatal(err)
			}
			started = time.Now()
			w = appDeviceOpen(f.p, appDeviceTestHost, token, nil)
			if w.Code != 401 || time.Since(started) > 500*time.Millisecond {
				t.Fatal("scope lookup masked revoked credential", w.Code)
			}
		})
	}
}

type appDeviceUnavailableDomain struct{ domains.Backend }

func (b appDeviceUnavailableDomain) Route(context.Context, *domainpb.Domain) (*domainpb.Domain, error) {
	return nil, status.Error(codes.Unavailable, "fixture authority unavailable")
}
func TestAppDeviceOwnerWideRevokeNeverNarrowsOnAuthorityFailure(t *testing.T) {
	f := newAppDeviceFixture(t)
	guest := appDeviceShareGuest(t, f, "authority-guest@example.com")
	d, _ := f.enroll(t, guest)
	f.p.domains = appDeviceUnavailableDomain{f.p.domains}
	if w := f.form(t, "/api/app-devices/revoke-all", url.Values{"scope": {"hostname"}}, nil); w.Code != 503 {
		t.Fatal("unknown owner scope returned success", w.Code)
	}
	var revoked int64
	if err := f.db.QueryRow(`SELECT revoked FROM app_devices WHERE id=?`, d.ID).Scan(&revoked); err != nil || revoked != 0 {
		t.Fatal("failed owner-wide revoke mutated delegated grant")
	}
}
