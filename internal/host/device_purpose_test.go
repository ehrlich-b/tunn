package host

import (
	"context"
	"encoding/json"
	"github.com/ehrlich-b/tunn/internal/storage"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func purposeCode(t *testing.T, p *ProxyServer, purpose string) string {
	t.Helper()
	r := httptest.NewRequest("POST", "https://tunn.test/api/device/code?purpose="+purpose, nil)
	w := httptest.NewRecorder()
	p.handleDeviceCode(w, r)
	var out struct {
		Code string `json:"device_code"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 200 || out.Code == "" {
		t.Fatal("code creation", w.Code)
	}
	if ok, err := p.storage.AuthorizeDeviceCode(context.Background(), out.Code, "owner@example.com"); err != nil || !ok {
		t.Fatal("consent", err)
	}
	return out.Code
}
func purposeExchange(p *ProxyServer, code string, durable bool) (*httptest.ResponseRecorder, durableTokenFixture) {
	path := "https://tunn.test/api/device/token?code=" + url.QueryEscape(code)
	if durable {
		path += "&durable=1"
	}
	w := httptest.NewRecorder()
	p.handleDeviceToken(w, httptest.NewRequest("GET", path, nil))
	var out durableTokenFixture
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}
func TestDevicePurposeExchangeOrder(t *testing.T) {
	for _, purpose := range []string{"publisher", "management"} {
		for _, firstDurable := range []bool{false, true} {
			p := durableFixture(t)
			code := purposeCode(t, p, purpose)
			accepted := 0
			for _, durable := range []bool{firstDurable, !firstDurable, firstDurable} {
				w, out := purposeExchange(p, code, durable)
				if out.Access != "" {
					accepted++
					if durable != (purpose == "publisher") {
						t.Fatalf("%s accepted mismatched exchange", purpose)
					}
					if w.Code != 200 {
						t.Fatal(w.Code)
					}
				}
			}
			if accepted != 1 {
				t.Fatalf("%s: %d successful exchanges", purpose, accepted)
			}
		}
	}
}
func TestDevicePurposeConcurrentConsumption(t *testing.T) {
	p := durableFixture(t)
	code := purposeCode(t, p, "management")
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan durableTokenFixture, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, out := purposeExchange(p, code, false); results <- out }()
	}
	close(start)
	wg.Wait()
	close(results)
	count := 0
	for out := range results {
		if out.Access != "" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d successful exchanges", count)
	}
}
func TestDevicePurposeManagementRevocation(t *testing.T) {
	p := durableFixture(t)
	code := purposeCode(t, p, "management")
	w, out := purposeExchange(p, code, false)
	if w.Code != 200 || out.Access == "" || out.Device == "" || out.Refresh != "" {
		t.Fatal("management issuance", w.Code)
	}
	request := httptest.NewRequest("GET", "https://tunn.test/api/sharing", nil)
	request.Header.Set("Authorization", "Bearer "+out.Access)
	if _, _, _, ok := p.getAuthFromTunnelBearer(request, &TunnelConnection{}); !ok {
		t.Fatal("management access rejected")
	}
	if _, err := p.devices.db.Exec(`UPDATE durable_devices SET revoked=1 WHERE id=?`, out.Device); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := p.getAuthFromTunnelBearer(request, &TunnelConnection{}); ok {
		t.Fatal("revoked management access accepted")
	}
}
func TestDevicePurposeConsentText(t *testing.T) {
	for _, purpose := range []string{"publisher", "management"} {
		p := durableFixture(t)
		w := httptest.NewRecorder()
		p.handleDeviceCode(w, httptest.NewRequest("POST", "https://tunn.test/api/device/code?purpose="+purpose, nil))
		var out struct {
			UserCode string `json:"user_code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		r := httptest.NewRequest("GET", "https://tunn.test/login?code="+out.UserCode, nil)
		r.AddCookie(securityCookie(t, p, "owner@example.com"))
		w = httptest.NewRecorder()
		p.showDeviceAuthorizePage(w, r, out.UserCode)
		label := "Publish and connect to tunnels"
		if purpose == "management" {
			label = "Manage your account"
		}
		if !strings.Contains(w.Body.String(), label) {
			t.Fatalf("missing %s consent", purpose)
		}
	}
}

func TestDevicePurposeAccountBindingAndReplica(t *testing.T) {
	p := durableFixture(t)
	owner, err := p.storage.GetAccountByEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	other, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"other@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	replica := securityReplicaStorage(t, p.storage.(*storage.LocalStorage))
	code, err := replica.CreateDeviceCodeForPurpose(context.Background(), "management", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if code.Purpose != "management" || code.AccountID != owner.ID {
		t.Fatal("scope lost over RPC")
	}
	if ok, err := replica.AuthorizeDeviceCode(context.Background(), code.Code, other.PrimaryEmail); err != nil || ok {
		t.Fatal("other account approved bound code", err)
	}
	if ok, err := replica.AuthorizeDeviceCode(context.Background(), code.Code, owner.PrimaryEmail); err != nil || !ok {
		t.Fatal("owner approval", err)
	}
	_, out := purposeExchange(p, code.Code, false)
	p.storage = replica
	r := httptest.NewRequest("GET", "https://tunn.test/api/sharing", nil)
	r.Header.Set("Authorization", "Bearer "+out.Access)
	if _, _, _, ok := p.getAuthFromTunnelBearer(r, &TunnelConnection{}); !ok {
		t.Fatal("replica management validation")
	}
	if _, err := p.devices.db.Exec(`UPDATE durable_devices SET revoked=1 WHERE id=?`, out.Device); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := p.getAuthFromTunnelBearer(r, &TunnelConnection{}); ok {
		t.Fatal("replica accepted revoked management")
	}
	if _, _, _, ok := p.getAuthFromTunnelBearer(r, &TunnelConnection{TunnelID: "api"}); ok {
		t.Fatal("management credential used on tunnel")
	}
}
