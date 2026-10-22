package host

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
)

func TestDogfoodDeviceCodeExpiryAndRecovery(t *testing.T) {
	local := securityDB(t)
	for _, replica := range []bool{false, true} {
		t.Run(map[bool]string{false: "login node", true: "replica"}[replica], func(t *testing.T) {
			p := securityProxy(local)
			if replica {
				p.storage = securityReplicaStorage(t, local)
			}
			w := httptest.NewRecorder()
			p.handleDeviceCode(w, httptest.NewRequest("POST", "https://tunn.test/api/device/code", nil))
			var code client.DeviceCodeResponse
			if err := json.Unmarshal(w.Body.Bytes(), &code); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || code.ExpiresIn < 599 || code.ExpiresIn > 600 || code.ExpiresAt < time.Now().Add(599*time.Second).Unix() {
				t.Fatalf("expiry response = %d %+v", w.Code, code)
			}
			if ok, err := p.storage.AuthorizeDeviceCode(context.Background(), code.DeviceCode, "owner@example.test"); err != nil || !ok {
				t.Fatalf("authorize = %v %v", ok, err)
			}
			poll := httptest.NewRecorder()
			p.handleDeviceToken(poll, httptest.NewRequest("GET", "https://tunn.test/api/device/token?code="+url.QueryEscape(code.DeviceCode), nil))
			if poll.Code != 400 || strings.Contains(poll.Body.String(), "access_token") {
				t.Fatalf("token polling = %d %s", poll.Code, poll.Body)
			}
			for _, usedCode := range []string{code.UserCode, "expired-fixture"} {
				page := httptest.NewRecorder()
				p.handleLoginPage(page, httptest.NewRequest("GET", "https://tunn.test/login?code="+usedCode, nil))
				assertDeviceRecovery(t, page)
				callback := httptest.NewRecorder()
				p.showDeviceAuthorizePage(callback, httptest.NewRequest("GET", "https://tunn.test/auth/callback", nil), usedCode)
				assertDeviceRecovery(t, callback)
			}
		})
	}
}

func assertDeviceRecovery(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != 400 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "expired or already used") || !strings.Contains(w.Body.String(), "If login has stopped, run tunn login again.") || !strings.Contains(w.Body.String(), "open its newest sign-in link") {
		t.Fatalf("recovery page = %d %s", w.Code, w.Body)
	}
}
