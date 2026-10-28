package host

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
)

func TestAppSessionRenewal(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	original := appSessionCookie(t, p, appOwnerEmail, "github", true, appHost)
	base, ok := p.parseDomainToken(original.Value, "session")
	if !ok {
		t.Fatal("initial session")
	}
	base["custom_claim"] = "preserved"
	for _, tc := range []struct {
		name       string
		age        time.Duration
		aud, epoch string
		want       int
		renew      bool
	}{
		{"past-renewal", 11 * time.Minute, appHost, "", 200, true},
		{"before-renewal", 5 * time.Minute, appHost, "", 200, false},
		{"revoked", 11 * time.Minute, appHost, "revoked", 302, false},
		{"wrong-audience", 11 * time.Minute, "other.example.com", "", 302, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			for k, v := range base {
				claims[k] = v
			}
			claims["iat"] = time.Now().Add(-tc.age).Unix()
			claims["exp"] = time.Now().Add(appSessionIdle - tc.age).Unix()
			claims["aud"], claims["session_epoch"] = tc.aud, tc.epoch
			raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
			if err != nil {
				t.Fatal(err)
			}
			w := appOpenWithCookie(p, &http.Cookie{Name: appCookie, Value: raw})
			if w.Code != tc.want {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			var renewed *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == appCookie && c.MaxAge > 0 {
					renewed = c
				}
			}
			if (renewed != nil) != tc.renew {
				t.Fatalf("renewed=%v", renewed != nil)
			}
			if renewed != nil {
				got, ok := p.parseDomainToken(renewed.Value, "session")
				if !ok || got["custom_claim"] != "preserved" || got["session_epoch"] != tc.epoch || got["aud"] != tc.aud || got["account_id"] != claims["account_id"] || got["exp"].(float64) <= float64(claims["exp"].(int64)) || renewed.MaxAge != int(appSessionIdle.Seconds()) {
					t.Fatalf("renewed claims: %v", got)
				}
			}
		})
	}
	if appSessionIdle > authCookieLifetime {
		t.Fatal("app lifetime exceeds platform lifetime")
	}
}

func TestAppSessionLoginResponses(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	cookie := appSessionCookie(t, p, appOwnerEmail, "github", true, appHost)
	claims, _ := p.parseDomainToken(cookie.Value, "session")
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"missing", "expired"} {
		for _, tc := range []struct {
			name, mode, accept string
			want               int
		}{
			{"fetch", "cors", "*/*", 401}, {"no-headers", "", "", 401}, {"json", "", "application/json", 401},
			{"navigate", "navigate", "text/html,application/xhtml+xml", 302},
			{"navigate-json", "navigate", "application/json", 302},
		} {
			t.Run(state+"/"+tc.name, func(t *testing.T) {
				r := httptest.NewRequest("GET", "https://"+appHost+"/", nil)
				r.Header.Set("Sec-Fetch-Mode", tc.mode)
				r.Header.Set("Accept", tc.accept)
				if state == "expired" {
					r.AddCookie(&http.Cookie{Name: appCookie, Value: raw})
				}
				w := httptest.NewRecorder()
				p.createHandler().ServeHTTP(w, r)
				if w.Code != tc.want {
					t.Fatalf("status %d: %s", w.Code, w.Body)
				}
				if tc.want == 401 {
					var body map[string]interface{}
					if w.Header().Get("Tunn-Auth") != "login" || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || json.Unmarshal(w.Body.Bytes(), &body) != nil || body["error"] == "" || w.Header().Get("Location") != "" {
						t.Fatal("invalid login response", w.Header(), w.Body)
					}
				} else if !strings.Contains(w.Header().Get("Location"), "/auth/domain?") {
					t.Fatal("missing handoff", w.Header())
				}
			})
		}
	}
}

func appNavigationRequest(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.Header.Set("Accept", "text/html")
	return r
}

func TestAppSessionClockAndAbsoluteCap(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	now := time.Now().Truncate(time.Second)
	p.now = func() time.Time { return now }
	original := appSessionCookie(t, p, appOwnerEmail, "github", true, appHost)
	claims, ok := p.parseDomainToken(original.Value, "session")
	if !ok {
		t.Fatal("original cookie invalid")
	}
	claims["auth_iat"] = now.Add(-authCookieLifetime + time.Hour).Unix()
	claims["iat"] = now.Add(-11 * time.Minute).Unix()
	claims["exp"] = now.Add(time.Hour).Unix()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	w := appOpenWithCookie(p, &http.Cookie{Name: appCookie, Value: raw})
	var renewed *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == appCookie && c.MaxAge > 0 {
			renewed = c
		}
	}
	if w.Code != 200 || renewed == nil {
		t.Fatalf("renewal: %d %v", w.Code, w.Header())
	}
	got, valid := p.parseDomainToken(renewed.Value, "session")
	if !valid || int64(got["exp"].(float64)) != now.Add(time.Hour).Unix() || int64(got["auth_iat"].(float64)) != claims["auth_iat"].(int64) {
		t.Fatalf("cap claims %v", got)
	}
	now = now.Add(time.Hour)
	w = appOpenWithCookie(p, renewed)
	if w.Code != 302 {
		t.Fatalf("cap should expire: %d", w.Code)
	}
}

func TestRenewalResponseCachePolicy(t *testing.T) {
	for _, tc := range []struct {
		cache string
		want  bool
	}{{"private, max-age=60", true}, {"public, max-age=60", false}, {"max-age=60, S-MaxAge=30", false}} {
		t.Run(tc.cache, func(t *testing.T) {
			h := make(http.Header)
			h.Set("Cache-Control", tc.cache)
			if responseAllowsAppRenewal(h, 200) != tc.want {
				t.Fatalf("cache policy %q", tc.cache)
			}
		})
	}
}

func TestAppSessionIdleAndPolling(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	now := time.Now().Truncate(time.Second)
	p.now = func() time.Time { return now }
	legacy := appSessionCookie(t, p, appOwnerEmail, "github", true, appHost)
	claims, _ := p.parseDomainToken(legacy.Value, "session")
	delete(claims, "auth_iat")
	claims["exp"] = now.Add(12 * time.Hour).Unix()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	legacy.Value = raw
	w := httptest.NewRecorder()
	if err := p.signAppSession(w, claims); err != nil {
		t.Fatal(err)
	}
	fresh := w.Result().Cookies()[0]
	now = now.Add(12*time.Hour + time.Minute)
	if got := appOpenWithCookie(p, legacy).Code; got != 302 {
		t.Fatalf("legacy after 12 hours: %d", got)
	}
	if got := appOpenWithCookie(p, fresh).Code; got != 200 {
		t.Fatalf("new session after 12 hours: %d", got)
	}
	for i := 0; i < 36; i++ {
		now = now.Add(5 * time.Minute)
		result := appOpenWithCookie(p, fresh)
		if result.Code != 200 {
			t.Fatalf("poll %d: %d", i, result.Code)
		}
		for _, c := range result.Result().Cookies() {
			if c.Name == appCookie && c.MaxAge > 0 {
				fresh = c
			}
		}
	}
}

func TestAppRenewalExcludedFromPublicUpstream(t *testing.T) {
	p, tunnel, _ := appProxyFixture(t)
	now := time.Now().Truncate(time.Second)
	p.now = func() time.Time { return now }
	cookie := appSessionCookie(t, p, appOwnerEmail, "github", true, appHost)
	now = now.Add(11 * time.Minute)
	stream := tunnel.Stream.(*meteringFixtureStream)
	stream.hook = func(msg *pb.TunnelMessage) error {
		if req := msg.GetHttpRequest(); req != nil {
			tunnel.pendingMu.RLock()
			ch := tunnel.pendingRequests[req.ConnectionId]
			tunnel.pendingMu.RUnlock()
			ch <- &pb.HttpResponse{ConnectionId: req.ConnectionId, StatusCode: 200, Headers: map[string]string{"Cache-Control": "public, max-age=60"}, Body: []byte("ok")}
		}
		return nil
	}
	w := appOpenWithCookie(p, cookie)
	if w.Code != 200 {
		t.Fatalf("response %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == appCookie {
			t.Fatalf("public response carried session: %v", c)
		}
	}
}

func TestAppSessionExactBoundariesAndBaseMigration(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	start := time.Now().Truncate(time.Second)
	now := start
	p.now = func() time.Time { return now }
	// The base release used a 12-hour app cookie with iat but no auth_iat.
	legacy := appSessionCookie(t, p, appOwnerEmail, "github", true, appHost)
	claims, _ := p.parseDomainToken(legacy.Value, "session")
	delete(claims, "auth_iat")
	claims["exp"] = start.Add(12 * time.Hour).Unix()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	legacy.Value = raw
	for _, tc := range []struct {
		age   time.Duration
		renew bool
	}{{10*time.Minute - time.Second, false}, {10 * time.Minute, true}} {
		now = start.Add(tc.age)
		out := appOpenWithCookie(p, legacy)
		if out.Code != 200 {
			t.Fatalf("age %v: status %d", tc.age, out.Code)
		}
		var renewed *http.Cookie
		for _, c := range out.Result().Cookies() {
			if c.Name == appCookie && c.MaxAge > 0 {
				renewed = c
			}
		}
		if (renewed != nil) != tc.renew {
			t.Fatalf("age %v: renewal %v", tc.age, renewed)
		}
		if renewed != nil {
			c, ok := p.parseDomainToken(renewed.Value, "session")
			if !ok || appAuthIAT(c) != start.Unix() {
				t.Fatalf("migration: %v", c)
			}
		}
	}
	now = start
	w := httptest.NewRecorder()
	if err := p.signAppSession(w, claims); err != nil {
		t.Fatal(err)
	}
	fresh := w.Result().Cookies()[0]
	now = start.Add(24*time.Hour - time.Second)
	if got := appOpenWithCookie(p, fresh).Code; got != 200 {
		t.Fatalf("before idle: %d", got)
	}
	now = start.Add(24 * time.Hour)
	if got := appOpenWithCookie(p, fresh).Code; got != 302 {
		t.Fatalf("at idle: %d", got)
	}
	// A renewal just before the cap must not extend beyond it.
	now = start.Add(authCookieLifetime - time.Second)
	w = httptest.NewRecorder()
	if err := p.signAppSession(w, claims); err != nil {
		t.Fatal(err)
	}
	capped := w.Result().Cookies()[0]
	if capped.MaxAge != 1 {
		t.Fatalf("remaining cap: %d", capped.MaxAge)
	}
	if got := appOpenWithCookie(p, capped).Code; got != 200 {
		t.Fatalf("before cap: %d", got)
	}
	now = start.Add(authCookieLifetime)
	if got := appOpenWithCookie(p, capped).Code; got != 302 {
		t.Fatalf("at cap: %d", got)
	}
}

func TestLegacyHandoffMigration(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	now := time.Now().Truncate(time.Second)
	p.now = func() time.Time { return now }
	platform := appSessionCookie(t, p, appOwnerEmail, "github", true, "")
	nav := httptest.NewRequest("GET", "https://"+appHost+"/", nil)
	init := httptest.NewRecorder()
	p.startDomainSSO(init, nav)
	login := httptest.NewRequest("GET", init.Header().Get("Location"), nil)
	login.AddCookie(platform)
	out := httptest.NewRecorder()
	p.handleDomainLogin(out, login)
	dest, err := url.Parse(out.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	claims, ok := p.parseDomainToken(dest.Query().Get("token"), "domain_handoff")
	if !ok {
		t.Fatal("handoff")
	}
	// The base handoff omitted both timestamps and expired after one minute.
	delete(claims, "iat")
	delete(claims, "auth_iat")
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	q := dest.Query()
	q.Set("token", raw)
	dest.RawQuery = q.Encode()
	callback := httptest.NewRequest("GET", dest.String(), nil)
	for _, c := range init.Result().Cookies() {
		callback.AddCookie(c)
	}
	complete := httptest.NewRecorder()
	p.handleDomainCallback(complete, callback)
	if complete.Code != 302 {
		t.Fatalf("legacy callback: %d %s", complete.Code, complete.Body)
	}
	for _, c := range complete.Result().Cookies() {
		if c.Name == appCookie {
			got, ok := p.parseDomainToken(c.Value, "session")
			if !ok || appAuthIAT(got) != now.Unix() {
				t.Fatalf("migrated: %v", got)
			}
			return
		}
	}
	t.Fatal("missing migrated app cookie")
}

func TestRenewalRepeatedCacheControl(t *testing.T) {
	h := http.Header{}
	h.Add("Cache-Control", "private, max-age=10")
	h.Add("Cache-Control", "s-MaXaGe=30")
	if responseAllowsAppRenewal(h, http.StatusOK) {
		t.Fatal("shared cache directive in second field")
	}
	h.Del("Cache-Control")
	h.Add("Cache-Control", "private")
	h.Add("Cache-Control", "no-store")
	if !responseAllowsAppRenewal(h, http.StatusNotModified) {
		t.Fatal("private 304 should allow renewal")
	}
	if responseAllowsAppRenewal(h, http.StatusSwitchingProtocols) {
		t.Fatal("websocket must not renew")
	}
}

func TestAppRenewalBufferedAndStreamingResponses(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, status := range []int{200, 304} {
			for _, shared := range []bool{false, true} {
				name := fmt.Sprintf("stream=%t/status=%d/shared=%t", streaming, status, shared)
				t.Run(name, func(t *testing.T) {
					p, tunnel, _ := appProxyFixture(t)
					now := time.Now().Truncate(time.Second)
					p.now = func() time.Time { return now }
					cookie := appSessionCookie(t, p, appOwnerEmail, "github", true, appHost)
					now = now.Add(10 * time.Minute)
					fields := []*pb.HttpHeader{{Name: "Cache-Control", Value: "private"}, {Name: "Set-Cookie", Value: "app_pref=blue; Path=/"}}
					if shared {
						fields = append(fields, &pb.HttpHeader{Name: "cache-control", Value: "s-MaXaGe=60"})
					} else {
						fields = append(fields, &pb.HttpHeader{Name: "cache-control", Value: "no-store"})
					}
					if streaming {
						tunnel.Capabilities = map[string]bool{common.CapabilityConnectionStreamV1: true, common.CapabilityHTTPStreamV1: true}
						tunnel.pendingStreams = make(map[string]*pendingConnection)
					}
					tunnel.Stream.(*meteringFixtureStream).hook = func(msg *pb.TunnelMessage) error {
						if req := msg.GetHttpRequest(); req != nil {
							tunnel.pendingMu.RLock()
							ch := tunnel.pendingRequests[req.ConnectionId]
							tunnel.pendingMu.RUnlock()
							ch <- &pb.HttpResponse{ConnectionId: req.ConnectionId, StatusCode: int32(status), HeaderFields: fields}
						}
						if half := msg.GetConnectionHalfClose(); half != nil {
							tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: half.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: int32(status), HeaderFields: fields}}}})
							tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: half.ConnectionId}}})
						}
						return nil
					}
					out := appOpenWithCookie(p, cookie)
					if out.Code != status {
						t.Fatalf("status %d: %s", out.Code, out.Body)
					}
					app, renewed := false, false
					for _, c := range out.Result().Cookies() {
						if c.Name == "app_pref" && c.Value == "blue" {
							app = true
						}
						if c.Name == appCookie && c.MaxAge > 0 {
							renewed = true
						}
					}
					if !app || renewed == shared {
						t.Fatalf("application cookie=%v renewal=%v headers=%v", app, renewed, out.Header())
					}
				})
			}
		}
	}
}

func TestAppRenewalExcludedRequests(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	now := time.Now().Truncate(time.Second)
	p.now = func() time.Time { return now }
	cookie := appSessionCookie(t, p, appOwnerEmail, "github", true, appHost)
	claims, _ := p.parseDomainToken(cookie.Value, "session")
	now = now.Add(11 * time.Minute)
	for _, tc := range []struct {
		name, path, authorization string
		websocket                 bool
	}{
		{"mcp", "/mcp", "", false},
		{"grant", "/", "Bearer tunn_gr_invalid", false},
		{"mcp-bearer", "/", "Bearer tunn_mcp_invalid", false},
		{"websocket", "/", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://"+appHost+tc.path, nil)
			r.AddCookie(cookie)
			if tc.authorization != "" {
				r.Header.Set("Authorization", tc.authorization)
			}
			if tc.websocket {
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
			}
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, r)
			for _, c := range w.Result().Cookies() {
				if c.Name == appCookie && c.MaxAge > 0 {
					t.Fatalf("unexpected renewal: %v", w.Header())
				}
			}
		})
	}
	r := httptest.NewRequest("GET", "https://"+appHost+"/", nil)
	r = r.WithContext(context.WithValue(r.Context(), inspectorReplayKey{}, &inspectorReplay{}))
	if p.appRenewalCookie(r, claims) != nil {
		t.Fatal("inspector replay renewed the browser cookie")
	}
}

func TestAppDeviceDoesNotRenewBrowserCookie(t *testing.T) {
	f := newAppDeviceFixture(t)
	_, secret := f.enroll(t, f.cookie)
	now := time.Now().Truncate(time.Second)
	f.p.now = func() time.Time { return now }
	browser := appSessionCookie(t, f.p, appDeviceTestEmail, "github", true, appDeviceTestHost)
	now = now.Add(11 * time.Minute)
	r := httptest.NewRequest("GET", "https://"+appDeviceTestHost+"/", nil)
	r.AddCookie(browser)
	r.Header.Set("Tunn-Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("device: %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == appCookie && c.MaxAge > 0 {
			t.Fatal("device request renewed browser cookie")
		}
	}
}
