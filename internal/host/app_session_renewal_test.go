package host

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	w := httptest.NewRecorder()
	if err := p.signAppSession(w, claims); err != nil {
		t.Fatal(err)
	}
	fresh := w.Result().Cookies()[0]
	now = now.Add(70 * time.Minute)
	if got := appOpenWithCookie(p, legacy).Code; got != 302 {
		t.Fatalf("legacy after 70 minutes: %d", got)
	}
	if got := appOpenWithCookie(p, fresh).Code; got != 200 {
		t.Fatalf("new session after 70 minutes: %d", got)
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
