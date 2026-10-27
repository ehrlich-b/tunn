package host

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		{"past-half", 7 * time.Hour, appHost, "", 200, true},
		{"before-half", 5 * time.Hour, appHost, "", 200, false},
		{"revoked", 7 * time.Hour, appHost, "revoked", 302, false},
		{"wrong-audience", 7 * time.Hour, "other.example.com", "", 302, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			for k, v := range base {
				claims[k] = v
			}
			claims["iat"] = time.Now().Add(-tc.age).Unix()
			claims["exp"] = time.Now().Add(appSessionLifetime - tc.age).Unix()
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
				if !ok || got["custom_claim"] != "preserved" || got["session_epoch"] != tc.epoch || got["aud"] != tc.aud || got["account_id"] != claims["account_id"] || got["exp"].(float64) <= float64(claims["exp"].(int64)) || renewed.MaxAge != int(appSessionLifetime.Seconds()) {
					t.Fatalf("renewed claims: %v", got)
				}
			}
		})
	}
	if appSessionLifetime > authCookieLifetime {
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
			{"navigate-json", "navigate", "application/json", 401},
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
					var body map[string]string
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
