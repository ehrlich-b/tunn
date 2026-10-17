package host

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/storage"
)

type rejectedBrowserAccountStorage struct {
	storage.Storage
	err error
}

func (s rejectedBrowserAccountStorage) GetAccount(context.Context, string) (*storage.Account, error) {
	return nil, s.err
}

func requireSessionCleared(t *testing.T, w *httptest.ResponseRecorder, name, domain string) {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge < 0 && c.Value == "" && c.Path == "/" && c.Domain == domain && c.Secure && c.HttpOnly && c.SameSite == http.SameSiteLaxMode {
			return
		}
	}
	t.Fatalf("session was not cleared with its original scope: %v", w.Header().Values("Set-Cookie"))
}

func TestRevokedBrowserSessionMatchesSignedOut(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "remote"
		}
		t.Run(name, func(t *testing.T) {
			f := newAppDeviceFixture(t)
			p := f.p
			var err error
			p.devices, err = newDeviceCredentialStore(f.db)
			if err != nil {
				t.Fatal(err)
			}
			if remote {
				p.storage = securityReplicaStorage(t, p.storage.(*storage.LocalStorage))
			}
			handler := p.createHandler()
			call := func(path, accept string, cookie *http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", "https://tunn.test"+path, nil)
				r.Header.Set("Accept", accept)
				if cookie != nil {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			// Repeat across both the initial empty epoch and a rotated epoch.
			for cycle := 0; cycle < 2; cycle++ {
				cookie := appSessionCookie(t, p, appDeviceTestEmail, "github", true, "")
				if w := call("/account", "text/html", cookie); w.Code != 200 {
					t.Fatalf("fresh login: %d %s", w.Code, w.Body)
				}
				if w := call("/api/account/tunnels", "application/json", cookie); w.Code != 200 {
					t.Fatalf("fresh API login: %d %s", w.Code, w.Body)
				}
				if w := appLogoutPost(t, p, cookie); w.Code != 302 {
					t.Fatalf("logout: %d %s", w.Code, w.Body)
				}
				routes := []string{"/account", "/api/account/tunnels", "/account/audit", "/account/audit.csv", "/account/audit.json", "/api/account/audit/00000000000000000000000000000000", "/upgrade", "/api/billing/status", "/account/emails", "/account/devices", "/account/app-devices", "/api/app-devices", "/account/inspect", "/api/inspector/endpoints", "/account/sharing"}
				for _, path := range routes {
					for _, accept := range []string{"text/html", "application/json"} {
						t.Run(nameOfSessionRoute(path, accept, cycle), func(t *testing.T) {
							none, stale := call(path, accept, nil), call(path, accept, cookie)
							if stale.Code != none.Code || stale.Body.String() != none.Body.String() || stale.Header().Get("Location") != none.Header().Get("Location") || stale.Header().Get("Content-Type") != none.Header().Get("Content-Type") {
								t.Fatalf("stale (%d %s %q) != signed out (%d %s %q)", stale.Code, stale.Header().Get("Location"), stale.Body, none.Code, none.Header().Get("Location"), none.Body)
							}
							requireSessionCleared(t, stale, authCookieName, "tunn.test")
						})
					}
				}
			}
		})
	}
}

func nameOfSessionRoute(path, accept string, cycle int) string {
	suffix := "initial"
	if cycle > 0 {
		suffix = "rotated"
	}
	return path + "/" + accept + "/" + suffix
}

func TestBrowserSessionLookupFailuresRemainUnavailable(t *testing.T) {
	f := newAppDeviceFixture(t)
	p := f.p
	var err error
	p.devices, err = newDeviceCredentialStore(f.db)
	if err != nil {
		t.Fatal(err)
	}
	original := p.storage
	cookie := f.cookie
	handler := p.createHandler()
	for _, failure := range []struct {
		name    string
		storage storage.Storage
	}{
		{"lookup-error", rejectedBrowserAccountStorage{Storage: original, err: errors.New("fixture lookup failure")}},
		{"missing-account", rejectedBrowserAccountStorage{Storage: original}},
		{"unavailable", nil},
	} {
		p.storage = failure.storage
		for _, path := range []string{"/account", "/api/account/tunnels", "/account/audit", "/account/audit.csv", "/account/audit.json", "/api/account/audit/00000000000000000000000000000000", "/account/emails", "/account/devices", "/account/app-devices", "/api/app-devices", "/account/inspect", "/api/inspector/endpoints", "/account/sharing"} {
			t.Run(failure.name+path, func(t *testing.T) {
				r := httptest.NewRequest("GET", "https://tunn.test"+path, nil)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if failure.name == "missing-account" {
					requireSessionCleared(t, w, authCookieName, "tunn.test")
					if w.Code != 302 && w.Code != 401 {
						t.Fatalf("missing account: %d %s", w.Code, w.Body)
					}
				} else {
					if w.Code != 503 {
						t.Fatalf("storage failure: %d %s", w.Code, w.Body)
					}
					for _, c := range w.Result().Cookies() {
						if c.Name == authCookieName && c.MaxAge < 0 {
							t.Fatal("storage failure discarded retry credential")
						}
					}
				}
			})
		}
	}
}

func TestRevokedAppSessionRestartsSignIn(t *testing.T) {
	p, _, _, _ := appProxyFixtureDB(t)
	platform := appSessionCookie(t, p, appOwnerEmail, "github", true, "")
	app := appSessionCookie(t, p, appOwnerEmail, "github", true, "dashboard.apps.example.com")
	handler := p.createHandler()
	call := func(target string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", target, nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	target := "https://dashboard.apps.example.com/report?x=1"
	none := call(target, nil)
	login := none.Header().Get("Location")
	signedOut := call(login, nil)
	if w := appLogoutPost(t, p, platform); w.Code != 302 {
		t.Fatal(w.Code)
	}
	for _, accept := range []string{"text/html", "application/json"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Header.Set("Accept", accept)
		r.AddCookie(app)
		stale := httptest.NewRecorder()
		handler.ServeHTTP(stale, r)
		if stale.Code != none.Code {
			t.Fatalf("app stale status %d != %d", stale.Code, none.Code)
		}
		requireSessionCleared(t, stale, appCookie, "")
		// SSO nonces are random: compare their signed host and return path.
		for _, w := range []*httptest.ResponseRecorder{none, stale} {
			u, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			claims, ok := p.parseDomainToken(u.Query().Get("request"), "domain_login_request")
			if !ok || u.Host != "tunn.test" || claims["host"] != "dashboard.apps.example.com" || claims["path"] != "/report?x=1" {
				t.Fatalf("invalid signed-out SSO: %v %v", u, claims)
			}
		}
	}
	stale := call(login, platform)
	if stale.Code != signedOut.Code || stale.Body.String() != signedOut.Body.String() || stale.Header().Get("Location") != signedOut.Header().Get("Location") {
		t.Fatalf("stale platform SSO differs from signed out: %d %s", stale.Code, stale.Body)
	}
	requireSessionCleared(t, stale, authCookieName, "tunn.test")
	fresh := appSessionCookie(t, p, appOwnerEmail, "github", true, "")
	if w := call(login, fresh); w.Code != 302 || !strings.Contains(w.Header().Get("Location"), appCallback) {
		t.Fatalf("fresh SSO: %d %s", w.Code, w.Body)
	}
	p.storage = rejectedBrowserAccountStorage{Storage: p.storage, err: errors.New("fixture lookup failure")}
	for _, request := range []struct {
		target string
		cookie *http.Cookie
	}{{target, app}, {login, platform}} {
		if w := call(request.target, request.cookie); w.Code != 503 {
			t.Fatalf("app lookup error: %d %s", w.Code, w.Body)
		}
	}
}
