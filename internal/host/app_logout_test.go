package host

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func appLogoutPost(t *testing.T, p *ProxyServer, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "https://tunn.test/auth/logout", nil)
	r.AddCookie(cookie)
	token, err := p.createCSRFToken(r, "/auth/logout")
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("POST", "https://tunn.test/auth/logout", strings.NewReader(url.Values{"csrf_token": {token}}.Encode()))
	r.Header.Set("Origin", "https://tunn.test")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}

func TestAppLogoutLiveAuthorityAndHandoff(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "remote"
		}
		t.Run(name, func(t *testing.T) {
			p, tunnel, _, db := appProxyFixtureDB(t)
			local := p.storage.(*storage.LocalStorage)
			if remote {
				listener := bufconn.Listen(1 << 20)
				server := grpc.NewServer()
				internalv1.RegisterLoginNodeDBServer(server, NewLoginNodeDBServer(local))
				go func() { _ = server.Serve(listener) }()
				conn, err := grpc.NewClient("passthrough:///logout-authority", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close(); server.Stop(); listener.Close() })
				proxy := storage.NewProxyStorage()
				proxy.SetConnection(conn)
				p.storage = proxy
			}
			platform := appSessionCookie(t, p, appOwnerEmail, "github", true, "")
			old := appSessionCookie(t, p, appOwnerEmail, "github", true, "dashboard.apps.example.com")
			// Simulate the old binary: its signed cookie has no epoch claim.
			legacyClaims, ok := p.parseDomainToken(old.Value, "session")
			if !ok {
				t.Fatal("invalid initial cookie")
			}
			delete(legacyClaims, "session_epoch")
			legacyRaw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, legacyClaims).SignedString(p.getJWTSigningKey())
			if err != nil {
				t.Fatal(err)
			}
			old.Value = legacyRaw
			other := appSessionCookie(t, p, "guest@example.com", "github", true, "dashboard.apps.example.com")
			tunnel.AllowedEmails = []string{"guest@example.com"}
			handler := p.createHandler()
			open := func(cookie *http.Cookie) int {
				r := httptest.NewRequest("GET", "https://dashboard.apps.example.com/", nil)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w.Code
			}
			if open(old) != 200 || open(other) != 200 {
				t.Fatal("initial app sessions refused")
			}
			// Capture an unconsumed handoff before sign-out.
			start := httptest.NewRecorder()
			handler.ServeHTTP(start, httptest.NewRequest("GET", "https://dashboard.apps.example.com/report", nil))
			r := httptest.NewRequest("GET", start.Header().Get("Location"), nil)
			r.AddCookie(platform)
			handoff := httptest.NewRecorder()
			handler.ServeHTTP(handoff, r)
			callback := handoff.Header().Get("Location")
			if !strings.Contains(callback, appCallback) {
				t.Fatal("missing handoff", handoff.Code, handoff.Body)
			}
			// Confirmation and rejected CSRF must leave both existing sessions valid.
			r = httptest.NewRequest("GET", "https://tunn.test/auth/logout", nil)
			r.AddCookie(platform)
			handler.ServeHTTP(httptest.NewRecorder(), r)
			invalid := httptest.NewRecorder()
			handler.ServeHTTP(invalid, httptest.NewRequest("POST", "https://tunn.test/auth/logout", nil))
			if invalid.Code != 403 || open(old) != 200 {
				t.Fatal("unconfirmed logout revoked access")
			}
			// A live idle app stream is checked by the same epoch enforcement.
			watch := httptest.NewRequest("GET", "https://dashboard.apps.example.com/", nil)
			watch.AddCookie(old)
			watch = watch.WithContext(context.WithValue(watch.Context(), domainOwnerKey{}, tunnel.AccountID))
			watched, stop := p.watchAppPermission(watch, tunnel)
			defer stop()
			if w := appLogoutPost(t, p, platform); w.Code != 302 {
				t.Fatal("logout", w.Code, w.Body)
			}
			if open(old) != 403 || open(other) != 200 {
				t.Fatal("revocation did not isolate the signed-out account")
			}
			select {
			case <-watched.Context().Done():
			case <-time.After(5 * time.Second):
				t.Fatal("idle app stream survived sign-out")
			}
			// The old platform cookie cannot issue another handoff.
			r = httptest.NewRequest("GET", start.Header().Get("Location"), nil)
			r.AddCookie(platform)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal("old platform session reissued SSO", w.Code)
			}
			r = httptest.NewRequest("GET", callback, nil)
			r.AddCookie(start.Result().Cookies()[0])
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal("pending handoff survived logout", w.Code, w.Body)
			}
			for _, c := range w.Result().Cookies() {
				if c.Name == appCookie {
					t.Fatal("revoked handoff minted cookie")
				}
			}
			// Reinitializing local storage demonstrates durable revocation.
			p.storage = storage.NewLocalStorage(db)
			if open(old) != 403 {
				t.Fatal("revocation lost after storage restart")
			}
			fresh := appSessionCookie(t, p, appOwnerEmail, "github", true, "dashboard.apps.example.com")
			if open(fresh) != 200 {
				t.Fatal("new sign-in did not restore access")
			}
			if w := appLogoutPost(t, p, platform); w.Code != 302 {
				t.Fatal("idempotent logout", w.Code)
			}
			if open(fresh) != 200 {
				t.Fatal("replayed logout revoked a later sign-in")
			}
			// Devices use a separate lifecycle and do not carry browser epochs.
			account, err := p.storage.GetAccount(context.Background(), tunnel.AccountID)
			if err != nil {
				t.Fatal(err)
			}
			if got, code := p.appAccountAccess(watch, appDeviceSession(appDevice{Account: account.ID, Email: appOwnerEmail}), account, tunnel); code != 200 || got == nil {
				t.Fatal("browser logout affected device authority", code)
			}
		})
	}
}

func TestAppLogoutAuthorityFailureDoesNotClaimSuccess(t *testing.T) {
	p, _, _, db := appProxyFixtureDB(t)
	platform := appSessionCookie(t, p, appOwnerEmail, "github", true, "")
	old := appSessionCookie(t, p, appOwnerEmail, "github", true, "dashboard.apps.example.com")
	if _, err := db.Exec(`CREATE TRIGGER refuse_browser_logout BEFORE INSERT ON browser_session_epochs BEGIN SELECT RAISE(ABORT,'fixture authority failure'); END`); err != nil {
		t.Fatal(err)
	}
	w := appLogoutPost(t, p, platform)
	if w.Code != 503 {
		t.Fatal("uncommitted logout reported success", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == authCookieName && c.MaxAge < 0 {
			t.Fatal("failed logout cleared the retry credential")
		}
	}
	db.Close()
	r := httptest.NewRequest("GET", "https://dashboard.apps.example.com/", nil)
	r.AddCookie(old)
	w = httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("app admission did not fail closed", w.Code)
	}
}

type appLogoutEmailRenewalStorage struct {
	storage.Storage
	storage.AccountEmailStorage
	storage.BrowserSessionStorage
	before, after func()
}

func (s *appLogoutEmailRenewalStorage) MutateAccountEmail(ctx context.Context, id, email, action string) (*storage.Account, error) {
	if s.before != nil {
		s.before()
	}
	account, err := s.AccountEmailStorage.MutateAccountEmail(ctx, id, email, action)
	if s.after != nil {
		s.after()
	}
	return account, err
}

func TestAppLogoutCannotBeUndoneByEmailSessionRenewal(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "remote"
		}
		for _, timing := range []string{"before-mutation", "after-mutation"} {
			t.Run(name+"/"+timing, func(t *testing.T) {
				p, _, _, _ := appProxyFixtureDB(t)
				if remote {
					p.storage = securityReplicaStorage(t, p.storage.(*storage.LocalStorage))
				}
				authority := &appLogoutEmailRenewalStorage{
					Storage:               p.storage,
					AccountEmailStorage:   p.storage.(storage.AccountEmailStorage),
					BrowserSessionStorage: p.storage.(storage.BrowserSessionStorage),
				}
				p.storage = authority
				handler := p.createHandler()
				open := func(cookie *http.Cookie) int {
					r := httptest.NewRequest("GET", "https://dashboard.apps.example.com/", nil)
					r.AddCookie(cookie)
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					return w.Code
				}
				// Repeat after a new sign-in to cover both the initial and rotated epochs.
				for cycle := 0; cycle < 2; cycle++ {
					platform := appSessionCookie(t, p, appOwnerEmail, "github", true, "")
					app := appSessionCookie(t, p, appOwnerEmail, "github", true, "dashboard.apps.example.com")
					if code := open(app); code != 200 {
						t.Fatalf("new sign-in: app status %d", code)
					}
					logout := func() {
						if w := appLogoutPost(t, p, platform); w.Code != 302 {
							t.Fatalf("interleaved logout: %d %s", w.Code, w.Body)
						}
						if code := open(app); code != 403 {
							t.Fatalf("old app cookie after logout: %d", code)
						}
					}
					if timing == "before-mutation" {
						authority.before = logout
					} else {
						authority.after = logout
					}
					r := httptest.NewRequest("GET", "https://tunn.test/account", nil)
					r.AddCookie(platform)
					csrf, err := p.createCSRFToken(r, accountEmailsPath)
					if err != nil {
						t.Fatal(err)
					}
					form := url.Values{"action": {"primary"}, "email": {appOwnerEmail}, "csrf_token": {csrf}}
					r = httptest.NewRequest("POST", "https://tunn.test/account/emails", strings.NewReader(form.Encode()))
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					r.Header.Set("Origin", "https://tunn.test")
					r.AddCookie(platform)
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					authority.before, authority.after = nil, nil
					if w.Code != 303 {
						t.Fatalf("primary-email update: %d %s", w.Code, w.Body)
					}
					var renewed *http.Cookie
					for _, cookie := range w.Result().Cookies() {
						if cookie.Name == authCookieName {
							renewed = cookie
						}
					}
					if renewed == nil {
						t.Fatal("email update did not return its renewed session")
					}
					// Try the actual app SSO route with the late response's cookie.
					start := httptest.NewRecorder()
					handler.ServeHTTP(start, httptest.NewRequest("GET", "https://dashboard.apps.example.com/report", nil))
					if start.Code != 302 {
						t.Fatalf("start SSO: %d", start.Code)
					}
					r = httptest.NewRequest("GET", start.Header().Get("Location"), nil)
					r.AddCookie(renewed)
					w = httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					if w.Code != 403 {
						t.Fatalf("email update restored app SSO after logout: %d %s", w.Code, w.Body)
					}
				}
			})
		}
	}
}
