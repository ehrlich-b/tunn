package host

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

type accountsMailCapture struct {
	to, link string
	calls    int
	err      error
}

func (s *accountsMailCapture) SendMagicLink(to, link string) error {
	s.calls++
	s.to, s.link = to, link
	return s.err
}

func magicFixturePost(p *ProxyServer, query, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://tunn.test/auth/magic?"+query, strings.NewReader(body))
	r.Header.Set("Origin", "https://tunn.test")
	r.RemoteAddr = "192.0.2.40:32100"
	w := httptest.NewRecorder()
	p.handleMagicLinkRequest(w, r)
	return w
}

func assertAccountsSessionCookie(t *testing.T, p *ProxyServer, w *httptest.ResponseRecorder, email string) *http.Cookie {
	t.Helper()
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name != authCookieName {
			continue
		}
		if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != int(authCookieLifetime.Seconds()) {
			t.Fatalf("invalid session cookie attributes: %+v", cookie)
		}
		r := httptest.NewRequest(http.MethodGet, "https://tunn.test/account", nil)
		r.AddCookie(cookie)
		if got, ok := p.getAuthFromCookie(r); !ok || got != email {
			t.Fatalf("session cannot authenticate: email=%q authenticated=%t", got, ok)
		}
		return cookie
	}
	t.Fatal("successful login did not set a session cookie")
	return nil
}

func assertNoAccountsSession(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == authCookieName && cookie.MaxAge > 0 {
			t.Fatalf("failed login issued a session: %+v", cookie)
		}
	}
}

func TestMagicLinkCompleteLoginReturnDeviceAndRestartReplay(t *testing.T) {
	for _, tc := range []struct {
		name, returnTo, destination string
		device                      bool
	}{
		{"account", "", "/account", false},
		{"relative_return", "/account/mcp?client=fixture", "/account/mcp?client=fixture", false},
		{"tunnel_return", "https://api.tunn.test/tasks?view=one", "https://api.tunn.test/tasks?view=one", false},
		{"external_return", "https://elsewhere.invalid/", "/account", false},
		{"device", "/account/mcp", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "login.db")
			db, err := store.OpenLocal(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			local := storage.NewLocalStorage(db)
			p := &ProxyServer{config: securityConfig(), storage: local}
			sink := new(accountsMailCapture)
			p.emailSender = sink
			query := url.Values{"return_to": {tc.returnTo}}
			destination := tc.destination
			var device *storage.DeviceCode
			if tc.device {
				device, err = local.CreateDeviceCode(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				query.Set("device_user_code", device.UserCode)
				destination = "/login?code=" + device.UserCode
			}
			if w := magicFixturePost(p, query.Encode(), `{"email":" Owner@Example.Invalid "}`); w.Code != 200 {
				t.Fatalf("request=%d %s", w.Code, w.Body.String())
			}
			if sink.calls != 1 || sink.to != "owner@example.invalid" {
				t.Fatalf("mail=%+v", sink)
			}
			link, err := url.Parse(sink.link)
			if err != nil || link.Scheme != "https" || link.Host != "tunn.test" || link.Path != "/auth/verify" || link.Query().Get("token") == "" {
				t.Fatalf("invalid mail link=%s err=%v", sink.link, err)
			}
			if account, err := local.GetAccountByEmail(context.Background(), sink.to); err != nil || account != nil {
				t.Fatalf("unverified request created account: %v %v", account, err)
			}
			w := httptest.NewRecorder()
			p.handleMagicLinkVerify(w, httptest.NewRequest(http.MethodGet, sink.link, nil))
			if w.Code != 302 || w.Header().Get("Location") != destination {
				t.Fatalf("verify=%d location=%s body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
			}
			cookie := assertAccountsSessionCookie(t, p, w, sink.to)
			account, err := local.GetAccountByEmail(context.Background(), sink.to)
			if err != nil || account == nil || account.Plan != "free" || account.OperationalState != "active" {
				t.Fatalf("verified account=%v err=%v", account, err)
			}
			if device != nil {
				pending, err := local.GetDeviceCode(context.Background(), device.Code)
				if err != nil || pending == nil || pending.Authorized {
					t.Fatalf("login bypassed device confirmation: %v %v", pending, err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = store.OpenLocal(path)
			if err != nil {
				t.Fatal(err)
			}
			p.storage = storage.NewLocalStorage(db)
			w = httptest.NewRecorder()
			p.handleMagicLinkVerify(w, httptest.NewRequest(http.MethodGet, sink.link, nil))
			if w.Code != 400 {
				t.Fatalf("replayed link accepted after restart: %d", w.Code)
			}
			assertNoAccountsSession(t, w)
			r := httptest.NewRequest(http.MethodGet, "https://tunn.test/account", nil)
			r.AddCookie(cookie)
			if email, ok := p.getAuthFromCookie(r); !ok || email != sink.to {
				t.Fatalf("session lost across restart: %s %t", email, ok)
			}
		})
	}
}

func TestMagicLinkRequestValidationDoesNotSendMail(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"missing_email", `{}`},
		{"malformed_email", `{"email":"not-an-address"}`},
		{"display_name", `{"email":"Owner <owner@example.invalid>"}`},
		{"header_injection", `{"email":"owner@example.invalid\r\nBcc: other@example.invalid"}`},
		{"unknown_field", `{"email":"owner@example.invalid","extra":true}`},
		{"second_value", `{"email":"owner@example.invalid"} {}`},
		{"trailing_text", `{"email":"owner@example.invalid"} text`},
		{"wrong_email_type", `{"email":42}`},
		{"above_request_limit", `{"email":"owner@example.invalid"}` + strings.Repeat(" ", 4097)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := stripeCorrectnessFixture(t)
			sink := new(accountsMailCapture)
			p.emailSender = sink
			w := magicFixturePost(p, "", tc.body)
			if w.Code != 400 || sink.calls != 0 {
				t.Fatalf("invalid signup status=%d mail calls=%d", w.Code, sink.calls)
			}
			assertNoAccountsSession(t, w)
		})
	}
}

func TestMagicLinkMailFailureCanRetryWithoutCreatingAccount(t *testing.T) {
	p, _ := stripeCorrectnessFixture(t)
	sink := &accountsMailCapture{err: errors.New("fixture mail delivery failed")}
	p.emailSender = sink
	if w := magicFixturePost(p, "", `{"email":"owner@example.invalid"}`); w.Code != 500 {
		t.Fatalf("failed delivery=%d", w.Code)
	}
	if account, err := p.storage.GetAccountByEmail(context.Background(), "owner@example.invalid"); err != nil || account != nil {
		t.Fatalf("failed mail created account: %v %v", account, err)
	}
	sink.err = nil
	if w := magicFixturePost(p, "", `{"email":"owner@example.invalid"}`); w.Code != 200 {
		t.Fatalf("retry=%d %s", w.Code, w.Body.String())
	}
	w := httptest.NewRecorder()
	p.handleMagicLinkVerify(w, httptest.NewRequest(http.MethodGet, sink.link, nil))
	if w.Code != 302 {
		t.Fatalf("delivered retry did not complete login: %d", w.Code)
	}
	assertAccountsSessionCookie(t, p, w, "owner@example.invalid")
}

type accountsReplayFailure struct{ storage.Storage }

func (accountsReplayFailure) MarkMagicTokenUsed(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("fixture replay authority failure")
}

func TestMagicLinkReplayAuthorityFailureAllowsRecovery(t *testing.T) {
	for _, failure := range []string{"unavailable", "commit_failure"} {
		t.Run(failure, func(t *testing.T) {
			p, db := stripeCorrectnessFixture(t)
			local := p.storage
			sink := new(accountsMailCapture)
			p.emailSender = sink
			if w := magicFixturePost(p, "", `{"email":"owner@example.invalid"}`); w.Code != 200 {
				t.Fatalf("request=%d", w.Code)
			}
			if failure == "unavailable" {
				p.storage = storage.NewProxyStorage()
			} else {
				p.storage = accountsReplayFailure{local}
			}
			w := httptest.NewRecorder()
			p.handleMagicLinkVerify(w, httptest.NewRequest(http.MethodGet, sink.link, nil))
			if w.Code != 400 {
				t.Fatalf("failed replay authority permitted login: %d", w.Code)
			}
			assertNoAccountsSession(t, w)
			var count int
			if err := db.QueryRow("SELECT count(*) FROM used_magic_tokens").Scan(&count); err != nil || count != 0 {
				t.Fatalf("failed authority consumed token: %d %v", count, err)
			}
			p.storage = local
			w = httptest.NewRecorder()
			p.handleMagicLinkVerify(w, httptest.NewRequest(http.MethodGet, sink.link, nil))
			if w.Code != 302 {
				t.Fatalf("recovered authority rejected unused link: %d %s", w.Code, w.Body.String())
			}
			assertAccountsSessionCookie(t, p, w, "owner@example.invalid")
			w = httptest.NewRecorder()
			p.handleMagicLinkVerify(w, httptest.NewRequest(http.MethodGet, sink.link, nil))
			if w.Code != 400 {
				t.Fatal("recovered token replay accepted")
			}
			assertNoAccountsSession(t, w)
		})
	}
}
