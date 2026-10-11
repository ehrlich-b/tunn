package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
)

type accountsHTTPFake func(*http.Request) (*http.Response, error)

func (f accountsHTTPFake) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func installAccountsHTTPFake(t *testing.T, f accountsHTTPFake) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func accountsProviderResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func accountsGitHubBrowserStart(t *testing.T, p *ProxyServer, query url.Values) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	p.handleGitHubLogin(w, httptest.NewRequest(http.MethodGet, "https://tunn.test/auth/github?"+query.Encode(), nil))
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != 302 || u.Scheme != "https" || u.Host != "github.com" || u.Path != "/login/oauth/authorize" || u.Query().Get("client_id") != p.config.GitHubClientID || u.Query().Get("redirect_uri") != p.getCallbackURL() || u.Query().Get("scope") != "user:email" {
		t.Fatalf("invalid provider redirect: status=%d location=%s err=%v", w.Code, w.Header().Get("Location"), err)
	}
	state := u.Query().Get("state")
	for _, c := range w.Result().Cookies() {
		if c.Name == oauthCookieName {
			if c.Value != state || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.MaxAge != 600 || c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("invalid browser binding cookie: %+v", c)
			}
			return state, c
		}
	}
	t.Fatal("OAuth initiation did not bind browser state")
	return "", nil
}

func accountsGitHubCallback(p *ProxyServer, state, code string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://tunn.test/auth/callback?"+url.Values{"state": {state}, "code": {code}}.Encode(), nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	p.handleCallback(w, r)
	return w
}

func TestGitHubCompleteBrowserLoginMergesVerifiedAliases(t *testing.T) {
	for _, tc := range []struct {
		name, returnTo, destination string
		device                      bool
	}{
		{"return_to", "/account/mcp?client=fixture", "/account/mcp?client=fixture", false},
		{"external_return", "https://outside.invalid/", "/account", false},
		{"device", "/account/mcp", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, db := stripeCorrectnessFixture(t)
			p.config.GitHubClientSecret = "github-client-secret-fixture"
			local := p.storage.(*storage.LocalStorage)
			ctx := context.Background()
			accounts := store.NewAccountStore(db)
			first, err := accounts.FindOrCreateByEmails([]string{"owner@example.invalid"}, "magic_link")
			if err != nil {
				t.Fatal(err)
			}
			alias, err := accounts.FindOrCreateByEmails([]string{"alias@example.invalid"}, "magic_link")
			if err != nil {
				t.Fatal(err)
			}
			billingAlias, err := local.GetAccount(ctx, alias.ID)
			if err != nil {
				t.Fatal(err)
			}
			reviewActivate(t, local, billingAlias, "cus_alias", "sub_alias")
			if err := accounts.RecordUsage(first.ID, 11); err != nil {
				t.Fatal(err)
			}
			if err := accounts.RecordUsage(alias.ID, 17); err != nil {
				t.Fatal(err)
			}
			if _, err := local.OperationsStore().Transition(ctx, accountOperationsAdmin(t, alias.ID), alias.ID, "suspended", "identity review", 0); err != nil {
				t.Fatal(err)
			}
			query := url.Values{"return_to": {tc.returnTo}}
			destination := tc.destination
			if tc.device {
				code, err := local.CreateDeviceCode(ctx)
				if err != nil {
					t.Fatal(err)
				}
				query.Set("device_user_code", code.UserCode)
				destination = "/login?code=" + code.UserCode
			}
			calls := 0
			installAccountsHTTPFake(t, func(r *http.Request) (*http.Response, error) {
				calls++
				switch r.URL.String() {
				case githubTokenURL:
					if r.Method != http.MethodPost || r.ParseForm() != nil || r.PostForm.Get("client_id") != p.config.GitHubClientID || r.PostForm.Get("client_secret") != p.config.GitHubClientSecret || r.PostForm.Get("code") != "one-time-provider-code" || r.PostForm.Get("redirect_uri") != p.getCallbackURL() || r.Header.Get("Accept") != "application/json" {
						t.Errorf("invalid token exchange: %s %v", r.Method, r.PostForm)
					}
					return accountsProviderResponse(r, 200, `{"access_token":"provider-access-token","token_type":"bearer","scope":"user:email"}`), nil
				case githubEmailsURL:
					if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer provider-access-token" {
						t.Errorf("invalid email lookup: %s %v", r.Method, r.Header)
					}
					return accountsProviderResponse(r, 200, `[{"email":"unverified@example.invalid","primary":true,"verified":false},{"email":"alias@example.invalid","primary":false,"verified":true},{"email":"owner@example.invalid","primary":true,"verified":true}]`), nil
				default:
					return nil, fmt.Errorf("unexpected provider call: %s", r.URL)
				}
			})
			state, browserCookie := accountsGitHubBrowserStart(t, p, query)
			w := accountsGitHubCallback(p, state, "one-time-provider-code", browserCookie)
			if w.Code != 302 || w.Header().Get("Location") != destination || calls != 2 {
				t.Fatalf("callback=%d location=%s calls=%d body=%s", w.Code, w.Header().Get("Location"), calls, w.Body.String())
			}
			assertAccountsSessionCookie(t, p, w, first.PrimaryEmail)
			merged, err := accounts.GetByEmail(first.PrimaryEmail)
			if err != nil || merged.ID != alias.ID || merged.Plan != "pro" || merged.OperationalState != "suspended" || len(merged.Emails) != 2 {
				t.Fatalf("provider merge lost account state: %v %v", merged, err)
			}
			if usage, err := accounts.GetMonthlyUsage(first.ID); err != nil || usage != 28 {
				t.Fatalf("merge lost usage: %d %v", usage, err)
			}
			if account, err := local.GetAccountByEmail(ctx, "unverified@example.invalid"); err != nil || account != nil {
				t.Fatalf("unverified provider email attached: %v %v", account, err)
			}
			cleared := false
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == oauthCookieName && cookie.MaxAge < 0 {
					cleared = true
				}
			}
			if !cleared {
				t.Fatal("callback retained OAuth browser cookie")
			}
		})
	}
}

func TestGitHubProviderFailuresDoNotIssueSessionOrAccount(t *testing.T) {
	for _, tc := range []struct {
		name           string
		tokenStatus    int
		tokenBody      string
		emailStatus    int
		emailBody      string
		transportError bool
		wantCalls      int
	}{
		{"token_transport", 200, `{}`, 200, `[]`, true, 1},
		{"token_http", 503, `{"error":"unavailable"}`, 200, `[]`, false, 1},
		{"token_json", 200, `{`, 200, `[]`, false, 1},
		{"token_denied", 200, `{"error":"bad_verification_code","error_description":"expired code"}`, 200, `[]`, false, 1},
		{"token_empty", 200, `{"access_token":""}`, 200, `[]`, false, 1},
		{"emails_http", 200, `{"access_token":"fixture"}`, 503, `[]`, false, 2},
		{"emails_json", 200, `{"access_token":"fixture"}`, 200, `{`, false, 2},
		{"emails_wrong_type", 200, `{"access_token":"fixture"}`, 200, `{"email":"owner@example.invalid"}`, false, 2},
		{"emails_empty", 200, `{"access_token":"fixture"}`, 200, `[]`, false, 2},
		{"emails_unverified", 200, `{"access_token":"fixture"}`, 200, `[{"email":"owner@example.invalid","primary":true,"verified":false}]`, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, db := stripeCorrectnessFixture(t)
			calls := 0
			installAccountsHTTPFake(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if tc.transportError {
					return nil, errors.New("fixture transport error")
				}
				switch r.URL.String() {
				case githubTokenURL:
					return accountsProviderResponse(r, tc.tokenStatus, tc.tokenBody), nil
				case githubEmailsURL:
					return accountsProviderResponse(r, tc.emailStatus, tc.emailBody), nil
				default:
					return nil, fmt.Errorf("unexpected provider call: %s", r.URL)
				}
			})
			state, cookie := accountsGitHubBrowserStart(t, p, url.Values{})
			w := accountsGitHubCallback(p, state, "provider-code", cookie)
			if w.Code != 500 || calls != tc.wantCalls {
				t.Fatalf("callback=%d calls=%d want=%d body=%s", w.Code, calls, tc.wantCalls, w.Body.String())
			}
			assertNoAccountsSession(t, w)
			var count int
			if err := db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); err != nil || count != 0 {
				t.Fatalf("failed provider created accounts=%d err=%v", count, err)
			}
		})
	}
}

func TestGitHubInvalidBrowserCallbackDoesNotCallProvider(t *testing.T) {
	for _, tc := range []string{"missing_cookie", "wrong_cookie", "missing_code", "invalid_state"} {
		t.Run(tc, func(t *testing.T) {
			p, _ := stripeCorrectnessFixture(t)
			calls := 0
			installAccountsHTTPFake(t, func(r *http.Request) (*http.Response, error) {
				calls++
				return nil, fmt.Errorf("unexpected provider call: %s", r.URL)
			})
			state, cookie := accountsGitHubBrowserStart(t, p, url.Values{})
			code := "provider-code"
			switch tc {
			case "missing_cookie":
				cookie = nil
			case "wrong_cookie":
				cookie.Value = "another-browser"
			case "missing_code":
				code = ""
			case "invalid_state":
				state = "invalid"
			}
			w := accountsGitHubCallback(p, state, code, cookie)
			if w.Code != 400 || calls != 0 {
				t.Fatalf("invalid callback=%d provider calls=%d", w.Code, calls)
			}
			assertNoAccountsSession(t, w)
		})
	}
}
