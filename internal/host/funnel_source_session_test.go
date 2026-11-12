package host

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestFunnelSourceProviderSessions(t *testing.T) {
	for _, public := range []string{"tunn.test", "login.test"} {
		for _, provider := range []string{"magic", "google", "github"} {
			t.Run(public+"/"+provider, func(t *testing.T) {
				p := newMCPOAuthFixture(t).p
				p.config.PublicAddr = public
				p.emailSender = new(accountsMailCapture)
				browser := funnelBrowser(t, p)
				funnelVisit(t, browser, "https://tunn.test/?src=alt")
				const email = "browser@example.invalid"
				if provider == "magic" {
					funnelSignup(t, browser, p, public)
				} else {
					start, callback := "/auth/google", "/auth/google/callback"
					if provider == "google" {
						p.config.GoogleClientID, p.config.GoogleClientSecret = "fixture-id", "fixture-secret"
						p.googleHTTPClient = googleFixtureTransport(t, p, true)
					} else {
						start, callback = "/auth/github", "/auth/callback"
						p.config.GitHubClientID, p.config.GitHubClientSecret = "fixture-id", "fixture-secret"
						installAccountsHTTPFake(t, func(r *http.Request) (*http.Response, error) {
							switch r.URL.String() {
							case githubTokenURL:
								if r.ParseForm() != nil || r.Form.Get("code") != email || r.Form.Get("redirect_uri") != p.getCallbackURL() {
									return nil, fmt.Errorf("incorrect fixture OAuth binding")
								}
								return accountsProviderResponse(r, 200, `{"access_token":"fixture-token"}`), nil
							case githubEmailsURL:
								if r.Header.Get("Authorization") != "Bearer fixture-token" {
									return nil, fmt.Errorf("missing fixture token")
								}
								return accountsProviderResponse(r, 200, `[{"email":"browser@example.invalid","verified":true,"primary":true}]`), nil
							default:
								return nil, fmt.Errorf("unexpected provider call: %s", r.URL)
							}
						})
					}
					reader := *browser
					reader.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
					response, err := reader.Get("https://" + public + start + "?src=saashub")
					if err != nil {
						t.Fatal(err)
					}
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if response.StatusCode != 302 {
						t.Fatal(response.StatusCode)
					}
					authorize, err := url.Parse(response.Header.Get("Location"))
					if err != nil {
						t.Fatal(err)
					}
					target := "https://" + public + callback + "?" + url.Values{"state": {authorize.Query().Get("state")}, "code": {email}}.Encode()
					response, err = reader.Get(target)
					if err != nil {
						t.Fatal(err)
					}
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if response.StatusCode != 302 || response.Header.Get("Location") != "/account" {
						t.Fatal(response.StatusCode, response.Header)
					}
					assertFunnelSessionCookie(t, p, public, response, false)
					funnelVisit(t, browser, "https://"+public+response.Header.Get("Location"))
					assertFunnelAccount(t, browser, p, public, email)
				}
				var n int
				if err := p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='signup' AND source='alt'`).Scan(&n); err != nil || n != 1 {
					t.Fatal(n, err)
				}
				if public == "login.test" {
					for _, target := range []string{"https://tunn.test/", "https://tools.tunn.test/"} {
						u, _ := url.Parse(target)
						for _, c := range browser.Jar.Cookies(u) {
							if c.Name == authCookieName || c.Name == funnelSourceCookie {
								t.Fatal("host-only state crossed origins", target)
							}
						}
					}
				}
				funnelSessionLifecycle(t, browser, p, public, email)
			})
		}
	}
}

func funnelSessionLifecycle(t *testing.T, browser *http.Client, p *ProxyServer, host, email string) {
	t.Helper()
	csrf := funnelCSRF(t, browser, p, host, "/auth/logout")
	// Missing and another session's token cannot sign this browser out.
	if response := funnelPostForm(t, browser, host, "/auth/logout", url.Values{}); response.StatusCode != 403 {
		t.Fatal(response.StatusCode)
	}
	r, _ := http.NewRequest("POST", "https://"+host+"/auth/logout", strings.NewReader(url.Values{"csrf_token": {csrf}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://"+host)
	u, _ := url.Parse("https://" + host + "/")
	var original *http.Cookie
	for _, c := range browser.Jar.Cookies(u) {
		if c.Name == authCookieName {
			original = c
		}
	}
	if original == nil {
		t.Fatal("session was rejected by cookie jar")
	}
	r.AddCookie(&http.Cookie{Name: authCookieName, Value: original.Value + "modified"})
	forger := *browser
	forger.Jar = nil
	response, err := forger.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("CSRF accepted another session", response.StatusCode)
	}
	r, _ = http.NewRequest("POST", "https://"+host+"/auth/logout", strings.NewReader(url.Values{"csrf_token": {csrf}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://tools.tunn.test")
	response, err = browser.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("publisher origin accepted", response.StatusCode)
	}
	assertFunnelAccount(t, browser, p, host, email)

	// Complete the existing mailbox proof and primary-mailbox reissue in the jar.
	mailCSRF := funnelCSRF(t, browser, p, host, accountEmailsPath)
	response = funnelPostForm(t, browser, host, accountEmailsPath, url.Values{"csrf_token": {mailCSRF}, "action": {"add"}, "email": {"alias@example.invalid"}})
	if response.StatusCode != 303 {
		t.Fatal("add mailbox", response.StatusCode)
	}
	link, err := url.Parse(p.emailSender.(*accountsMailCapture).link)
	if err != nil || link.Host != host {
		t.Fatal("mailbox link", link, err)
	}
	funnelVisit(t, browser, link.String())
	response = funnelPostForm(t, browser, host, accountEmailsPath, url.Values{"csrf_token": {mailCSRF}, "token": {link.Query().Get("token")}})
	if response.StatusCode != 303 {
		t.Fatal("verify mailbox", response.StatusCode)
	}
	before, ok := p.parseDomainToken(original.Value, "session")
	if !ok {
		t.Fatal("invalid original session")
	}
	response = funnelPostForm(t, browser, host, accountEmailsPath, url.Values{"csrf_token": {mailCSRF}, "action": {"primary"}, "email": {"alias@example.invalid"}})
	if response.StatusCode != 303 {
		t.Fatal("primary mailbox", response.StatusCode)
	}
	assertFunnelSessionCookie(t, p, host, response, false)
	var reissued *http.Cookie
	for _, c := range response.Cookies() {
		if c.Name == authCookieName {
			reissued = c
		}
	}
	after, ok := p.parseDomainToken(reissued.Value, "session")
	if !ok || before["account_id"] != after["account_id"] || before["session_epoch"] != after["session_epoch"] || before["auth_iat"] != after["auth_iat"] {
		t.Fatal("reissue changed sign-in authority")
	}
	assertFunnelAccount(t, browser, p, host, "alias@example.invalid")
	if response := funnelPostForm(t, browser, host, "/auth/logout", url.Values{"csrf_token": {csrf}}); response.StatusCode != 403 {
		t.Fatal("old-session CSRF accepted", response.StatusCode)
	}

	csrf = funnelCSRF(t, browser, p, host, "/auth/logout")
	response = funnelPostForm(t, browser, host, "/auth/logout", url.Values{"csrf_token": {csrf}})
	if response.StatusCode != 302 {
		t.Fatal("logout", response.StatusCode)
	}
	assertFunnelSessionCookie(t, p, host, response, true)
	for _, c := range browser.Jar.Cookies(u) {
		if c.Name == authCookieName {
			t.Fatal("logout failed to clear session")
		}
	}
	account, err := p.storage.GetAccount(context.Background(), after["account_id"].(string))
	if err != nil || account == nil || account.BrowserSessionEpoch == browserSessionEpoch(after) {
		t.Fatal("logout did not revoke sessions", err)
	}
	// A stolen pre-logout session is rejected by live authority and cleared using
	// the same request-aware scope, even though its signature is still valid.
	browser.Jar.SetCookies(u, []*http.Cookie{reissued})
	reader := *browser
	reader.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err = reader.Get("https://" + host + "/account")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 302 || !strings.HasPrefix(response.Header.Get("Location"), "/auth/login") {
		t.Fatal("revoked account session accepted", response.StatusCode)
	}
	assertFunnelSessionCookie(t, p, host, response, true)
	for _, c := range browser.Jar.Cookies(u) {
		if c.Name == authCookieName {
			t.Fatal("invalid-session clearing failed")
		}
	}
}

func TestFunnelSourceSessionAuthority(t *testing.T) {
	p := newMCPOAuthFixture(t).p
	p.config.PublicAddr = "login.test"
	for _, host := range []string{"tools.tunn.test", "login.test:444", "untrusted.invalid", "tunn.test.attacker.invalid"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "https://"+host+"/", nil)
		if err := p.signedPlatformSession(w, r, jwt.MapClaims{}); err == nil {
			t.Fatal("untrusted session authority", host)
		}
		p.clearAuthCookie(w, r)
		if len(w.Result().Cookies()) != 0 {
			t.Fatal("platform cookie on untrusted authority", host)
		}
	}
	p.config.PublicAddr = "www.tunn.test"
	if domain, err := p.platformSessionDomain(httptest.NewRequest("GET", "https://www.tunn.test/", nil)); err != nil || domain != ".tunn.test" {
		t.Fatal("in-domain platform cookie changed", domain, err)
	}
	p.config.PublicAddr = "login.tunn.test"
	if p.isPlatformHost("login.tunn.test") {
		t.Fatal("publisher origin granted platform trust")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://login.tunn.test/", nil)
	if err := p.signedPlatformSession(w, r, jwt.MapClaims{}); err == nil || len(w.Result().Cookies()) != 0 {
		t.Fatal("publisher PublicAddr accepted")
	}
}
