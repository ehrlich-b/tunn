package host

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
)

const githubEmailFallback = "Signed up with GitHub? Continue with email using the same address and your account carries over."

func TestLoginGitHubEmailFallback(t *testing.T) {
	for _, github := range []bool{false, true} {
		for _, email := range []bool{false, true} {
			t.Run(fmt.Sprintf("github_%t_email_%t", github, email), func(t *testing.T) {
				p := &ProxyServer{config: securityConfig()}
				if email {
					p.emailSender = new(accountsMailCapture)
				}
				if !github {
					p.config.GitHubClientID = ""
				}
				w := httptest.NewRecorder()
				p.handleLogin(w, httptest.NewRequest(http.MethodGet, "https://tunn.test/auth/login", nil))
				body := w.Body.String()
				if w.Code != http.StatusOK {
					t.Fatalf("login status=%d", w.Code)
				}
				if strings.Contains(body, `id="email-form"`) != email || strings.Contains(body, "Continue with Email") != email {
					t.Fatal("email form does not match configuration")
				}
				wantLines := 0
				if !github && email {
					wantLines = 1
				}
				if got := strings.Count(body, "<p>"+githubEmailFallback+"</p>"); got != wantLines {
					t.Fatalf("fallback lines=%d; want %d", got, wantLines)
				}
				if strings.Contains(body, "Continue with GitHub") != github {
					t.Fatal("GitHub button does not match configuration")
				}
			})
		}
	}
}

func TestGitHubAccountMagicLinkFallbackForBothVerifiedEmails(t *testing.T) {
	for _, email := range []string{"primary@example.invalid", "alias@example.invalid"} {
		t.Run(email, func(t *testing.T) {
			p, db := stripeCorrectnessFixture(t)
			// Exercise the actual GitHub callback with local provider responses.
			installAccountsHTTPFake(t, func(r *http.Request) (*http.Response, error) {
				switch r.URL.String() {
				case githubTokenURL:
					return accountsProviderResponse(r, 200, `{"access_token":"fixture"}`), nil
				case githubEmailsURL:
					return accountsProviderResponse(r, 200, `[{"email":"alias@example.invalid","primary":false,"verified":true},{"email":"primary@example.invalid","primary":true,"verified":true}]`), nil
				default:
					return nil, fmt.Errorf("unexpected provider request: %s", r.URL)
				}
			})
			state, browserCookie := accountsGitHubBrowserStart(t, p, url.Values{})
			github := accountsGitHubCallback(p, state, "fixture-code", browserCookie)
			if github.Code != http.StatusFound {
				t.Fatalf("GitHub callback=%d", github.Code)
			}
			githubCookie := assertAccountsSessionCookie(t, p, github, "primary@example.invalid")
			r := httptest.NewRequest(http.MethodGet, "https://tunn.test/account", nil)
			r.AddCookie(githubCookie)
			before, ok := p.accountSession(r)
			if !ok || before["provider"] != "github" {
				t.Fatal("missing GitHub account session")
			}
			original, err := p.sessionAccount(r, before)
			if err != nil || original == nil || len(original.Emails) != 2 || original.PrimaryEmail != "primary@example.invalid" {
				t.Fatalf("GitHub did not create both verified aliases: account=%v err=%v", original, err)
			}
			for _, alias := range original.Emails {
				if alias.VerifiedVia != "github" {
					t.Fatalf("alias verification=%q", alias.VerifiedVia)
				}
			}

			p.config.GitHubClientID, p.config.GitHubClientSecret = "", ""
			sink := new(accountsMailCapture)
			p.emailSender = sink
			if w := magicFixturePost(p, "", fmt.Sprintf(`{"email":%q}`, email)); w.Code != 200 || sink.calls != 1 || sink.to != email {
				t.Fatalf("email request=%d deliveries=%d", w.Code, sink.calls)
			}
			verified := httptest.NewRecorder()
			p.handleMagicLinkVerify(verified, httptest.NewRequest(http.MethodGet, sink.link, nil))
			if verified.Code != http.StatusFound || verified.Header().Get("Location") != "/account" {
				t.Fatalf("email verification=%d", verified.Code)
			}
			cookie := assertAccountsSessionCookie(t, p, verified, email)
			r = httptest.NewRequest(http.MethodGet, "https://tunn.test/account", nil)
			r.AddCookie(cookie)
			after, ok := p.accountSession(r)
			if !ok || after["provider"] != "magic_link" || after["account_id"] != before["account_id"] {
				t.Fatal("email session did not carry over the GitHub account ID")
			}
			account, err := p.sessionAccount(r, after)
			if err != nil || account == nil || account.ID != original.ID || account.PrimaryEmail != original.PrimaryEmail || len(account.Emails) != 2 {
				t.Fatalf("email login changed account: %v %v", account, err)
			}
			var count int
			if err := db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); err != nil || count != 1 {
				t.Fatalf("accounts=%d err=%v", count, err)
			}
			t.Logf("magic-link login for %s preserves the GitHub account ID, primary address and both aliases; account count=1", email)
		})
	}
}

func TestCLIDeviceLoginThroughEmailWithoutGitHub(t *testing.T) {
	t.Setenv("TUNN_CONFIG_DIR", t.TempDir())
	f := newMCPOAuthFixture(t)
	p := f.p
	p.config.GitHubClientID, p.config.GitHubClientSecret = "", ""
	sink := new(accountsMailCapture)
	p.emailSender = sink
	relay := httptest.NewTLSServer(p.createHandler())
	defer relay.Close()
	hc := relay.Client()
	cliHTTP := *hc
	cliHTTP.Transport = policyHostTransport{hc.Transport}
	var output bytes.Buffer
	login := &client.LoginClient{ServerAddr: relay.Listener.Addr().String(), HTTPClient: &cliHTTP, Output: &output}
	login.OpenBrowser = func(link string) {
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		code := u.Query().Get("code")
		if code == "" {
			t.Fatal("CLI omitted the browser device code")
		}
		page := f.request("GET", link, "", "", "", nil)
		if page.Code != 302 {
			t.Fatalf("device login redirect=%d", page.Code)
		}
		page = f.request("GET", "https://tunn.test"+page.Header().Get("Location"), "", "", "", nil)
		if page.Code != 200 || !strings.Contains(page.Body.String(), githubEmailFallback) || strings.Contains(page.Body.String(), "Continue with GitHub") {
			t.Fatalf("email-only device login page=%d", page.Code)
		}
		match := regexp.MustCompile(`fetch\('([^']+)'`).FindStringSubmatch(page.Body.String())
		if len(match) != 2 {
			t.Fatal("missing email form endpoint")
		}
		magicURL, err := url.Parse(match[1])
		if err != nil || magicURL.Query().Get("device_user_code") != code {
			t.Fatal("email form lost the device code")
		}
		if w := magicFixturePost(p, magicURL.RawQuery, `{"email":"owner@example.com"}`); w.Code != 200 || sink.calls != 1 {
			t.Fatalf("device email request=%d deliveries=%d", w.Code, sink.calls)
		}
		verified := f.request("GET", sink.link, "", "", "", nil)
		if verified.Code != 302 || verified.Header().Get("Location") != "/login?code="+code {
			t.Fatalf("magic link lost device flow: status=%d", verified.Code)
		}
		cookie := assertAccountsSessionCookie(t, p, verified, "owner@example.com")
		pending := f.request("GET", "https://tunn.test/login?code="+code, "", "", "", nil)
		if pending.Code != 302 {
			t.Fatal("magic link authorized device without confirmation")
		}
		page = f.request("GET", "https://tunn.test"+verified.Header().Get("Location"), "", "", "", cookie)
		if page.Code != 200 || !strings.Contains(page.Body.String(), "Publish and connect to tunnels") {
			t.Fatalf("device confirmation=%d", page.Code)
		}
		match = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
		if len(match) != 2 {
			t.Fatal("device confirmation missing CSRF")
		}
		form := url.Values{"code": {code}, "csrf_token": {match[1]}}
		authorized := f.request("POST", "https://tunn.test/auth/device/authorize", form.Encode(), "application/x-www-form-urlencoded", "", cookie)
		if authorized.Code != 200 || !strings.Contains(authorized.Body.String(), "Return to your terminal.") {
			t.Fatalf("device authorization=%d", authorized.Code)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := login.Run(ctx); err != nil {
		t.Fatal(err)
	}
	token, manager, err := client.LoadTunnelToken(ctx, login.ServerAddr, false)
	if err != nil || token == "" || manager == nil {
		t.Fatalf("CLI did not save renewable credentials: err=%v renewable=%t", err, manager != nil)
	}
	email, device, _, err := parseDeviceToken(token, p.getJWTSigningKey(), time.Now())
	if err != nil || email != "owner@example.com" || device == "" {
		t.Fatalf("saved device identity=%q err=%v", email, err)
	}
	if !strings.Contains(output.String(), "Signed in as owner@example.com") {
		t.Fatal("CLI did not report successful email login")
	}
	t.Log("GitHub unset: CLI device request -> email form -> captured magic link -> session -> CSRF device approval -> token poll -> saved renewable publisher credentials")
}
