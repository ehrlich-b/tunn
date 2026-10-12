package host

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func securityFormToken(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatal("confirmation page has no CSRF token")
	}
	return html.UnescapeString(match[1])
}

func TestSecurityDeviceAuthorizationRequiresOriginAndSessionToken(t *testing.T) {
	s := securityDB(t)
	p := securityProxy(s)
	cookie := securityCookie(t, p, "victim@example.test")
	for _, test := range []struct {
		name, origin, tokenMode string
		want                    int
	}{
		{"sibling with real token", "https://attacker.tunn.test", "valid", 403},
		{"same origin without token", "https://tunn.test", "missing", 403},
		{"no origin", "", "valid", 403},
		{"null origin", "null", "valid", 403},
		{"suffix origin", "https://tunn.test.evil.test", "valid", 403},
		{"wrong port", "https://tunn.test:444", "valid", 403},
		{"HTTP origin", "http://tunn.test", "valid", 403},
		{"tampered token", "https://tunn.test", "tampered", 403},
		{"another session token", "https://tunn.test", "other", 403},
		{"same origin", "https://tunn.test", "valid", 200},
		{"default HTTPS port", "https://tunn.test:443", "valid", 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, err := s.CreateDeviceCode(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			page := httptest.NewRequest("GET", "https://tunn.test/login?code="+code.UserCode, nil)
			page.AddCookie(cookie)
			if test.tokenMode == "other" {
				page.Header.Del("Cookie")
				page.AddCookie(securityCookie(t, p, "other@example.test"))
			}
			pageWriter := httptest.NewRecorder()
			p.createHandler().ServeHTTP(pageWriter, page)
			token := securityFormToken(t, pageWriter.Body.String())
			if test.tokenMode == "missing" {
				token = ""
			}
			if test.tokenMode == "tampered" {
				token += "x"
			}
			form := url.Values{"code": {code.UserCode}, "csrf_token": {token}}
			req := httptest.NewRequest("POST", "https://tunn.test/auth/device/authorize", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.origin != "" {
				req.Header.Set("Origin", test.origin)
			}
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, req)
			if w.Code != test.want {
				t.Errorf("status = %d, want %d", w.Code, test.want)
			}
			current, err := s.GetDeviceCode(context.Background(), code.Code)
			if err != nil {
				t.Fatal(err)
			}
			if current.Authorized != (test.want == 200) {
				t.Fatalf("authorized = %v", current.Authorized)
			}
		})
	}
}

func TestSecurityAuthMutationsRejectSiblingOrigins(t *testing.T) {
	p := securityProxy(securityDB(t))
	for _, path := range []string{"/auth/magic", "/api/device/code", "/auth/logout"} {
		req := httptest.NewRequest("POST", "https://tunn.test"+path, strings.NewReader(`{"email":"victim@example.test"}`))
		req.Header.Set("Origin", "https://attacker.tunn.test")
		req.AddCookie(securityCookie(t, p, "victim@example.test"))
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", path, w.Code)
		}
	}
	// The CLI uses no browser cookies or Origin when requesting a device code.
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, httptest.NewRequest("POST", "https://tunn.test/api/device/code", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("CLI code creation status = %d", w.Code)
	}
}

func TestSecurityTunnelOriginCannotReadPlatformForms(t *testing.T) {
	p := securityProxy(securityDB(t))
	code, err := p.storage.CreateDeviceCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/login?code=" + code.UserCode, "/auth/logout", "/account", "/auth/mock"} {
		req := httptest.NewRequest("GET", "https://attacker.tunn.test"+path, nil)
		req.AddCookie(securityCookie(t, p, "victim@example.test"))
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, req)
		if w.Code == 200 || w.Code == 302 || strings.Contains(w.Body.String(), "csrf_token") {
			t.Errorf("sibling host served platform flow %s: %d", path, w.Code)
		}
	}
}

func TestSecurityLogoutRequiresExplicitSessionBoundPost(t *testing.T) {
	p := securityProxy(securityDB(t))
	cookie := securityCookie(t, p, "victim@example.test")
	req := httptest.NewRequest("GET", "https://tunn.test/auth/logout", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.Name == authCookieName && c.MaxAge < 0 {
			t.Error("GET logged the user out")
		}
	}
	token := securityFormToken(t, w.Body.String())
	form := url.Values{"csrf_token": {token}}
	post := httptest.NewRequest("POST", "https://tunn.test/auth/logout", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://tunn.test")
	post.AddCookie(cookie)
	result := httptest.NewRecorder()
	p.createHandler().ServeHTTP(result, post)
	if result.Code != 302 {
		t.Fatalf("logout status = %d", result.Code)
	}
	for _, c := range result.Result().Cookies() {
		if c.Name == authCookieName && c.MaxAge < 0 {
			return
		}
	}
	t.Fatal("authorized logout did not delete the cookie")
}

type securityRoundTripper func(*http.Request) (*http.Response, error)

func (f securityRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSecurityOAuthCallbackRequiresInitiatingBrowser(t *testing.T) {
	// Successful account-bound login requires the local account authority.
	p := securityProxy(securityDB(t))
	start := httptest.NewRecorder()
	p.handleGitHubLogin(start, httptest.NewRequest("GET", "https://tunn.test/auth/github", nil))
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil || location.Query().Get("state") == "" {
		t.Fatalf("OAuth start fixture: %v", err)
	}
	// A transport fixture stands in for GitHub. Unexpected URLs cannot leave
	// the process; no external request is ever made.
	original := http.DefaultTransport
	http.DefaultTransport = securityRoundTripper(func(r *http.Request) (*http.Response, error) {
		body := ""
		switch r.URL.String() {
		case githubTokenURL:
			body = `{"access_token":"fixture-provider-token"}`
		case githubEmailsURL:
			body = `[{"email":"attacker@example.test","primary":true,"verified":true}]`
		default:
			return nil, fmt.Errorf("unexpected fixture URL %q", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	// The callback arrives in a different browser with no cookies or browser
	// state; a signature proves the state was issued, not who initiated it.
	callback := "https://tunn.test/auth/callback?code=fixture-code&state=" + url.QueryEscape(location.Query().Get("state"))
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, httptest.NewRequest("GET", callback, nil))
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == authCookieName && cookie.Value != "" {
			t.Error("copied OAuth callback set attacker login in an unrelated browser without initiating state")
		}
	}
	// The initiating browser must still complete the same flow successfully.
	initiating := httptest.NewRequest("GET", callback, nil)
	for _, cookie := range start.Result().Cookies() {
		if cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" {
			t.Fatal("OAuth state cookie does not enforce host-only browser binding")
		}
		initiating.AddCookie(cookie)
	}
	result := httptest.NewRecorder()
	p.createHandler().ServeHTTP(result, initiating)
	if result.Code != http.StatusFound {
		t.Fatalf("initiating browser callback status = %d", result.Code)
	}
	for _, cookie := range result.Result().Cookies() {
		if cookie.Name == authCookieName {
			replay := httptest.NewRequest("GET", "https://tunn.test/account", nil)
			replay.AddCookie(cookie)
			if email, ok := p.getAuthFromCookie(replay); !ok || email != "attacker@example.test" {
				t.Fatal("initiating browser received invalid session")
			}
			return
		}
	}
	t.Fatal("initiating browser received no session")
}
