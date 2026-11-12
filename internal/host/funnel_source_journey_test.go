package host

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

var funnelBrowserEntries = []string{
	"/", "/about", "/privacy", "/terms", "/pricing", "/ngrok-alternative",
	"/docs", "/docs/", "/docs/status", "/docs/docker", "/docs/mcp-to-claude",
	"/docs/webhook-verification", "/docs/ip-restrictions",
	"/client-previews", "/mcp-to-claude", "/share-dev-server-oauth",
	"/agents", "/agents/SKILLS.md", "/agents/prompt.md", "/agents/skill/SKILL.md", "/status", "/report", "/login", "/auth/login", "/upgrade",
}

func assertFunnelSessionCookie(t *testing.T, p *ProxyServer, host string, response *http.Response, clearing bool) {
	t.Helper()
	for _, c := range response.Cookies() {
		if c.Name != authCookieName {
			continue
		}
		wantDomain := ""
		if requestHostname(host) == p.config.Domain {
			wantDomain = p.config.Domain
		}
		if c.Domain != wantDomain || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
			t.Fatalf("session scope at %s: %+v", host, c)
		}
		if clearing && (c.MaxAge != -1 || c.Value != "") || !clearing && (c.MaxAge != int(authCookieLifetime.Seconds()) || c.Value == "") {
			t.Fatalf("session lifetime at %s: %+v", host, c)
		}
		return
	}
	t.Fatalf("missing session cookie at %s", host)
}

func assertFunnelAccount(t *testing.T, browser *http.Client, p *ProxyServer, host, email string) {
	t.Helper()
	for i := 0; i < 2; i++ {
		// Stop redirects so a login page cannot masquerade as account success.
		reader := *browser
		reader.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := reader.Get("https://" + host + "/account")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), email) {
			t.Fatalf("account reload %d on %s: status=%d location=%q; missing verified buyer %s", i, host, response.StatusCode, response.Header.Get("Location"), email)
		}
		r, _ := http.NewRequest("GET", "https://"+host+"/account", nil)
		for _, c := range browser.Jar.Cookies(r.URL) {
			r.AddCookie(c)
		}
		claims, ok := p.accountSession(r)
		if !ok || claims["email"] != email || claims["email_verified"] != true {
			t.Fatal("jar lacks verified buyer session")
		}
		account, err := p.storage.GetAccountByEmail(context.Background(), email)
		if err != nil || account == nil || claims["account_id"] != account.ID {
			t.Fatal("session does not identify the buyer account", err)
		}
	}
}

func TestFunnelSourceSignupStorageFailure(t *testing.T) {
	for _, public := range []string{"tunn.test", "login.test"} {
		t.Run(public, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			f.p.config.PublicAddr = public
			f.p.emailSender = new(accountsMailCapture)
			failFunnelWrites(t, f.p.mcpOAuth.db)
			browser := funnelBrowser(t, f.p)
			funnelVisit(t, browser, "https://tunn.test/docs?src=alt")
			funnelSignup(t, browser, f.p, public)
			var n int
			if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE source='alt'`).Scan(&n); err != nil || n != 0 {
				t.Fatalf("best-effort write: %d %v", n, err)
			}
		})
	}
}

func funnelPostForm(t *testing.T, browser *http.Client, host, path string, values url.Values) *http.Response {
	t.Helper()
	r, err := http.NewRequest("POST", "https://"+host+path, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Origin", "https://"+host)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reader := *browser
	reader.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := reader.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response
}

func funnelCSRF(t *testing.T, browser *http.Client, p *ProxyServer, host, path string) string {
	t.Helper()
	r, _ := http.NewRequest("GET", "https://"+host+path, nil)
	for _, c := range browser.Jar.Cookies(r.URL) {
		r.AddCookie(c)
	}
	token, err := p.createCSRFToken(r, path)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
