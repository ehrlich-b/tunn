package host

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/golang-jwt/jwt/v4"
)

func emailSession(t *testing.T, p *ProxyServer, email string) *http.Cookie {
	t.Helper()
	a, err := p.storage.GetAccountByEmail(context.Background(), email)
	if err != nil || a == nil {
		t.Fatal(a, err)
	}
	w := httptest.NewRecorder()
	if err = p.setAccountCookie(w, httptest.NewRequest("GET", "https://"+p.loginAuthority()+"/", nil), a, email, "magic_link"); err != nil {
		t.Fatal(err)
	}
	return assertAccountsSessionCookie(t, p, w, email)
}
func emailAction(t *testing.T, f *mcpOAuthFixture, c *http.Cookie, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "https://tunn.test/account", nil)
	r.AddCookie(c)
	csrf, err := f.p.createCSRFToken(r, accountEmailsPath)
	if err != nil {
		t.Fatal(err)
	}
	values.Set("csrf_token", csrf)
	return f.request("POST", "https://tunn.test/account/emails", values.Encode(), "application/x-www-form-urlencoded", "", c)
}
func TestAccountEmailsLifecycleAndIdentity(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "login-node-RPC"
		}
		t.Run(name, func(t *testing.T) { accountEmailsLifecycle(t, remote) })
	}
}
func accountEmailsLifecycle(t *testing.T, remote bool) {
	f := newMCPOAuthFixture(t)
	p := f.p
	ctx := context.Background()
	sink := &accountsMailCapture{}
	p.emailSender = sink
	local := p.storage.(*storage.LocalStorage)
	if remote {
		p.storage = securityReplicaStorage(t, local)
	}
	a, err := local.GetAccountByEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	accounts := store.NewAccountStore(p.devices.db)
	if err = accounts.ReserveSubdomain(a.ID, "email-fixture"); err != nil {
		t.Fatal(err)
	}
	if err = local.RecordUsage(ctx, a.ID, 1234); err != nil {
		t.Fatal(err)
	}
	code, err := local.CreateDeviceCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := local.AuthorizeDeviceCode(ctx, code.Code, a.PrimaryEmail); err != nil || !ok {
		t.Fatal(ok, err)
	}
	device, secret, err := p.devices.issue(code.Code, "laptop", p.currentTime())
	if err != nil {
		t.Fatal(err)
	}
	c := emailSession(t, p, a.PrimaryEmail)
	post := func(action, email string) *httptest.ResponseRecorder {
		return emailAction(t, f, c, url.Values{"action": {action}, "email": {email}})
	}
	if w := post("add", " Alias@Example.com "); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	if sink.calls != 1 || sink.to != "alias@example.com" {
		t.Fatal(sink)
	}
	if sink.subject != "Verify this address for your tunn.to account" ||
		!strings.Contains(sink.body, "your signed-in tunn.to account") ||
		!strings.Contains(sink.body, ">Verify this address</a>") ||
		!strings.Contains(sink.body, "expires in 5 minutes") ||
		strings.Contains(strings.ToLower(sink.subject+sink.body), "log in") ||
		strings.Contains(strings.ToLower(sink.subject+sink.body), "login") {
		t.Fatalf("unexpected verification email: %q %q", sink.subject, sink.body)
	}

	if unverified, err := local.GetAccountByEmail(ctx, sink.to); err != nil || unverified != nil {
		t.Fatal("linked before verification", unverified, err)
	}
	if w := f.request("GET", sink.link, "", "", "", c); w.Code != 200 || !strings.Contains(w.Body.String(), "Verify and add email") {
		t.Fatal(w.Code, w.Body)
	}
	if unverified, err := local.GetAccountByEmail(ctx, sink.to); err != nil || unverified != nil {
		t.Fatal("GET mutated account", unverified, err)
	}
	u, _ := url.Parse(sink.link)
	raw := u.Query().Get("token")
	// A mailbox-management proof cannot authenticate as an ordinary login link.
	if w := f.request("GET", "https://tunn.test/auth/verify?token="+url.QueryEscape(raw), "", "", "", nil); w.Code != 400 {
		t.Fatal("link accepted as login", w.Code)
	}
	if w := emailAction(t, f, c, url.Values{"token": {raw}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	linked, err := local.GetAccountByEmail(ctx, sink.to)
	if err != nil || linked.ID != a.ID || len(linked.Emails) != 2 {
		t.Fatal(linked, err)
	}
	for _, e := range linked.Emails {
		if e.Email == sink.to && e.VerifiedVia != "magic_link" {
			t.Fatal(e)
		}
	}
	if w := emailAction(t, f, c, url.Values{"token": {raw}}); w.Code != 400 {
		t.Fatal("replay", w.Code)
	}
	w := post("primary", sink.to)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	c = assertAccountsSessionCookie(t, p, w, sink.to)
	req := httptest.NewRequest("GET", "https://tunn.test/account", nil)
	req.AddCookie(c)
	claims, ok := p.accountSession(req)
	if !ok || claims["account_id"] != a.ID || claims["email"] != sink.to {
		t.Fatal(claims)
	}
	current, err := p.sessionAccount(req, claims)
	if err != nil || current.ID != a.ID || current.PrimaryEmail != sink.to || current.Plan != a.Plan {
		t.Fatal(current, err)
	}
	if usage, err := local.GetMonthlyUsage(ctx, a.ID); err != nil || usage != 1234 {
		t.Fatal(usage, err)
	}
	if reservations, err := accounts.GetReservedSubdomains(a.ID); err != nil || len(reservations) != 1 {
		t.Fatal(reservations, err)
	}
	if f.tunnel.AccountID != a.ID {
		t.Fatal("tunnel owner changed")
	}
	// The existing refresh credential still works after choosing a different primary.
	if d, _, err := p.devices.rotate(secret, strings.Repeat("p", 32), p.getJWTSigningKey(), p.currentTime()); err != nil || d.ID != device.ID {
		t.Fatal(d, err)
	}
	page := f.request("GET", "https://tunn.test/account", "", "", "", c)
	if page.Code != 200 || !strings.Contains(page.Body.String(), `id="emails"`) || !strings.Contains(page.Body.String(), "Primary") || strings.Contains(page.Body.String(), `value="remove"`) {
		t.Fatal(page.Code, page.Body)
	}
	p.config.GoogleClientID = "fixture"
	p.config.GoogleClientSecret = "fixture"
	p.googleHTTPClient = googleFixtureTransport(t, p, true)
	for _, email := range []string{a.PrimaryEmail, sink.to} {
		start := f.request("GET", "https://tunn.test/auth/google", "", "", "", nil)
		authURL, _ := url.Parse(start.Header().Get("Location"))
		r := httptest.NewRequest("GET", "https://tunn.test/auth/google/callback?state="+url.QueryEscape(authURL.Query().Get("state"))+"&code="+url.QueryEscape(email), nil)
		for _, cookie := range start.Result().Cookies() {
			r.AddCookie(cookie)
		}
		out := httptest.NewRecorder()
		p.createHandler().ServeHTTP(out, r)
		if out.Code != 302 {
			t.Fatal(email, out.Code, out.Body)
		}
		foundCookie := false
		for _, cookie := range out.Result().Cookies() {
			if cookie.Name == authCookieName {
				foundCookie = true
				r := httptest.NewRequest("GET", "https://tunn.test/account", nil)
				r.AddCookie(cookie)
				claims, ok := p.accountSession(r)
				if !ok || claims["account_id"] != a.ID {
					t.Fatal(email, claims)
				}
			}
		}
		if !foundCookie {
			t.Fatal("Google login omitted account session", email)
		}
	}
}

func TestAccountEmailsRefusals(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "login-node-RPC"
		}
		t.Run(name, func(t *testing.T) { accountEmailsRefusals(t, remote) })
	}
}
func accountEmailsRefusals(t *testing.T, remote bool) {
	f := newMCPOAuthFixture(t)
	p := f.p
	ctx := context.Background()
	sink := &accountsMailCapture{}
	p.emailSender = sink
	if remote {
		p.storage = securityReplicaStorage(t, p.storage.(*storage.LocalStorage))
	}
	c := emailSession(t, p, "owner@example.com")
	owner, _ := p.storage.GetAccountByEmail(ctx, "owner@example.com")
	other, err := p.storage.FindOrCreateByEmails(ctx, []string{"other@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	if w := emailAction(t, f, c, url.Values{"action": {"add"}, "email": {other.PrimaryEmail}}); w.Code != 409 || !strings.Contains(w.Body.String(), "another account") {
		t.Fatal(w.Code, w.Body)
	}
	if sink.calls != 0 {
		t.Fatal("conflict sent email")
	}
	// Ownership can change between sending and confirmation; verification rechecks it.
	if w := emailAction(t, f, c, url.Values{"action": {"add"}, "email": {"later@example.com"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	u, _ := url.Parse(sink.link)
	raw := u.Query().Get("token")
	if _, err = p.storage.FindOrCreateByEmails(ctx, []string{"later@example.com"}, "magic_link"); err != nil {
		t.Fatal(err)
	}
	if w := emailAction(t, f, c, url.Values{"token": {raw}}); w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
	for _, action := range []string{"primary"} {
		if w := emailAction(t, f, c, url.Values{"action": {action}, "email": {other.PrimaryEmail}}); w.Code != 409 {
			t.Fatal(action, w.Code)
		}
	}
	for _, action := range []string{"add", "primary"} {
		w := f.request("POST", "https://tunn.test/account/emails", url.Values{"action": {action}, "email": {"csrf@example.com"}}.Encode(), "application/x-www-form-urlencoded", "", c)
		if w.Code != 403 {
			t.Fatal(action, w.Code)
		}
	}
	token, err := p.generateMailboxToken("new@example.com", "", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	otherCookie := emailSession(t, p, other.PrimaryEmail)
	if w := f.request("GET", "https://tunn.test/account/emails?token="+url.QueryEscape(token), "", "", "", otherCookie); w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
	if w := emailAction(t, f, otherCookie, url.Values{"token": {token}}); w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
	if w := f.request("POST", "https://tunn.test/account/emails", url.Values{"token": {token}}.Encode(), "application/x-www-form-urlencoded", "", c); w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"type": "account_email_link", "account_id": owner.ID, "email": "expired@example.com", "jti": "expired", "exp": time.Now().Add(-time.Minute).Unix()}).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	if w := emailAction(t, f, c, url.Values{"token": {expired}}); w.Code != 400 {
		t.Fatal(w.Code, w.Body)
	}
	if w := f.request("GET", "https://tunn.test/account/emails?token="+url.QueryEscape(token), "", "", "", nil); w.Code != 302 {
		t.Fatal(w.Code)
	}
	for _, id := range []string{owner.ID, other.ID} {
		a, err := p.storage.GetAccount(ctx, id)
		if err != nil || a == nil || a.ID != id {
			t.Fatal("accounts merged", a, err)
		}
	}
	t.Log("foreign ownership rejected before send and at confirmation; no merge; wrong session, CSRF, expiry and unauthenticated actions refused")
}

// Set ACCOUNT_EMAILS_CAPTURE_DIR to save the real account response for visual review.
func TestAccountEmailsCapture(t *testing.T) {
	dir := os.Getenv("ACCOUNT_EMAILS_CAPTURE_DIR")
	if dir == "" {
		t.Skip("visual capture only")
	}
	f := newMCPOAuthFixture(t)
	p := f.p
	a, err := p.storage.GetAccountByEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.storage.(storage.AccountEmailStorage).MutateAccountEmail(context.Background(), a.ID, "owner@example.com", "link"); err != nil {
		t.Fatal(err)
	}
	c := emailSession(t, p, a.PrimaryEmail)
	for _, sent := range []bool{false, true} {
		target := "https://tunn.test/account"
		name := "account.html"
		if sent {
			target += "?email_sent=1"
			name = "account-sent.html"
		}
		w := f.request("GET", target, "", "", "", c)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		if err = os.WriteFile(filepath.Join(dir, name), w.Body.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAccountEmailLinkWriteFailureCanRetry(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprint("RPC=", remote), func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			p := f.p
			local := p.storage.(*storage.LocalStorage)
			if remote {
				p.storage = securityReplicaStorage(t, local)
			}
			account, err := local.GetAccountByEmail(context.Background(), "owner@example.com")
			if err != nil {
				t.Fatal(err)
			}
			cookie := emailSession(t, p, account.PrimaryEmail)
			raw, err := p.generateMailboxToken("retry@example.com", "", account.ID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.devices.db.Exec(`CREATE TRIGGER fail_email_link BEFORE INSERT ON account_emails WHEN NEW.email='retry@example.com' BEGIN SELECT RAISE(ABORT,'injected write failure'); END`); err != nil {
				t.Fatal(err)
			}
			if w := emailAction(t, f, cookie, url.Values{"token": {raw}}); w.Code != 503 {
				t.Fatal(w.Code, w.Body)
			}
			proof, _ := p.parseDomainToken(raw, "account_email_link")
			var used int
			if err := p.devices.db.QueryRow("SELECT count(*) FROM used_magic_tokens WHERE jti=?", proof["jti"]).Scan(&used); err != nil || used != 0 {
				t.Fatal("failed link consumed proof", used, err)
			}
			if a, err := local.GetAccountByEmail(context.Background(), "retry@example.com"); err != nil || a != nil {
				t.Fatal("failed link committed", a, err)
			}
			if _, err := p.devices.db.Exec("DROP TRIGGER fail_email_link"); err != nil {
				t.Fatal(err)
			}
			if w := emailAction(t, f, cookie, url.Values{"token": {raw}}); w.Code != 303 {
				t.Fatal("retry failed", w.Code, w.Body)
			}
			if a, err := local.GetAccountByEmail(context.Background(), "retry@example.com"); err != nil || a == nil || a.ID != account.ID {
				t.Fatal(a, err)
			}
			if w := emailAction(t, f, cookie, url.Values{"token": {raw}}); w.Code != 400 {
				t.Fatal("proof replay accepted", w.Code, w.Body)
			}
		})
	}
}
