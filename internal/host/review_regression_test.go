package host

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestReviewPrimaryEmailMustNotResetAppAbsoluteCap(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	start := time.Now().Truncate(time.Second)
	now := start
	p.now = func() time.Time { return now }
	// Exercise the real magic-link provider verification, not a synthetic cookie.
	request := magicFixturePost(p, "", `{"email":"owner@example.com"}`)
	if request.Code != 200 {
		t.Fatalf("magic request: %d %s", request.Code, request.Body)
	}
	verify := httptest.NewRecorder()
	p.handleMagicLinkVerify(verify, httptest.NewRequest("GET", p.emailSender.(*accountsMailCapture).link, nil))
	if verify.Code != 302 {
		t.Fatalf("provider sign-in: %d %s", verify.Code, verify.Body)
	}
	platform := assertAccountsSessionCookie(t, p, verify, appOwnerEmail)
	original, _ := p.parseDomainToken(platform.Value, "session")
	if appAuthIAT(original) != start.Unix() {
		t.Fatalf("provider auth_iat: %v", original)
	}
	now = start.Add(6 * 24 * time.Hour)
	// Selecting the already-primary mailbox also reissues the platform cookie.
	out := emailAction(t, &mcpOAuthFixture{p: p}, platform, url.Values{"action": {"primary"}, "email": {appOwnerEmail}})
	if out.Code != 303 {
		t.Fatalf("primary: %d %s", out.Code, out.Body)
	}
	var updated *http.Cookie
	for _, c := range out.Result().Cookies() {
		if c.Name == authCookieName {
			updated = c
		}
	}
	if updated == nil {
		t.Fatal("missing platform cookie")
	}
	// Take the real SSO redirect path and inspect its signed handoff.
	nav := httptest.NewRequest("GET", "https://"+appHost+"/", nil)
	init := httptest.NewRecorder()
	p.startDomainSSO(init, nav)
	login := httptest.NewRequest("GET", init.Header().Get("Location"), nil)
	login.AddCookie(updated)
	handoffResponse := httptest.NewRecorder()
	p.handleDomainLogin(handoffResponse, login)
	if handoffResponse.Code != 302 {
		t.Fatalf("handoff: %d %s", handoffResponse.Code, handoffResponse.Body)
	}
	dest, err := url.Parse(handoffResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	handoff, valid := p.parseDomainToken(dest.Query().Get("token"), "domain_handoff")
	if !valid {
		t.Fatal("invalid handoff")
	}
	if appAuthIAT(handoff) != start.Unix() {
		t.Fatalf("handoff reset authentication time: %v", handoff)
	}
	callback := httptest.NewRequest("GET", dest.String(), nil)
	for _, c := range init.Result().Cookies() {
		callback.AddCookie(c)
	}
	complete := httptest.NewRecorder()
	p.handleDomainCallback(complete, callback)
	if complete.Code != 302 {
		t.Fatalf("callback: %d %s", complete.Code, complete.Body)
	}
	var app *http.Cookie
	for _, c := range complete.Result().Cookies() {
		if c.Name == appCookie {
			app = c
		}
	}
	if app == nil {
		t.Fatal("no app cookie")
	}
	now = start.Add(6*24*time.Hour + 12*time.Hour)
	poll := appOpenWithCookie(p, app)
	if poll.Code != 200 {
		t.Fatalf("poll: %d", poll.Code)
	}
	for _, c := range poll.Result().Cookies() {
		if c.Name == appCookie && c.MaxAge > 0 {
			app = c
		}
	}
	// Repeated handoffs remain anchored to the original provider sign-in.
	now = start.Add(6*24*time.Hour + 23*time.Hour)
	init2 := httptest.NewRecorder()
	p.startDomainSSO(init2, nav)
	login2 := httptest.NewRequest("GET", init2.Header().Get("Location"), nil)
	login2.AddCookie(updated)
	response2 := httptest.NewRecorder()
	p.handleDomainLogin(response2, login2)
	dest2, err := url.Parse(response2.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	handoff2, valid := p.parseDomainToken(dest2.Query().Get("token"), "domain_handoff")
	if !valid || appAuthIAT(handoff2) != start.Unix() {
		t.Fatalf("repeated handoff: %v", handoff2)
	}
	callback2 := httptest.NewRequest("GET", dest2.String(), nil)
	for _, c := range init2.Result().Cookies() {
		callback2.AddCookie(c)
	}
	complete2 := httptest.NewRecorder()
	p.handleDomainCallback(complete2, callback2)
	if complete2.Code != 302 {
		t.Fatalf("repeated callback: %d %s", complete2.Code, complete2.Body)
	}
	for _, c := range complete2.Result().Cookies() {
		if c.Name == appCookie {
			app = c
		}
	}
	got, ok := p.parseDomainToken(app.Value, "session")
	if !ok || appAuthIAT(got) != start.Unix() {
		t.Fatalf("repeated callback auth: %v", got)
	}
	now = start.Add(authCookieLifetime)
	init3 := httptest.NewRecorder()
	p.startDomainSSO(init3, nav)
	login3 := httptest.NewRequest("GET", init3.Header().Get("Location"), nil)
	login3.AddCookie(updated)
	expiredLogin := httptest.NewRecorder()
	p.handleDomainLogin(expiredLogin, login3)
	if !strings.HasPrefix(expiredLogin.Header().Get("Location"), "/auth/login?") {
		t.Fatalf("cap must require fresh provider login: %d %s", expiredLogin.Code, expiredLogin.Header().Get("Location"))
	}
	now = start.Add(authCookieLifetime + time.Hour)
	afterCap := appOpenWithCookie(p, app)
	if afterCap.Code == 200 {
		t.Fatalf("app still authorized 7d+1h after original sign-in; auth clock reset without sign-in")
	}
}

// The old platform format had iat but no auth_iat. Its last known issue time
// is the migration anchor, including when primary-email selection reissues it.
func TestLegacyPlatformPrimaryReissuePreservesIssueTime(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	start := time.Now().Truncate(time.Second)
	now := start
	p.now = func() time.Time { return now }
	platform := appSessionCookie(t, p, appOwnerEmail, "github", true, "")
	claims, _ := p.parseDomainToken(platform.Value, "session")
	delete(claims, "auth_iat")
	claims["exp"] = start.Add(authCookieLifetime).Unix()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	platform.Value = raw
	now = start.Add(6 * 24 * time.Hour)
	out := emailAction(t, &mcpOAuthFixture{p: p}, platform, url.Values{"action": {"primary"}, "email": {appOwnerEmail}})
	if out.Code != 303 {
		t.Fatalf("primary: %d %s", out.Code, out.Body)
	}
	for _, c := range out.Result().Cookies() {
		if c.Name == authCookieName {
			got, ok := p.parseDomainToken(c.Value, "session")
			if !ok || appAuthIAT(got) != start.Unix() {
				t.Fatalf("legacy migration: %v", got)
			}
			return
		}
	}
	t.Fatal("missing reissued platform cookie")
}
