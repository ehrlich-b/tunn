package host

import (
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func reviewBeginDestination(t *testing.T, f *orgOIDCFixture, destination string) *http.Request {
	t.Helper()
	w := f.finish(httptest.NewRequest("GET", "https://tunn.test/auth/org/company?return_to="+url.QueryEscape(destination), nil))
	if w.Code != 302 {
		t.Fatal("start failed", w.Code, w.Body.String())
	}
	authorize, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := authorize.Query()
	now := time.Now()
	claims := jwt.MapClaims{"iss": f.org.Issuer, "sub": "stable-subject", "aud": f.org.ClientID, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": q.Get("nonce"), "email": "alice@example.com", "email_verified": true, "groups": []string{"remote-engineering"}}
	f.mu.Lock()
	f.codes[q.Get("state")] = orgFixtureCode{Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge"), Redirect: q.Get("redirect_uri"), Claims: claims}
	f.mu.Unlock()
	r := httptest.NewRequest("GET", f.p.orgCallbackURL(f.org.ID)+"?state="+url.QueryEscape(q.Get("state"))+"&code="+url.QueryEscape(q.Get("state")), nil)
	for _, cookie := range w.Result().Cookies() {
		r.AddCookie(cookie)
	}
	return r
}

func TestReviewBackslashReturnTo(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	w := f.finish(reviewBeginDestination(t, f, `/\evil.example`))
	if w.Code != 302 || w.Header().Get("Location") != "/account" {
		t.Fatalf("unsafe browser destination accepted, got %d %q", w.Code, w.Header().Get("Location"))
	}

	for _, target := range []string{"https://evil.example/", "https://tunn.test.evil.example/", "https://tunn.test@evil.example/", "//evil.example/", "https://tunn.test:444/"} {
		if f.p.sanitizeReturnTo(target) != "/" {
			t.Fatal("unsafe absolute return URL accepted", target)
		}
	}
}

func TestReturnToBrowserNormalization(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	for _, target := range []string{`/\evil.example`, "/\t/evil.example", "/\r/evil.example", "/\n/evil.example", "\x00/evil.example", "/%5cevil.example", "/%2fevil.example", "/%09/evil.example", "https://tunn.test/\n/evil.example", "https://tunn.test/\\evil.example", "/%zz"} {
		if got := f.p.sanitizeReturnTo(target); got != "/" {
			t.Errorf("accepted %q as %q", target, got)
		}
	}
	for _, target := range []string{"/account", "/apps/a?x=1#section", "https://tunn.test/account", "https://api.tunn.test/a?b=c", "/a%20b"} {
		if got := f.p.sanitizeReturnTo(target); got != target {
			t.Errorf("valid destination %q became %q", target, got)
		}
	}
	// Revalidate old/persisted login state at callback too.
	r := reviewBeginDestination(t, f, "/account")
	if _, err := f.p.orgLogins.db.Exec("UPDATE org_oidc_logins SET return_to=? WHERE state=?", `/\evil.example`, orgStateDigest(r.URL.Query().Get("state"))); err != nil {
		t.Fatal(err)
	}
	if w := f.finish(r); w.Code != 302 || w.Header().Get("Location") != "/account" {
		t.Fatal("persisted destination bypassed validation", w.Code, w.Header().Get("Location"))
	}
}
