package host

import (
	"context"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReviewPersonMatchingAndResourceIsolation(t *testing.T) {
	p, tunnel, ledger, _ := webSharingFixture(t)
	ctx := context.Background()
	_, err := ledger.Sharing(ctx, &mp.SharingRequest{Operation: "share", Owner: tunnel.AccountID, Endpoint: "api", Email: "alice@gmail.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		email  string
		status int
	}{
		{"ALICE@GMAIL.COM", 200}, {"ａｌｉｃｅ@gmail.com", 200},
		{"аlice@gmail.com", 403}, {"alice+tag@gmail.com", 403},
		{"a.lice@gmail.com", 403}, {"alice@googlemail.com", 403},
		{"alice@gmail.com.evil.test", 403}, {"alice@ɡmail.com", 403},
	} {
		if w := webOpen(t, p, tc.email); w.Code != tc.status {
			t.Fatalf("email %q=%d, want %d", tc.email, w.Code, tc.status)
		}
		t.Logf("email %q => %d", tc.email, tc.status)
	}
	other, err := ledger.Sharing(ctx, &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: "other", Mode: "private", InitialEmails: []string{"stranger@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if w := webOpen(t, p, "stranger@example.com"); w.Code != 403 {
		t.Fatal("other-resource permission crossed into api")
	}
	if _, err = ledger.Sharing(ctx, &mp.SharingRequest{Operation: "get", Owner: tunnel.AccountID, Endpoint: "api", ResourceId: other.Resources[0].Id}); err == nil {
		t.Fatal("cross-generation lookup accepted")
	}
}

func TestReviewOAuthStateRedirectAndCookieScope(t *testing.T) {
	p, _, _, _ := webSharingFixture(t)
	for _, target := range []string{"https://evil.test", "//evil.test/", "https://api.tunn.test.evil.test/", "https://tunn.test@evil.test/", "https://api.tunn.test:444/"} {
		if got := p.sanitizeReturnTo(target); got != "/" {
			t.Fatalf("accepted external return_to %q as %q", target, got)
		}
	}
	for _, target := range []string{"/\\evil.test/", "/\t/evil.test/"} {
		t.Logf("browser-ambiguous relative return_to %q -> %q", target, p.sanitizeReturnTo(target))
	}
	first, _ := p.createOAuthState("/account", "")
	second, _ := p.createOAuthState("/account", "")
	for _, tc := range []struct {
		state, cookie string
		want          bool
	}{{first, "", false}, {first, second, false}, {first, first, true}} {
		r := httptest.NewRequest("GET", "https://tunn.test/auth/callback", nil)
		if tc.cookie != "" {
			r.AddCookie(&http.Cookie{Name: oauthCookieName, Value: tc.cookie})
		}
		if got := requireOAuthBrowser(httptest.NewRecorder(), r, tc.state); got != tc.want {
			t.Fatal("state browser binding", got)
		}
	}
	w := httptest.NewRecorder()
	if err := p.setAuthCookie(w, httptest.NewRequest("GET", "https://"+p.loginAuthority()+"/", nil), "owner@example.com"); err != nil {
		t.Fatal(err)
	}
	c := w.Result().Cookies()[0]
	if !c.HttpOnly || !c.Secure || c.Domain != "" || c.SameSite != http.SameSiteLaxMode {
		t.Fatal(c)
	}
	if got := stripPlatformCookies("tunn_auth=secret; __Host-tunn_oauth=state; app=ok"); got != "app=ok" {
		t.Fatal(got)
	}
	dst := make(http.Header)
	copyApplicationResponseHeaders(dst, map[string]string{"Set-Cookie": "tunn_auth=forged; Domain=tunn.test, app=ok; Path=/"})
	if strings.Contains(strings.Join(dst.Values("Set-Cookie"), " "), "tunn_auth") {
		t.Fatal("upstream forged platform cookie")
	}
}
