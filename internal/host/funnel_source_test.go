package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
)

func TestFunnelSourceSignup(t *testing.T) {
	for _, remote := range []bool{false, true} {
		mode := "local"
		if remote {
			mode = "replica"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct{ name, src, want string }{
				{"alt", "alt", "alt"}, {"saashub", "saashub", "saashub"}, {"docs", "docs", "docs"}, {"thread", "thread", "thread"},
				{"unknown", "unknown-channel", "other"}, {"long", strings.Repeat("a", 1024), "other"}, {"absent", "", "direct"},
				{"url", "https://private.invalid/path?email=buyer@example.invalid", "other"},
				{"ip", "192.0.2.99", "other"}, {"email", "buyer@example.invalid", "other"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := newMCPOAuthFixture(t)
					p, db := f.p, f.p.mcpOAuth.db
					if remote {
						p.storage = securityReplicaStorage(t, p.storage.(*storage.LocalStorage))
					}
					p.emailSender = new(accountsMailCapture)
					handler := p.createHandler()
					target := "https://tunn.test/docs"
					if tc.src != "" {
						target += "?src=" + url.QueryEscape(tc.src)
					}
					visit := httptest.NewRequest("GET", target, nil)
					visit.Header.Set("Referer", "https://referrer.invalid/private-thread")
					visit.RemoteAddr = "192.0.2.99:12345"
					first := httptest.NewRecorder()
					handler.ServeHTTP(first, visit)
					var cookie *http.Cookie
					for _, c := range first.Result().Cookies() {
						if c.Name == funnelSourceCookie {
							cookie = c
						}
					}
					if cookie == nil {
						t.Fatal("landing visit did not capture source")
					}
					if cookie.Value != tc.want || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 30*24*60*60 {
						t.Fatalf("unsafe or incorrect source cookie: %+v", cookie)
					}
					later := httptest.NewRequest("GET", "https://tunn.test/login?src=saashub", nil)
					later.AddCookie(cookie)
					second := httptest.NewRecorder()
					handler.ServeHTTP(second, later)
					for _, c := range second.Result().Cookies() {
						if c.Name == funnelSourceCookie {
							t.Fatal("later visit rewrote first source")
						}
					}
					signup := httptest.NewRequest("POST", "https://tunn.test/auth/magic?src=thread", strings.NewReader(`{"email":"buyer@example.invalid"}`))
					signup.Header.Set("Origin", "https://tunn.test")
					signup.AddCookie(cookie)
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, signup)
					if w.Code != 200 {
						t.Fatalf("request: %d %s", w.Code, w.Body)
					}
					verify := httptest.NewRequest("GET", p.emailSender.(*accountsMailCapture).link, nil)
					verify.AddCookie(cookie)
					verify.Header.Set("Referer", "https://referrer.invalid/private-thread")
					verify.RemoteAddr = "192.0.2.99:12345"
					w = httptest.NewRecorder()
					handler.ServeHTTP(w, verify)
					if w.Code != 302 {
						t.Fatalf("verify: %d %s", w.Code, w.Body)
					}
					// Repeat account lookup with a different source; signup must be immutable.
					if _, err := p.storage.FindOrCreateByEmails(common.WithFunnelSource(context.Background(), "saashub"), []string{"buyer@example.invalid"}, "fixture"); err != nil {
						t.Fatal(err)
					}
					rows, err := db.Query(`SELECT stage,account_hash,occurred_at,source FROM funnel_events`)
					if err != nil {
						t.Fatal(err)
					}
					defer rows.Close()
					signupCount := 0
					for rows.Next() {
						var stage, hash, stamp, source string
						if err := rows.Scan(&stage, &hash, &stamp, &source); err != nil {
							t.Fatal(err)
						}
						if stage == "signup" {
							signupCount++
						}
						// The fixture's original owner is direct; the newly signed-up buyer
						// must carry the first landing token.
						if source != tc.want && source != "direct" {
							t.Fatalf("unrecognized source %q", source)
						}
						raw, _ := json.Marshal([]string{stage, hash, stamp, source})
						for _, private := range []string{"https://", "referrer.invalid", "private.invalid", "192.0.2.99", "buyer@example.invalid", "owner@example.com"} {
							if strings.Contains(string(raw), private) {
								t.Fatalf("private input %q stored in funnel_events: %s", private, raw)
							}
						}
						if len(hash) != 64 || common.NormalizeFunnelSource(source) != source {
							t.Fatalf("unsafe ledger row: %s", raw)
						}
					}
					if err := rows.Err(); err != nil {
						t.Fatal(err)
					}
					rows.Close()
					if signupCount != 2 {
						t.Fatalf("signups=%d want=2", signupCount)
					}
					var count int
					wantCount := 1
					if tc.want == "direct" {
						wantCount = 2
					}
					if err := db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='signup' AND source=?`, tc.want).Scan(&count); err != nil || count != wantCount {
						t.Fatalf("signups from %s: count=%d want=%d err=%v", tc.want, count, wantCount, err)
					}
				})
			}
		})
	}
}

func TestFunnelSourceGoogleRPC(t *testing.T) {
	f := newMCPOAuthFixture(t)
	remote := securityReplicaStorage(t, f.p.storage.(*storage.LocalStorage))
	ctx := common.WithFunnelSource(context.Background(), "thread")
	if _, err := remote.FindOrCreateGoogleIdentity(ctx, "new-subject", "buyer@gmail.com", "", true); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='signup' AND source='thread'`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

func TestFunnelSourceOriginIsolation(t *testing.T) {
	p := newMCPOAuthFixture(t).p
	for _, host := range []string{"tools.tunn.test", "unrelated.invalid"} {
		r := httptest.NewRequest("GET", "https://"+host+"/docs?src=thread", nil)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		for _, c := range w.Result().Cookies() {
			if c.Name == funnelSourceCookie {
				t.Fatalf("source cookie on %s", host)
			}
		}
	}
}

func TestFunnelSourceBackgroundRequests(t *testing.T) {
	p := newMCPOAuthFixture(t).p
	handler := p.createHandler()
	for _, path := range []string{"/health", "/install.sh", "/favicon.ico", "/api/device/token", "/auth/org/disabled", "/auth/google?org=disabled"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.test"+path, nil))
		for _, cookie := range w.Result().Cookies() {
			if cookie.Name == funnelSourceCookie {
				t.Fatalf("background or disabled route %s claimed first touch", path)
			}
		}
	}
	// A direct browser visit must persist, even before a later attributed link.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.test/about", nil))
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == funnelSourceCookie {
			if cookie.Value != "direct" {
				t.Fatal(cookie)
			}
			return
		}
	}
	t.Fatal("direct entry page did not persist first touch")
}
