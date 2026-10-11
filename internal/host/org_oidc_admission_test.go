package host

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReviewUnauthenticatedGlobalStateExhaustion(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	other := f.org
	other.ID = "other"
	f.p.config.OIDCOrgs = append(f.p.config.OIDCOrgs, other)
	handler := f.p.createHandler()
	for i := 0; i < 4096; i++ {
		r := httptest.NewRequest("GET", "https://tunn.test/auth/org/company", nil)
		r.RemoteAddr = fmt.Sprintf("192.0.2.1:%d", 10000+i)
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.%d.%d", i/256, i%256))
		r.Header.Set("X-Real-IP", fmt.Sprintf("203.0.113.%d", i%256))
		r.Header.Set("Forwarded", fmt.Sprintf("for=198.51.100.%d", i%256))
		r.Header.Set("Cookie", fmt.Sprintf("%s=forged-%d", orgCookieName, i))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := 429
		if i < orgLoginSourceLimit {
			want = 302
		}
		if w.Code != want {
			t.Fatalf("start %d: got %d, want %d", i, w.Code, want)
		}
	}
	var count int
	if err := f.p.orgLogins.db.QueryRow("SELECT count(*) FROM org_oidc_logins").Scan(&count); err != nil || count != orgLoginSourceLimit {
		t.Fatal("unbounded pending logins", count, err)
	}
	// A distributed attacker can fill only its org partition.
	for i := orgLoginSourceLimit; i < orgLoginOrgLimit; i++ {
		r := httptest.NewRequest("GET", "https://tunn.test/auth/org/company", nil)
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:12345", i)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 302 {
			t.Fatalf("org partition start %d: %d", i, w.Code)
		}
	}
	for _, tc := range []struct {
		org  string
		want int
	}{{"company", 429}, {"other", 302}} {
		r := httptest.NewRequest("GET", "https://tunn.test/auth/org/"+tc.org, nil)
		r.RemoteAddr = "198.51.100.5:44321"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: got %d, want %d", tc.org, w.Code, tc.want)
		}
	}
	f.p.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.test/auth/org/company", nil))
	if w.Code != 302 {
		t.Fatal("expired state did not recover", w.Code)
	}
}

func TestOrgLoginAdmissionSurvivesRestartAndConsumption(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	now := time.Now()
	login := orgLogin{Org: "company", Source: "peer", Expires: now.Add(time.Minute).Unix()}
	for i := 0; i < orgLoginSourceLimit; i++ {
		if err := f.p.orgLogins.begin(context.Background(), fmt.Sprint(i), login, now); err != nil {
			t.Fatal(err)
		}
	}
	restarted, err := newOrgLoginStore(f.p.orgLogins.db)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.begin(context.Background(), "blocked", login, now); err != errOrgLoginAdmission {
		t.Fatal("restart reset admission", err)
	}
	if _, err = restarted.consume(context.Background(), "0", "company", now); err != nil {
		t.Fatal(err)
	}
	if err = restarted.begin(context.Background(), "recovered", login, now); err != nil {
		t.Fatal(err)
	}
}

func TestOrgLoginSourceIPv6AndHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "https://tunn.test/", nil)
	r.RemoteAddr = "[2001:db8:1:2::1]:1234"
	a := orgLoginSource(r)
	r.RemoteAddr = "[2001:db8:1:2::abcd]:9999"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if orgLoginSource(r) != a {
		t.Fatal("IPv6 privacy address or headers bypassed admission")
	}
	r.RemoteAddr = "[::ffff:192.0.2.1]:1234"
	a = orgLoginSource(r)
	r.RemoteAddr = "192.0.2.1:5678"
	if orgLoginSource(r) != a {
		t.Fatal("IPv4 mapped address bypassed admission")
	}
}
