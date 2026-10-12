package host

import (
	"context"
	"encoding/json"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/golang-jwt/jwt/v4"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestR3GoogleThirdPartyEmailCannotAcquireOwner(t *testing.T) {
	f := newMCPOAuthFixture(t)
	p := f.p
	p.config.GoogleClientID, p.config.GoogleClientSecret = "fixture-id", "fixture-secret"
	accounts := store.NewAccountStore(p.mcpOAuth.db)
	original, err := accounts.FindOrCreateByEmails([]string{"owner@example.com", "private-alias@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	p.googleHTTPClient = &http.Client{Transport: securityRoundTripper(func(r *http.Request) (*http.Response, error) {
		data := `{"access_token":"stale-google-email-account"}`
		if r.URL.String() == googleUserInfoURL {
			data = `{"sub":"different-google-subject","email":"owner@example.com","email_verified":true}` // no hd
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(data))}, nil
	})}
	start := httptest.NewRecorder()
	p.createHandler().ServeHTTP(start, httptest.NewRequest("GET", "https://tunn.test/auth/google?return_to=%2Faccount", nil))
	u, _ := url.Parse(start.Header().Get("Location"))
	req := httptest.NewRequest("GET", "https://tunn.test/auth/google/callback?state="+url.QueryEscape(u.Query().Get("state"))+"&code=fixture", nil)
	for _, c := range start.Result().Cookies() {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-authoritative callback=%d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == authCookieName {
			t.Fatal("non-authoritative identity received a central session")
		}
	}
	got, err := p.storage.GetAccountByEmail(context.Background(), "owner@example.com")
	if err != nil || got.ID != original.ID || len(got.Emails) != 2 {
		t.Fatal("callback changed owner account", got, err)
	}
	t.Log("third-party Google email refused before owner session issuance")
}

func TestR3GoogleAuthoritativeIdentityBeforeSessionAndDeviceEnrollment(t *testing.T) {
	for _, tc := range []struct {
		name, email, hd, subject string
		verified, allowed        bool
	}{
		{"gmail", "alice@gmail.com", "", "gmail-sub", true, true},
		{"workspace", "alice@example.com", "example.com", "workspace-sub", true, true},
		{"third-party", "owner@example.com", "", "third-party-sub", true, false},
		{"unverified-workspace", "owner@example.com", "example.com", "unverified-sub", false, false},
		{"wrong-hosted-domain", "owner@example.com", "other.example", "wrong-domain-sub", true, false},
		{"gmail-suffix", "owner@gmail.com.evil.test", "", "suffix-sub", true, false},
		{"missing-subject", "alice@gmail.com", "", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newMCPOAuthFixture(t).p
			p.config.GoogleClientID, p.config.GoogleClientSecret = "fixture-id", "fixture-secret"
			device, err := p.storage.CreateDeviceCode(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			p.googleHTTPClient = &http.Client{Transport: securityRoundTripper(func(r *http.Request) (*http.Response, error) {
				data := `{"access_token":"fixture"}`
				if r.URL.String() == googleUserInfoURL {
					raw, _ := json.Marshal(map[string]any{"sub": tc.subject, "email": tc.email, "email_verified": tc.verified, "hd": tc.hd})
					data = string(raw)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(data))}, nil
			})}
			start := httptest.NewRecorder()
			p.createHandler().ServeHTTP(start, httptest.NewRequest("GET", "https://tunn.test/auth/google?device_user_code="+url.QueryEscape(device.UserCode), nil))
			u, _ := url.Parse(start.Header().Get("Location"))
			req := httptest.NewRequest("GET", "https://tunn.test/auth/google/callback?state="+url.QueryEscape(u.Query().Get("state"))+"&code=fixture", nil)
			for _, c := range start.Result().Cookies() {
				req.AddCookie(c)
			}
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, req)
			want := http.StatusForbidden
			if tc.allowed {
				want = http.StatusFound
			}
			if w.Code != want {
				t.Fatalf("callback=%d %s", w.Code, w.Body.String())
			}
			var auth *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == authCookieName {
					auth = c
				}
			}
			if (auth != nil) != tc.allowed {
				t.Fatal("session issuance disagrees with provider authority")
			}
			if auth != nil {
				req.AddCookie(auth)
				if email, ok := p.getAuthFromCookie(req); !ok || email != tc.email {
					t.Fatal("invalid accepted session", email, ok)
				}
			}
			got, err := p.storage.GetDeviceCode(context.Background(), device.Code)
			if err != nil || got.Authorized {
				t.Fatal("callback authorized device without confirmation", got, err)
			}
		})
	}
}

func TestR3GoogleIdentityAuthorityOnRemoteLoginNode(t *testing.T) {
	local := securityDB(t)
	remote := securityReplicaStorage(t, local)
	ctx := context.Background()
	owner, err := local.FindOrCreateByEmails(ctx, []string{"owner@example.com"}, "github")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = remote.FindOrCreateGoogleIdentity(ctx, "third-party", "owner@example.com", "", true); err == nil {
		t.Fatal("remote authority accepted a non-authoritative identity")
	}
	got, err := remote.FindOrCreateGoogleIdentity(ctx, "workspace-subject", "owner@example.com", "example.com", true)
	if err != nil || got.ID != owner.ID {
		t.Fatal("remote authoritative binding failed", got, err)
	}
	if _, err = remote.FindOrCreateGoogleIdentity(ctx, "workspace-subject", "other@example.com", "example.com", true); err == nil {
		t.Fatal("remote authority rebound a subject by email")
	}
}

func TestR3OldGoogleSessionsWithoutAuthorityAreRejected(t *testing.T) {
	p := newMCPOAuthFixture(t).p
	w := httptest.NewRecorder()
	if err := p.signedSession(w, jwt.MapClaims{"email": "owner@example.com", "sub": "historical-subject", "provider": "google", "email_verified": true}, authCookieName, ".tunn.test", time.Hour); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "https://tunn.test/account/sharing", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	if _, ok := p.getAuthFromCookie(req); ok {
		t.Fatal("historical Google cookie retained account authority")
	}
	if _, ok := p.googleSession(req); ok {
		t.Fatal("historical Google cookie retained app handoff authority")
	}
}
