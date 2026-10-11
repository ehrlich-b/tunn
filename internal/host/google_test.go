package host

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func googleFixtureTransport(t *testing.T, p *ProxyServer, verified bool) *http.Client {
	t.Helper()
	return &http.Client{Transport: securityRoundTripper(func(r *http.Request) (*http.Response, error) {
		data := ""
		switch r.URL.String() {
		case googleTokenURL:
			if err := r.ParseForm(); err != nil {
				return nil, err
			}
			if r.Form.Get("client_id") != p.config.GoogleClientID || r.Form.Get("client_secret") != p.config.GoogleClientSecret || len(r.Form.Get("code_verifier")) != 43 || r.Form.Get("redirect_uri") != p.googleCallbackURL() {
				return nil, fmt.Errorf("wrong Google token binding")
			}
			data = fmt.Sprintf(`{"access_token":%q}`, r.Form.Get("code"))
		case googleUserInfoURL:
			email := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !strings.Contains(email, "@") {
				email = "alice@example.com"
			}
			data = fmt.Sprintf(`{"sub":"fixture-subject","email":%q,"email_verified":%v}`, email, verified)
		default:
			return nil, fmt.Errorf("unexpected Google call")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(data)), Header: make(http.Header)}, nil
	})}
}
func TestGoogleLoginVerifiedEmailAndBrowserBinding(t *testing.T) {
	for _, verified := range []bool{true, false} {
		t.Run(fmt.Sprint(verified), func(t *testing.T) {
			p, _, _, _ := webSharingFixture(t)
			p.config.GoogleClientID = "fixture-id"
			p.config.GoogleClientSecret = "fixture-secret"
			p.googleHTTPClient = googleFixtureTransport(t, p, verified)
			start := httptest.NewRequest("GET", "https://tunn.test/auth/google?return_to=https%3A%2F%2Fapi.tunn.test%2F", nil)
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, start)
			authorize, err := url.Parse(w.Header().Get("Location"))
			if err != nil || w.Code != 302 || authorize.Host != "accounts.google.com" || authorize.Query().Get("scope") != "openid email" || authorize.Query().Get("code_challenge_method") != "S256" {
				t.Fatal(w)
			}
			q := authorize.Query()
			callback := "https://tunn.test/auth/google/callback?state=" + url.QueryEscape(q.Get("state")) + "&code=alice%40example.com"
			for _, binding := range []bool{false, true} {
				r := httptest.NewRequest("GET", callback, nil)
				if binding {
					for _, c := range w.Result().Cookies() {
						r.AddCookie(c)
					}
				}
				out := httptest.NewRecorder()
				p.createHandler().ServeHTTP(out, r)
				want := 400
				if binding {
					want = 403
					if verified {
						want = 302
					}
				}
				if out.Code != want {
					t.Fatalf("binding %v verified %v=%d %s", binding, verified, out.Code, out.Body.String())
				}
				if binding && verified {
					if out.Header().Get("Location") != "https://api.tunn.test/" {
						t.Fatal("lost resource redirect")
					}
					if len(out.Result().Cookies()) < 2 {
						t.Fatal("missing login cookie")
					}
				}
			}
			// PKCE shape and entropy are checked without calling a real provider.
			for _, c := range w.Result().Cookies() {
				if c.Name == googleStateCookie {
					parts := strings.Split(c.Value, ".")
					raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
					if !strings.Contains(string(raw), `"google_pkce"`) {
						t.Fatal("unbound provider cookie")
					}
				}
			}
			if len(q.Get("code_challenge")) != 43 {
				t.Fatal("invalid PKCE challenge")
			}
		})
	}
	p, _, _, _ := webSharingFixture(t)
	w := httptest.NewRecorder()
	p.handleGoogleLogin(w, httptest.NewRequest("GET", "https://tunn.test/auth/google", nil))
	if w.Code != 503 {
		t.Fatal("unconfigured Google offered")
	}
}
