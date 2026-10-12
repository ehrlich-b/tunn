package host

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/golang-jwt/jwt/v4"
)

// Independent security corpus retained from the blocking SSO review.
func TestReviewJWKSCacheAndRotation(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	base := f.p.orgOIDCHTTPClient.Transport
	var fetches atomic.Int64
	var unavailable atomic.Bool
	f.p.orgOIDCHTTPClient.Transport = securityRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/keys" {
			fetches.Add(1)
			if unavailable.Load() {
				return nil, fmt.Errorf("simulated JWKS outage")
			}
		}
		return base.RoundTrip(r)
	})
	r, _ := f.begin(t, nil, "")
	orgResponseCookie(t, f.finish(r))
	if fetches.Load() != 1 {
		t.Fatal("initial key fetch count", fetches.Load())
	}
	unavailable.Store(true)
	r, _ = f.begin(t, nil, "")
	orgResponseCookie(t, f.finish(r))
	if fetches.Load() != 1 {
		t.Fatal("cache not reused", fetches.Load())
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.key, f.kid = newKey, "rotated"
	f.mu.Unlock()
	r, _ = f.begin(t, nil, "")
	if w := f.finish(r); w.Code != 401 {
		t.Fatal("unavailable uncached key accepted", w.Code)
	}
	unavailable.Store(false)
	r, _ = f.begin(t, nil, "")
	orgResponseCookie(t, f.finish(r))
	if fetches.Load() != 3 {
		t.Fatal("rotation did not refetch", fetches.Load())
	}
	t.Log("valid cache survives outage; unknown key fails closed during outage and succeeds after rotation")
}

func TestReviewTwoOrgsAndTokenSubstitution(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	owner := relayJWT(t, f.p, "owner@example.com")
	other := f.org
	other.ID = "other"
	f.p.config.OIDCOrgs = append(f.p.config.OIDCOrgs, other)
	if w := sharingCall(t, f.p, "POST", "api", owner, `{"group":"company:engineering"}`); w.Code != 200 {
		t.Fatal(w)
	}
	r, _ := f.begin(t, nil, "")
	companyCookie := orgResponseCookie(t, f.finish(r))
	f.org = other
	r, _ = f.begin(t, nil, "")
	otherCookie := orgResponseCookie(t, f.finish(r))
	if orgOpen(f.p, companyCookie).Code != 200 || orgOpen(f.p, otherCookie).Code != 403 {
		t.Fatal("two-org membership leaked")
	}
	a, _ := f.p.storage.GetAccountByEmail(context.Background(), orgPrincipal(f.p.config.OIDCOrgs[0], "stable-subject"))
	b, _ := f.p.storage.GetAccountByEmail(context.Background(), orgPrincipal(other, "stable-subject"))
	if a == nil || b == nil || a.ID == b.ID {
		t.Fatal("two-org subjects merged")
	}
	for name, mutate := range map[string]func(jwt.MapClaims){
		"other issuer": func(c jwt.MapClaims) { c["iss"] = "https://other-tenant.example" },
		"other client": func(c jwt.MapClaims) { c["aud"] = "other-client" },
		"other nonce":  func(c jwt.MapClaims) { c["nonce"] = "other-flow-nonce" },
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := f.begin(t, mutate, "")
			if w := f.finish(r); w.Code != 401 {
				t.Fatal("substituted token accepted", w.Code)
			}
		})
	}
}

func TestReviewMembershipRemovalAndNoRefreshExtension(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	owner := relayJWT(t, f.p, "owner@example.com")
	if w := sharingCall(t, f.p, "POST", "api", owner, `{"group":"company:engineering"}`); w.Code != 200 {
		t.Fatal(w)
	}
	r, _ := f.begin(t, nil, "")
	oldCookie := orgResponseCookie(t, f.finish(r))
	issuedRequest := httptest.NewRequest(http.MethodGet, "https://api.tunn.test/", nil)
	issuedRequest.AddCookie(oldCookie)
	issuedSession, ok := f.p.getOrgSession(issuedRequest)
	if !ok {
		t.Fatal("issued membership snapshot is invalid")
	}
	issuedExpiry := time.Unix(issuedSession.Expires, 0)
	r, _ = f.begin(t, func(c jwt.MapClaims) { c["groups"] = []string{} }, "")
	removedCookie := orgResponseCookie(t, f.finish(r))
	if orgOpen(f.p, oldCookie).Code != 200 || orgOpen(f.p, removedCookie).Code != 403 {
		t.Fatal("membership snapshot or fresh removal inconsistent")
	}
	f.p.now = func() time.Time { return issuedExpiry.Add(-time.Second) }
	if orgOpen(f.p, oldCookie).Code != 200 {
		t.Fatal("snapshot unexpectedly expired before bound")
	}
	f.p.now = func() time.Time { return issuedExpiry.Add(time.Second) }
	if orgOpen(f.p, oldCookie).Code == 200 {
		t.Fatal("membership retained beyond 15 minutes")
	}
	t.Log("removed upstream membership persists in old cookie until its 15-minute bound; fresh login denies immediately")
}

func TestReviewClockSkewAndProviderVerification(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	for _, seconds := range []int64{30, 90} {
		r, _ := f.begin(t, func(c jwt.MapClaims) {
			c["iat"] = time.Now().Add(time.Duration(seconds) * time.Second).Unix()
			c["nbf"] = c["iat"]
		}, "")
		w := f.finish(r)
		if seconds == 30 {
			orgResponseCookie(t, w)
		} else if w.Code != 403 {
			t.Fatal("excess clock skew accepted", w.Code)
		}
	}
	for _, provider := range []string{"okta", "google", "entra"} {
		t.Run(provider, func(t *testing.T) {
			f := newOrgOIDCFixture(t, provider)
			r, _ := f.begin(t, func(c jwt.MapClaims) { delete(c, "email_verified") }, "")
			w := f.finish(r)
			if provider == "entra" {
				orgResponseCookie(t, w)
			} else if w.Code != 403 {
				t.Fatal("missing provider verification accepted", w.Code)
			}
		})
	}
}

func TestReviewOrgSetupAndBrowserNamespace(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
		w := f.finish(httptest.NewRequest(method, "https://tunn.test/auth/org/attacker?issuer=https%3A%2F%2Fevil.example&domain=example.com", nil))
		if w.Code != 404 && w.Code != 405 {
			t.Fatal("unconfigured organization accepted", method, w.Code)
		}
	}
	if len(f.p.config.OIDCOrgs) != 1 {
		t.Fatal("request modified organization configuration")
	}
	w := f.finish(httptest.NewRequest("GET", "https://api.tunn.test/auth/org/company", nil))
	if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "https://tunn.test/auth/login?") {
		t.Fatal("application route bypassed normal platform sign-in", w.Code, w.Header().Get("Location"))
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == orgCookieName {
			t.Fatal("application origin started organization login")
		}
	}
	w = httptest.NewRecorder()
	f.p.handleOrgOIDCFor(w, httptest.NewRequest("GET", "https://api.tunn.test/auth/org/company", nil), "company", false)
	if w.Code != 403 {
		t.Fatal("org handler accepted application origin", w.Code)
	}
	stripped := stripPlatformCookies("tunn_auth=secret; __Host-tunn_org_login=state; app=retained")
	if stripped != "app=retained" {
		t.Fatal("platform cookie leaked to origin", stripped)
	}
	for _, c := range []string{"tunn_auth=forged; Domain=tunn.test; Path=/", "__Host-tunn_org_login=forged; Secure; Path=/"} {
		dst := http.Header{}
		copyApplicationResponseHeaders(dst, map[string]string{"Set-Cookie": c})
		if dst.Get("Set-Cookie") != "" {
			t.Fatal("application could set platform cookie")
		}
	}
	// A client-supplied redirect_uri never changes the registered callback.
	w = f.finish(httptest.NewRequest("GET", "https://tunn.test/auth/org/company?redirect_uri=https%3A%2F%2Fevil.example%2Fcallback", nil))
	u, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != 302 || u.Query().Get("redirect_uri") != f.p.orgCallbackURL("company") {
		t.Fatal("client controlled callback URI")
	}
}

func TestReviewRSAPublicKeyHMACConfusion(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	provider, err := f.p.orgProvider(context.Background(), f.org)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := jwt.MapClaims{"iss": f.org.Issuer, "aud": f.org.ClientID, "sub": "attacker", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	publicBytes, _ := json.Marshal(f.key.PublicKey)
	raw, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(publicBytes)
	if _, err := provider.provider.Verifier(&oidc.Config{ClientID: f.org.ClientID, SupportedSigningAlgs: []string{"RS256"}}).Verify(context.Background(), raw); err == nil {
		t.Fatal("public-key HMAC confusion accepted")
	}
	// Confirm PKCE rejects a substituted verifier at the token endpoint itself.
	r, _ := f.begin(t, nil, "")
	state := r.URL.Query().Get("state")
	f.mu.Lock()
	code := f.codes[state]
	f.mu.Unlock()
	wrong := sha256.Sum256([]byte("attacker-verifier"))
	if code.Challenge == base64.RawURLEncoding.EncodeToString(wrong[:]) {
		t.Fatal("unexpected verifier collision")
	}
	body := url.Values{"code": {state}, "code_verifier": {"attacker-verifier"}, "grant_type": {"authorization_code"}, "redirect_uri": {code.Redirect}}
	req, _ := http.NewRequest("POST", f.server.URL+"/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.org.ClientID, f.org.ClientSecret)
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 400 {
		t.Fatal("substituted PKCE verifier accepted", resp.StatusCode)
	}
}

func TestReviewEntraMultiTenantConfigRejected(t *testing.T) {
	for _, tenant := range []string{"common", "organizations", "consumers", "{tenantid}", "example.com"} {
		org := config.OIDCOrg{ID: "company", Name: "Company", Provider: "entra", Issuer: "https://login.microsoftonline.com/" + tenant + "/v2.0", ClientID: "client", ClientSecret: "secret", AllowedDomains: []string{"example.com"}}
		if err := (&config.Config{OIDCOrgs: []config.OIDCOrg{org}}).ValidateOIDCOrgs(); err == nil {
			t.Fatal("multi-tenant issuer accepted", tenant)
		}
	}
}

func TestReviewJWKSRemovedKeyStillCached(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	provider, err := f.p.orgProvider(context.Background(), f.org)
	if err != nil {
		t.Fatal(err)
	}
	verify := provider.provider.Verifier(&oidc.Config{ClientID: f.org.ClientID, SupportedSigningAlgs: []string{"RS256"}})
	now := time.Now()
	claims := jwt.MapClaims{"iss": f.org.Issuer, "aud": f.org.ClientID, "sub": "stable-subject", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	old := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	old.Header["kid"] = f.kid
	oldRaw, err := old.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify.Verify(context.Background(), oldRaw); err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.key, f.kid = newKey, "replacement-only"
	f.mu.Unlock()
	if _, err := verify.Verify(context.Background(), oldRaw); err != nil {
		t.Fatal("expected prior key to remain cached", err)
	}
	replacement := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	replacement.Header["kid"] = "replacement-only"
	replacementRaw, err := replacement.SignedString(newKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify.Verify(context.Background(), replacementRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := verify.Verify(context.Background(), oldRaw); err == nil {
		t.Fatal("removed key accepted after cache was replaced")
	}
	t.Log("cache has no periodic removal check: deleted signing key is accepted until a cache miss refreshes keys or relay restarts")
}

func TestReviewPerOrgAllowedDomains(t *testing.T) {
	for _, provider := range []string{"okta", "entra", "google"} {
		t.Run(provider, func(t *testing.T) {
			f := newOrgOIDCFixture(t, provider)
			other := f.org
			other.ID, other.AllowedDomains = "other", []string{"other.example"}
			f.p.config.OIDCOrgs = append(f.p.config.OIDCOrgs, other)
			r, _ := f.begin(t, func(c jwt.MapClaims) {
				c["email"] = "alice@other.example"
				if provider == "google" {
					c["hd"] = "other.example"
				}
			}, "")
			if w := f.finish(r); w.Code != 403 {
				t.Fatal("another org's allowed domain admitted this login", w.Code)
			}
		})
	}
}
