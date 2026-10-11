package host

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
)

const fixtureEntraTenant = "11111111-2222-3333-4444-555555555555"
const fixtureEntraObject = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

type orgFixtureCode struct {
	Nonce, Challenge, Redirect string
	Claims                     jwt.MapClaims
	Algorithm                  string
}

type orgOIDCFixture struct {
	p               *ProxyServer
	org             config.OIDCOrg
	server          *httptest.Server
	key             *rsa.PrivateKey
	kid             string
	mu              sync.Mutex
	codes           map[string]orgFixtureCode
	graphID         string
	graphNext       string
	graphError      bool
	googleError     bool
	groupCalls      int
	delegationCalls int
}

func newOrgOIDCFixture(t *testing.T, provider string) *orgOIDCFixture {
	t.Helper()
	p, tunnel, ledger, _ := webSharingFixture(t)
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	p.storage = storage.NewLocalStorage(db)
	owner, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	tunnel.AccountID = owner.ID
	out, err := ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: owner.ID, Endpoint: tunnel.TunnelID, Mode: "private"})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.ResourceID = out.Resources[0].Id
	p.orgLogins, err = newOrgLoginStore(db)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &orgOIDCFixture{p: p, key: key, kid: "key-1", codes: map[string]orgFixtureCode{}, graphID: fixtureEntraObject}
	f.org = config.OIDCOrg{ID: "company", Name: "Company", Provider: provider, ClientID: "company-client", ClientSecret: "company-secret", AllowedDomains: []string{"example.com"}, Groups: []config.OIDCGroup{{ID: "engineering", Name: "Engineering", Claim: "groups", Value: "remote-engineering"}}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.org.Issuer = f.server.URL
	if provider == "entra" {
		f.org.Issuer += "/" + fixtureEntraTenant + "/v2.0"
		f.org.Groups = append(f.org.Groups, config.OIDCGroup{ID: "readers", Name: "Readers", Claim: "roles", Value: "App.Reader"})
	}
	if provider == "google" {
		f.org.Issuer = "https://accounts.google.com"
		f.org.GoogleDirectoryAdmin = "admin@example.com"
		f.org.GoogleCredentialsFile = filepath.Join(t.TempDir(), "delegation.json")
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		data, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "directory@fixture.iam.gserviceaccount.com", "private_key": string(keyPEM), "private_key_id": "delegated-key", "token_uri": googleTokenURL})
		if err = os.WriteFile(f.org.GoogleCredentialsFile, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = (&config.Config{OIDCOrgs: []config.OIDCOrg{f.org}}).ValidateOIDCOrgs(); err != nil {
		t.Fatal(err)
	}
	p.config.OIDCOrgs = []config.OIDCOrg{f.org}
	fixtureURL, _ := url.Parse(f.server.URL)
	base := f.server.Client().Transport
	p.orgOIDCHTTPClient = &http.Client{Transport: securityRoundTripper(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		u := *r.URL
		clone.URL = &u
		switch r.URL.Host {
		case fixtureURL.Host:
		case "accounts.google.com":
			clone.URL.Path = "/discovery"
		case "graph.microsoft.com":
			clone.URL.Path = "/graph" + r.URL.Path
		case "oauth2.googleapis.com":
			clone.URL.Path = "/delegation"
		case "admin.googleapis.com":
			clone.URL.Path = "/directory"
		default:
			return nil, fmt.Errorf("fixture refuses unexpected identity endpoint %s", r.URL.Host)
		}
		clone.URL.Host = fixtureURL.Host
		return base.RoundTrip(clone)
	})}
	return f
}

func (f *orgOIDCFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") || r.URL.Path == "/discovery":
		json.NewEncoder(w).Encode(map[string]any{"issuer": f.org.Issuer, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	case r.URL.Path == "/keys":
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": f.kid, "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes())}}})
	case r.URL.Path == "/token":
		if r.Method != "POST" || r.ParseForm() != nil {
			http.Error(w, "invalid token method", 400)
			return
		}
		code, exists := f.codes[r.PostForm.Get("code")]
		digest := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		clientID, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		if f.org.Provider == "okta" {
			basicID, basicSecret, ok := r.BasicAuth()
			if !ok || clientID != "" || secret != "" {
				http.Error(w, "fixture requires Okta client_secret_basic", 400)
				return
			}
			clientID, secret = basicID, basicSecret
		}
		if !exists || clientID != f.org.ClientID || secret != f.org.ClientSecret || r.PostForm.Get("redirect_uri") != code.Redirect || base64.RawURLEncoding.EncodeToString(digest[:]) != code.Challenge || r.PostForm.Get("grant_type") != "authorization_code" {
			http.Error(w, "fixture PKCE/client/callback binding failed", 400)
			return
		}
		method := jwt.SigningMethodRS256
		token := jwt.NewWithClaims(method, code.Claims)
		token.Header["kid"] = f.kid
		var signingKey any = f.key
		if code.Algorithm == "HS256" {
			token = jwt.NewWithClaims(jwt.SigningMethodHS256, code.Claims)
			signingKey = []byte("not-the-org-signing-key")
		}
		if code.Algorithm == "none" {
			token = jwt.NewWithClaims(jwt.SigningMethodNone, code.Claims)
			signingKey = jwt.UnsafeAllowNoneSignatureType
		}
		raw, err := token.SignedString(signingKey)
		if err != nil {
			http.Error(w, "fixture signing failed", 500)
			return
		}
		if code.Algorithm == "bad-signature" {
			parts := strings.Split(raw, ".")
			parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 256))
			raw = strings.Join(parts, ".")
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "provider-secret-access", "token_type": "Bearer", "expires_in": 3600, "id_token": raw, "refresh_token": "must-not-store"})
	case r.URL.Path == "/graph/v1.0/me":
		f.groupCalls++
		json.NewEncoder(w).Encode(map[string]string{"id": f.graphID})
	case strings.HasPrefix(r.URL.Path, "/graph/v1.0/me/transitiveMemberOf"):
		f.groupCalls++
		if f.graphError || r.Header.Get("Authorization") != "Bearer provider-secret-access" {
			http.Error(w, "fixture Graph denied", 403)
			return
		}
		if r.URL.Query().Get("$skiptoken") == "next" {
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{{"id": "remote-engineering"}}})
		} else {
			next := f.graphNext
			if next == "" {
				next = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.group?$skiptoken=next"
			}
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]string{{"id": "remote-other"}}, "@odata.nextLink": next})
		}
	case r.URL.Path == "/delegation":
		f.delegationCalls++
		if r.ParseForm() != nil {
			http.Error(w, "bad delegation form", 400)
			return
		}
		delegation, err := jwt.Parse(r.Form.Get("assertion"), func(*jwt.Token) (any, error) { return &f.key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}))
		if err != nil || !delegation.Valid {
			http.Error(w, "bad delegation signature", 400)
			return
		}
		claims := delegation.Claims.(jwt.MapClaims)
		if claims["scope"] != directoryGroupsScope || claims["sub"] != f.org.GoogleDirectoryAdmin || claims["aud"] != googleTokenURL || claims["iss"] != "directory@fixture.iam.gserviceaccount.com" {
			http.Error(w, "wrong delegation scope, subject or audience", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "directory-only-access", "token_type": "Bearer", "expires_in": 3600})
	case r.URL.Path == "/directory":
		f.groupCalls++
		if f.googleError || r.URL.Query().Get("userKey") != "stable-subject" || r.Header.Get("Authorization") != "Bearer directory-only-access" {
			http.Error(w, "fixture Directory denied", 403)
			return
		}
		if r.URL.Query().Get("pageToken") == "next" {
			json.NewEncoder(w).Encode(map[string]any{"groups": []map[string]string{{"id": "remote-engineering"}}})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"groups": []map[string]string{{"id": "remote-other"}}, "nextPageToken": "next"})
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *orgOIDCFixture) begin(t *testing.T, mutate func(jwt.MapClaims), algorithm string) (*http.Request, []*http.Cookie) {
	t.Helper()
	path := "/auth/org/" + f.org.ID
	if f.org.Provider == "google" {
		path = "/auth/google?org=" + f.org.ID + "&"
	} else {
		path += "?"
	}
	r := httptest.NewRequest("GET", "https://tunn.test"+path+"return_to=https%3A%2F%2Fapi.tunn.test%2F", nil)
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatalf("start login: %d %s", w.Code, w.Body.String())
	}
	authorize, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := authorize.Query()
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("nonce") == "" || q.Get("response_type") != "code" || q.Get("client_id") != f.org.ClientID || q.Get("redirect_uri") != f.p.orgCallbackURL(f.org.ID) || !strings.Contains(q.Get("scope"), "openid") {
		t.Fatal("missing OIDC/PKCE/client/nonce/callback binding")
	}
	if f.org.Provider == "google" && q.Get("hd") != "example.com" {
		t.Fatal("missing Workspace hint")
	}
	if f.org.Provider == "okta" && !strings.Contains(q.Get("scope"), "groups") {
		t.Fatal("missing Okta groups scope")
	}
	if f.org.Provider == "entra" && !strings.Contains(q.Get("scope"), "https://graph.microsoft.com/User.Read") {
		t.Fatal("missing delegated Graph scope")
	}
	now := time.Now()
	claims := jwt.MapClaims{"iss": f.org.Issuer, "sub": "stable-subject", "aud": f.org.ClientID, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": q.Get("nonce"), "email": "alice@example.com", "email_verified": true, "groups": []string{"remote-engineering"}}
	if f.org.Provider == "entra" {
		delete(claims, "email")
		delete(claims, "email_verified")
		claims["preferred_username"], claims["tid"], claims["oid"], claims["roles"] = "alice@example.com", fixtureEntraTenant, fixtureEntraObject, []string{"App.Reader"}
	}
	if f.org.Provider == "google" {
		claims["hd"] = "example.com"
		delete(claims, "groups")
	}
	if mutate != nil {
		mutate(claims)
	}
	code := q.Get("state")
	f.mu.Lock()
	f.codes[code] = orgFixtureCode{Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge"), Redirect: q.Get("redirect_uri"), Claims: claims, Algorithm: algorithm}
	f.mu.Unlock()
	callback := httptest.NewRequest("GET", f.p.orgCallbackURL(f.org.ID)+"?state="+url.QueryEscape(q.Get("state"))+"&code="+url.QueryEscape(code), nil)
	for _, c := range w.Result().Cookies() {
		callback.AddCookie(c)
	}
	return callback, w.Result().Cookies()
}

func (f *orgOIDCFixture) finish(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.p.createHandler().ServeHTTP(w, r)
	return w
}

func orgResponseCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	if w.Code != 302 || w.Header().Get("Location") != "https://api.tunn.test/" {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == authCookieName {
			if len(c.Value) > 3800 || !c.Secure || !c.HttpOnly || c.MaxAge > 900 || strings.Contains(c.Value, "provider-secret-access") {
				t.Fatal("invalid org session cookie")
			}
			return c
		}
	}
	t.Fatal("org session cookie missing")
	return nil
}

func orgOpen(p *ProxyServer, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://api.tunn.test/", nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}

func TestOrgOIDCProviderShapesAndGroupSharing(t *testing.T) {
	for _, provider := range []string{"okta", "entra", "google"} {
		t.Run(provider, func(t *testing.T) {
			f := newOrgOIDCFixture(t, provider)
			owner := relayJWT(t, f.p, "owner@example.com")
			if w := sharingCall(t, f.p, "POST", "api", owner, `{"group":"company:engineering"}`); w.Code != 200 {
				t.Fatalf("share group: %d %s", w.Code, w.Body.String())
			}
			r, _ := f.begin(t, nil, "")
			cookie := orgResponseCookie(t, f.finish(r))
			identity := httptest.NewRequest("GET", "https://tunn.test/account", nil)
			identity.AddCookie(cookie)
			session, ok := f.p.getOrgSession(identity)
			if !ok || session.Org != "company" || session.Email != "alice@example.com" || len(session.Groups) == 0 || session.Groups[0] != "group:company:engineering" {
				t.Fatal("wrong org identity/groups", session)
			}
			principal, ok := f.p.getAuthFromCookie(identity)
			if !ok || principal == "alice@example.com" || principal != orgPrincipal(f.org, "stable-subject") {
				t.Fatal("corporate subject collapsed into email")
			}
			if w := orgOpen(f.p, cookie); w.Code != 200 {
				t.Fatalf("group member denied: %d %s", w.Code, w.Body.String())
			}
			if w := webOpen(t, f.p, "alice@example.com"); w.Code != 403 {
				t.Fatal("personal email inherited org group")
			}
			if w := sharingCall(t, f.p, "DELETE", "api", owner, `{"group":"company:engineering"}`); w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			if w := orgOpen(f.p, cookie); w.Code != 403 {
				t.Fatal("removed group retained access")
			}
			if w := f.finish(r.Clone(r.Context())); w.Code != 400 {
				t.Fatal("OIDC state/callback replay accepted")
			}
			f.mu.Lock()
			if provider == "google" && (f.delegationCalls != 1 || f.groupCalls != 2) {
				t.Error("Workspace did not use scoped delegated paginated groups")
			}
			f.mu.Unlock()
		})
	}
}

func TestOrgOIDCNegativeTokenCorpus(t *testing.T) {
	cases := []struct {
		name, algorithm string
		mutate          func(jwt.MapClaims)
		want            int
	}{
		{"wrong issuer", "", func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }, 401},
		{"wrong audience", "", func(c jwt.MapClaims) { c["aud"] = "another-client" }, 401},
		{"wrong authorized party", "", func(c jwt.MapClaims) { c["azp"] = "another-client" }, 403},
		{"multiple audiences without azp", "", func(c jwt.MapClaims) { c["aud"] = []string{"company-client", "another-client"} }, 403},
		{"missing nonce", "", func(c jwt.MapClaims) { delete(c, "nonce") }, 401},
		{"wrong nonce", "", func(c jwt.MapClaims) { c["nonce"] = "another-browser" }, 401},
		{"expired", "", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, 401},
		{"missing expiry", "", func(c jwt.MapClaims) { delete(c, "exp") }, 401},
		{"future issued", "", func(c jwt.MapClaims) { c["iat"] = time.Now().Add(10 * time.Minute).Unix() }, 403},
		{"missing issued", "", func(c jwt.MapClaims) { delete(c, "iat") }, 403},
		{"not yet valid", "", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(2 * time.Minute).Unix() }, 403},
		{"unverified email", "", func(c jwt.MapClaims) { c["email_verified"] = false }, 403},
		{"domain lookalike", "", func(c jwt.MapClaims) { c["email"] = "alice@example.com.evil.test" }, 403},
		{"subdomain", "", func(c jwt.MapClaims) { c["email"] = "alice@sub.example.com" }, 403},
		{"missing subject", "", func(c jwt.MapClaims) { delete(c, "sub") }, 403},
		{"malformed groups", "", func(c jwt.MapClaims) { c["groups"] = "remote-engineering" }, 403},
		{"malformed role", "", func(c jwt.MapClaims) { c["roles"] = []any{17} }, 403},
		{"invalid group entry", "", func(c jwt.MapClaims) { c["groups"] = []string{""} }, 403},
		{"access token substitution", "", func(c jwt.MapClaims) { c["at_hash"] = "wrong-access-token" }, 401},
		{"HMAC confusion", "HS256", nil, 401},
		{"invalid signature", "bad-signature", nil, 401},
		{"signature stripping", "none", nil, 401},
	}
	f := newOrgOIDCFixture(t, "okta")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := f.begin(t, tc.mutate, tc.algorithm)
			w := f.finish(r)
			if w.Code != tc.want {
				t.Fatalf("attack returned %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == authCookieName {
					t.Fatal("rejected identity received session")
				}
			}
			if again := f.finish(r.Clone(r.Context())); again.Code != 400 {
				t.Fatal("failed callback was replayable")
			}
		})
	}
}

func TestOrgOIDCEntraOverageAndRoles(t *testing.T) {
	for _, mode := range []string{"claim_names", "hasgroups", "wrong_graph_subject", "graph_denied", "hostile_pagination", "wrong_tenant", "malformed_overage"} {
		t.Run(mode, func(t *testing.T) {
			f := newOrgOIDCFixture(t, "entra")
			f.graphError = mode == "graph_denied"
			if mode == "wrong_graph_subject" {
				f.graphID = "another-user"
			}
			if mode == "hostile_pagination" {
				f.graphNext = "https://evil.example/steal-graph-token"
			}
			r, _ := f.begin(t, func(c jwt.MapClaims) {
				delete(c, "groups")
				c["_claim_names"] = map[string]string{"groups": "src1"}
				// This URL must never be followed, even when supplied by a signed IDP.
				c["_claim_sources"] = map[string]any{"src1": map[string]string{"endpoint": "https://evil.example/ssrf", "access_token": "attacker"}}
				if mode == "hasgroups" {
					delete(c, "_claim_names")
					c["hasgroups"] = true
				}
				if mode == "wrong_tenant" {
					c["tid"] = "another-tenant"
				}
				if mode == "malformed_overage" {
					c["hasgroups"] = "true"
				}
			}, "")
			w := f.finish(r)
			want := 503
			if mode == "claim_names" || mode == "hasgroups" {
				want = 302
			} else if mode == "wrong_tenant" || mode == "malformed_overage" {
				want = 403
			}
			if w.Code != want {
				t.Fatalf("Entra %s: %d %s", mode, w.Code, w.Body.String())
			}
			if want == 302 {
				cookie := orgResponseCookie(t, w)
				req := httptest.NewRequest("GET", "https://tunn.test/", nil)
				req.AddCookie(cookie)
				session, ok := f.p.getOrgSession(req)
				if !ok || strings.Join(session.Groups, " ") != "group:company:engineering group:company:readers" {
					t.Fatal("overage/roles lost membership", session)
				}
				f.mu.Lock()
				if f.groupCalls != 3 {
					t.Error("Graph membership pagination incomplete")
				}
				f.mu.Unlock()
			}
		})
	}
}

func TestOrgOIDCWorkspaceHostedDomainAndDirectoryFailures(t *testing.T) {
	for _, mode := range []string{"missing_hd", "wrong_hd", "gmail_with_hd", "unverified", "missing_verified", "directory_denied", "spoofed_token_group"} {
		t.Run(mode, func(t *testing.T) {
			f := newOrgOIDCFixture(t, "google")
			f.googleError = mode == "directory_denied"
			if mode == "spoofed_token_group" {
				f.org.Groups = append(f.org.Groups, config.OIDCGroup{ID: "attackers", Name: "Attackers", Claim: "groups", Value: "attacker-group"})
				f.p.config.OIDCOrgs[0] = f.org
			}
			r, _ := f.begin(t, func(c jwt.MapClaims) {
				switch mode {
				case "missing_hd":
					delete(c, "hd")
				case "wrong_hd":
					c["hd"] = "other.example.com"
				case "gmail_with_hd":
					c["email"] = "alice@gmail.com"
				case "unverified":
					c["email_verified"] = false
				case "missing_verified":
					delete(c, "email_verified")
				case "spoofed_token_group":
					c["groups"] = []string{"attacker-group"}
				}
			}, "")
			w := f.finish(r)
			want := 403
			if mode == "directory_denied" {
				want = 503
			}
			if mode == "spoofed_token_group" {
				want = 302
			}
			if w.Code != want {
				t.Fatalf("Workspace %s: %d %s", mode, w.Code, w.Body.String())
			}
			if mode == "spoofed_token_group" {
				request := httptest.NewRequest("GET", "https://tunn.test/", nil)
				request.AddCookie(orgResponseCookie(t, w))
				session, ok := f.p.getOrgSession(request)
				if !ok || len(session.Groups) != 1 || session.Groups[0] != "group:company:engineering" {
					t.Fatal("token groups overrode Directory membership", session)
				}
			}
		})
	}
}

func TestOrgOIDCBrowserStateOrgBindingAndKeyRotation(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	r, _ := f.begin(t, nil, "")
	missing := r.Clone(r.Context())
	missing.Header = r.Header.Clone()
	missing.Header.Del("Cookie")
	if w := f.finish(missing); w.Code != 400 {
		t.Fatal("login CSRF accepted")
	}
	other := f.org
	other.ID, other.Name = "other", "Other company"
	f.p.config.OIDCOrgs = append(f.p.config.OIDCOrgs, other)
	wrong := r.Clone(r.Context())
	copyURL := *r.URL
	wrong.URL = &copyURL
	wrong.URL.Path = "/auth/org/other/callback"
	if w := f.finish(wrong); w.Code != 400 {
		t.Fatal("state accepted by another org")
	}
	orgResponseCookie(t, f.finish(r))
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.key, f.kid = newKey, "key-2"
	f.mu.Unlock()
	next, _ := f.begin(t, nil, "")
	orgResponseCookie(t, f.finish(next))
}

func TestOrgOIDCSubjectIsolationAndSessionExpiry(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	r, _ := f.begin(t, func(c jwt.MapClaims) { c["email"] = "owner@example.com"; c["groups"] = []string{} }, "")
	cookie := orgResponseCookie(t, f.finish(r))
	if w := orgOpen(f.p, cookie); w.Code != 403 {
		t.Fatal("same email took over resource owner")
	}
	owner, _ := f.p.storage.GetAccountByEmail(context.Background(), "owner@example.com")
	orgAccount, _ := f.p.storage.GetAccountByEmail(context.Background(), orgPrincipal(f.org, "stable-subject"))
	if owner == nil || orgAccount == nil || owner.ID == orgAccount.ID {
		t.Fatal("same-email accounts merged")
	}
	if w := sharingCall(t, f.p, "GET", "api", cookie.Value, ""); w.Code != 401 {
		t.Fatal("browser-only org session accepted as bearer")
	}
	request := httptest.NewRequest("GET", "https://tunn.test/account", nil)
	request.AddCookie(cookie)
	f.p.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	if _, ok := f.p.getAuthFromCookie(request); ok {
		t.Fatal("expired org session accepted")
	}
	f.p.now = nil
	f.p.config.OIDCOrgs[0].Groups[0].Value = "remapped-group"
	if _, ok := f.p.getOrgSession(request); ok {
		t.Fatal("policy change retained session")
	}
}

func TestOrgOIDCLiveStreamSessionExpiry(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	owner := relayJWT(t, f.p, "owner@example.com")
	if w := sharingCall(t, f.p, "POST", "api", owner, `{"group":"company:engineering"}`); w.Code != 200 {
		t.Fatal(w)
	}
	r, _ := f.begin(t, nil, "")
	cookie := orgResponseCookie(t, f.finish(r))
	request := httptest.NewRequest("GET", "https://api.tunn.test/", nil)
	request.AddCookie(cookie)
	var offset atomic.Int64
	f.p.now = func() time.Time { return time.Now().Add(time.Duration(offset.Load()) * time.Second) }
	tunnel, _ := f.p.tunnelServer.GetTunnel("api")
	watch, stop := f.p.watchWebPermission(request, tunnel, []string{orgPrincipal(f.org, "stable-subject")}, false)
	defer stop()
	offset.Store(16 * 60)
	select {
	case <-watch.Context().Done():
	case <-time.After(4 * time.Second):
		t.Fatal("org session expiry did not cancel live stream")
	}
}

func TestOrgOIDCStateAtomicConsumptionAndRestart(t *testing.T) {
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	logins, err := newOrgLoginStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = logins.begin(context.Background(), "one-state", orgLogin{Org: "company", Nonce: "one-nonce", Expires: time.Now().Add(time.Minute).Unix()}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// A new store instance, as on relay restart, must preserve replay state.
	restarted, err := newOrgLoginStore(db)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := restarted.consume(context.Background(), "one-state", "company", time.Now()); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("state consumed %d times", successes.Load())
	}
	if err := logins.begin(context.Background(), "expired", orgLogin{Org: "company", Expires: time.Now().Add(-time.Second).Unix()}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.consume(context.Background(), "expired", "company", time.Now()); err == nil {
		t.Fatal("expired state accepted")
	}
}

func TestOrgOIDCHTTPBoundsAndNoCredentialRedirect(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	var calls atomic.Int64
	f.p.orgOIDCHTTPClient = &http.Client{Transport: securityRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://evil.example/steal"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	client := f.p.orgHTTPClient(f.org)
	r, _ := http.NewRequest("POST", "https://fixture.example/token", strings.NewReader("client_secret=private"))
	response, err := client.Do(r)
	if err != nil || response.StatusCode != 302 || calls.Load() != 1 {
		t.Fatal("credential redirect followed", err)
	}
	response.Body.Close()
	if _, err := client.Get("http://fixture.example/token"); err == nil || calls.Load() != 1 {
		t.Fatal("HTTP identity endpoint accepted")
	}
	f.p.orgOIDCHTTPClient = &http.Client{Transport: securityRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", (1<<20)+1)))}, nil
	})}
	response, err = f.p.orgHTTPClient(f.org).Get("https://fixture.example/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadAll(response.Body); err == nil {
		t.Fatal("unbounded chunked identity response accepted")
	}
}

func TestOrgOIDCGroupDashboardAndTenantBoundary(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	owner := relayJWT(t, f.p, "owner@example.com")
	for _, body := range []string{`{"group":"unknown:engineering"}`, `{"group":"company:unknown"}`, `{"group":"company:engineering","email":"alice@example.com"}`} {
		if w := sharingCall(t, f.p, "POST", "api", owner, body); w.Code != 400 {
			t.Fatal("ambiguous/unknown group accepted", w.Code)
		}
	}
	other := f.org
	other.ID, other.Name = "other", "Other company"
	f.p.config.OIDCOrgs = append(f.p.config.OIDCOrgs, other)
	if w := sharingCall(t, f.p, "POST", "api", owner, `{"group":"other:engineering"}`); w.Code != 200 {
		t.Fatal(w)
	}
	r, _ := f.begin(t, nil, "")
	cookie := orgResponseCookie(t, f.finish(r))
	if w := orgOpen(f.p, cookie); w.Code != 403 {
		t.Fatal("same group name crossed orgs")
	}
	get := httptest.NewRequest("GET", "https://tunn.test/account/sharing?tunnel=api", nil)
	get.AddCookie(&http.Cookie{Name: authCookieName, Value: owner})
	w := f.finish(get)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Company · Engineering") {
		t.Fatal("missing group share control")
	}
	csrf := hiddenMCPField(t, w.Body.String(), "csrf_token")
	form := url.Values{"group": {"group:company:engineering"}, "action": {"share"}, "csrf_token": {csrf}}
	post := httptest.NewRequest("POST", get.URL.String(), strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://tunn.test")
	post.AddCookie(get.Cookies()[0])
	if w := f.finish(post); w.Code != 303 {
		t.Fatal("group dashboard share failed", w.Code, w.Body.String())
	}
	if w := orgOpen(f.p, cookie); w.Code != 200 {
		t.Fatal("dashboard grant did not admit member")
	}
	post = httptest.NewRequest("POST", get.URL.String(), strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://api.tunn.test")
	post.AddCookie(get.Cookies()[0])
	if w := f.finish(post); w.Code != 403 {
		t.Fatal("origin application changed group permission")
	}
	request := httptest.NewRequest("GET", "https://api.tunn.test/", nil)
	request.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, f.p, "alice@example.com")})
	request.Header.Set("X-Tunn-Groups", "group:company:engineering")
	request.Header.Set("X-Tunn-Org", "company")
	if w := f.finish(request); w.Code != 403 {
		t.Fatal("group headers conferred authority")
	}
}

func TestOrgOIDCLiveStreamGroupRevocation(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	owner := relayJWT(t, f.p, "owner@example.com")
	if w := sharingCall(t, f.p, "POST", "api", owner, `{"group":"company:engineering"}`); w.Code != 200 {
		t.Fatal(w)
	}
	r, _ := f.begin(t, nil, "")
	cookie := orgResponseCookie(t, f.finish(r))
	request := httptest.NewRequest("GET", "https://api.tunn.test/", nil)
	request.AddCookie(cookie)
	tunnel, _ := f.p.tunnelServer.GetTunnel("api")
	watch, stop := f.p.watchWebPermission(request, tunnel, []string{orgPrincipal(f.org, "stable-subject")}, false)
	defer stop()
	if w := sharingCall(t, f.p, "DELETE", "api", owner, `{"group":"company:engineering"}`); w.Code != 200 {
		t.Fatal(w)
	}
	select {
	case <-watch.Context().Done():
	case <-time.After(4 * time.Second):
		t.Fatal("group removal did not cancel live stream")
	}
}

func TestOrgOIDCDeviceConfirmationAndNoGroupBearerAuthority(t *testing.T) {
	f := newOrgOIDCFixture(t, "okta")
	r, _ := f.begin(t, nil, "")
	cookie := orgResponseCookie(t, f.finish(r))
	dc, err := f.p.storage.CreateDeviceCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	confirmation := httptest.NewRequest("GET", "https://tunn.test/login?code="+url.QueryEscape(dc.UserCode), nil)
	confirmation.AddCookie(cookie)
	w := f.finish(confirmation)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "alice@example.com") {
		t.Fatal("company identity not shown in device confirmation")
	}
	csrf := hiddenMCPField(t, w.Body.String(), "csrf_token")
	form := url.Values{"code": {dc.UserCode}, "csrf_token": {csrf}}
	post := httptest.NewRequest("POST", "https://tunn.test/auth/device/authorize", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://tunn.test")
	post.AddCookie(cookie)
	if w := f.finish(post); w.Code != 200 {
		t.Fatal("company login could not enroll publisher", w.Code)
	}
	exchange := httptest.NewRequest("GET", "https://tunn.test/api/device/token?code="+url.QueryEscape(dc.Code), nil)
	w = f.finish(exchange)
	var response struct {
		AccessToken string `json:"access_token"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.AccessToken == "" {
		t.Fatal("publisher token missing", w.Code, w.Body.String())
	}
	claims, err := jwt.Parse(response.AccessToken, func(*jwt.Token) (any, error) { return f.p.getJWTSigningKey(), nil })
	if err != nil || claims.Claims.(jwt.MapClaims)["email"] != orgPrincipal(f.org, "stable-subject") {
		t.Fatal("device token lost stable company subject")
	}
	owner := relayJWT(t, f.p, "owner@example.com")
	if w := sharingCall(t, f.p, "POST", "api", owner, `{"group":"company:engineering"}`); w.Code != 200 {
		t.Fatal(w)
	}
	request := httptest.NewRequest("GET", "https://api.tunn.test/", nil)
	request.Header.Set("Authorization", "Bearer "+response.AccessToken)
	if w := f.finish(request); w.Code != 403 {
		t.Fatal("publisher/device credential inherited browser group authority", w.Code)
	}
}

func TestOrgOIDCGroupPublicationRequiresManagedOwner(t *testing.T) {
	for _, mode := range []string{"managed", "unknown_group", "uppercase_group", "no_authority", "no_owner", "tcp", "mcp"} {
		t.Run(mode, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			s := f.p.tunnelServer
			org := config.OIDCOrg{ID: "company", Name: "Company", Provider: "okta", Issuer: "https://company.okta.com", ClientID: "client", ClientSecret: "secret", AllowedDomains: []string{"example.com"}, Groups: []config.OIDCGroup{{ID: "engineering", Name: "Engineering", Claim: "groups", Value: "Engineering"}}}
			s.cfg.OIDCOrgs = []config.OIDCOrg{org}
			s.sharing = f.p.meter.(metering.SharingBackend)
			owner, err := s.storage.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			reg := &pb.RegisterClient{TunnelId: "preview", TargetUrl: "http", AuthToken: createTestJWT("owner@example.com", s.cfg.JWTSecret), TunnelKey: s.cfg.WellKnownKey, AllowedEmails: []string{"group:company:engineering"}, ExposureVersion: 1, ExposureMode: "private"}
			switch mode {
			case "unknown_group":
				reg.AllowedEmails[0] = "group:company:unknown"
			case "uppercase_group":
				reg.AllowedEmails[0] = "group:Company:engineering"
			case "no_authority":
				s.sharing = nil
			case "no_owner":
				s.cfg.ClientSecret, reg.AuthToken = "shared-secret", "shared-secret"
			case "tcp":
				reg.TargetUrl, reg.EndpointProtocol = "tcp", "tcp"
				reg.Capabilities = []string{"connection-stream-v1"}
			case "mcp":
				reg.TargetUrl = "mcp"
			}
			stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
			stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: reg}}
			close(stream.recvQueue)
			_ = s.EstablishTunnel(stream)
			if len(stream.sentMsgs) == 0 || stream.sentMsgs[0].GetRegisterResponse().Success != (mode == "managed") {
				t.Fatalf("group publication %s: %v", mode, stream.sentMsgs)
			}
			if mode == "managed" {
				result, err := s.sharing.Sharing(context.Background(), &mp.SharingRequest{Operation: "get", Owner: owner.ID, Endpoint: "preview"})
				if err != nil || len(result.Resources) != 1 || result.Resources[0].Mode != "private" || len(result.Resources[0].People) != 1 || result.Resources[0].People[0].Consumer != reg.AllowedEmails[0] {
					t.Fatal("publication did not seed an owner-scoped private group grant", err)
				}
			}
		})
	}
}
