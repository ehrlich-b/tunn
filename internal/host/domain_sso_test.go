package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/identity"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
)

const appOwnerEmail = "owner@example.com"

func appKeyFile(t *testing.T, p *ProxyServer) ed25519.PublicKey {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring := identity.Ring{Active: "current", Keys: []identity.Key{{Kty: "OKP", Crv: "Ed25519", Alg: "EdDSA", Use: "sig", Kid: "current", X: base64.RawURLEncoding.EncodeToString(pub), D: base64.RawURLEncoding.EncodeToString(key.Seed())}}}
	data, _ := json.Marshal(ring)
	p.config.IdentityKeysFile = filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p.config.IdentityKeysFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	return pub
}
func appProxyFixture(t *testing.T) (*ProxyServer, *TunnelConnection, ed25519.PublicKey) {
	t.Helper()
	p, tunnel, pub, _ := appProxyFixtureDB(t)
	return p, tunnel, pub
}
func appProxyFixtureDB(t *testing.T) (*ProxyServer, *TunnelConnection, ed25519.PublicKey, *sql.DB) {
	t.Helper()
	p, registry, dns := domainProxyFixture(t)
	p.config.PublicAddr = "tunn.test"
	p.config.GitHubClientID = "fixture-client"
	p.emailSender = new(accountsMailCapture)
	d, err := registry.Add(context.Background(), &domainpb.Domain{Name: "*.apps.example.com", Tunnel: "dashboard", Owner: "ad38bf44-0c4a-40ce-bdee-2d8579bf63cc"})
	if err != nil {
		t.Fatal(err)
	}
	dns.target = d.CnameTarget
	if _, err := registry.Verify(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	tunnel, _ := p.tunnelServer.GetTunnel("api")
	delete(p.tunnelServer.tunnels, "api")
	tunnel.TunnelID = d.AppNames[0].Tunnel
	p.tunnelServer.tunnels[tunnel.TunnelID] = tunnel
	tunnel.AllowedEmails = nil // Explicitly public publisher still receives the forced gate.
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO accounts(id,primary_email,plan,created_at) VALUES(?,?,'free',1)`, tunnel.AccountID, appOwnerEmail); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO account_emails(email,account_id,verified_via,added_at) VALUES(?,?,'github',1)`, appOwnerEmail, tunnel.AccountID); err != nil {
		t.Fatal(err)
	}
	p.storage = storage.NewLocalStorage(db)
	tunnel.CreatorEmail = appOwnerEmail
	return p, tunnel, appKeyFile(t, p), db
}
func appSessionCookie(t *testing.T, p *ProxyServer, email, provider string, verified bool, aud string) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	name, domain := appCookie, ""
	if aud == "" {
		name, domain = authCookieName, ".tunn.test"
	}
	id := "invalid"
	if validGoogleEmail(email) {
		account, err := p.storage.FindOrCreateByEmails(context.Background(), []string{email}, provider)
		if err != nil {
			t.Fatal(err)
		}
		id = account.ID
	}
	if err := p.signedSession(w, jwt.MapClaims{"account_id": id, "email": strings.ToLower(email), "sub": "google:123", "provider": provider, "email_verified": verified, "google_authoritative": verified, "issuer": common.GoogleIssuer, "aud": aud}, name, domain, time.Hour); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies()[0]
}
func TestDomainAppAccountOwnerAndSignedIdentity(t *testing.T) {
	p, tunnel, pub := appProxyFixture(t)
	stream := tunnel.Stream.(*meteringFixtureStream)
	hook := stream.hook
	var headers map[string]string
	stream.hook = func(msg *pb.TunnelMessage) error {
		if req := msg.GetHttpRequest(); req != nil {
			headers = req.Headers
		}
		return hook(msg)
	}
	for _, tc := range []struct {
		email, provider string
		verified        bool
		want            int
	}{
		{appOwnerEmail, "google", true, 200}, {"OWNER@EXAMPLE.COM", "google", true, 200},
		{"other@gmail.com", "google", true, 403}, {"owner+apps@example.com", "google", true, 403}, {"owner@example.com.evil.test", "google", true, 403}, {"оwner@example.com", "google", true, 302}, {"ｏwner@example.com", "google", true, 302},
		{appOwnerEmail, "github", true, 200}, {appOwnerEmail, "magic_link", true, 200}, {"other@gmail.com", "github", true, 403}, {"other@example.com", "magic_link", true, 403}, {appOwnerEmail, "google", false, 302},
	} {
		headers = nil
		r := appNavigationRequest("GET", "https://dashboard.apps.example.com/", nil)
		r.AddCookie(appSessionCookie(t, p, tc.email, tc.provider, tc.verified, "dashboard.apps.example.com"))
		r.Header.Set(identity.Header, "spoof")
		r.Header.Set("Connection", "X-Tunn-Identity, x-tunn-user-email")
		r.Header["x-tunn-user-email"] = []string{"evil@gmail.com"}
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%+v: %d %s", tc, w.Code, w.Body.String())
		}
		if tc.want != 200 {
			if headers != nil {
				t.Fatal("denied request reached app")
			}
			continue
		}
		if headers[identity.EmailHeader] != appOwnerEmail {
			t.Fatalf("email=%v", headers)
		}
		token, err := jwt.Parse(headers[identity.Header], func(tok *jwt.Token) (interface{}, error) {
			if tok.Header["kid"] != "current" {
				t.Fatal("missing kid")
			}
			return pub, nil
		}, jwt.WithValidMethods([]string{"EdDSA"}))
		if err != nil || !token.Valid {
			t.Fatalf("assertion=%v", err)
		}
		claims := token.Claims.(jwt.MapClaims)
		if !claims.VerifyAudience("dashboard.apps.example.com", true) || claims.VerifyAudience("other.apps.example.com", true) || claims["email"] != appOwnerEmail || claims["sub"] != tunnel.AccountID || claims["account_id"] != tunnel.AccountID || claims["provider"] != tc.provider || claims["idp"] != tc.provider || claims["email_verified"] != true || claims["iss"] != "https://tunn.test" {
			t.Fatal(claims)
		}
		if claims["exp"].(float64)-claims["iat"].(float64) != 120 {
			t.Fatal("assertion not short lived")
		}
		if strings.Contains(headers["Cookie"], appCookie) {
			t.Fatal("session leaked to app")
		}
	}
	for _, token := range []string{relayJWT(t, p, appOwnerEmail), "tunn_gr_fake", "tunn_mcp_fake"} {
		r := appNavigationRequest("GET", "https://dashboard.apps.example.com/", nil)
		r.Header.Set("Tunn-Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("bearer bypassed account gate", w.Code)
		}
	}
	r := appNavigationRequest("GET", "https://dashboard.apps.example.com/", nil)
	r.AddCookie(appSessionCookie(t, p, appOwnerEmail, "google", true, "other.apps.example.com"))
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatal("cross-host cookie accepted")
	}
	tunnel.AccountID = "other-owner"
	w = httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("publisher ownership bypass")
	}
	w = httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.test/.well-known/tunn-jwks.json", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), `"d":`) {
		t.Fatal("JWKS failed or leaked private key")
	}

}
func TestDomainSSOBrowserBindingReplayAndRepeatApp(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	handler := p.createHandler()
	initial := httptest.NewRecorder()
	handler.ServeHTTP(initial, appNavigationRequest("GET", "https://dashboard.apps.example.com/report?q=1", nil))
	if initial.Code != 302 {
		t.Fatal(initial.Code)
	}
	login := initial.Header().Get("Location")
	nonce := initial.Result().Cookies()[0]
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", login, nil))
	if w.Code != 302 || strings.Contains(w.Header().Get("Location"), "google_only") {
		t.Fatal("missing normal login page")
	}
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest("GET", "https://tunn.test"+w.Header().Get("Location"), nil))
	if !strings.Contains(page.Body.String(), "GitHub") || strings.Contains(page.Body.String(), "Continue with Google") {
		t.Fatal("wrong login providers")
	}
	r := httptest.NewRequest("GET", login, nil)
	r.AddCookie(appSessionCookie(t, p, appOwnerEmail, "google", true, ""))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatal(w.Code, w.Body)
	}
	callback := w.Header().Get("Location")
	for _, bad := range []string{"missing-cookie", "different-cookie", "different-host", "tamper"} {
		target := callback
		if bad == "different-host" {
			target = strings.Replace(target, "dashboard.apps.example.com", "other.apps.example.com", 1)
		}
		if bad == "tamper" {
			target += "x"
		}
		r := httptest.NewRequest("GET", target, nil)
		if bad != "missing-cookie" {
			c := *nonce
			if bad == "different-cookie" {
				c.Value = "wrong"
			}
			r.AddCookie(&c)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		want := 400
		if bad == "different-host" {
			want = 403 // Unknown app routing is rejected before login credentials.
		}
		if out.Code != want {
			t.Fatalf("%s=%d", bad, out.Code)
		}
	}
	// A background request from another tab must not overwrite the binding.
	background := httptest.NewRequest("GET", "https://dashboard.apps.example.com/poll", nil)
	background.Header.Set("Sec-Fetch-Mode", "cors")
	background.AddCookie(nonce)
	bg := httptest.NewRecorder()
	handler.ServeHTTP(bg, background)
	if bg.Code != 401 || bg.Header().Get("Location") != "" {
		t.Fatalf("background: %d %v", bg.Code, bg.Header())
	}
	for _, c := range bg.Result().Cookies() {
		if c.Name == appNonceCookie {
			t.Fatal("background request changed nonce")
		}
	}
	r = httptest.NewRequest("GET", callback, nil)
	r.AddCookie(nonce)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 302 || w.Header().Get("Location") != "/report?q=1" {
		t.Fatal(w.Code, w.Body.String())
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == appCookie {
			session = c
		}
	}
	if session == nil || session.Domain != "" || !session.HttpOnly || !session.Secure {
		t.Fatal("missing private host cookie")
	}
	repeat := httptest.NewRecorder()
	handler.ServeHTTP(repeat, r)
	if repeat.Code != 400 {
		t.Fatal("handoff replay accepted")
	}
	r = appNavigationRequest("GET", "https://dashboard.apps.example.com/report?q=1", nil)
	r.AddCookie(session)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("SSO did not open app", w.Code, w.Body.String())
	}
	// A central account session serves another app handoff without another IdP login.
	r = httptest.NewRequest("GET", login, nil)
	r.AddCookie(appSessionCookie(t, p, appOwnerEmail, "google", true, ""))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	u, _ := url.Parse(w.Header().Get("Location"))
	if u.Host != "dashboard.apps.example.com" || u.Path != appCallback {
		t.Fatal("repeat SSO reauthenticated")
	}
}
func TestGoogleLookalikesAreRejectedBeforeNormalization(t *testing.T) {
	for _, email := range []string{"ｏwner@example.com", "оwner@example.com", " owner@example.com", "a@@gmail.com"} {
		if validGoogleEmail(email) {
			t.Fatalf("accepted %q", email)
		}
	}
}

func TestDomainIdentityHeadersCannotBeSpoofedOnPublicPlatform(t *testing.T) {
	p, _, _, stream := meteringRelay(t, false, "public app")
	tunnel, _ := p.tunnelServer.GetTunnel("api")
	tunnel.AllowedEmails = nil
	var headers map[string]string
	hook := stream.hook
	stream.hook = func(msg *pb.TunnelMessage) error {
		if req := msg.GetHttpRequest(); req != nil {
			headers = req.Headers
		}
		return hook(msg)
	}
	r := httptest.NewRequest("GET", "https://api.tunn.test/", nil)
	r.Header.Set(identity.Header, "spoof")
	r.Header["x-tunn-user-email"] = []string{appOwnerEmail}
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for key := range headers {
		if strings.EqualFold(key, identity.Header) || strings.EqualFold(key, identity.EmailHeader) {
			t.Fatal("public client spoof reached app")
		}
	}
}
func TestGoogleCallbackRejectsUnverifiedEmailAndLookalikes(t *testing.T) {
	for _, tc := range []struct {
		email    string
		verified bool
	}{{appOwnerEmail, false}, {"ｏwner@example.com", true}, {"оwner@example.com", true}, {"ownİr@example.com", true}} {
		p, _, _, _ := webSharingFixture(t)
		p.config.GoogleClientID = "fixture-id"
		p.config.GoogleClientSecret = "fixture-secret"
		p.googleHTTPClient = googleFixtureTransport(t, p, tc.verified)
		start := httptest.NewRecorder()
		p.handleGoogleLogin(start, httptest.NewRequest("GET", "https://tunn.test/auth/google", nil))
		authorize, err := url.Parse(start.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "https://tunn.test/auth/google/callback?state="+url.QueryEscape(authorize.Query().Get("state"))+"&code="+url.QueryEscape(tc.email), nil)
		for _, c := range start.Result().Cookies() {
			r.AddCookie(c)
		}
		out := httptest.NewRecorder()
		p.handleGoogleCallback(out, r)
		if out.Code != 403 {
			t.Fatalf("%+v accepted: %d", tc, out.Code)
		}
	}
}
