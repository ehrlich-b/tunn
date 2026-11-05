package host

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	meterpb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

func TestProdAuthPublisherOriginsOwnEveryRoute(t *testing.T) {
	for _, principal := range prodAuthPrincipals {
		t.Run(principal, func(t *testing.T) {
			f := newProdAuthFixture(t)
			for _, route := range prodAuthRoutes {
				t.Run(route.method+" "+route.path, func(t *testing.T) {
					before := f.forwarded
					w := f.routeRequest(t, route, principal, "tools.tunn.test")
					want := 200
					switch principal {
					case "anonymous":
						want = 302
					case "other-cookie", "other-jwt":
						want = 403
					case "mcp-oauth", "login-proof", "expired-jwt":
						want = 401
					}
					if w.Code != want {
						t.Fatalf("publisher status = %d, want %d: %s", w.Code, want, w.Body)
					}
					if (f.forwarded > before) != (want == 200) {
						t.Fatalf("publisher delivery did not match admission: %d -> %d, status %d", before, f.forwarded, w.Code)
					}
					if want == 200 && route.method == http.MethodHead && w.Body.Len() != 0 {
						t.Fatal("publisher HEAD returned a body")
					}
					if want == 200 && route.method != http.MethodHead && w.Body.String() != `{"jsonrpc":"2.0","id":1,"result":{}}` {
						t.Fatalf("publisher path received a platform response: %s", w.Body)
					}
					if strings.Contains(w.Body.String(), "csrf_token") {
						t.Fatal("publisher origin exposed platform session state")
					}
					for _, cookie := range w.Result().Cookies() {
						if principal != "anonymous" || cookie.Name != appNonceCookie || cookie.Domain != "" || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" {
							t.Fatal("publisher origin received a cookie other than its host-only SSO nonce", cookie)
						}
					}
				})
			}
		})
	}
}

func TestProdAuthEndpointPolicyMatrix(t *testing.T) {
	for _, policy := range []string{"public", "private", "token-only"} {
		t.Run(policy, func(t *testing.T) {
			for _, principal := range prodAuthPrincipals {
				t.Run(principal, func(t *testing.T) {
					f := newProdAuthFixture(t)
					if policy != "private" {
						f.tunnel.AllowedEmails = nil
					}
					if policy == "public" {
						f.tunnel.updateAccessTokenDigest(nil)
					}
					w := f.routeRequest(t, prodAuthRoute{method: "POST", path: "/mcp"}, principal, "tools.tunn.test")
					want := 200
					if policy != "public" {
						switch principal {
						case "anonymous", "login-proof", "expired-jwt":
							want = 401
						case "other-jwt", "other-cookie":
							want = 403
						}
					}
					if w.Code != want {
						t.Fatalf("status = %d, want %d: %s", w.Code, want, w.Body)
					}
					if (f.forwarded > 0) != (want == 200) {
						t.Fatalf("publisher deliveries = %d for status %d", f.forwarded, w.Code)
					}
					out, err := f.p.meter.Export(context.Background(), &meterpb.ExportRequest{Owner: f.tunnel.AccountID, Endpoint: "tools", Month: time.Now().UTC().Format("2006-01")})
					if err != nil {
						t.Fatal(err)
					}
					var audited *meterpb.Event
					for _, event := range out.Events {
						if event.RequestId == w.Header().Get("Tunn-Request-ID") {
							audited = event
							break
						}
					}
					if audited == nil || audited.Status != int32(w.Code) || audited.Forwarded != (want == 200) || audited.Allowed != (want == 200) || !audited.Finished {
						t.Fatalf("incorrect admission audit: %v", audited)
					}
					if want != 200 && audited.Reason == "" {
						t.Fatal("denied request has no audit reason")
					}
					if principal == "mcp-oauth" && (audited.AuthMethod != "mcp_oauth" || audited.GrantId == "") {
						t.Fatal("MCP call lost its grant attribution")
					}
					if principal == "consumer-grant" && (audited.AuthMethod != "grant" || audited.GrantId != f.grantID) {
						t.Fatal("agent call lost its grant attribution")
					}
				})
			}
		})
	}
}

func TestProdAuthGrantScopeRevocationAndNoCookieFallback(t *testing.T) {
	for _, policy := range []string{"public", "private"} {
		for _, state := range []string{"wrong-endpoint", "wrong-owner", "revoked", "expired", "unknown"} {
			t.Run(policy+"/"+state, func(t *testing.T) {
				f := newProdAuthFixture(t)
				if policy == "public" {
					f.tunnel.AllowedEmails = nil
					f.tunnel.updateAccessTokenDigest(nil)
				}
				credential := "tunn_gr_other-grant"
				digest := sha256.Sum256([]byte(credential))
				grant := &meterpb.Grant{Owner: f.tunnel.AccountID, Endpoint: "tools", TokenSha256: digest[:], ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}
				switch state {
				case "wrong-endpoint":
					grant.Endpoint = "another"
				case "wrong-owner":
					account, err := f.p.storage.GetAccountByEmail(context.Background(), "other@example.com")
					if err != nil {
						t.Fatal(err)
					}
					grant.Owner = account.ID
				}
				if state != "unknown" {
					created, err := f.p.meter.CreateGrant(context.Background(), grant)
					if err != nil {
						t.Fatal(err)
					}
					if state == "revoked" {
						if _, err := f.p.meter.RevokeGrant(context.Background(), created); err != nil {
							t.Fatal(err)
						}
					}
					if state == "expired" {
						grant.Id = created.Id
						grant.ExpiresAt = time.Now().Add(-time.Minute).UnixMilli()
						data, err := json.Marshal(grant)
						if err != nil {
							t.Fatal(err)
						}
						if _, err := f.p.mcpOAuth.db.Exec(`UPDATE meter_grants SET expires=?, data=? WHERE id=?`, grant.ExpiresAt, data, created.Id); err != nil {
							t.Fatal(err)
						}
					}
				}
				for _, header := range []string{"Authorization", "Tunn-Authorization"} {
					r := httptest.NewRequest("POST", "https://tools.tunn.test/mcp", strings.NewReader(`{}`))
					r.Header.Set(header, "Bearer "+credential)
					r.AddCookie(&http.Cookie{Name: authCookieName, Value: f.credentials["owner-cookie"]})
					w := httptest.NewRecorder()
					f.p.createHandler().ServeHTTP(w, r)
					if w.Code != 403 || f.forwarded != 0 {
						t.Fatalf("%s grant decision = %d, publisher deliveries = %d", header, w.Code, f.forwarded)
					}
				}
			})
		}
	}
}

func TestProdAuthEmailAllowListProperties(t *testing.T) {
	cases := []struct {
		email string
		allow []string
		want  bool
	}{
		{"alice@company.com", []string{"@company.com"}, true},
		{"ALICE@COMPANY.COM", []string{"@company.com"}, true},
		{"alice@sub.company.com", []string{"@company.com"}, false},
		{"alice@company.com.evil.test", []string{"@company.com"}, false},
		{"alice@evilcompany.com", []string{"@company.com"}, false},
		{"alice@company.com", []string{"bob@company.com"}, false},
		{"alice@company.com", nil, false},
		{"ＡＬＩＣＥ@ＣＯＭＰＡＮＹ.ＣＯＭ", []string{"alice@company.com"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.email+fmt.Sprint(tc.allow), func(t *testing.T) {
			if got := isEmailAllowed(tc.email, tc.allow); got != tc.want {
				t.Fatalf("allow = %v, want %v", got, tc.want)
			}
		})
	}
	rng := rand.New(rand.NewSource(20261010))
	for i := 0; i < 128; i++ {
		domain := fmt.Sprintf("org%d.example", rng.Intn(10000))
		email := fmt.Sprintf("user%d@%s", rng.Intn(10000), domain)
		bucket := []string{"unrelated@elsewhere.test", email}
		allowed := []string{"@" + domain}
		if !isEmailBucketAllowed(bucket, allowed) || !isEmailBucketAllowed([]string{strings.ToUpper(email)}, allowed) {
			t.Fatalf("seeded identity %q lost normalized domain access", email)
		}
		for _, other := range []string{strings.Replace(email, "@", "@sub.", 1), email + ".elsewhere", strings.Replace(email, "@", "@prefix-", 1)} {
			if isEmailAllowed(other, allowed) {
				t.Fatalf("domain boundary admitted %q for %q", other, domain)
			}
		}
		if isEmailAllowed(common.NormalizeEmail(email), []string{"different@" + domain}) {
			t.Fatal("an exact-email rule became a domain wildcard")
		}
	}
}
