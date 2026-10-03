package host

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	"github.com/golang-jwt/jwt/v4"
)

func newTestGrant(t *testing.T, p *ProxyServer, local *storage.LocalStorage, tunnel *TunnelConnection, limit int64) (*store.Grant, string) {
	t.Helper()
	reg, err := local.RegisterEndpoint(context.Background(), tunnel.TunnelID, tunnel.AccountID, "synthetic-node", "http")
	if err != nil || !reg.Allowed {
		t.Fatalf("register=%+v %v", reg, err)
	}
	g, token, err := local.CreateGrant(context.Background(), store.GrantCreate{AccountID: tunnel.AccountID, EndpointID: tunnel.TunnelID, Label: "investigator", ExpiresAt: time.Now().Add(time.Hour), RequestLimit: limit})
	if err != nil {
		t.Fatal(err)
	}
	return g, token
}

func TestGrantIngressScopesPrecedenceAndAttribution(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, kind := range []string{"allowed", "dedicated", "revoked", "invalid", "malformed", "scope", "encoded-scope", "budget", "quota"} {
			t.Run(kind+map[bool]string{false: "/buffered", true: "/streaming"}[streaming], func(t *testing.T) {
				p, local, tunnel, _ := newIngressProxy(t, streaming)
				g, token := newTestGrant(t, p, local, tunnel, 1)
				path := "/mcp"
				status, reason, forwarded := 200, "grant", true
				switch kind {
				case "revoked":
					if _, err := local.RevokeGrant(context.Background(), tunnel.AccountID, g.ID); err != nil {
						t.Fatal(err)
					}
					status, reason, forwarded = 403, "grant_revoked", false
				case "invalid":
					token = store.GrantTokenPrefix + "invalid"
					status, reason, forwarded = 401, "grant_invalid", false
				case "malformed":
					token += " extra"
					status, reason, forwarded = 401, "grant_invalid", false
				case "scope":
					path = "/admin"
					status, reason, forwarded = 403, "grant_scope_denied", false
				case "encoded-scope":
					path = "/%6dcp"
					status, reason, forwarded = 403, "grant_scope_denied", false
				case "budget":
					if out, err := local.AdmitGrant(context.Background(), store.GrantAdmissionRequest{AccountID: tunnel.AccountID, EndpointID: tunnel.TunnelID, Token: token, RequestID: "already-admitted"}); err != nil || !out.Allowed {
						t.Fatal(out, err)
					}
					status, reason, forwarded = 429, "grant_exhausted", false
				case "quota":
					if err := local.RecordUsage(context.Background(), tunnel.AccountID, 1<<50); err != nil {
						t.Fatal(err)
					}
					status, reason, forwarded = 429, "owner_quota_exceeded", false
				}
				req := httptest.NewRequest(http.MethodPost, "https://tools.tunn.to"+path, strings.NewReader("request"))
				req.Header.Set("Authorization", "Bearer "+token)
				if kind == "dedicated" {
					req.Header.Set("Tunn-Authorization", "Bearer "+token)
					req.Header.Set("Authorization", "Bearer application-secret")
				}
				req.AddCookie(&http.Cookie{Name: authCookieName, Value: ingressJWT(t, p, "owner@example.test")})
				req.Header.Set("X-Tunn-Request-ID", "already-admitted")
				w := httptest.NewRecorder()
				p.createHandler().ServeHTTP(w, req)
				if w.Code != status {
					t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
				}
				events := exportIngress(t, local, tunnel.AccountID, false).Events
				if len(events) != 1 || events[0].Reason != reason || events[0].Forwarded != forwarded {
					t.Fatalf("events=%+v", events)
				}
				if reason == "grant" || reason == "grant_revoked" || reason == "grant_exhausted" {
					if events[0].CallerID != "grant:"+g.ID || events[0].AuthMethod != "grant" {
						t.Fatalf("attribution=%+v", events[0])
					}
				}
				if !forwarded && (events[0].RequestBytes != 0 || events[0].ResponseBytes != 0) {
					t.Fatalf("denial bytes=%+v", events[0])
				}
				list, err := local.ListGrants(context.Background(), tunnel.AccountID, tunnel.TunnelID)
				if err != nil || len(list) != 1 {
					t.Fatal(list, err)
				}
				wantUsed := int64(0)
				if forwarded || kind == "budget" {
					wantUsed = 1
				}
				if list[0].Used != wantUsed {
					t.Fatalf("denied request consumed admission: %+v", list)
				}
			})
		}
	}
}

type ambiguousGrantStorage struct {
	*storage.LocalStorage
	calls       int
	unavailable bool
}

func (s *ambiguousGrantStorage) AdmitGrant(ctx context.Context, q store.GrantAdmissionRequest) (*store.GrantAdmission, error) {
	s.calls++
	if s.unavailable {
		return nil, errors.New("synthetic unavailable")
	}
	out, err := s.LocalStorage.AdmitGrant(ctx, q)
	if s.calls == 1 && err == nil && out.Allowed {
		return nil, errors.New("synthetic lost acknowledgement")
	}
	return out, err
}

func TestGrantAdmissionAmbiguousRetryAndUnavailable(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry", true: "unavailable"}[unavailable], func(t *testing.T) {
			p, local, tunnel, _ := newIngressProxy(t, false)
			_, token := newTestGrant(t, p, local, tunnel, 1)
			wrapper := &ambiguousGrantStorage{LocalStorage: local, unavailable: unavailable}
			p.storage = wrapper
			r := httptest.NewRequest("POST", "https://tools.tunn.to/mcp", strings.NewReader("request"))
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, r)
			status := 200
			if unavailable {
				status = 503
			}
			if w.Code != status || wrapper.calls != 2 {
				t.Fatalf("status=%d attempts=%d", w.Code, wrapper.calls)
			}
			list, err := local.ListGrants(context.Background(), tunnel.AccountID, tunnel.TunnelID)
			if err != nil {
				t.Fatal(err)
			}
			want := int64(1)
			if unavailable {
				want = 0
			}
			if list[0].Used != want {
				t.Fatal(list)
			}
		})
	}
}

func TestGrantOwnerAPICredentialBoundary(t *testing.T) {
	p, local, tunnel, _ := newIngressProxy(t, false)
	_, existing := newTestGrant(t, p, local, tunnel, 20)
	owner := ingressJWT(t, p, "owner@example.test")
	request := func(method, path, token, body string, cookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://tunn.to"+path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if cookie {
			r.AddCookie(&http.Cookie{Name: authCookieName, Value: owner})
		}
		w := httptest.NewRecorder()
		p.createHandler().ServeHTTP(w, r)
		return w
	}
	body := `{"endpoint":"tools","label":"client B","ttl_seconds":1800,"request_limit":20}`
	for _, token := range []string{"", existing} {
		if w := request("POST", "/api/grants", token, body, true); w.Code != 401 {
			t.Fatalf("capability/cookie minted: %d", w.Code)
		}
	}
	if w := request("POST", "/api/grants", ingressJWT(t, p, "alice@example.test"), body, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w := request("POST", "/api/grants", owner, body, false)
	if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("creation=%d %s", w.Code, w.Body.String())
	}
	var created struct {
		Grant store.Grant `json:"grant"`
		Token string      `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	listed := request("GET", "/api/grants?endpoint=tools", owner, "", false)
	if listed.Code != 200 || strings.Contains(listed.Body.String(), created.Token) || strings.Contains(listed.Body.String(), "token_digest") {
		t.Fatal("credential leaked in owner list")
	}
	if revoked := request("DELETE", "/api/grants/"+created.Grant.ID, owner, "", false); revoked.Code != 204 {
		t.Fatal(revoked.Code)
	}
	if duplicate := request("DELETE", "/api/grants/"+created.Grant.ID, owner, "", false); duplicate.Code != 204 {
		t.Fatal("revoke must be idempotent")
	}
}

func TestAccountAccessTokenTypeBoundary(t *testing.T) {
	p, _, _, _ := newIngressProxy(t, false)
	for _, kind := range []string{"magic_link", "oauth_state", "access", ""} {
		claims := jwt.MapClaims{"email": "owner@example.test", "exp": time.Now().Add(time.Hour).Unix()}
		if kind != "" {
			claims["type"] = kind
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(p.getJWTSigningKey())
		if err != nil {
			t.Fatal(err)
		}
		want := kind == "access" || kind == ""
		r := httptest.NewRequest("GET", "https://tunn.to/api/grants", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.AddCookie(&http.Cookie{Name: authCookieName, Value: token})
		if _, _, _, ok := p.getAuthFromTunnelBearer(r, &TunnelConnection{}); ok != want {
			t.Errorf("bearer type=%q accepted=%v", kind, ok)
		}
		if _, ok := p.getAuthFromCookie(r); ok != want {
			t.Errorf("cookie type=%q accepted=%v", kind, ok)
		}
		if _, err := p.tunnelServer.validateJWTAndExtractEmail(token); (err == nil) != want {
			t.Errorf("publisher type=%q err=%v", kind, err)
		}
	}
}

func TestGrantPlatformCredentialRedaction(t *testing.T) {
	p, _, tunnel, _ := newIngressProxy(t, false)
	magic, err := p.generateMagicLinkToken("owner@example.test")
	if err != nil {
		t.Fatal(err)
	}
	appJWT, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"email": "app-user", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte("synthetic-application-key"))
	if err != nil {
		t.Fatal(err)
	}
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"email": "owner@example.test", "exp": time.Now().Add(-time.Hour).Unix()}).SignedString(p.getJWTSigningKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		token string
		strip bool
	}{
		{ingressJWT(t, p, "owner@example.test"), true}, {magic, true}, {expired, true}, {"synthetic-endpoint-token", true}, {"tunn_ep_rotated-or-other-endpoint", true}, {store.GrantTokenPrefix + "old-or-other-grant", true}, {"application-secret", false}, {appJWT, false},
	} {
		r := httptest.NewRequest("POST", "https://tools.tunn.to/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+test.token)
		r.Header.Set("Tunn-Authorization", "Bearer selected-credential")
		clean := p.stripPlatformAuthorization(r, tunnel)
		if (clean.Header.Get("Authorization") == "") != test.strip {
			t.Errorf("strip=%v expected=%v", clean.Header.Get("Authorization") == "", test.strip)
		}
		if r.Header.Get("Authorization") == "" {
			t.Fatal("redaction mutated original request")
		}
	}
}

func TestGrantMultiValueHeaderRedaction(t *testing.T) {
	p, _, tunnel, _ := newIngressProxy(t, false)
	r := httptest.NewRequest("POST", "https://tools.tunn.to/mcp", nil)
	r.Header.Add("Authorization", "")
	r.Header.Add("Authorization", "Bearer "+ingressJWT(t, p, "owner@example.test"))
	if values := p.stripPlatformAuthorization(r, tunnel).Header.Values("Authorization"); len(values) != 0 {
		t.Fatal("secondary platform credential retained")
	}
	r.Header.Add("Cookie", "app_session=keep")
	r.Header.Add("Cookie", authCookieName+"=synthetic-cookie")
	r.Header.Add("Cookie", "tunn_session=synthetic-legacy")
	if cookie := forwardedRequestHeaders(r.Header)["Cookie"]; cookie != "app_session=keep" {
		t.Fatalf("cookies=%q", cookie)
	}
}
