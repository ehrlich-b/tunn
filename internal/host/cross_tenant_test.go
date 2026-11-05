package host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/storage"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
)

func TestCrossTenantCookieScope(t *testing.T) {
	f := newMCPOAuthFixture(t)
	cookie := emailSession(t, f.p, "owner@example.com")
	if cookie.Name != "__Host-tunn_auth" || cookie.Domain != "" || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("unsafe session: %v", cookie)
	}
	// Old parent-domain credentials, even valid signed ones, are no longer read.
	r := httptest.NewRequest("GET", "https://tunn.test/account", nil)
	r.AddCookie(&http.Cookie{Name: "tunn_auth", Value: cookie.Value})
	if _, ok := f.p.getAuthFromCookie(r); ok {
		t.Fatal("accepted legacy tossed cookie")
	}
	token, _, _ := new(jwt.Parser).ParseUnverified(cookie.Value, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)
	claims["aud"] = "attacker.tunn.test"
	raw, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(f.p.getJWTSigningKey())
	if _, err := accountIdentityEmail(claims); err == nil {
		t.Fatal("tunnel cookie became bearer account authority")
	}
	for _, host := range []string{"tunn.test", "tools.tunn.test"} {
		r := httptest.NewRequest("GET", "https://"+host+"/", nil)
		r.AddCookie(&http.Cookie{Name: authCookieName, Value: raw})
		if _, ok := f.p.getAuthFromCookie(r); ok {
			t.Fatal("tunnel credential crossed audience", host)
		}
		if _, ok := f.p.accountSession(r); ok {
			t.Fatal("tunnel credential became platform session", host)
		}
	}
}

func TestCrossTenantBrowser(t *testing.T) {
	python := os.Getenv("TUNN_CROSS_TENANT_PYTHON")
	if python == "" {
		t.Skip("use make test-cross-tenant for the required browser suite")
	}
	for _, negative := range []bool{false, true} {
		name := "protected"
		if negative {
			name = "negative"
		}
		t.Run(name, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			p := f.p
			prepareMCPAuthorityFixture(t, f)
			client := discoverMCPClient(t, f)
			if _, err := p.storage.FindOrCreateByEmails(t.Context(), []string{"attacker@example.com"}, "magic_link"); err != nil {
				t.Fatal(err)
			}
			attacker := emailSession(t, p, "attacker@example.com")
			owner := emailSession(t, p, "owner@example.com")
			for _, id := range []string{"attacker", "private"} {
				tunnel, _ := securityEndpoint(p, id, "owner@example.com", f.tunnel.AccountID, nil, false)
				if id == "private" {
					out, err := p.sharingBackend().Sharing(t.Context(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: id, Mode: "private"})
					if err != nil {
						t.Fatal(err)
					}
					tunnel.ResourceID = out.Resources[0].Id
					tunnel.AllowedEmails = []string{"owner@example.com"}
					continue
				}
				tunnel.CreatorEmail = "attacker@example.com"
				a, err := p.storage.GetAccountByEmail(t.Context(), tunnel.CreatorEmail)
				if err != nil || a == nil {
					t.Fatal(a, err)
				}
				tunnel.AccountID = a.ID
				tunnel.Stream = &securityStream{onSend: func(m *pb.TunnelMessage) error {
					req := m.GetHttpRequest()
					if req == nil {
						return nil
					}
					headers := map[string]string{"Content-Type": "text/html", "Cache-Control": "no-store"}
					body := fmt.Sprintf(`<html><body>Attacker tenant<script>
function plantCookies() {
 const token=%q;
 for (const name of ['tunn_auth','__Host-tunn_auth'])
  for (const path of ['/','/account'])
   document.cookie = name+'='+token+'; Domain=tunn.test; Path='+path+'; Secure; SameSite=Lax';
}
function postToAccount(url, values) {
 const f=document.createElement('form'); f.method='POST'; f.action=url;
 const frame=document.createElement('iframe'); frame.name='post-target'; document.body.append(frame); f.target=frame.name;
 for(const [name,value] of Object.entries(values)) {const i=document.createElement('input');i.name=name;i.value=value;f.append(i);}
 document.body.append(f); f.submit();
}
function frameConsent(url) {const f=document.createElement('iframe');f.src=url;document.body.append(f);}
function readCookies() {return document.cookie;}
</script></body></html>`, attacker.Value)
					switch strings.Split(req.Path, "?")[0] {
					case "/headers":
						// Publisher attempts both the legacy name and the new protected name.
						headers["Set-Cookie"] = "tunn_auth=" + attacker.Value + "; Domain=tunn.test; Path=/; Secure; HttpOnly, tunn_auth=" + attacker.Value + "; Domain=tunn.test; Path=/account; Secure; HttpOnly, __Host-tunn_auth=" + attacker.Value + "; Domain=tunn.test; Path=/; Secure"
					case "/read":
						payload, _ := json.Marshal(req.Headers)
						body = string(payload)
						headers["Content-Type"] = "application/json"
					}
					tunnel.pendingMu.RLock()
					ch := tunnel.pendingRequests[req.ConnectionId]
					tunnel.pendingMu.RUnlock()
					ch <- &pb.HttpResponse{ConnectionId: req.ConnectionId, StatusCode: 200, Headers: headers, Body: []byte(body)}
					return nil
				}}
			}
			handler := p.createHandler()
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Fixture-Fetch-Site", r.Header.Get("Sec-Fetch-Site"))
				// Test-build-only negative control: restore the vulnerable parent-domain
				// cookie transport. Production code has no switch to disable isolation.
				if negative {
					if c, err := r.Cookie("tunn_auth"); err == nil {
						r.AddCookie(&http.Cookie{Name: authCookieName, Value: c.Value})
					}
				}
				if p.isPlatformHost(r.Host) && r.URL.Path == "/fixture/login" {
					c := *owner
					if r.URL.Query().Get("person") == "attacker" {
						c = *attacker
					}
					if negative {
						c.Name = "tunn_auth"
						c.Domain = "tunn.test"
					}
					http.SetCookie(w, &c)
					fmt.Fprint(w, "fixture provider session")
					return
				}
				handler.ServeHTTP(w, r)
			}))
			_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			p.config.PublicAddr = "tunn.test:" + port
			client.query.Set("resource", "https://tools.tunn.test:"+port+"/mcp")
			server.StartTLS()
			defer server.Close()
			dir := os.Getenv("TUNN_CROSS_TENANT_EVIDENCE")
			if dir == "" {
				dir = t.TempDir()
			}
			dir = filepath.Join(dir, name)
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			spki := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
			input, _ := json.Marshal(map[string]string{"spki": base64.StdEncoding.EncodeToString(spki[:]), "port": port, "attacker_cookie": attacker.Value, "consent": "/oauth/authorize?" + client.query.Encode(), "negative": fmt.Sprint(negative)})
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, python, "../../scripts/integration-tests/cross-tenant-attacks.py", dir)
			cmd.Stdin = strings.NewReader(string(input))
			cmd.Env = append(os.Environ(), "NO_PROXY=*")
			output, err := cmd.CombinedOutput()
			t.Log(string(output))
			if negative {
				if err == nil || !strings.Contains(string(output), "EXPLOITED: login-fixation") {
					t.Fatalf("negative control failed to detect exploit: %v", err)
				}
			} else if err != nil {
				t.Fatalf("browser attacks: %v", err)
			}
		})
	}
}

func TestCrossTenantHandoffNonce(t *testing.T) {
	f := newMCPOAuthFixture(t)
	p := f.p
	r := httptest.NewRequest("GET", "https://private.tunn.test/secret", nil)
	w := httptest.NewRecorder()
	p.startDomainSSO(w, r)
	nonce := w.Result().Cookies()[0]
	location, _ := url.Parse(w.Header().Get("Location"))
	r = httptest.NewRequest("GET", location.String(), nil)
	r.AddCookie(emailSession(t, p, "owner@example.com"))
	w = httptest.NewRecorder()
	p.handleDomainLogin(w, r)
	if w.Code != 302 {
		t.Fatal(w.Code, w.Body)
	}
	callback := w.Header().Get("Location")
	// Wrong browser and wrong destination cannot redeem a handoff.
	for _, target := range []string{callback, strings.Replace(callback, "private.", "attacker.", 1)} {
		r = httptest.NewRequest("GET", target, nil)
		if target != callback {
			r.AddCookie(nonce)
		}
		w = httptest.NewRecorder()
		p.handleTunnelCallback(w, r)
		if w.Code != 400 {
			t.Fatal("unbound handoff", w.Code)
		}
	}
	r = httptest.NewRequest("GET", callback, nil)
	r.AddCookie(nonce)
	w = httptest.NewRecorder()
	p.handleTunnelCallback(w, r)
	if w.Code != 302 {
		t.Fatal(w.Code, w.Body)
	}
	session := w.Result().Cookies()[0]
	r = httptest.NewRequest("GET", "https://private.tunn.test/secret", nil)
	r.AddCookie(session)
	if email, ok := p.getAuthFromCookie(r); !ok || email != "owner@example.com" {
		t.Fatal("handoff failed", email)
	}
	r = httptest.NewRequest("GET", callback, nil)
	r.AddCookie(nonce)
	w = httptest.NewRecorder()
	p.handleTunnelCallback(w, r)
	if w.Code != 400 {
		t.Fatal("handoff replay", w.Code)
	}
	account, _ := p.storage.GetAccountByEmail(t.Context(), "owner@example.com")
	if err := p.storage.(storage.BrowserSessionStorage).RevokeBrowserSessions(t.Context(), account.ID, ""); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("GET", "https://private.tunn.test/secret", nil)
	r.AddCookie(session)
	if _, ok := p.getAuthFromCookie(r); ok {
		t.Fatal("scoped cookie survived account logout")
	}
}
