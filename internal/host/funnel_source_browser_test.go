package host

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Exercise HTTPS navigation and host-only cookie selection with a browser jar.
// Every connection is pinned to this fixture, never a provider or public host.
func funnelBrowser(t *testing.T, p *ProxyServer) *http.Client {
	t.Helper()
	server := httptest.NewTLSServer(p.createHandler())
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	// httptest's trusted fixture certificate names example.com. The dialer
	// below pins every logical browser origin to that one TLS server.
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || (host != "tunn.test" && host != "login.test" && host != "untrusted.invalid") {
			t.Errorf("unexpected browser destination %q", addr)
			return nil, net.InvalidAddrError(addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: transport, Jar: jar}
}

func funnelVisit(t *testing.T, client *http.Client, target string) *http.Response {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("visit %s: %d", target, response.StatusCode)
	}
	return response
}

func funnelSignup(t *testing.T, client *http.Client, p *ProxyServer, host string) {
	t.Helper()
	request, err := http.NewRequest("POST", "https://"+host+"/auth/magic?src=thread", strings.NewReader(`{"email":"browser@example.invalid"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "https://"+host)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("signup: %d %s", response.StatusCode, body)
	}
	// Verify the signed link on the configured public host, with that host's jar.
	link := p.emailSender.(*accountsMailCapture).link
	target, _ := url.Parse(link)
	if target.Host != p.config.PublicAddr {
		t.Fatal(target)
	}
	verifier := *client
	verifier.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err = verifier.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("verify: %d", response.StatusCode)
	}
}

func TestFunnelSourceCrossHostInitiation(t *testing.T) {
	f := newMCPOAuthFixture(t)
	f.p.config.PublicAddr = "login.test"
	f.p.emailSender = new(accountsMailCapture)
	browser := funnelBrowser(t, f.p)
	landing := funnelVisit(t, browser, "https://tunn.test/docs?src=alt")
	t.Logf("landing completed at %s", landing.Request.URL)
	funnelVisit(t, browser, "https://login.test/auth/login")
	funnelSignup(t, browser, f.p, "login.test")
	var source string
	if err := f.p.mcpOAuth.db.QueryRow(`SELECT source FROM funnel_events WHERE stage='signup' AND source='alt'`).Scan(&source); err != nil {
		t.Fatalf("first-touch alt missing: %v", err)
	}
}

func TestFunnelSourceBrowserFirstTouch(t *testing.T) {
	for _, public := range []string{"tunn.test", "login.test"} {
		t.Run(public, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			f.p.config.PublicAddr = public
			f.p.emailSender = new(accountsMailCapture)
			browser := funnelBrowser(t, f.p)
			funnelVisit(t, browser, "https://tunn.test/docs?src=alt")
			// Later touches on either platform entry must retain the first source.
			funnelVisit(t, browser, "https://tunn.test/docs?src=thread")
			funnelVisit(t, browser, "https://"+public+"/auth/login?src=saashub")
			funnelSignup(t, browser, f.p, public)
			var count int
			if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='signup' AND source='alt'`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("first-touch signups=%d err=%v", count, err)
			}
		})
	}
}

func TestFunnelSourcePolicyFirstTouch(t *testing.T) {
	for _, path := range []string{"/privacy", "/terms"} {
		for _, public := range []string{"tunn.test", "login.test"} {
			t.Run(path+"/"+public, func(t *testing.T) {
				f := newMCPOAuthFixture(t)
				f.p.config.PublicAddr = public
				f.p.emailSender = new(accountsMailCapture)
				browser := funnelBrowser(t, f.p)
				funnelVisit(t, browser, "https://tunn.test"+path)
				funnelVisit(t, browser, "https://tunn.test/docs?src=alt")
				funnelVisit(t, browser, "https://"+public+"/auth/login?src=saashub")
				funnelSignup(t, browser, f.p, public)
				var count int
				if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='signup' AND source='direct'`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				// The fixture's owner and the new buyer must both be direct.
				if count != 2 {
					t.Fatalf("later source overwrote direct first visit: direct signups=%d want=2", count)
				}
			})
		}
	}
}

// Change a signed payload while retaining its signature, as an untrusted client
// could. The JWT parser is used only to locate the payload, not to validate it.
func tamperFunnelClaim(t *testing.T, raw, key string, value any) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("expected signed token")
	}
	payload, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.MapClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims[key] = value
	payload, err = json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = jwt.EncodeSegment(payload)
	return strings.Join(parts, ".")
}

func TestFunnelSourceBrowserCookieControls(t *testing.T) {
	for _, mode := range []string{"unsigned", "tampered", "expired", "wrong-audience", "wrong-purpose"} {
		t.Run(mode, func(t *testing.T) {
			f := newMCPOAuthFixture(t)
			f.p.config.PublicAddr = "login.test"
			f.p.emailSender = new(accountsMailCapture)
			browser := funnelBrowser(t, f.p)
			funnelVisit(t, browser, "https://tunn.test/docs?src=alt")
			origin, _ := url.Parse("https://login.test/")
			cookies := browser.Jar.Cookies(origin)
			if len(cookies) != 1 || cookies[0].Name != funnelSourceCookie {
				t.Fatal(cookies)
			}
			raw := cookies[0].Value
			switch mode {
			case "unsigned":
				raw = "saashub"
			case "tampered":
				raw = tamperFunnelClaim(t, raw, "source", "saashub")
			default:
				claims := jwt.MapClaims{"type": "funnel_source", "source": "saashub", "aud": "login.test:443", "exp": time.Now().Add(time.Hour).Unix()}
				if mode == "expired" {
					claims["exp"] = time.Now().Add(-time.Hour).Unix()
				}
				if mode == "wrong-audience" {
					claims["aud"] = "tunn.test:443"
				}
				if mode == "wrong-purpose" {
					claims["type"] = "session"
				}
				var err error
				raw, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(f.p.getJWTSigningKey())
				if err != nil {
					t.Fatal(err)
				}
			}
			browser.Jar.SetCookies(origin, []*http.Cookie{{Name: funnelSourceCookie, Value: raw, Path: "/", Secure: true, HttpOnly: true}})
			// No unsigned source on a POST may replace a missing/invalid cookie.
			funnelSignup(t, browser, f.p, "login.test")
			var count int
			if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='signup' AND source!='direct'`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("untrusted source accepted: count=%d err=%v", count, err)
			}
		})
	}
}

func TestFunnelSourceBrowserOriginAndMagicControls(t *testing.T) {
	f := newMCPOAuthFixture(t)
	f.p.config.PublicAddr = "login.test"
	f.p.emailSender = new(accountsMailCapture)
	browser := funnelBrowser(t, f.p)
	funnelVisit(t, browser, "https://tunn.test/docs?src=alt")
	for _, origin := range []string{"https://untrusted.invalid", "https://tools.tunn.test", "https://tunn.test", "null", ""} {
		request, _ := http.NewRequest("POST", "https://login.test/auth/magic?src=saashub", strings.NewReader(`{"email":"browser@example.invalid"}`))
		request.Header.Set("Origin", origin)
		response, err := browser.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q: %d", origin, response.StatusCode)
		}
		if f.p.emailSender.(*accountsMailCapture).link != "" {
			t.Fatal("untrusted origin requested email")
		}
	}
	// The unrelated host receives neither cookies nor a platform redirect.
	untrusted, _ := url.Parse("https://untrusted.invalid/docs?src=thread")
	if len(browser.Jar.Cookies(untrusted)) != 0 {
		t.Fatal("cookie leaked to unrelated host")
	}
	response, err := browser.Get(untrusted.String())
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.Header.Get("Location") != "" || len(response.Cookies()) != 0 {
		t.Fatal("platform state on unrelated origin")
	}
	// Obtain a real signed email link, but do not let the browser verify it yet.
	request, _ := http.NewRequest("POST", "https://login.test/auth/magic?src=saashub", strings.NewReader(`{"email":"browser@example.invalid"}`))
	request.Header.Set("Origin", "https://login.test")
	response, err = browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.StatusCode)
	}
	link, _ := url.Parse(f.p.emailSender.(*accountsMailCapture).link)
	query := link.Query()
	original := query.Get("token")
	query.Set("token", tamperFunnelClaim(t, original, "source", "saashub"))
	link.RawQuery = query.Encode()
	response, err = browser.Get(link.String())
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered link: %d", response.StatusCode)
	}
	var count int
	if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='signup'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("tampered link created account: %d %v", count, err)
	}
	// A valid link retains its signed first source even with no source cookie.
	public, _ := url.Parse("https://login.test/")
	browser.Jar.SetCookies(public, []*http.Cookie{{Name: funnelSourceCookie, Path: "/", MaxAge: -1}})
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Retain the older cross-host verification case too: signup started on
	// PublicAddr, but the signed email link opens on the other platform host.
	link, _ = url.Parse(f.p.emailSender.(*accountsMailCapture).link)
	link.Host = "tunn.test"
	for i, want := range []int{http.StatusFound, http.StatusBadRequest} {
		response, err = browser.Get(link.String())
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("verify attempt %d: %d want %d", i, response.StatusCode, want)
		}
	}
	if err := f.p.mcpOAuth.db.QueryRow(`SELECT count(*) FROM funnel_events WHERE stage='signup' AND source='alt'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("signed source lost: %d %v", count, err)
	}
}

func TestFunnelSourceUnsupportedPublicNamespace(t *testing.T) {
	p := newMCPOAuthFixture(t).p
	p.config.PublicAddr = "login.tunn.test"
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, httptest.NewRequest("GET", "https://tunn.test/docs?src=alt", nil))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Location") != "" || len(w.Result().Cookies()) != 0 {
		t.Fatalf("publisher namespace received attribution: %d %s", w.Code, w.Header())
	}
}
