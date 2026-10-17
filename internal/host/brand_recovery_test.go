package host

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/metering"
	"golang.org/x/net/html"
)

func recoveryLinks(t *testing.T, body string, rel string) []string {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var links []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "link" || rel == "" && n.Data == "a") {
			var href, relation string
			for _, a := range n.Attr {
				switch a.Key {
				case "href":
					href = a.Val
				case "rel":
					relation = a.Val
				}
			}
			if href != "" && (rel == "" && n.Data == "a" || rel != "" && relation == rel) {
				links = append(links, href)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links
}

func TestIPDeniedIconsUseReachablePlatformOrigin(t *testing.T) {
	for _, customer := range []bool{false, true} {
		name := "publisher"
		if customer {
			name = "customer"
		}
		t.Run(name, func(t *testing.T) {
			var p *ProxyServer
			var endpoint, host string
			if customer {
				proxy, tunnel, _, db := appProxyFixtureDB(t)
				ledger, err := metering.New(db)
				if err != nil {
					t.Fatal(err)
				}
				p, endpoint, host = proxy, tunnel.TunnelID, appHost
				p.meter = ledger
			} else {
				proxy, _, _, _ := webSharingFixture(t)
				p, endpoint, host = proxy, "api", "api.tunn.test"
			}
			p.config.PublicAddr = "tunn.test:443"
			setHostPolicy(t, p, endpoint, []string{"192.0.2.0/24"}, nil)
			handler := p.createHandler()
			request := func(target string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", target, nil)
				r.RemoteAddr = "198.51.100.9:1234"
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			pageURL := "https://" + host + "/report"
			page := request(pageURL)
			if page.Code != 403 || page.Header().Get("Tunn-Limit-Reason") != "ip_policy_denied" {
				t.Fatal("expected IP denial", page.Code, page.Body)
			}
			var links []string
			for _, rel := range []string{"icon", "apple-touch-icon", "manifest"} {
				links = append(links, recoveryLinks(t, page.Body.String(), rel)...)
			}
			if len(links) != 4 {
				t.Fatalf("got %d icon links", len(links))
			}
			for _, target := range links {
				u, err := url.Parse(target)
				if err != nil || u.Scheme != "https" || u.Host != p.loginAuthority() {
					t.Fatalf("icon uses an untrusted origin: %s", target)
				}
				asset := request(target)
				if asset.Code != 200 || asset.Body.Len() == 0 || strings.Contains(asset.Header().Get("Content-Type"), "text/html") {
					t.Fatalf("icon %s: %d %s", target, asset.Code, asset.Header().Get("Content-Type"))
				}
				if u.Path == "/assets/site.webmanifest" {
					if asset.Header().Get("Access-Control-Allow-Origin") != "*" {
						t.Fatal("cross-origin manifest blocked by CORS")
					}
					var manifest struct{ Icons []struct{ Src string } }
					if err := json.Unmarshal(asset.Body.Bytes(), &manifest); err != nil || len(manifest.Icons) != 2 {
						t.Fatal("invalid manifest", err)
					}
					for _, icon := range manifest.Icons {
						ref, err := url.Parse(icon.Src)
						if err != nil {
							t.Fatal(err)
						}
						if image := request(u.ResolveReference(ref).String()); image.Code != 200 || image.Header().Get("Content-Type") != "image/png" {
							t.Fatal("manifest image unavailable", image.Code)
						}
					}
				}
			}
			if page := request(pageURL); page.Code != 403 {
				t.Fatal("asset delivery bypassed IP admission")
			}
		})
	}
}

func TestAccessDeniedIconsUseReachablePlatformOriginWithoutExtraAccessRows(t *testing.T) {
	p, _, ledger, _ := webSharingFixture(t)
	p.config.PublicAddr = "tunn.test:8443"
	handler := p.createHandler()
	cookie := &http.Cookie{Name: authCookieName, Value: relayJWT(t, p, "stranger@example.com")}
	request := func(target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", target, nil)
		r.Header.Set("Accept", "text/html")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	pageURL, err := url.Parse("https://api.tunn.test/")
	if err != nil {
		t.Fatal(err)
	}
	page := request(pageURL.String())
	if page.Code != http.StatusForbidden || !strings.Contains(page.Body.String(), "Access denied") {
		t.Fatalf("expected access denial: %d %s", page.Code, page.Body.String())
	}
	assertSingleDenial := func() {
		t.Helper()
		events := relayExport(t, ledger).Events
		if len(events) != 1 || events[0].Allowed || events[0].Caller != "email:stranger@example.com" || events[0].Reason != "allowlist_denied" {
			t.Fatalf("expected only the stranger's original denial: %v", events)
		}
	}
	assertSingleDenial()
	var links []string
	for _, rel := range []string{"icon", "apple-touch-icon", "manifest"} {
		links = append(links, recoveryLinks(t, page.Body.String(), rel)...)
	}
	if len(links) != 4 {
		t.Fatalf("got %d icon links", len(links))
	}
	for _, target := range links {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		if u.Scheme != "https" || u.Host != p.loginAuthority() {
			t.Errorf("icon uses an untrusted origin: %s", target)
		}
		asset := request(pageURL.ResolveReference(u).String())
		if asset.Code != http.StatusOK || asset.Body.Len() == 0 || strings.Contains(asset.Header().Get("Content-Type"), "text/html") {
			t.Errorf("icon %s: %d %s", target, asset.Code, asset.Header().Get("Content-Type"))
		}
	}
	assertSingleDenial()
}

func TestDeniedAppRecoveryReplacesGuestSessionAfterOwnerEmailLogin(t *testing.T) {
	p, _, _ := appProxyFixture(t)
	handler := p.createHandler()
	jar, _ := cookiejar.New(nil)
	appURL := "https://" + appHost + "/report?q=1"
	u, _ := url.Parse(appURL)
	guest := appSessionCookie(t, p, "guest@example.com", "magic_link", true, appHost)
	jar.SetCookies(u, []*http.Cookie{guest})
	request := func(method, target, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Accept", "text/html")
		if method == "POST" {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "https://tunn.test")
		}
		for _, cookie := range jar.Cookies(r.URL) {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		jar.SetCookies(r.URL, w.Result().Cookies())
		return w
	}
	machineRequest := httptest.NewRequest("GET", appURL, nil)
	machineRequest.Header.Set("Accept", "application/json")
	machineRequest.AddCookie(guest)
	machine := httptest.NewRecorder()
	handler.ServeHTTP(machine, machineRequest)
	if machine.Code != 403 || machine.Body.String() != "Forbidden\n" || len(machine.Result().Cookies()) != 0 {
		t.Fatal("machine denial changed its session or response", machine.Code)
	}
	denied := request("GET", appURL, "")
	if denied.Code != 403 {
		t.Fatal("guest reached app", denied.Code)
	}
	for _, cookie := range jar.Cookies(u) {
		if cookie.Name == appCookie {
			t.Fatal("denied app session still pins the browser to the guest")
		}
	}
	var recovery string
	for _, link := range recoveryLinks(t, denied.Body.String(), "") {
		if strings.HasSuffix(link, "/auth/login") {
			recovery = link
		}
	}
	if recovery != "https://tunn.test/auth/login" {
		t.Fatal("missing platform recovery", recovery)
	}
	if login := request("GET", recovery, ""); login.Code != 200 {
		t.Fatal("recovery login unavailable", login.Code)
	}
	if sent := request("POST", "https://tunn.test/auth/magic", `{"email":"owner@example.com"}`); sent.Code != 200 {
		t.Fatal("owner email request failed", sent.Code, sent.Body)
	}
	mail := p.emailSender.(*accountsMailCapture)
	if verified := request("GET", mail.link, ""); verified.Code != 302 {
		t.Fatal("owner email login failed", verified.Code, verified.Body)
	}
	// Retry the original app after signing in; follow the real SSO exchange.
	for _, step := range []string{"start SSO", "platform handoff", "app callback"} {
		response := request("GET", appURL, "")
		if response.Code != 302 || response.Header().Get("Location") == "" {
			t.Fatal(step, response.Code, response.Body)
		}
		appURL = response.Header().Get("Location")
		if strings.HasPrefix(appURL, "/") {
			appURL = "https://" + appHost + appURL
		}
	}
	if appURL != u.String() {
		t.Fatalf("lost app path: %s", appURL)
	}
	if allowed := request("GET", appURL, ""); allowed.Code != 200 {
		t.Fatal("owner could not recover app access", allowed.Code, allowed.Body)
	}
}
