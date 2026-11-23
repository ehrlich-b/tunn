package host

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// Every registered route has a deliberate classification. The AST inventory
// makes a newly registered route require an explicit browser-entry decision.
func TestFunnelSourceRouteInventory(t *testing.T) {
	classified := map[string]bool{}
	for _, path := range funnelBrowserEntries {
		classified[path] = true
	}
	for _, path := range []string{
		"/health", "/healthz", "/readyz", "/ops/reports", "/status.json", "/install.sh", "/dl/examples/mcp/echo.py", "/dl/",
		"/auth/domain", "/.well-known/tunn-jwks.json", "/auth/github", "/auth/google", "/auth/google/callback", "/auth/org/", "/auth/mock", "/auth/callback", "/auth/magic", "/auth/verify", "/auth/logout",
		"/account", "/account/names", "/api/account/tunnels", "/account/audit", "/account/audit.csv", "/account/audit.json", "/api/account/audit/", "/account/emails", "/account/tunnel-alerts", "/account/inspect", "/api/inspector/", "/api/billing/status",
		"/account/mcp", "/api/mcp/clients", "/.well-known/oauth-authorization-server", "/oauth/", "/api/hosts", "/api/ssh/keys", "/auth/ssh-key", "/api/device/code", "/api/device/token", "/api/device/refresh", "/account/devices", "/account/app-devices", "/pair/app-device", "/api/app-devices", "/api/app-devices/", "/api/endpoints/", "/api/ip-policy", "/api/ip-policy/", "/account/ip-policy", "/api/sharing", "/api/sharing/", "/account/sharing", "/api/usage", "/api/grants", "/api/domains/publisher", "/api/domains", "/api/domains/", "/api/reports", "/auth/device/authorize", "/webhooks/stripe",
		"/favicon.ico", "/robots.txt", "/sitemap.xml", "/llms.txt", "/guides.css", "/assets/",
	} {
		classified[path] = false
	}
	for _, page := range agentKitPages {
		classified[page.path] = true
	}
	inventory := map[string]bool{}
	literal := func(expr ast.Expr) string {
		if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			value, _ := strconv.Unquote(lit.Value)
			return value
		}
		return ""
	}
	for file, function := range map[string]string{"proxy.go": "createHandler", "webproxy.go": "handleApexDomain", "distribution.go": "serveDistributionPage"} {
		tree, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range tree.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != function {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if file == "proxy.go" {
					call, ok := node.(*ast.CallExpr)
					if !ok || len(call.Args) == 0 {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || (selector.Sel.Name != "Handle" && selector.Sel.Name != "HandleFunc") {
						return true
					}
					if path := literal(call.Args[0]); path != "" {
						inventory[path] = true
					}
				} else if clause, ok := node.(*ast.CaseClause); ok {
					for _, expr := range clause.List {
						if path := literal(expr); path != "" {
							inventory[path] = true
						}
					}
				}
				return true
			})
		}
	}
	for _, page := range agentKitPages {
		inventory[page.path] = true
	}
	for path := range inventory {
		if _, ok := classified[path]; !ok {
			t.Errorf("unclassified platform route %s", path)
		}
	}
	p := newMCPOAuthFixture(t).p
	p.config.GitHubClientID = ""
	for path, want := range classified {
		for _, suffix := range []string{"", "?src=alt", "?src=thread&org=disabled"} {
			for _, method := range []string{"GET", "HEAD", "POST"} {
				r := httptest.NewRequest(method, "https://tunn.test"+path+suffix, nil)
				if got := p.funnelSourceEntry(r); got != (want && method != "POST") {
					t.Errorf("entry %s %s%s=%t", method, path, suffix, got)
				}
			}
		}
	}
}

func TestFunnelSourceExcludedQueries(t *testing.T) {
	p := newMCPOAuthFixture(t).p
	p.config.GitHubClientID = ""
	p.config.PublicAddr = "login.test"
	for _, path := range []string{
		"/health", "/healthz", "/readyz", "/status.json", "/favicon.ico", "/assets/account.js", "/assets/site.webmanifest", "/guides.css", "/robots.txt", "/sitemap.xml", "/llms.txt",
		"/install.sh", "/dl/tunn", "/api/device/code", "/api/reports", "/webhooks/stripe", "/auth/verify", "/auth/google/callback", "/auth/callback", "/auth/org/disabled", "/auth/google?org=disabled", "/auth/github", "/auth/mock", "/unregistered",
	} {
		for _, query := range []string{"", "src=alt"} {
			target := "https://tunn.test" + path
			if query != "" {
				if path == "/auth/google?org=disabled" {
					target += "&" + query
				} else {
					target += "?" + query
				}
			}
			r := httptest.NewRequest("GET", target, nil)
			w := httptest.NewRecorder()
			if p.canonicalFunnelEntry(w, r) {
				t.Fatal("background route canonicalized", target)
			}
			p.captureFunnelSource(w, r)
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("background route claimed first touch", target)
			}
		}
	}
	// An enabled login start is justified even without a source query. A disabled
	// organization route must remain excluded when ordinary Google is enabled.
	p.config.GoogleClientID, p.config.GoogleClientSecret = "fixture", "fixture"
	p.config.GitHubClientID = "fixture"
	for _, path := range []string{"/auth/google", "/auth/github"} {
		for _, suffix := range []string{"", "?src=alt"} {
			if !p.funnelSourceEntry(httptest.NewRequest("GET", "https://login.test"+path+suffix, nil)) {
				t.Fatal("enabled login start excluded", path)
			}
		}
	}
	if p.funnelSourceEntry(httptest.NewRequest(http.MethodGet, "https://login.test/auth/google?org=disabled&src=alt", nil)) {
		t.Fatal("disabled organization start attributed")
	}
}

func TestFunnelSourcePublisherJarIsolation(t *testing.T) {
	p := newMCPOAuthFixture(t).p
	p.emailSender = new(accountsMailCapture)
	browser := funnelBrowser(t, p)
	funnelVisit(t, browser, "https://tunn.test/docs?src=alt")
	funnelSignup(t, browser, p, "tunn.test")
	reader := *browser
	reader.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, path := range []string{"/docs?src=thread", "/auth/login?src=alt", "/account", "/auth/verify?token=unsigned"} {
		response, err := reader.Get("https://tools.tunn.test" + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		for _, c := range response.Cookies() {
			if c.Name != appNonceCookie || c.Domain != "" || !c.Secure || !c.HttpOnly {
				t.Fatalf("publisher received platform state %s: %s", path, c.Name)
			}
		}
		if location := response.Header.Get("Location"); location != "" {
			u, err := url.Parse(location)
			if err != nil || u.Host != "tunn.test" || u.Path != "/auth/domain" {
				t.Fatalf("unexpected publisher redirect %s: %s", path, location)
			}
			claims, ok := p.parseDomainToken(u.Query().Get("request"), "domain_login_request")
			if !ok || claims["host"] != "tools.tunn.test" || claims["path"] != path {
				t.Fatalf("invalid publisher handoff %s", path)
			}
		}
	}
}
