package host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/mcpcheck"
)

// Chromium receives the actual headers, form and HTTP redirects. Only DNS,
// fixture certificate trust and email delivery are local substitutions.
func TestMCPOAuthBrowserConsent(t *testing.T) {
	if os.Getenv("TUNN_PLAYWRIGHT_MODULE") == "" {
		t.Skip("set TUNN_PLAYWRIGHT_MODULE for Chromium consent acceptance")
	}
	for _, port := range []string{"443", "18443"} {
		for _, scenario := range []string{"allow-desktop", "allow-phone", "deny", "cloud"} {
			t.Run(port+"/"+scenario, func(t *testing.T) {
				f := newMCPOAuthFixture(t)
				prepareMCPAuthorityFixture(t, f)
				attachConnectorEcho(t, f)
				f.p.config.PublicAddr = "tunn.test:" + port
				apex := "https://tunn.test"
				if port != "443" {
					apex += ":" + port
				}
				cloudCallbacks := make(chan string, 1)
				routes := f.p.createHandler()
				server := appDeviceTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Host == strings.TrimPrefix(strings.Replace(apex, "tunn.test", "client.tunn.test", 1), "https://") && r.URL.Path == "/callback" {
						cloudCallbacks <- "https://" + r.Host + r.URL.RequestURI()
						fmt.Fprintln(w, "Return to the connector.")
						return
					}
					routes.ServeHTTP(w, r)
				}))
				transport := server.Client().Transport.(*http.Transport).Clone()
				transport.TLSClientConfig = transport.TLSClientConfig.Clone()
				transport.TLSClientConfig.ServerName = "tunn.test"
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					u, _ := url.Parse(apex)
					if address != net.JoinHostPort(u.Hostname(), port) && address != net.JoinHostPort("tools.tunn.test", port) {
						return nil, fmt.Errorf("non-fixture destination refused")
					}
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				}
				defer transport.CloseIdleConnections()
				checker := mcpcheck.New(transport)
				ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
				defer cancel()
				d, err := checker.Discover(ctx, relayPublicURL(f.p.Domain, f.p.config.PublicAddr, "tools")+"/mcp")
				if err != nil {
					t.Fatal(err)
				}
				visit := func(link string) {
					u, _ := url.Parse(link)
					magic, err := f.p.generateMagicLinkTokenForReturnTo("owner@example.com", u.RequestURI())
					if err != nil {
						t.Fatal(err)
					}
					spki := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
					input, _ := json.Marshal(map[string]string{
						"apex": apex, "address": server.Listener.Addr().String(), "port": port,
						"spki": base64.StdEncoding.EncodeToString(spki[:]), "scenario": scenario,
						"login":    apex + "/auth/verify?" + url.Values{"token": {magic}}.Encode(),
						"callback": u.Query().Get("redirect_uri"),
					})
					cmd := exec.CommandContext(ctx, "node", "../../scripts/integration-tests/mcp-consent-browser.cjs")
					cmd.Stdin = strings.NewReader(string(input))
					out, err := cmd.CombinedOutput()
					t.Log(string(out))
					if err != nil {
						t.Fatalf("Chromium consent: %v", err)
					}
				}
				var token string
				if scenario == "cloud" {
					a, err := checker.BeginOAuth(ctx, d, "http://127.0.0.1:12345/callback")
					if err != nil {
						t.Fatal(err)
					}
					// A separate HTTPS client exercises the supported cloud callback.
					u, _ := url.Parse(a.URL)
					client, err := f.p.mcpOAuth.client(ctx, u.Query().Get("client_id"))
					if err != nil {
						t.Fatal(err)
					}
					client.ID += "_cloud"
					client.RedirectURIs = []string{strings.Replace(apex, "tunn.test", "client.tunn.test", 1) + "/callback"}
					if err := f.p.mcpOAuth.register(ctx, client); err != nil {
						t.Fatal(err)
					}
					q := u.Query()
					q.Set("redirect_uri", client.RedirectURIs[0])
					q.Set("client_id", client.ID)
					u.RawQuery = q.Encode()
					visit(u.String())
					select {
					case callback := <-cloudCallbacks:
						cb, _ := url.Parse(callback)
						if cb.Query().Get("state") != q.Get("state") || cb.Query().Get("iss") != apex || cb.Query().Get("code") == "" {
							t.Fatal("incorrect cloud callback")
						}
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				} else {
					token, err = checker.Authenticate(ctx, d, visit)
					if scenario == "deny" {
						if err == nil || !strings.Contains(err.Error(), "[denied]") {
							t.Fatalf("denial diagnostic: %v", err)
						}
						var grants int
						if err := f.p.mcpOAuth.db.QueryRow("SELECT (SELECT COUNT(*) FROM mcp_oauth_codes) + (SELECT COUNT(*) FROM mcp_oauth_authorizations WHERE approved=1)").Scan(&grants); err != nil || grants != 0 {
							t.Fatalf("denial created codes: %d %v", grants, err)
						}
					} else {
						if err != nil {
							t.Fatal(err)
						}
						if _, err := checker.CheckTools(ctx, d, token, mcpcheck.ToolOptions{Expected: []string{"echo"}, Call: "echo", Arguments: json.RawMessage(`{"text":"browser consent"}`)}); err != nil {
							t.Fatal(err)
						}
					}
				}
				t.Log("PASS untouched Chromium form, exact callback, origin/state/issuer and consent outcome")
			})
		}
	}
}
