package host

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/identity"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/storage"
	domainpb "github.com/ehrlich-b/tunn/pkg/proto/domainv1"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"github.com/golang-jwt/jwt/v4"
)

const appHost = "dashboard.apps.ehrlich.dev"

// Only the external provider/SMTP delivery is replaced. These tests acquire
// platform cookies through production callbacks, then follow the whole app SSO.
func TestDomainAccountCompleteProviderLogin(t *testing.T) {
	for _, provider := range []string{"github", "magic_link", "google"} {
		for _, email := range []string{bryanEmail, "stranger@gmail.com"} {
			t.Run(provider+"/"+email, func(t *testing.T) {
				p, tunnel, _ := appProxyFixture(t)
				handler := p.createHandler()
				initial := httptest.NewRecorder()
				handler.ServeHTTP(initial, httptest.NewRequest("GET", "https://"+appHost+"/report?q=1", nil))
				login, nonce := initial.Header().Get("Location"), initial.Result().Cookies()[0]
				var central *http.Cookie
				switch provider {
				case "github":
					installAccountsHTTPFake(t, func(r *http.Request) (*http.Response, error) {
						if r.URL.String() == githubTokenURL {
							return accountsProviderResponse(r, 200, `{"access_token":"fixture"}`), nil
						}
						if r.URL.String() == githubEmailsURL {
							return accountsProviderResponse(r, 200, fmt.Sprintf(`[{"email":%q,"primary":true,"verified":true}]`, email)), nil
						}
						return nil, fmt.Errorf("unexpected provider URL")
					})
					state, browser := accountsGitHubBrowserStart(t, p, url.Values{"return_to": {login}})
					callback := accountsGitHubCallback(p, state, "fixture", browser)
					if callback.Code != 302 || callback.Header().Get("Location") != login {
						t.Fatal("provider did not preserve app return")
					}
					central = assertAccountsSessionCookie(t, p, callback, email)
				case "magic_link":
					body, _ := json.Marshal(map[string]string{"email": email})
					if w := magicFixturePost(p, url.Values{"return_to": {login}}.Encode(), string(body)); w.Code != 200 {
						t.Fatal(w.Code, w.Body)
					}
					callback := httptest.NewRecorder()
					p.handleMagicLinkVerify(callback, httptest.NewRequest("GET", p.emailSender.(*accountsMailCapture).link, nil))
					if callback.Code != 302 || callback.Header().Get("Location") != login {
						t.Fatal("email did not preserve app return", callback.Code, callback.Body)
					}
					central = assertAccountsSessionCookie(t, p, callback, email)
				case "google":
					p.config.GoogleClientID, p.config.GoogleClientSecret = "fixture", "fixture"
					p.googleHTTPClient = googleFixtureTransport(t, p, true)
					start := httptest.NewRecorder()
					p.handleGoogleLogin(start, httptest.NewRequest("GET", "https://tunn.test/auth/google?return_to="+url.QueryEscape(login), nil))
					u, _ := url.Parse(start.Header().Get("Location"))
					req := httptest.NewRequest("GET", "https://tunn.test/auth/google/callback?code="+url.QueryEscape(email)+"&state="+url.QueryEscape(u.Query().Get("state")), nil)
					for _, c := range start.Result().Cookies() {
						req.AddCookie(c)
					}
					callback := httptest.NewRecorder()
					p.handleGoogleCallback(callback, req)
					central = assertAccountsSessionCookie(t, p, callback, email)
				}
				request := httptest.NewRequest("GET", login, nil)
				request.AddCookie(central)
				handoff := httptest.NewRecorder()
				handler.ServeHTTP(handoff, request)
				if handoff.Code != 302 {
					t.Fatal("handoff", handoff.Code, handoff.Body)
				}
				request = httptest.NewRequest("GET", handoff.Header().Get("Location"), nil)
				request.AddCookie(nonce)
				callback := httptest.NewRecorder()
				handler.ServeHTTP(callback, request)
				if callback.Code != 302 || callback.Header().Get("Location") != "/report?q=1" {
					t.Fatal("app callback", callback.Code, callback.Body)
				}
				request = httptest.NewRequest("GET", "https://"+appHost+"/report?q=1", nil)
				for _, c := range callback.Result().Cookies() {
					if c.Name == appCookie {
						request.AddCookie(c)
					}
				}
				result := httptest.NewRecorder()
				handler.ServeHTTP(result, request)
				want := 403
				if email == bryanEmail {
					want = 200
				}
				if result.Code != want {
					t.Fatalf("app=%d want=%d %s", result.Code, want, result.Body)
				}
				if want == 200 {
					claims, ok := p.accountSession(request)
					if !ok || claims["account_id"] != tunnel.AccountID || claims["provider"] != provider {
						t.Fatal("account binding missing")
					}
				}
			})
		}
	}
}

func appOpenWithCookie(p *ProxyServer, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://"+appHost+"/", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	return w
}
func appShare(t *testing.T, p *ProxyServer, tunnel *TunnelConnection, op, email string) {
	t.Helper()
	_, err := p.meter.(metering.SharingBackend).Sharing(context.Background(), &mp.SharingRequest{Operation: op, Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Email: email, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
}
func appResource(t *testing.T, p *ProxyServer, tunnel *TunnelConnection, mode string) {
	t.Helper()
	out, err := p.meter.(metering.SharingBackend).Sharing(context.Background(), &mp.SharingRequest{Operation: "register", Owner: tunnel.AccountID, Endpoint: tunnel.TunnelID, Mode: mode})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.ResourceID = out.Resources[0].Id
}
func TestDomainAccountSharingAndLegacyAllowList(t *testing.T) {
	for _, mode := range []string{"legacy", "private", "public"} {
		t.Run(mode, func(t *testing.T) {
			p, tunnel, _ := appProxyFixture(t)
			// An alias is allowed because it was verified into the same UUID, independent
			// of the account's primary email or the provider used for this login.
			account, err := p.storage.FindOrCreateByEmails(context.Background(), []string{bryanEmail, "owner-alias@example.com"}, "github")
			if err != nil || account.ID != tunnel.AccountID {
				t.Fatal(err)
			}
			owner := appSessionCookie(t, p, "owner-alias@example.com", "magic_link", true, appHost)
			guest := appSessionCookie(t, p, "guest@example.com", "github", true, appHost)
			if mode != "legacy" {
				appResource(t, p, tunnel, mode)
			}
			if appOpenWithCookie(p, owner).Code != 200 || appOpenWithCookie(p, guest).Code != 403 {
				t.Fatal("owner/private default")
			}
			if mode == "public" {
				return
			} // Existing sharing authority requires private mode to add people.
			if mode == "legacy" {
				tunnel.AllowedEmails = []string{"guest@example.com"}
			} else {
				appShare(t, p, tunnel, "share", "guest@example.com")
			}
			if w := appOpenWithCookie(p, guest); w.Code != 200 {
				t.Fatal("share denied", w.Code, w.Body)
			}
			if mode == "legacy" {
				tunnel.AllowedEmails = nil
			} else {
				appShare(t, p, tunnel, "unshare", "guest@example.com")
			}
			if appOpenWithCookie(p, guest).Code != 403 {
				t.Fatal("removed guest retained access")
			}
		})
	}
}
func TestDomainAccountSessionBindingAndRevocation(t *testing.T) {
	p, tunnel, _ := appProxyFixture(t)
	owner := appSessionCookie(t, p, bryanEmail, "github", true, appHost)
	guest := appSessionCookie(t, p, "guest@example.com", "magic_link", true, appHost)
	guestRequest := httptest.NewRequest("GET", "https://"+appHost+"/", nil)
	guestRequest.AddCookie(guest)
	claims, _ := p.accountSession(guestRequest)
	// A signed assertion for another UUID cannot gain ownership by naming the
	// owner's mailbox. Neither primary-email equality nor email lookup authorizes.
	claims["email"] = bryanEmail
	w := httptest.NewRecorder()
	if err := p.signedSession(w, claims, appCookie, "", time.Hour); err != nil {
		t.Fatal(err)
	}
	if appOpenWithCookie(p, w.Result().Cookies()[0]).Code != 403 {
		t.Fatal("cross-account email alias")
	}
	for _, kind := range []string{"legacy", "unknown-provider", "missing-expiry", "expired"} {
		r := httptest.NewRequest("GET", "https://"+appHost+"/", nil)
		r.AddCookie(owner)
		c, _ := p.accountSession(r)
		switch kind {
		case "legacy":
			delete(c, "account_id")
		case "unknown-provider":
			c["provider"] = "attacker"
		case "missing-expiry":
			delete(c, "exp")
		case "expired":
			c["exp"] = time.Now().Add(-time.Minute).Unix()
		}
		raw, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(p.getJWTSigningKey())
		if appOpenWithCookie(p, &http.Cookie{Name: appCookie, Value: raw}).Code != 302 {
			t.Fatal("invalid session", kind)
		}
	}
	local := p.storage.(*storage.LocalStorage)
	if _, err := local.OperationsStore().Transition(context.Background(), accountOperationsAdmin(t, tunnel.AccountID), tunnel.AccountID, "suspended", "test", 0); err != nil {
		t.Fatal(err)
	}
	if appOpenWithCookie(p, owner).Code != 403 {
		t.Fatal("suspended account")
	}
	p.storage = storage.NewProxyStorage()
	if w := appOpenWithCookie(p, owner); w.Code != 403 && w.Code != 503 {
		t.Fatal("authority outage", w.Code)
	}
}

// Exercise the actual wire transports, including signed headers and idle
// cancellation. Removing a guest permission must close SSE and WebSocket paths.
func TestDomainAccountStreamingAndWebSocketRevocation(t *testing.T) {
	for _, transport := range []string{"stream", "websocket"} {
		t.Run(transport, func(t *testing.T) {
			p, tunnel, pub := appProxyFixture(t)
			appResource(t, p, tunnel, "private")
			appShare(t, p, tunnel, "share", "guest@example.com")
			cookie := appSessionCookie(t, p, "guest@example.com", "magic_link", true, appHost)
			tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true, common.CapabilityWebSocketV1: true}
			tunnel.pendingStreams = make(map[string]*pendingConnection)
			headers := make(chan map[string]string, 1)
			stream := tunnel.Stream.(*meteringFixtureStream)
			stream.hook = func(msg *pb.TunnelMessage) error {
				if open := msg.GetConnectionOpen(); open != nil {
					headers <- open.HttpRequest.Headers
					if transport == "websocket" {
						tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 101, Headers: map[string]string{"Upgrade": "websocket", "Connection": "upgrade", "Sec-WebSocket-Accept": common.WebSocketAccept("dGhlIHNhbXBsZSBub25jZQ==")}}}}})
					}
				}
				if half := msg.GetConnectionHalfClose(); half != nil && transport == "stream" {
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: half.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/event-stream"}}}}})
					tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: half.ConnectionId, Data: []byte("data: ready\n\n")}}})
				}
				return nil
			}
			request := httptest.NewRequest("GET", "https://"+appHost+"/events", nil)
			request.AddCookie(cookie)
			request.Header.Set(identity.Header, "spoof")
			request.Header.Set(identity.EmailHeader, "spoof@example.com")
			var reader io.Reader
			var closeTransport func()
			if transport == "stream" {
				server := httptest.NewServer(p.createHandler())
				defer server.Close()
				req, _ := http.NewRequest("GET", server.URL+"/events", nil)
				req.Host = appHost
				req.Header = request.Header.Clone()
				server.Client().Timeout = 6 * time.Second
				response, err := server.Client().Do(req)
				if err != nil || response.StatusCode != 200 {
					t.Fatal("stream open", response, err)
				}
				reader = response.Body
				closeTransport = func() { response.Body.Close() }
				ready := make([]byte, len("data: ready\n\n"))
				if _, err := io.ReadFull(reader, ready); err != nil {
					t.Fatal(err)
				}
			} else {
				request.Header.Set("Upgrade", "websocket")
				request.Header.Set("Connection", "upgrade, X-Tunn-Identity, X-Tunn-User-Email")
				request.Header.Set("Sec-WebSocket-Version", "13")
				request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				serverConn, clientConn := net.Pipe()
				defer serverConn.Close()
				defer clientConn.Close()
				clientConn.SetDeadline(time.Now().Add(6 * time.Second))
				go p.createHandler().ServeHTTP(&pipeUpgradeWriter{httptest.NewRecorder(), serverConn}, request)
				buffered := bufio.NewReader(clientConn)
				response, err := http.ReadResponse(buffered, request)
				if err != nil || response.StatusCode != 101 {
					t.Fatal("websocket open", response, err)
				}
				reader = buffered
				closeTransport = func() { clientConn.Close() }
			}
			defer closeTransport()
			forwarded := <-headers
			token, err := jwt.Parse(forwarded[identity.Header], func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"EdDSA"}))
			if err != nil || !token.Valid {
				t.Fatal("transport identity", err)
			}
			claims := token.Claims.(jwt.MapClaims)
			if claims["provider"] != "magic_link" || claims["email"] != "guest@example.com" || !claims.VerifyAudience(appHost, true) || forwarded[identity.EmailHeader] != "guest@example.com" || strings.Contains(forwarded["Cookie"], appCookie) {
				t.Fatal("transport identity binding")
			}
			started := time.Now()
			appShare(t, p, tunnel, "unshare", "guest@example.com")
			if transport == "stream" {
				if _, err := io.ReadAll(reader); err == nil {
					t.Fatal("revoked SSE ended successfully")
				}
			} else {
				// The relay may send a WebSocket policy close before closing TCP.
				_, _ = io.ReadAll(reader)
			}
			if time.Since(started) >= 5*time.Second {
				t.Fatal("revocation exceeded five seconds")
			}
			if appOpenWithCookie(p, cookie).Code != 403 {
				t.Fatal("revoked new request admitted")
			}
		})
	}
}

func TestDomainAccountNamespaceRevocationClosesIdleRequest(t *testing.T) {
	p, tunnel, _ := appProxyFixture(t)
	r := httptest.NewRequest("GET", "https://"+appHost+"/events", nil)
	r.AddCookie(appSessionCookie(t, p, bryanEmail, "github", true, appHost))
	r = r.WithContext(context.WithValue(r.Context(), domainOwnerKey{}, tunnel.AccountID))
	watched, stop := p.watchAppPermission(r, tunnel)
	defer stop()
	if _, err := p.domains.Delete(context.Background(), &domainpb.Domain{Name: "*.apps.ehrlich.dev", Owner: tunnel.AccountID}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-watched.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("namespace removal retained idle connection")
	}
}
