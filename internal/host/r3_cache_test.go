package host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestR3BrowserCacheCannotBypassRevocation(t *testing.T) {
	python := os.Getenv("TUNN_SHARE_BROWSER_PYTHON")
	if python == "" {
		t.Skip("set TUNN_SHARE_BROWSER_PYTHON to Python with Playwright for the browser cache gate")
	}
	p, tunnel, ledger, stream := webSharingFixture(t)
	ctx := context.Background()
	if _, err := ledger.Sharing(ctx, &mp.SharingRequest{Operation: "share", Owner: tunnel.AccountID, Endpoint: "api", Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	stream.hook = func(msg *pb.TunnelMessage) error {
		if req := msg.GetHttpRequest(); req != nil {
			if strings.Contains(req.Headers["Cookie"], "tunn_auth") {
				t.Error("platform cookie reached upstream")
			}
			body := "PRIVATE-ASSET-REVIEW"
			headers := map[string]string{"Content-Type": "text/plain", "Cache-Control": "public, max-age=3600"}
			if req.Path == "/" {
				body = "<html><body>app page</body></html>"
				headers = map[string]string{"Content-Type": "text/html", "Cache-Control": "no-store"}
			}
			tunnel.pendingMu.RLock()
			ch := tunnel.pendingRequests[req.ConnectionId]
			tunnel.pendingMu.RUnlock()
			ch <- &pb.HttpResponse{ConnectionId: req.ConnectionId, StatusCode: 200, Headers: headers, Body: []byte(body)}
		}
		return nil
	}
	handler := p.createHandler()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/review/login":
			_ = p.setAuthCookie(w, r.URL.Query().Get("email"))
			fmt.Fprint(w, "session fixture")
		case "/review/revoke":
			_, err := ledger.Sharing(r.Context(), &mp.SharingRequest{Operation: "unshare", Owner: tunnel.AccountID, Endpoint: "api", Email: "alice@example.com"})
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			fmt.Fprint(w, "revoked")
		case "/review/redirect":
			http.Redirect(w, r, p.sanitizeReturnTo(r.URL.Query().Get("return_to")), 302)
		default:
			handler.ServeHTTP(w, r)
		}
	}))
	u, _ := url.Parse("https://" + server.Listener.Addr().String())
	p.config.PublicAddr = "tunn.test:" + u.Port()
	server.StartTLS()
	defer server.Close()
	script, err := filepath.Abs("../../scripts/integration-tests/r3-cache-browser.py")
	if err != nil {
		t.Fatal(err)
	}
	runctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	spki := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	cmd := exec.CommandContext(runctx, python, script, u.Port(), base64.StdEncoding.EncodeToString(spki[:]))
	cmd.Env = append(os.Environ(), "NO_PROXY=*")
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if result["cached_after_revocation"] != false || result["network_after_revocation"] != float64(403) {
		t.Fatal(result)
	}
}

func assertR3PrivateCachePolicy(t *testing.T, h http.Header) {
	t.Helper()
	if h.Get("Cache-Control") != "no-store" {
		t.Fatal("protected response retained upstream caching", h)
	}
	for _, name := range []string{"Expires", "Surrogate-Control", "CDN-Cache-Control", "Cloudflare-CDN-Cache-Control"} {
		if h.Get(name) != "" {
			t.Fatal("conflicting cache policy", name, h)
		}
	}
	vary := strings.ToLower(strings.Join(h.Values("Vary"), ","))
	for _, name := range []string{"cookie", "authorization", "tunn-authorization"} {
		if !strings.Contains(vary, name) {
			t.Fatal("missing identity variation", name, h)
		}
	}
}

func TestR3PrivateBufferedAndStreamingCachePolicyAllStatuses(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, status := range []int{200, 302, 304, 404, 500} {
			for _, method := range []string{"GET", "HEAD"} {
				t.Run(fmt.Sprintf("stream=%v/status=%d/method=%s", streaming, status, method), func(t *testing.T) {
					p, tunnel, _, stream := webSharingFixture(t)
					headers := map[string]string{"Cache-Control": "public, max-age=3600, s-maxage=3600", "Vary": "Accept-Encoding", "Expires": "Thu, 01 Jan 2099 00:00:00 GMT", "Surrogate-Control": "max-age=3600", "CDN-Cache-Control": "public", "Cloudflare-CDN-Cache-Control": "public"}
					if streaming {
						tunnel.Capabilities = map[string]bool{common.CapabilityConnectionStreamV1: true, common.CapabilityHTTPStreamV1: true}
						tunnel.pendingStreams = make(map[string]*pendingConnection)
					}
					stream.hook = func(msg *pb.TunnelMessage) error {
						if req := msg.GetHttpRequest(); req != nil {
							tunnel.pendingMu.RLock()
							ch := tunnel.pendingRequests[req.ConnectionId]
							tunnel.pendingMu.RUnlock()
							ch <- &pb.HttpResponse{ConnectionId: req.ConnectionId, StatusCode: int32(status), Headers: headers}
						}
						if half := msg.GetConnectionHalfClose(); half != nil {
							tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: half.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: int32(status), Headers: headers}}}})
							tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: half.ConnectionId}}})
						}
						return nil
					}
					req := httptest.NewRequest(method, "https://api.tunn.test/cache", nil)
					req.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, p, "owner@example.com")})
					w := httptest.NewRecorder()
					p.createHandler().ServeHTTP(w, req)
					if w.Code != status {
						t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
					}
					assertR3PrivateCachePolicy(t, w.Result().Header)
					if !strings.Contains(w.Result().Header.Get("Vary"), "Accept-Encoding") {
						t.Fatal("lost application variation")
					}
				})
			}
		}
	}
}

func TestR3PrivateCachePolicyOnAdmissionErrorsAndPlatformRedirects(t *testing.T) {
	p, _, _, _ := webSharingFixture(t)
	for _, tc := range []struct {
		url, email string
		status     int
	}{
		{"https://api.tunn.test/", "", 302},
		{"https://api.tunn.test/", "stranger@example.com", 403},
		{"https://offline.tunn.test/", "", 503},
		{"https://tunn.test/account/sharing", "", 302},
		{"https://tunn.test/api/sharing/api", "", 401},
		{"https://tunn.test/auth/google/callback", "", 503},
	} {
		t.Run(tc.url+tc.email, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.url, nil)
			if tc.email != "" {
				req.AddCookie(&http.Cookie{Name: authCookieName, Value: relayJWT(t, p, tc.email)})
			}
			w := httptest.NewRecorder()
			p.createHandler().ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status=%d %s", w.Code, w.Body.String())
			}
			assertR3PrivateCachePolicy(t, w.Result().Header)
		})
	}
}

func TestR3PrivateWebSocketUpgradeCachePolicy(t *testing.T) {
	stack := startWebSocketStack(t, func(p *client.ServeClient) { p.AllowedEmails = []string{"alice@example.com"} })
	conn, _, response, err := stack.dial("/echo", http.Header{"Cookie": {stack.cookie(t, "alice@example.com")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatal("upgrade status", response.StatusCode)
	}
	assertR3PrivateCachePolicy(t, response.Header)
}
