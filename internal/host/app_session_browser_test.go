package host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

// The browser uses real TLS, cookies, redirects, and the relay handlers. The
// identity email delivery, app upstream, and clock are disposable fixtures.
func TestAppSessionRenewalBrowserJourney(t *testing.T) {
	python := os.Getenv("TUNN_SHARE_BROWSER_PYTHON")
	if python == "" {
		t.Skip("set TUNN_SHARE_BROWSER_PYTHON to run the browser journey")
	}
	p, tunnel, _ := appProxyFixture(t)
	start := time.Now().Truncate(time.Second)
	var offset atomic.Int64
	var callbackPending atomic.Bool
	releaseCallback := make(chan struct{}, 1)
	p.now = func() time.Time { return start.Add(time.Duration(offset.Load()) * time.Second) }
	stream := tunnel.Stream.(*meteringFixtureStream)
	stream.hook = func(msg *pb.TunnelMessage) error {
		if req := msg.GetHttpRequest(); req != nil {
			status, body, contentType := 200, "ok", "text/plain"
			if req.Path == "/" {
				contentType = "text/html"
				body = `<html><body>Fixture app<script>
async function poll(path='/poll') {let r=await fetch(path,{redirect:'manual',cache:'no-store'}); return {status:r.status,auth:r.headers.get('Tunn-Auth'),location:r.headers.get('Location')};}
async function recover(path='/poll') {let r=await fetch(path,{cache:'no-store'}); if(r.status===401 && r.headers.get('Tunn-Auth')==='login') window.location.reload(); return r.status;}
</script></body></html>`
			} else if req.Path == "/ordinary-401" {
				status, body = 401, "upstream unauthorized"
			}
			tunnel.pendingMu.RLock()
			ch := tunnel.pendingRequests[req.ConnectionId]
			tunnel.pendingMu.RUnlock()
			ch <- &pb.HttpResponse{ConnectionId: req.ConnectionId, StatusCode: int32(status), Headers: map[string]string{"Content-Type": contentType, "Cache-Control": "no-store"}, Body: []byte(body)}
		}
		return nil
	}
	handler := p.createHandler()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fixture/clock":
			value, err := strconv.ParseInt(r.URL.Query().Get("seconds"), 10, 64)
			if err != nil {
				http.Error(w, "clock", 400)
				return
			}
			offset.Store(value)
			fmt.Fprint(w, "clock updated")
		case "/fixture/pending":
			fmt.Fprint(w, callbackPending.Load())
		case "/fixture/release":
			releaseCallback <- struct{}{}
			fmt.Fprint(w, "released")
		case appCallback:
			if offset.Load() >= int64(authCookieLifetime/time.Second) {
				callbackPending.Store(true)
				select {
				case <-releaseCallback:
				case <-r.Context().Done():
					return
				}
				callbackPending.Store(false)
			}
			handler.ServeHTTP(w, r)
		case "/auth/login":
			// Emulate delivery of a fresh provider magic link. Verification and session
			// issuance are the real provider handlers; return_to remains server-checked.
			token, err := p.generateMagicLinkTokenForReturnTo(appOwnerEmail, p.sanitizeReturnTo(r.URL.Query().Get("return_to")))
			if err != nil {
				http.Error(w, "fixture provider", 500)
				return
			}
			http.Redirect(w, r, "/auth/verify?token="+url.QueryEscape(token), 302)
		default:
			handler.ServeHTTP(w, r)
		}
	}))
	server.StartTLS()
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	script, err := filepath.Abs("../../scripts/integration-tests/app-session-browser.py")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, script, port, base64.StdEncoding.EncodeToString(spki[:]))
	cmd.Env = append(os.Environ(), "NO_PROXY=*")
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(fmt.Errorf("browser journey: %w", err))
	}
}
