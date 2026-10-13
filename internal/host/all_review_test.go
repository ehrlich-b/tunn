package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	mp "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestAllForwardedAppCredentialCannotFallBackToCookie(t *testing.T) {
	for _, ws := range []bool{false, true} {
		for _, carrier := range []string{"Tunn-Authorization", "Authorization"} {
			t.Run(carrier+map[bool]string{false: "/HTTP", true: "/WS"}[ws], func(t *testing.T) {
				f := newAppDeviceFixture(t)
				_, ownerToken := f.enroll(t, nil)
				guest := appDeviceShareGuest(t, f, "unshared@example.com")
				_, guestToken := f.enroll(t, guest)
				if _, err := f.ledger.Sharing(context.Background(), &mp.SharingRequest{Operation: "unshare", Owner: f.tunnel.AccountID, Endpoint: f.tunnel.TunnelID, ResourceId: f.tunnel.ResourceID, Email: "unshared@example.com"}); err != nil {
					t.Fatal(err)
				}
				ownerCookie := appSessionCookie(t, f.p, appDeviceTestEmail, "github", true, appDeviceTestHost)
				var dispatches atomic.Int64
				original := f.stream.hook
				if f.tunnel.Capabilities == nil {
					f.tunnel.Capabilities = make(map[string]bool)
				}
				f.tunnel.Capabilities[common.CapabilityWebSocketV1] = true
				f.stream.hook = func(m *pb.TunnelMessage) error {
					if m.GetHttpRequest() != nil {
						dispatches.Add(1)
					}
					if open := m.GetConnectionOpen(); open != nil && open.Protocol == "websocket" {
						dispatches.Add(1)
						f.tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: open.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 101, Headers: map[string]string{"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}}}}})
						return nil
					}
					return original(m)
				}
				front, _ := appDeviceForwardFixture(t, f)
				server := appDeviceTLSServer(t, front.createHandler())
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				for _, cookie := range []*http.Cookie{nil, ownerCookie} {
					for _, test := range []struct {
						name, token string
						want        int
					}{{"owner", ownerToken, 200}, {"unshared", guestToken, 403}, {"invalid", "tunn_app_invalid-fixture", 401}} {
						before := dispatches.Load()
						r, _ := http.NewRequest("GET", server.URL+"/socket", nil)
						r.Host = appDeviceTestHost
						r.Header.Set(carrier, "Bearer "+test.token)
						// Mixed-case nominations must not erase credential precedence at a hop.
						r.Header["Connection"] = []string{"keep-alive", strings.ToLower(carrier)}
						if cookie != nil {
							r.AddCookie(cookie)
						}
						want := test.want
						if ws {
							r.Header.Add("Connection", "Upgrade")
							r.Header.Set("Upgrade", "websocket")
							r.Header.Set("Sec-WebSocket-Version", "13")
							r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
							if want == 200 {
								want = 101
							}
						}
						conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{RootCAs: roots})
						if err != nil {
							t.Fatal(err)
						}
						conn.SetDeadline(time.Now().Add(4 * time.Second))
						if err = r.Write(conn); err != nil {
							conn.Close()
							t.Fatal(err)
						}
						reader := bufio.NewReader(conn)
						response, err := http.ReadResponse(reader, r)
						for err == nil && response.StatusCode >= 100 && response.StatusCode < 200 && response.StatusCode != 101 {
							response.Body.Close()
							response, err = http.ReadResponse(reader, r)
						}
						if err != nil {
							conn.Close()
							t.Fatal(err)
						}
						got := response.StatusCode
						if got != 101 {
							_, _ = io.Copy(io.Discard, response.Body)
							response.Body.Close()
						}
						conn.Close()
						if got != want {
							t.Errorf("state=%s cookie=%t status=%d want=%d", test.name, cookie != nil, got, want)
						}
						if want >= 400 && dispatches.Load() != before {
							t.Error("denied device reached origin through cookie fallback")
						}
					}
				}
			})
		}
	}
}

func TestAllCONNECTRelayTrustFailsClosed(t *testing.T) {
	var received atomic.Int64
	remote := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); w.WriteHeader(200) }))
	remote.EnableHTTP2 = true
	remote.StartTLS()
	defer remote.Close()
	wrong := appDeviceTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer wrong.Close()
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad-ca.pem")
	untrusted := filepath.Join(dir, "untrusted-ca.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(untrusted, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrong.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": "", "invalid": bad, "untrusted": untrusted} {
		t.Run(name, func(t *testing.T) {
			p := &ProxyServer{config: &config.Config{NodeSecret: "trust-fixture", InternalCACert: path}}
			r := httptest.NewRequest("CONNECT", "https://api.tunn.test/", nil)
			w := httptest.NewRecorder()
			before := received.Load()
			p.proxyToNode(w, r, remote.Listener.Addr().String(), "api")
			if w.Code != 503 || received.Load() != before {
				t.Fatalf("untrusted CONNECT status=%d origin=%d", w.Code, received.Load()-before)
			}
		})
	}
}
