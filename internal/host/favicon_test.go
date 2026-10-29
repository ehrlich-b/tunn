package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/color"
	"image/png"
	"io"
	"math/bits"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
	ipb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/protobuf/proto"
)

func faviconBody(t *testing.T, host string) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	if !serveTunnelFavicon(w, httptest.NewRequest("GET", "https://"+host+"/favicon.ico", nil), &TunnelConnection{}) {
		t.Fatal("not served")
	}
	img, err := png.Decode(bytes.NewReader(w.Body.Bytes()))
	if err != nil || img.Bounds().Dx() != 32 {
		t.Fatalf("invalid PNG: %v", err)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Header())
	}
	return w.Body.Bytes()
}
func TestFaviconDeterminism(t *testing.T) {
	a := faviconBody(t, "api.example.com")
	if !bytes.Equal(a, faviconBody(t, "API.example.com:443")) {
		t.Fatal("hostname normalization changed icon")
	}
}
func TestFaviconDistinctness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		b := string(faviconBody(t, fmt.Sprintf("app-%d.example.com", i)))
		if seen[b] {
			t.Fatalf("collision at %d", i)
		}
		seen[b] = true
	}
}
func TestFaviconProxy(t *testing.T) {
	for _, streamed := range []bool{false, true} {
		for _, path := range []string{"/favicon.ico", "/favicon.svg"} {
			for _, status := range []int{200, 404, 410, 500} {
				for _, disabled := range []bool{false, true} {
					t.Run(fmt.Sprintf("stream=%v%s/%d/disabled=%v", streamed, path, status, disabled), func(t *testing.T) {
						cfg := webproxyTestConfig()
						stream := &meteringFixtureStream{}
						tunnel := &TunnelConnection{TunnelID: "api", NoFavicon: disabled, Stream: stream, pendingRequests: make(map[string]chan *pb.HttpResponse)}
						if streamed {
							tunnel.Capabilities = map[string]bool{common.CapabilityHTTPStreamV1: true}
						}
						server := NewTunnelServer(cfg, nil, nil, nil)
						server.tunnels["api"] = tunnel
						proxy := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: server, storage: storage.NewProxyStorage()}
						headers := map[string]string{"Content-Type": "image/png", "Content-Length": "12", "Set-Cookie": "backend=secret", "Content-Encoding": "identity", "ETag": "backend"}
						stream.hook = func(m *pb.TunnelMessage) error {
							if req := m.GetHttpRequest(); req != nil {
								tunnel.pendingMu.RLock()
								ch := tunnel.pendingRequests[req.ConnectionId]
								tunnel.pendingMu.RUnlock()
								ch <- &pb.HttpResponse{StatusCode: int32(status), Headers: headers, Body: []byte("backend-icon")}
							}
							if end := m.GetConnectionHalfClose(); end != nil {
								tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: end.ConnectionId, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: int32(status), Headers: headers}}}})
								tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: end.ConnectionId, Data: []byte("backend-icon")}}})
								tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: end.ConnectionId}}})
							}
							return nil
						}
						w := httptest.NewRecorder()
						proxy.handleWebProxy(w, httptest.NewRequest("GET", "https://api.tunn.to"+path, nil))
						fallback := !disabled && (status == 404 || status == 410)
						if fallback {
							if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
								t.Fatalf("proxy cache policy: %v", w.Header())
							}
							if w.Code != 200 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("ETag") != "" || w.Header().Get("Content-Encoding") != "" {
								t.Fatalf("fallback: %d %v", w.Code, w.Header())
							}
							if path == "/favicon.ico" {
								if !bytes.Equal(w.Body.Bytes(), faviconBody(t, "api.tunn.to")) {
									t.Fatal("wrong PNG")
								}
							} else if w.Header().Get("Content-Type") != "image/svg+xml" || !bytes.Contains(w.Body.Bytes(), []byte("<svg")) {
								t.Fatal("wrong SVG")
							}
						} else if w.Code != status || w.Body.String() != "backend-icon" || w.Header().Get("ETag") != "backend" {
							t.Fatalf("pass through: %d %v %q", w.Code, w.Header(), w.Body.String())
						}
					})
				}
			}
		}
	}
}
func TestFaviconPrivateUnauthenticated(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		for _, path := range []string{"/favicon.ico", "/favicon.svg", "/private"} {
			cfg := webproxyTestConfig()
			server := NewTunnelServer(cfg, nil, nil, nil)
			server.tunnels["api"] = &TunnelConnection{TunnelID: "api", NoFavicon: disabled, AllowedEmails: []string{"owner@example.com"}}
			proxy := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: server, storage: storage.NewProxyStorage()}
			w := httptest.NewRecorder()
			proxy.handleWebProxy(w, httptest.NewRequest("GET", "https://api.tunn.to"+path, nil))
			want := 302
			if !disabled && path != "/private" {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("%s disabled=%v: %d", path, disabled, w.Code)
			}
			if want == 200 && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("private proxy cache policy: %v", w.Header())
			}
		}
	}
}
func TestFaviconMethods(t *testing.T) {
	for _, method := range []string{"HEAD", "POST"} {
		w := httptest.NewRecorder()
		served := serveTunnelFavicon(w, httptest.NewRequest(method, "https://api.tunn.to/favicon.ico", nil), &TunnelConnection{})
		if served != (method == "HEAD") || w.Body.Len() != 0 {
			t.Fatal(method, served, w.Body.Len())
		}
	}
}
func TestFaviconRegistrationWireDefault(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		wire, err := proto.Marshal(&pb.RegisterClient{NoFavicon: disabled})
		if err != nil {
			t.Fatal(err)
		}
		var reg pb.RegisterClient
		if err := proto.Unmarshal(wire, &reg); err != nil {
			t.Fatal(err)
		}
		if reg.NoFavicon != disabled {
			t.Fatal("wire lost opt-out")
		}
	}
}

func TestFaviconCustomDomainPrivate(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		p, tunnel, _ := appProxyFixture(t)
		tunnel.NoFavicon = disabled
		stream := tunnel.Stream.(*meteringFixtureStream)
		stream.hook = func(*pb.TunnelMessage) error { t.Error("private favicon reached backend"); return nil }
		w := httptest.NewRecorder()
		p.handleWebProxy(w, httptest.NewRequest("GET", "https://dashboard.apps.example.com/favicon.ico", nil))
		want := 200
		if disabled {
			want = http.StatusUnauthorized
		}
		if w.Code != want {
			t.Fatalf("disabled=%v: %d %s", disabled, w.Code, w.Body.String())
		}
		if disabled && (w.Header().Get("Tunn-Auth") != "login" || !strings.Contains(w.Body.String(), `"error":"login_required"`)) {
			t.Fatalf("disabled favicon must retain background login recovery: %v %s", w.Header(), w.Body.String())
		}
	}
}

func TestFaviconRegistrationHonored(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		cfg := testConfig()
		cfg.PublicMode = true
		server := NewTunnelServer(cfg, nil, nil, nil)
		stream := &securityStream{mockTunnelStream: mockTunnelStream{recvQueue: make(chan *pb.TunnelMessage, 1)}}
		stream.recvQueue <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "favicon-test", TunnelKey: cfg.WellKnownKey, NoFavicon: disabled}}}
		close(stream.recvQueue)
		checked := false
		stream.onSend = func(m *pb.TunnelMessage) error {
			if reg := m.GetRegisterResponse(); reg != nil {
				if !reg.Success {
					t.Fatalf("registration failed: %s", reg.ErrorMessage)
				}
				tunnel, ok := server.GetTunnel("favicon-test")
				if !ok || tunnel.NoFavicon != disabled {
					t.Fatal("registration lost opt-out")
				}
				checked = true
			}
			return nil
		}
		if err := server.EstablishTunnel(stream); err != nil {
			t.Fatal(err)
		}
		if !checked {
			t.Fatal("no registration reply")
		}
	}
}

func TestFaviconForwardedPrivate(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		for _, method := range []string{"GET", "HEAD", "POST"} {
			for _, path := range []string{"/favicon.ico", "/favicon.svg", "/private"} {
				cfg := webproxyTestConfig()
				server := NewTunnelServer(cfg, nil, nil, nil)
				server.tunnels["favicon-test"] = &TunnelConnection{TunnelID: "favicon-test", NoFavicon: disabled, AllowedEmails: []string{"owner@example.com"}}
				proxy := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: server, storage: storage.NewProxyStorage()}
				internal := &InternalServer{proxy: proxy}
				out, err := internal.CheckForwardedPermission(context.Background(), &ipb.ForwardedPermissionRequest{TunnelId: "favicon-test", Host: "favicon-test.tunn.to", Path: path, Method: method, Admission: true})
				if err != nil {
					t.Fatal(err)
				}
				want := !disabled && method != "POST" && path != "/private"
				if out.Allowed != want {
					t.Fatalf("disabled=%v %s %s: %#v", disabled, method, path, out)
				}
				if want && out.Status != 200 {
					t.Fatalf("favicon status=%d", out.Status)
				}
			}
		}
	}
}

// Compare rendered cells and colors rather than relying on encoded PNG bytes.
func TestFaviconVisualDistinctness(t *testing.T) {
	type signature struct {
		ink   color.RGBA
		cells uint32
	}
	for _, format := range []string{"app-%d.example.com", "svc%d.apps.ehrlich.dev"} {
		var seen []signature
		for i := 0; i < 50; i++ {
			host := fmt.Sprintf(format, i)
			img := faviconPixels(host)
			var current signature
			for row := 0; row < 5; row++ {
				for col := 0; col < 5; col++ {
					pixel := img.RGBAAt(3+col*5, 3+row*5)
					if pixel != img.RGBAAt(3+(4-col)*5, 3+row*5) {
						t.Fatalf("asymmetric icon for %s", host)
					}
					if pixel.R != 245 || pixel.G != 245 || pixel.B != 245 {
						current.cells |= 1 << uint(row*5+col)
						current.ink = pixel
					}
				}
			}
			for j, previous := range seen {
				dr := int(current.ink.R) - int(previous.ink.R)
				dg := int(current.ink.G) - int(previous.ink.G)
				db := int(current.ink.B) - int(previous.ink.B)
				if bits.OnesCount32(current.cells^previous.cells) < 2 && dr*dr+dg*dg+db*db < 30*30 {
					t.Fatalf("near-identical rendered icons: %s and %s", host, fmt.Sprintf(format, j))
				}
			}
			seen = append(seen, current)
		}
	}
}

type faviconInformationalRecorder struct {
	*httptest.ResponseRecorder
	hints []http.Header
}

func (w *faviconInformationalRecorder) WriteHeader(status int) {
	if status < 200 {
		w.hints = append(w.hints, w.Header().Clone())
		return
	}
	w.ResponseRecorder.WriteHeader(status)
}
func TestFaviconInformationalHeaders(t *testing.T) {
	for _, status := range []int{200, 404, 410} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			rec := &faviconInformationalRecorder{ResponseRecorder: httptest.NewRecorder()}
			w := &faviconResponseWriter{ResponseWriter: rec, request: httptest.NewRequest("GET", "https://api.tunn.to/favicon.ico", nil), tunnel: &TunnelConnection{}, header: make(http.Header)}
			w.Header().Set("Link", "</backend.css>; rel=preload")
			w.WriteHeader(http.StatusEarlyHints)
			if len(rec.hints) != 1 || rec.hints[0].Get("Link") != "</backend.css>; rel=preload" {
				t.Fatal(rec.hints)
			}
			w.Header().Del("Link")
			w.Header().Set("ETag", "backend")
			w.WriteHeader(status)
			_, _ = w.Write([]byte("backend-icon"))
			if rec.Header().Get("Link") != "" {
				t.Fatal("informational header leaked into final response")
			}
			if status != 200 && (rec.Code != 200 || rec.Header().Get("ETag") != "" || rec.Body.String() == "backend-icon") {
				t.Fatalf("fallback leaked backend: %v", rec)
			}
			if status == 200 && (rec.Code != 200 || rec.Header().Get("ETag") != "backend" || rec.Body.String() != "backend-icon") {
				t.Fatalf("pass-through changed: %v", rec)
			}
		})
	}
}

func TestFaviconMetering(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, path := range []string{"/favicon.ico", "/favicon.svg"} {
			for _, method := range []string{"GET", "HEAD"} {
				for _, limited := range []bool{false, true} {
					if limited && method == "HEAD" {
						continue
					}
					t.Run(fmt.Sprintf("stream=%v%s/%s/limited=%v", streaming, path, method, limited), func(t *testing.T) {
						p, tunnel, ledger, stream := meteringRelay(t, streaming, "")
						icon := httptest.NewRecorder()
						serveTunnelFavicon(icon, httptest.NewRequest("GET", "https://api.tunn.test"+path, nil), tunnel)
						budget := int64(icon.Body.Len())
						if limited {
							budget--
						}
						_, token := relayGrant(t, ledger, 1, budget)
						// Larger than the entire allowance: none of these discarded bytes
						// should be charged or recorded as egress.
						backend := strings.Repeat("error page", 1024)
						headers := map[string]string{"Content-Type": "text/html", "Content-Length": strconv.Itoa(len(backend))}
						stream.hook = func(m *pb.TunnelMessage) error {
							if req := m.GetHttpRequest(); req != nil {
								tunnel.pendingMu.RLock()
								ch := tunnel.pendingRequests[req.ConnectionId]
								tunnel.pendingMu.RUnlock()
								ch <- &pb.HttpResponse{StatusCode: 404, Headers: headers, Body: []byte(backend)}
							}
							if end := m.GetConnectionHalfClose(); end != nil {
								id := end.ConnectionId
								tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionAccept{ConnectionAccept: &pb.ConnectionAccept{ConnectionId: id, Success: true, HttpResponse: &pb.HttpResponseHead{StatusCode: 410, Headers: headers}}}})
								if method != "HEAD" {
									tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionData{ConnectionData: &pb.ConnectionData{ConnectionId: id, Data: []byte(backend)}}})
								}
								tunnel.routeConnectionMessage(&pb.TunnelMessage{Message: &pb.TunnelMessage_ConnectionHalfClose{ConnectionHalfClose: &pb.ConnectionHalfClose{ConnectionId: id}}})
							}
							return nil
						}
						req := httptest.NewRequest(method, "https://api.tunn.test"+path, nil)
						req.Header.Set("Tunn-Authorization", "Bearer "+token)
						rec := httptest.NewRecorder()
						p.handleWebProxy(rec, req)
						out := relayExport(t, ledger)
						if len(out.Events) != 1 {
							t.Fatal(out)
						}
						event := out.Events[0]
						if limited {
							if rec.Code != 429 || event.Status != 429 || event.ResponseBytes != 0 || !event.Finished {
								t.Fatalf("limit: response=%d event=%v", rec.Code, event)
							}
							return
						}
						if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
							t.Fatalf("response=%d %v", rec.Code, rec.Header())
						}
						expected := icon.Body.Bytes()
						if method == "HEAD" {
							expected = nil
						}
						if !bytes.Equal(rec.Body.Bytes(), expected) {
							t.Fatalf("wrong body: %d bytes", rec.Body.Len())
						}
						if !event.Finished || event.Status != 200 || event.ResponseBytes != int64(len(expected)) {
							t.Fatalf("event=%v, sent=%d", event, len(expected))
						}
						if len(out.Usage) != 1 || out.Usage[0].ResponseBytes != int64(len(expected)) {
							t.Fatalf("usage=%v", out.Usage)
						}
					})
				}
			}
		}
	}
}

func TestFaviconBackendMetering(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprint(streaming), func(t *testing.T) {
			p, _, ledger, _ := meteringRelay(t, streaming, "backend-icon")
			_, token := relayGrant(t, ledger, 1, 10000)
			req := httptest.NewRequest("GET", "https://api.tunn.test/favicon.ico", nil)
			req.Header.Set("Tunn-Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			p.handleWebProxy(rec, req)
			out := relayExport(t, ledger)
			if rec.Code != 200 || rec.Body.String() != "backend-icon" || len(out.Events) != 1 {
				t.Fatalf("response=%d %q export=%v", rec.Code, rec.Body.String(), out)
			}
			if event := out.Events[0]; event.ResponseBytes != int64(rec.Body.Len()) || event.Status != 200 || !event.Finished {
				t.Fatal(event)
			}
		})
	}
}

type faviconFailedWriter struct{ *httptest.ResponseRecorder }

func (w *faviconFailedWriter) Write(body []byte) (int, error) { return 0, io.ErrClosedPipe }
func TestFaviconDeliveryError(t *testing.T) {
	rec := &faviconFailedWriter{httptest.NewRecorder()}
	err := writeTunnelFavicon(rec, httptest.NewRequest("GET", "https://api.tunn.test/favicon.ico", nil))
	var truncated *truncatedHTTPResponseError
	if rec.Code != 200 || !responseHasStarted(err) || !errors.As(err, &truncated) || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("delivery error=%v status=%d", err, rec.Code)
	}
}

func TestFaviconWebSocketUpgrade(t *testing.T) {
	r := httptest.NewRequest("GET", "https://api.tunn.test/favicon.ico", nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	w := httptest.NewRecorder()
	if serveTunnelFavicon(w, r, &TunnelConnection{}) || w.Body.Len() != 0 {
		t.Fatal("WebSocket request replaced by favicon")
	}
}
