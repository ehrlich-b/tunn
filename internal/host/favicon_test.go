package host

import (
	"bytes"
	"context"
	"fmt"
	ipb "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
	"image/png"
	"net/http/httptest"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/storage"
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
	if w.Header().Get("Cache-Control") != "public, max-age=86400" {
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
			want = 302
		}
		if w.Code != want {
			t.Fatalf("disabled=%v: %d %s", disabled, w.Code, w.Body.String())
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
