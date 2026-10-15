package host

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
)

func TestWebSocketResponseCookies(t *testing.T) {
	cookies := []string{
		"session=one,two=three; Expires=Wed, 21 Oct 2037 07:28:00 GMT; Path=/; HttpOnly",
		"preference=dark; Path=/; SameSite=Lax",
	}
	for _, status := range []int{http.StatusSwitchingProtocols, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			seen := make(chan http.Header, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Clone()
				for _, cookie := range cookies {
					w.Header().Add("Set-Cookie", cookie)
				}
				for _, name := range []string{"tunn_auth", "__Host-tunn_auth", "__Secure-tunn_auth"} {
					w.Header().Add("Set-Cookie", name+"=must-not-escape; Path=/; Secure")
				}
				w.Header().Add("X-Application", "first")
				w.Header().Add("X-Application", "second")
				w.Header().Set("Tunn-Authorization", "must-not-escape")
				w.Header().Set("Cache-Control", "public, max-age=3600")
				w.Header().Set("Pragma", "cache")
				w.Header().Set("Expires", "Wed, 21 Oct 2037 07:28:00 GMT")
				w.Header().Set("Surrogate-Control", "max-age=3600")
				w.Header().Set("CDN-Cache-Control", "public")
				w.Header().Add("Vary", "Origin")
				w.Header().Add("Vary", "Accept-Language")
				if status != http.StatusSwitchingProtocols {
					http.Error(w, "upstream denied", status)
					return
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n")
				_ = w.Header().Write(rw)
				_, _ = rw.WriteString("\r\n")
				_ = rw.Flush()
				// Retain the origin connection until the downstream closes it.
				_, _ = fixtureReadFrame(rw, true)
			})
			var origin *httptest.Server
			var originPipe *webSocketMemoryListener
			if *webSocketMemory {
				originPipe = newWebSocketMemoryListener("127.0.0.1:10081")
				origin = &httptest.Server{Listener: originPipe, Config: &http.Server{Handler: handler}}
				origin.Start()
			} else {
				origin = httptest.NewServer(handler)
			}
			t.Cleanup(origin.Close)
			s := startWebSocketStack(t, func(p *client.ServeClient) {
				p.TargetURL = origin.URL
				p.AllowedEmails = []string{"alice@example.com"}
				if originPipe != nil {
					baseDial := p.DialContext
					p.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
						if address == originPipe.Addr().String() {
							return originPipe.Dial(ctx)
						}
						return baseDial(ctx, network, address)
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			dial := (&net.Dialer{}).DialContext
			if s.transportDial != nil {
				dial = s.transportDial
			}
			raw, err := dial(ctx, "tcp", s.relay.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
			defer conn.Close()
			if err := conn.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			request, _ := http.NewRequest(http.MethodGet, s.relay.URL+"/cookies", nil)
			request.Host = "websocket-fixture.tunn.test"
			request.Header = http.Header{
				"Upgrade": {"websocket"}, "Connection": {"Upgrade"},
				"Sec-Websocket-Version": {"13"}, "Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="},
				"Authorization": {"Bearer application-secret"}, "Tunn-Authorization": {"Bearer must-not-leak"},
				"Cookie": {s.cookie(t, "alice@example.com") + "; app_session=kept"},
			}
			if err := request.Write(conn); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			var wire strings.Builder
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Fatal(err)
				}
				wire.WriteString(line)
				if line == "\r\n" {
					break
				}
			}
			t.Logf("raw downstream response:\n%s", wire.String())
			response, err := http.ReadResponse(bufio.NewReader(io.MultiReader(strings.NewReader(wire.String()), reader)), request)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != status {
				t.Fatalf("status = %d, want %d", response.StatusCode, status)
			}
			if got := response.Header.Values("Set-Cookie"); !reflect.DeepEqual(got, cookies) {
				t.Errorf("cookie lines = %q, want %q", got, cookies)
			}
			for _, cookie := range cookies {
				if strings.Count(wire.String(), "Set-Cookie: "+cookie+"\r\n") != 1 {
					t.Errorf("missing separate raw cookie line %q", cookie)
				}
			}
			if got := response.Header.Values("X-Application"); !reflect.DeepEqual(got, []string{"first", "second"}) {
				t.Errorf("application fields = %q", got)
			}
			if response.Header.Get("Tunn-Authorization") != "" || strings.Contains(wire.String(), "must-not-escape") {
				t.Error("platform response authority escaped")
			}
			if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" {
				t.Error("private response policy was overridden")
			}
			for _, name := range []string{"Expires", "Surrogate-Control", "CDN-Cache-Control"} {
				if response.Header.Get(name) != "" {
					t.Errorf("cache header %s escaped", name)
				}
			}
			vary := "," + strings.ReplaceAll(strings.Join(response.Header.Values("Vary"), ","), " ", "") + ","
			for _, name := range []string{"Origin", "Accept-Language", "Cookie", "Authorization", "Tunn-Authorization"} {
				if !strings.Contains(vary, ","+name+",") {
					t.Errorf("missing Vary: %s", name)
				}
			}
			select {
			case headers := <-seen:
				for name, want := range map[string]string{"Authorization": "Bearer application-secret", "Tunn-Authorization": "", "Cookie": "app_session=kept"} {
					if got := headers.Get(name); got != want {
						t.Errorf("origin %s = %q, want %q", name, got, want)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("origin did not receive request")
			}
			if status == http.StatusForbidden {
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != "upstream denied\n" {
					t.Errorf("rejection body = %q, error = %v", body, err)
				}
			} else if got := response.Header.Get("Sec-WebSocket-Accept"); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
				t.Errorf("invalid handshake accept %q", got)
			}
		})
	}
}
