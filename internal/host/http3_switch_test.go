package host

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3SwitchListenersAndAdvertisement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     config.Environment
		setting string
		enabled bool
	}{
		{"production default", config.EnvProd, "", false},
		{"production on", config.EnvProd, "on", true},
		{"production off", config.EnvProd, "off", false},
		{"development default", config.EnvDev, "", true},
		{"development off", config.EnvDev, "off", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, client, _ := opsProxy(t)
			p.config.Environment = tc.env
			p.config.HTTP3 = tc.setting
			// Occupying UDP proves disabled startup never attempts to bind it.
			if !tc.enabled {
				socket, err := net.ListenPacket("udp", p.HTTP3Addr)
				if err != nil {
					t.Fatal(err)
				}
				defer socket.Close()
			}
			cancel, done := opsStart(t, p)
			defer func() { cancel(); opsWaitStopped(t, done) }()
			opsWaitHealth(t, p, client, "/readyz", http.StatusOK)
			req, _ := http.NewRequest("GET", "https://"+p.HTTP2Addr+"/healthz", nil)
			req.Host = p.Domain
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.ProtoMajor != 2 || resp.StatusCode != 200 {
				t.Fatalf("HTTP/2 response: %s %d", resp.Proto, resp.StatusCode)
			}
			wantHeader := ""
			if tc.enabled {
				_, port, _ := net.SplitHostPort(p.HTTP3Addr)
				wantHeader = `h3=":` + port + `"; ma=3600`
			}
			if got := resp.Header.Get("Alt-Svc"); got != wantHeader {
				t.Fatalf("Alt-Svc=%q want %q", got, wantHeader)
			}
			if got := p.listenerState.Load()&listenerHTTP3 != 0; got != tc.enabled {
				t.Fatalf("HTTP/3 listener=%v want %v", got, tc.enabled)
			}
			if tc.enabled {
				tr := &http3.Transport{TLSClientConfig: client.Transport.(*http.Transport).TLSClientConfig.Clone()}
				defer tr.Close()
				ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
				defer stop()
				h3req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+p.HTTP3Addr+"/healthz", nil)
				h3req.Host = p.Domain
				h3resp, err := tr.RoundTrip(h3req)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, h3resp.Body)
				h3resp.Body.Close()
				if err != nil || h3resp.ProtoMajor != 3 || h3resp.StatusCode != 200 {
					t.Fatalf("HTTP/3 response: %v %s %d", err, h3resp.Proto, h3resp.StatusCode)
				}
			}
		})
	}
}
