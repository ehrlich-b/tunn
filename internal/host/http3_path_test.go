package host

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
)

// pathProxy preserves the ingress socket while independently controlling the
// server-facing mapping and the datagrams returned by the real QUIC listener.
type pathProxy struct {
	front     *net.UDPConn
	mu        sync.Mutex
	back      *net.UDPConn
	client    *net.UDPAddr
	server    *net.UDPAddr
	cap       atomic.Int64
	dropOne   atomic.Bool
	dropBurst atomic.Int64
	blackhole atomic.Bool
	dropped   atomic.Int64
	largest   atomic.Int64
	wg        sync.WaitGroup
}

func newPathProxy(t *testing.T, addr string) *pathProxy {
	t.Helper()
	server, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := &pathProxy{front: front, server: server}
	p.rebind(t)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		b := make([]byte, 65536)
		for {
			n, a, err := front.ReadFromUDP(b)
			if err != nil {
				return
			}
			p.mu.Lock()
			p.client = a
			back := p.back
			p.mu.Unlock()
			if !p.blackhole.Load() {
				_, _ = back.WriteToUDP(b[:n], p.server)
			}
		}
	}()
	t.Cleanup(func() { _ = p.front.Close(); p.mu.Lock(); _ = p.back.Close(); p.mu.Unlock(); p.wg.Wait() })
	return p
}
func (p *pathProxy) rebind(t *testing.T) {
	t.Helper()
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	if p.back != nil {
		_ = p.back.Close()
	}
	p.back = back
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		b := make([]byte, 65536)
		for {
			n, _, err := back.ReadFromUDP(b)
			if err != nil {
				return
			}
			for old := p.largest.Load(); int64(n) > old && !p.largest.CompareAndSwap(old, int64(n)); old = p.largest.Load() {
			}
			if p.blackhole.Load() || (p.cap.Load() > 0 && int64(n) > p.cap.Load()) || (n > 1100 && (p.dropOne.CompareAndSwap(true, false) || p.loseBurst())) {
				p.dropped.Add(1)
				continue
			}
			p.mu.Lock()
			client := p.client
			p.mu.Unlock()
			if client != nil {
				_, _ = p.front.WriteToUDP(b[:n], client)
			}
		}
	}()
}

func TestHTTP3PathDatagrams(t *testing.T) {
	for _, mode := range []string{"mtu-reduction", "probe-blackhole", "one-lost-datagram", "burst-loss", "rebind", "rebind-then-mtu-reduction", "complete-loss"} {
		t.Run(mode, func(t *testing.T) {
			p, h2, _ := opsProxy(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			payload := bytes.Repeat([]byte("path-body-"), 32768)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				// Keep the headers in their own datagram, like small production HEADERS
				// arriving before missing DATA. No artificial wait applies to warm-up.
				if r.URL.Path == "/body" {
					time.Sleep(20 * time.Millisecond)
				}
				_, _ = w.Write(payload)
			})
			done := make(chan error, 1)
			go func() { done <- p.startHTTP3Server(ctx, handler) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("listener failed to stop")
				}
			})
			deadline := time.Now().Add(3 * time.Second)
			for p.listenerState.Load()&listenerHTTP3 == 0 {
				if time.Now().After(deadline) {
					t.Fatal("listener not ready")
				}
				time.Sleep(time.Millisecond)
			}
			proxy := newPathProxy(t, p.HTTP3Addr)
			if mode == "probe-blackhole" {
				proxy.cap.Store(1280)
			}
			tlsConfig := h2.Transport.(*http.Transport).TLSClientConfig.Clone()
			tlsConfig.NextProtos = []string{http3.NextProtoH3}
			dialCtx, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			conn, err := quic.DialAddr(dialCtx, proxy.front.LocalAddr().String(), tlsConfig, &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, Tracer: qlog.DefaultConnectionTracer})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseWithError(0, "")
			transport := &http3.Transport{}
			client := transport.NewClientConn(conn)
			get := func(path string, timeout time.Duration) (bool, int, error) {
				reqCtx, stop := context.WithTimeout(ctx, timeout)
				defer stop()
				req, _ := http.NewRequestWithContext(reqCtx, "GET", "https://"+p.HTTP3Addr+path, nil)
				start := time.Now()
				response, err := client.RoundTrip(req)
				if err != nil {
					return false, 0, err
				}
				ttfb := time.Since(start)
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				t.Logf("path=%s status=%d headers=%s full=%s bytes=%d err=%v dropped=%d largest=%d", path, response.StatusCode, ttfb, time.Since(start), len(body), err, proxy.dropped.Load(), proxy.largest.Load())
				if err == nil && !bytes.Equal(body, payload) {
					t.Error("body corrupted")
				}
				return response.StatusCode == 200, len(body), err
			}
			// Give DPLPMTUD time and traffic to raise its validated packet size before
			// changing the path. The client remains fixed at 1200 in every experiment.
			for i := 0; i < 8; i++ {
				if _, _, err := get("/warm", 3*time.Second); err != nil {
					t.Fatal(err)
				}
				time.Sleep(50 * time.Millisecond)
			}
			switch mode {
			case "mtu-reduction":
				proxy.cap.Store(1200)
			case "one-lost-datagram":
				proxy.dropOne.Store(true)
			case "burst-loss":
				proxy.dropBurst.Store(8)
			case "rebind", "rebind-then-mtu-reduction":
				proxy.rebind(t)
			case "complete-loss":
				proxy.blackhole.Store(true)
			}
			if mode == "rebind-then-mtu-reduction" {
				for i := 0; i < 8; i++ {
					if _, _, err := get("/warm", 3*time.Second); err != nil {
						t.Fatal(err)
					}
					time.Sleep(50 * time.Millisecond)
				}
				proxy.cap.Store(1200)
			}
			headers, n, err := get("/body", 2*time.Second)
			if mode == "complete-loss" {
				if err == nil {
					t.Fatal("blackholed response completed")
				}
				return
			}
			if !headers || err != nil || n != len(payload) {
				t.Fatalf("incomplete reused HTTP/3 response: headers=%t bytes=%d err=%v", headers, n, err)
			}
			if (mode == "mtu-reduction" || mode == "rebind-then-mtu-reduction") && proxy.largest.Load() > 1200 {
				t.Fatalf("listener exceeded UDP ceiling: %d", proxy.largest.Load())
			}
			if mode == "one-lost-datagram" && proxy.dropped.Load() != 1 {
				t.Fatal("single loss was not exercised")
			}
			if mode == "burst-loss" && proxy.dropped.Load() != 8 {
				t.Fatal("burst loss was not exercised")
			}
		})
	}
}

func (p *pathProxy) loseBurst() bool {
	for n := p.dropBurst.Load(); n > 0; n = p.dropBurst.Load() {
		if p.dropBurst.CompareAndSwap(n, n-1) {
			return true
		}
	}
	return false
}
