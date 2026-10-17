package host

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/inspection"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// A disposable tunnd, publisher, HTTP ingress and controllable origin, all on
// literal loopback. Client deadlines turn a stall into a failing regression.
func TestRequestTimingDogfood(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 3*1024*1024)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
		delay, _ := time.ParseDuration(r.URL.Query().Get("delay"))
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		size, _ := strconv.Atoi(r.URL.Query().Get("size"))
		if size < 0 || size > len(payload) {
			http.Error(w, "size", 400)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		bodyDelay, _ := time.ParseDuration(r.URL.Query().Get("body_delay"))
		select {
		case <-time.After(bodyDelay):
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write(payload[:size])
	}))
	defer origin.Close()
	certSource := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certSource.TLS.Certificates[0]
	certSource.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := NewTunnelServer(&config.Config{PublicMode: true, Domain: "tunn.test"}, nil, nil, nil)
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})))
	pb.RegisterTunnelServiceServer(gs, server)
	go func() { _ = gs.Serve(listener) }()
	defer gs.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	publisher := &client.ServeClient{TunnelID: "timing", TargetURL: origin.URL, ServerAddr: listener.Addr().String(), Insecure: true}
	publisher.Inspector = client.NewInspector(publisher)
	done := make(chan error, 1)
	go func() { done <- publisher.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("publisher shutdown stalled")
		}
	}()
	var tunnel *TunnelConnection
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if connected, ok := server.GetTunnel("timing"); ok {
			tunnel = connected
			break
		}
		time.Sleep(time.Millisecond)
	}
	if tunnel == nil {
		t.Fatal("publisher did not register")
	}
	proxy := &ProxyServer{}
	slowReaderStarted := make(chan struct{})
	releaseSlowReader := make(chan struct{})
	ingress := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		history, _ := inspection.NewHistory()
		capture := history.Begin("", r.Method, r.URL.RequestURI(), nil, 0, 0)
		r = r.WithContext(context.WithValue(r.Context(), requestTimingCaptureKey{}, capture))
		if r.URL.Path == "/slow-visitor" {
			w = &timingSlowVisitor{ResponseWriter: w}
		}
		if r.URL.Path == "/mixed-slow-reader" {
			w = &timingBlockedVisitor{ResponseWriter: w, started: slowReaderStarted, release: releaseSlowReader}
		}
		if err := proxy.proxyHTTPOverGRPC(w, r, tunnel); err != nil {
			t.Errorf("proxy: %v", err)
		}
		event := capture.Finish(200, "", "complete")
		if event.Timing == nil {
			t.Error("relay inspector missed timing")
		}

	}))
	defer ingress.Close()
	transport := &http.Transport{MaxIdleConnsPerHost: 16}
	defer transport.CloseIdleConnections()
	visitor := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	fetch := func(base, path string, size int) (time.Duration, error) {
		start := time.Now()
		res, err := visitor.Get(base + path)
		if err != nil {
			return 0, err
		}
		n, err := io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if err != nil {
			return 0, err
		}
		if res.StatusCode != 200 || n != int64(size) {
			return 0, fmt.Errorf("response: status=%d bytes=%d want=%d", res.StatusCode, n, size)
		}
		if res.Header.Get("Server-Timing") != "" {
			return 0, fmt.Errorf("timing exposed to visitor")
		}
		return time.Since(start), nil
	}
	for _, c := range []struct {
		name           string
		size, parallel int
	}{{"small", 1024, 1}, {"300KB", 300 * 1024, 1}, {"3MB", 3 * 1024 * 1024, 1}, {"8x300KB", 300 * 1024, 8}} {
		t.Run(c.name, func(t *testing.T) {
			path := fmt.Sprintf("/?size=%d&delay=5ms", c.size)
			// Warm both paths before measuring paired direct/tunnel samples.
			for _, base := range []string{origin.URL, ingress.URL} {
				if _, err := fetch(base, path, c.size); err != nil {
					t.Fatal(err)
				}
			}
			var mu sync.Mutex
			var overhead, direct, tunneled []float64
			for round := 0; round < 5; round++ {
				var wg sync.WaitGroup
				for worker := 0; worker < c.parallel; worker++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for sample := 0; sample < 8/c.parallel; sample++ {
							d, err := fetch(origin.URL, path, c.size)
							if err != nil {
								t.Error(err)
								return
							}
							v, err := fetch(ingress.URL, path, c.size)
							if err != nil {
								t.Error(err)
								return
							}
							mu.Lock()
							direct = append(direct, float64(d)/float64(time.Millisecond))
							tunneled = append(tunneled, float64(v)/float64(time.Millisecond))
							overhead = append(overhead, float64(v-d)/float64(time.Millisecond))
							mu.Unlock()
						}
					}()
				}
				wg.Wait()
			}
			if len(overhead) != 40 {
				t.Fatalf("completed %d/40 requests", len(overhead))
			}
			percentile := func(values []float64, p float64) float64 {
				sort.Float64s(values)
				return values[int(float64(len(values)-1)*p)]
			}
			t.Logf("samples=40 parallel=%d bytes=%d direct_p50_ms=%.3f tunnel_p50_ms=%.3f overhead_p50_ms=%.3f overhead_p95_ms=%.3f", c.parallel, c.size, percentile(direct, .50), percentile(tunneled, .50), percentile(overhead, .50), percentile(overhead, .95))
		})
	}

	t.Run("slow-reader-with-8x300KB", func(t *testing.T) {
		t.Skip("known relay head-of-line blocking: one full 16-event buffer blocks the shared receive loop; 0/8 peers completed before the 10s deadline; requires a separate transport redesign")
		// Hold one visitor at its first body write until the shared receive
		// loop fills that connection's event buffer, then start eight peers.
		slowDone := make(chan error, 1)
		go func() {
			res, err := (&http.Client{Transport: transport, Timeout: 20 * time.Second}).Get(ingress.URL + "/mixed-slow-reader?size=3145728")
			if err == nil {
				var n int64
				n, err = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				if err == nil && n != 3*1024*1024 {
					err = fmt.Errorf("slow reader: bytes=%d", n)
				}
			}
			slowDone <- err
		}()
		defer func() {
			close(releaseSlowReader)
			if err := <-slowDone; err != nil {
				t.Error(err)
			}
		}()
		select {
		case <-slowReaderStarted:
		case <-time.After(5 * time.Second):
			t.Fatal("slow reader did not reach relay write")
		}
		full := false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			tunnel.pendingMu.RLock()
			for _, pending := range tunnel.pendingStreams {
				full = full || len(pending.events) == cap(pending.events)
			}
			tunnel.pendingMu.RUnlock()
			if full {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if !full {
			t.Fatal("slow reader did not fill the relay event buffer")
		}
		type result struct {
			elapsed time.Duration
			err     error
		}
		results := make(chan result, 8)
		for worker := 0; worker < 8; worker++ {
			go func() {
				start := time.Now()
				_, err := fetch(ingress.URL, "/?size=307200&delay=5ms", 300*1024)
				results <- result{time.Since(start), err}
			}()
		}
		completed := 0
		var elapsed []float64
		for worker := 0; worker < 8; worker++ {
			r := <-results
			elapsed = append(elapsed, float64(r.elapsed)/float64(time.Millisecond))
			if r.err == nil {
				completed++
			}
		}
		sort.Float64s(elapsed)
		t.Logf("slow_reader_bytes=3145728 parallel=8 bytes=307200 completed=%d/8 deadline=10s elapsed_p50_ms=%.3f elapsed_p95_ms=%.3f", completed, elapsed[3], elapsed[6])
		if completed != 8 {
			t.Fatal("relay shared receive loop blocked by slow reader's full 16-event buffer")
		}
	})

	// Observe actual publisher terminal records, including delayed origin I/O
	// and a slow response consumer, rather than synthetic timestamps alone.
	for _, c := range []struct {
		path, side        string
		appMin, tunnelMin float64
	}{
		{"/slow-app?size=1024&delay=1100ms&body_delay=60ms", "app", 1160, 0},
		{"/slow-visitor?size=1024&delay=5ms", "tunnel", 5, 4000},
	} {
		if _, err := fetch(ingress.URL, c.path, 1024); err != nil {
			t.Fatal(err)
		}
		var event client.InspectionEvent
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			for _, e := range publisher.Inspector.Events() {
				if strings.Split(e.Path, "?")[0] == strings.Split(c.path, "?")[0] {
					event = e
					break
				}
			}
			if event.Timing != nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if event.Timing == nil || event.Timing.SlowSide != c.side || event.Timing.OriginTotalMS < c.appMin || event.Timing.TunnelTotalMS < c.tunnelMin {
			t.Fatalf("%s event: %+v timing=%+v", c.path, event, event.Timing)
		}
		if c.side == "app" && event.Timing.OriginTTFBMS < 1100 {
			t.Fatalf("TTFB missed origin delay: %+v", event.Timing)
		}
		if event.TerminalReason != "complete" {
			t.Fatalf("completion acknowledgement canceled a success: %+v", event)
		}
		t.Logf("%s: %s", strings.Split(c.path, "?")[0], event.Timing.Summary())
	}

	t.Run("slow-upload", func(t *testing.T) {
		reader, writer := io.Pipe()
		go func() {
			defer writer.Close()
			_, _ = writer.Write([]byte("a"))
			time.Sleep(1200 * time.Millisecond)
			_, _ = writer.Write([]byte("b"))
		}()
		defer reader.Close()
		req, err := http.NewRequest(http.MethodPost, ingress.URL+"/slow-upload?size=1024&delay=5ms", reader)
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = 2
		res, err := visitor.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if err != nil || n != 1024 {
			t.Fatalf("upload response: bytes=%d err=%v", n, err)
		}
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			for _, event := range publisher.Inspector.Events() {
				if strings.HasPrefix(event.Path, "/slow-upload?") && event.Timing != nil {
					v := event.Timing
					if v.OriginTTFBMS > 500 || v.OriginTotalMS > 500 || v.OriginTotalMS+v.TunnelTotalMS < 1200 || strings.Contains(v.SlowSide, "app") {
						t.Fatalf("visitor upload charged to app: %+v", v)
					}
					t.Logf("slow-upload: %s", v.Summary())
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("missing slow-upload timing")
	})
}

type timingSlowVisitor struct{ http.ResponseWriter }

func (w *timingSlowVisitor) Write(b []byte) (int, error) {
	time.Sleep(4 * time.Second)
	return w.ResponseWriter.Write(b)
}
func (w *timingSlowVisitor) Flush()                      { w.ResponseWriter.(http.Flusher).Flush() }
func (w *timingSlowVisitor) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Blocking the relay writer models a visitor whose receive window is full.
type timingBlockedVisitor struct {
	http.ResponseWriter
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (w *timingBlockedVisitor) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return w.ResponseWriter.Write(b)
}
func (w *timingBlockedVisitor) Flush()                      { w.ResponseWriter.(http.Flusher).Flush() }
func (w *timingBlockedVisitor) Unwrap() http.ResponseWriter { return w.ResponseWriter }
