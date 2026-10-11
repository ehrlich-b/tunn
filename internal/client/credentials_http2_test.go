package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/testnet"
)

// Exercise the actual HTTP/2 request-body lifecycle without loopback binds:
// a 401 must not consume stdin, and an accepted CONNECT must flush before upload.
func TestDurableConnectHTTP2MemoryRetry(t *testing.T) {
	manager, state := credentialFixture(t)
	var refreshes atomic.Int64
	manager.HTTPClient = &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		refreshes.Add(1)
		return refreshFixtureResponse(r, "renewed-access", "renewed-refresh"), nil
	})}
	var attempts atomic.Int64
	var bytesRead atomic.Int64
	listener := testnet.NewListener()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != "CONNECT" {
			t.Error("CONNECT did not use HTTP/2")
		}
		attempts.Add(1)
		if r.Header.Get("Tunn-Authorization") == "Bearer "+state.Access {
			http.Error(w, "expired", 401)
			return
		}
		if r.Header.Get("Tunn-Authorization") != "Bearer renewed-access" {
			http.Error(w, "invalid token", 401)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "SSH identification" {
			t.Error("SSH upload lost", string(body), err)
		}
		bytesRead.Add(int64(len(body)))
		_, _ = io.WriteString(w, "SSH reply")
	})
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}, EnableHTTP2: true}
	server.StartTLS()
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) { return listener.Dial() }
	defer transport.CloseIdleConnections()
	connector := &ConnectClient{EndpointURL: server.URL, Credentials: manager}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var output strings.Builder
	if err := connector.connectStreams(ctx, &http.Client{Transport: transport}, strings.NewReader("SSH identification"), &output); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 || refreshes.Load() != 1 || bytesRead.Load() != 18 || output.String() != "SSH reply" {
		t.Fatal(attempts.Load(), refreshes.Load(), bytesRead.Load(), output.String())
	}
}
