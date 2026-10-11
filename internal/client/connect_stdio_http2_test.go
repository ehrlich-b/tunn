package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/testnet"
)

// Ordinary-host acceptance: actual verified TLS, HTTP/2 CONNECT and stdio EOF.
// This deliberately fails when the environment does not permit loopback.
func TestLoopbackConnectStdioHTTP2(t *testing.T) {
	connectStdioHTTP2(t, false)
}

func TestConnectStdioHTTP2Memory(t *testing.T) {
	connectStdioHTTP2(t, true)
}

func connectStdioHTTP2(t *testing.T, memory bool) {
	t.Helper()
	observed := make(chan string, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.ProtoMajor != 2 || r.Header.Get(common.TCPConnectHeader) != common.TCPConnectValue || r.Header.Get("Tunn-Authorization") != "Bearer account-jwt" {
			http.Error(w, "invalid authenticated HTTP/2 CONNECT", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "SSH-2.0-forge\r\n")
		w.(http.Flusher).Flush()
		body, err := io.ReadAll(r.Body)
		observed <- string(body)
		if err == nil {
			_, _ = io.WriteString(w, "response-after-half-close")
		}
	})
	var server *httptest.Server
	var listener *testnet.Listener
	if memory {
		listener = testnet.NewListener()
		server = &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	} else {
		server = httptest.NewUnstartedServer(handler)
	}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	input, applicationInput := io.Pipe()
	output, applicationOutput := io.Pipe()
	defer func() { _ = applicationInput.Close(); _ = output.Close() }()
	transport := server.Client().Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	if listener != nil {
		transport.DialContext = func(context.Context, string, string) (net.Conn, error) { return listener.Dial() }
	}
	c := &ConnectClient{EndpointURL: server.URL + common.TCPConnectPath, Token: "account-jwt", HTTPClient: &http.Client{Transport: transport}}
	done := make(chan error, 1)
	go func() { done <- c.RunStdio(ctx, input, applicationOutput) }()
	banner := make([]byte, len("SSH-2.0-forge\r\n"))
	if _, err := io.ReadFull(output, banner); err != nil || string(banner) != "SSH-2.0-forge\r\n" {
		t.Fatalf("server-first banner = %q, %v", banner, err)
	}
	if _, err := io.WriteString(applicationInput, "SSH-2.0-laptop\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = applicationInput.Close()
	body, err := io.ReadAll(output)
	if err != nil || string(body) != "response-after-half-close" {
		t.Fatalf("half-close response = %q, %v", body, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := <-observed; got != "SSH-2.0-laptop\r\n" {
		t.Fatalf("uploaded bytes = %q", got)
	}
}
