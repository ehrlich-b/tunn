package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func TestInboundConnectionStreamsTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = connection.Close() }()
		body, err := io.ReadAll(connection)
		if err == nil && string(body) != "ping-through-tunn" {
			err = &unexpectedTCPBody{got: string(body)}
		}
		if err == nil {
			_, err = connection.Write([]byte("pong-from-target"))
		}
		serverDone <- err
	}()

	serveClient := &ServeClient{TargetURL: listener.Addr().String(), EndpointProtocol: "tcp"}
	sender := &mockEstablishTunnelClient{}
	manager := newInboundConnectionManager()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	defer manager.closeAll(io.EOF)

	manager.open(ctx, serveClient, sender, &pb.ConnectionOpen{ConnectionId: "tcp-1", Protocol: "tcp"})
	manager.write("tcp-1", []byte("ping-through-"))
	manager.write("tcp-1", []byte("tunn"))
	manager.halfClose("tcp-1")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var response bytes.Buffer
		accepted := false
		halfClosed := false
		sender.mu.Lock()
		for _, message := range sender.sentMsgs {
			if accept := message.GetConnectionAccept(); accept != nil {
				accepted = accept.Success
			}
			if data := message.GetConnectionData(); data != nil {
				response.Write(data.Data)
			}
			if message.GetConnectionHalfClose() != nil {
				halfClosed = true
			}
		}
		sender.mu.Unlock()
		if accepted && halfClosed {
			if response.String() != "pong-from-target" {
				t.Fatalf("TCP response = %q", response.String())
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("TCP stream did not complete")
}

func TestInboundConnectionStreamsUnixSocket(t *testing.T) {
	placeholder, err := os.CreateTemp("", "tunn-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	socketPath := placeholder.Name()
	_ = placeholder.Close()
	_ = os.Remove(socketPath)
	defer func() { _ = os.Remove(socketPath) }()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		body, _ := io.ReadAll(connection)
		_, _ = connection.Write(bytes.ToUpper(body))
	}()

	serveClient := &ServeClient{
		TargetURL:        socketPath,
		EndpointProtocol: "tcp",
		TargetNetwork:    "unix",
	}
	sender := &mockEstablishTunnelClient{}
	manager := newInboundConnectionManager()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	defer manager.closeAll(io.EOF)
	manager.open(ctx, serveClient, sender, &pb.ConnectionOpen{ConnectionId: "unix-1", Protocol: "tcp"})
	manager.write("unix-1", []byte("docker"))
	manager.halfClose("unix-1")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var response bytes.Buffer
		halfClosed := false
		sender.mu.Lock()
		for _, message := range sender.sentMsgs {
			if data := message.GetConnectionData(); data != nil {
				response.Write(data.Data)
			}
			halfClosed = halfClosed || message.GetConnectionHalfClose() != nil
		}
		sender.mu.Unlock()
		if halfClosed {
			if response.String() != "DOCKER" {
				t.Fatalf("Unix response = %q", response.String())
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Unix socket stream did not complete")
}

func TestInboundConnectionServesHTTPOverUnixSocket(t *testing.T) {
	placeholder, err := os.CreateTemp("", "tunn-http-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	socketPath := placeholder.Name()
	_ = placeholder.Close()
	_ = os.Remove(socketPath)
	defer func() { _ = os.Remove(socketPath) }()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"path":"` + r.URL.Path + `"}`))
	})}
	go func() { _ = httpServer.Serve(listener) }()
	defer func() { _ = httpServer.Close() }()

	serveClient := &ServeClient{
		TargetURL:        "http://unix",
		EndpointProtocol: "http",
		TargetNetwork:    "unix",
		DialAddress:      socketPath,
	}
	sender := &mockEstablishTunnelClient{}
	manager := newInboundConnectionManager()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	defer manager.closeAll(io.EOF)
	manager.open(ctx, serveClient, sender, &pb.ConnectionOpen{
		ConnectionId: "unix-http-1",
		Protocol:     "http",
		HttpRequest: &pb.HttpRequestHead{
			Method: http.MethodGet,
			Path:   "/info",
		},
	})
	manager.halfClose("unix-http-1")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var response bytes.Buffer
		accepted := false
		halfClosed := false
		sender.mu.Lock()
		for _, message := range sender.sentMsgs {
			if accept := message.GetConnectionAccept(); accept != nil {
				accepted = accept.Success && accept.HttpResponse.StatusCode == http.StatusOK
			}
			if data := message.GetConnectionData(); data != nil {
				response.Write(data.Data)
			}
			halfClosed = halfClosed || message.GetConnectionHalfClose() != nil
		}
		sender.mu.Unlock()
		if accepted && halfClosed {
			if response.String() != `{"path":"/info"}` {
				t.Fatalf("HTTP-over-Unix response = %q", response.String())
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("HTTP-over-Unix stream did not complete")
}

type unexpectedTCPBody struct{ got string }

func (e *unexpectedTCPBody) Error() string { return "unexpected TCP body: " + e.got }

func TestConnectClientPumpsLocalSocket(t *testing.T) {
	var gotMethod, gotPath, gotToken string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		gotMethod = request.Method
		gotPath = request.URL.Path
		gotToken = request.Header.Get("Tunn-Authorization")
		responseReader, responseWriter := io.Pipe()
		go func() {
			requestBytes := make([]byte, 4)
			_, err := io.ReadFull(request.Body, requestBytes)
			if err == nil {
				_, err = responseWriter.Write(bytes.ToUpper(requestBytes))
			}
			_ = responseWriter.CloseWithError(err)
		}()
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       responseReader,
			Request:    request,
		}, nil
	})
	httpClient := &http.Client{Transport: transport}
	connector := &ConnectClient{
		EndpointURL: "https://database.tunn.to" + common.TCPConnectPath,
		Token:       "endpoint-secret",
	}
	connectorSide, applicationSide := net.Pipe()
	defer func() { _ = applicationSide.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- connector.handleConnection(ctx, httpClient, connectorSide) }()

	if _, err := applicationSide.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(applicationSide, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "PING" {
		t.Fatalf("connector response = %q", response)
	}
	_ = applicationSide.Close()
	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("connector did not close")
	}
	if gotMethod != http.MethodConnect || gotPath != common.TCPConnectPath {
		t.Fatalf("CONNECT request = %s %s", gotMethod, gotPath)
	}
	if gotToken != "Bearer endpoint-secret" {
		t.Fatalf("authorization = %q", gotToken)
	}
}

func TestConnectClientOverHTTP2CONNECT(t *testing.T) {
	observed := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Method + " " + r.URL.Path + " " + r.Proto
		if r.Method != http.MethodConnect || r.URL.Path != "" {
			http.Error(w, "wrong CONNECT target", http.StatusBadRequest)
			return
		}
		if r.Header.Get(common.TCPConnectHeader) != common.TCPConnectValue {
			http.Error(w, "wrong CONNECT protocol", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Tunn-Authorization"); got != "Bearer endpoint-secret" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		requestBytes := make([]byte, 4)
		if _, err := io.ReadFull(r.Body, requestBytes); err != nil {
			return
		}
		_, _ = w.Write(bytes.ToUpper(requestBytes))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	connector := &ConnectClient{
		EndpointURL: server.URL + common.TCPConnectPath,
		Token:       "endpoint-secret",
	}
	connectorSide, applicationSide := net.Pipe()
	defer func() { _ = applicationSide.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- connector.handleConnection(ctx, &http.Client{Transport: transport}, connectorSide)
	}()

	if _, err := applicationSide.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(applicationSide, response); err != nil {
		select {
		case connectionErr := <-done:
			t.Fatalf("read response: %v; connector: %v; server saw: %s", err, connectionErr, <-observed)
		default:
			t.Fatal(err)
		}
	}
	if string(response) != "PING" {
		t.Fatalf("HTTP/2 CONNECT response = %q", response)
	}
	_ = applicationSide.Close()
	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "closed pipe") {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP/2 CONNECT did not close")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
