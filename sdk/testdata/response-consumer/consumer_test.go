package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	tunn "github.com/ehrlich-b/tunn/sdk"
)

type pipeListener struct {
	incoming chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.incoming:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80} }
func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.incoming <- server:
		return client, nil
	case <-ctx.Done():
		client.Close()
		server.Close()
		return nil, ctx.Err()
	}
}

func pipeClient(t *testing.T, handler http.Handler) *http.Client {
	t.Helper()
	listener := &pipeListener{incoming: make(chan net.Conn), done: make(chan struct{})}
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	transport := &http.Transport{DialContext: listener.dial}
	t.Cleanup(func() { transport.CloseIdleConnections(); server.Close(); <-done })
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func TestExternalConsumerStreamingHandler(t *testing.T) {
	finishChannel := make(chan struct{})
	finish := sync.OnceFunc(func() { close(finishChannel) })
	defer finish()
	response, err := pipeClient(t, responseHandler(finishChannel)).Get("http://fixture.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	if err = consumeResponse(response, finish); err != nil {
		t.Fatal(err)
	}
}

func TestExternalConsumerRejectsInterruptedBody(t *testing.T) {
	response := &http.Response{StatusCode: 202, Header: http.Header{"Set-Cookie": []string{"first=\"one,fragment=two\"; Path=/", "second=three; Path=/"}}, Trailer: make(http.Header), Body: io.NopCloser(io.MultiReader(strings.NewReader(prefix), &failedBody{}))}
	if err := consumeResponse(response, func() {}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("consumer accepted unfinished response: %v", err)
	}
}

type failedBody struct{}

func (*failedBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestExternalConsumerExportedEntryPoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tunn.PublishHandler(ctx, responseHandler(make(chan struct{})), tunn.Options{Reconnect: &tunn.ReconnectPolicy{MaxAttempts: 0}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("public entry point: %v", err)
	}
}
