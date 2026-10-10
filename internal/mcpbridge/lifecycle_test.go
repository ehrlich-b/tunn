package mcpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type lifecycleWriter struct{ bytes.Buffer }

func (*lifecycleWriter) Close() error { return nil }

type lifecycleWriteFunc func([]byte) (int, error)

func (f lifecycleWriteFunc) Write(message []byte) (int, error) { return f(message) }
func (lifecycleWriteFunc) Close() error                        { return nil }

// These tests exercise the real handler without binding a loopback socket.
func TestBridgeLifecycleErrorIDs(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		output     *childOutput
		status     int
	}{
		{"timeout", `{"jsonrpc":"2.0","id":"call-9","method":"tools/call","params":{"name":"echo"}}`, nil, http.StatusGatewayTimeout},
		{"child exit", `{"jsonrpc":"2.0","id":"call-9","method":"tools/call","params":{"name":"echo"}}`, &childOutput{err: io.EOF}, http.StatusBadGateway},
		{"invalid child output", `{"jsonrpc":"2.0","id":"call-9","method":"tools/call","params":{"name":"echo"}}`, &childOutput{message: []byte(`invalid`)}, http.StatusBadGateway},
		{"modern initialization failure", `{"jsonrpc":"2.0","id":"call-9","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`, &childOutput{err: io.EOF}, http.StatusBadGateway},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bridge := &Bridge{
				stdin:          &lifecycleWriter{},
				outputs:        make(chan childOutput, 1),
				requestTimeout: 20 * time.Millisecond,
			}
			if tt.output != nil {
				bridge.outputs <- *tt.output
			}
			request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tt.body))
			request.Header.Set("Content-Type", "application/json")
			if strings.HasPrefix(tt.name, "modern") {
				request.Header.Set("Mcp-Protocol-Version", modernProtocolVersion)
				request.Header.Set("Mcp-Method", "server/discover")
			}
			response := httptest.NewRecorder()
			bridge.ServeHTTP(response, request)
			if response.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, tt.status, response.Body)
			}
			var message struct {
				ID    string `json:"id"`
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &message); err != nil {
				t.Fatal(err)
			}
			if message.ID != "call-9" || message.Error.Code != -32603 {
				t.Fatalf("uncorrelated bridge error: %s", response.Body)
			}
		})
	}
}

func lifecycleRequest(ctx context.Context, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestBridgeLifecycleCanceledQueue(t *testing.T) {
	writes := make(chan []byte, 4)
	bridge := &Bridge{
		stdin: lifecycleWriteFunc(func(message []byte) (int, error) {
			if json.Valid(message) {
				writes <- append([]byte(nil), message...)
			}
			return len(message), nil
		}),
		outputs:        make(chan childOutput),
		requestTimeout: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstDone := make(chan struct{})
	go func() {
		bridge.ServeHTTP(httptest.NewRecorder(), lifecycleRequest(ctx,
			`{"jsonrpc":"2.0","id":"first","method":"tools/list","params":{}}`))
		close(firstDone)
	}()
	select {
	case <-writes:
	case <-time.After(time.Second):
		t.Fatal("first request did not reach the child")
	}

	queuedCtx, cancelQueued := context.WithCancel(context.Background())
	cancelQueued()
	queuedDone := make(chan struct{})
	go func() {
		bridge.ServeHTTP(httptest.NewRecorder(), lifecycleRequest(queuedCtx,
			`{"jsonrpc":"2.0","id":"queued","method":"tools/list","params":{}}`))
		close(queuedDone)
	}()
	stuck := false
	select {
	case <-queuedDone:
	case <-time.After(100 * time.Millisecond):
		stuck = true
	}
	cancel()
	for _, done := range []chan struct{}{firstDone, queuedDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("request did not finish after cancellation")
		}
	}
	if stuck {
		t.Error("canceled request waited for the active child call")
	}
	if len(writes) != 0 {
		t.Error("canceled queued request reached the child")
	}
}

func TestBridgeLifecycleQueueDeadline(t *testing.T) {
	started := make(chan struct{}, 4)
	bridge := &Bridge{
		stdin: lifecycleWriteFunc(func(message []byte) (int, error) {
			if json.Valid(message) {
				started <- struct{}{}
			}
			return len(message), nil
		}),
		outputs:        make(chan childOutput),
		requestTimeout: 100 * time.Millisecond,
	}
	firstDone := make(chan struct{})
	go func() {
		bridge.ServeHTTP(httptest.NewRecorder(), lifecycleRequest(context.Background(),
			`{"jsonrpc":"2.0","id":"first","method":"tools/list","params":{}}`))
		close(firstDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first request did not reach the child")
	}
	response := httptest.NewRecorder()
	start := time.Now()
	bridge.ServeHTTP(response, lifecycleRequest(context.Background(),
		`{"jsonrpc":"2.0","id":"queued","method":"tools/list","params":{}}`))
	elapsed := time.Since(start)
	<-firstDone
	if response.Code != http.StatusGatewayTimeout || elapsed >= 170*time.Millisecond {
		t.Fatalf("queued request status = %d after %s; queue exceeded the 100 ms budget", response.Code, elapsed)
	}
	t.Logf("queue and response bounded in %s", elapsed)
}

func TestBridgeLifecycleInitializationDeadline(t *testing.T) {
	bridge := &Bridge{outputs: make(chan childOutput, 1), requestTimeout: 100 * time.Millisecond}
	bridge.stdin = lifecycleWriteFunc(func(message []byte) (int, error) {
		var request envelope
		if json.Unmarshal(message, &request) == nil && request.Method == "initialize" {
			time.AfterFunc(60*time.Millisecond, func() {
				bridge.outputs <- childOutput{message: []byte(`{"jsonrpc":"2.0","id":` + string(request.ID) + `,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`)}
			})
		}
		return len(message), nil
	})
	request := lifecycleRequest(context.Background(), `{"jsonrpc":"2.0","id":"call","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`)
	request.Header.Set("Mcp-Protocol-Version", modernProtocolVersion)
	request.Header.Set("Mcp-Method", "tools/list")
	response := httptest.NewRecorder()
	start := time.Now()
	bridge.ServeHTTP(response, request)
	elapsed := time.Since(start)
	if response.Code != http.StatusGatewayTimeout || elapsed >= 140*time.Millisecond {
		t.Fatalf("initialize plus call status = %d after %s; initialization reset the 100 ms budget", response.Code, elapsed)
	}
	t.Logf("initialization and response bounded in %s", elapsed)
}

func TestBridgeLifecycleBlockedPipeDeadline(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	bridge := &Bridge{stdin: writer, outputs: make(chan childOutput), requestTimeout: 50 * time.Millisecond}
	body := `{"jsonrpc":"2.0","id":"large","method":"tools/call","params":{"name":"echo","arguments":{"text":"` + strings.Repeat("x", 1024*1024) + `"}}}`
	response := httptest.NewRecorder()
	start := time.Now()
	bridge.ServeHTTP(response, lifecycleRequest(context.Background(), body))
	elapsed := time.Since(start)
	if response.Code != http.StatusGatewayTimeout || elapsed > 200*time.Millisecond {
		t.Fatalf("blocked child stdin status = %d after %s: %s", response.Code, elapsed, response.Body)
	}
	t.Logf("blocked pipe bounded in %s", elapsed)
}
