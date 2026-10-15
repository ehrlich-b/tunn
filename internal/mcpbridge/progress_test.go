package mcpbridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

const progressNotification = `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"p","progress":1}}`

func TestBridgeLegacyProgressBeforeResult(t *testing.T) {
	f := newCancellationFixture(t)
	session := f.session(t, true)
	server := httptest.NewServer(f.bridge)
	defer server.Close()
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":"call","method":"tools/call","params":{"name":"blocked","_meta":{"progressToken":"p"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	request.Header.Set("Mcp-Session-Id", session)
	type firstEvent struct {
		response *http.Response
		reader   *bufio.Reader
		event    string
		err      error
	}
	first := make(chan firstEvent, 1)
	go func() {
		response, err := server.Client().Do(request)
		if err != nil {
			first <- firstEvent{err: err}
			return
		}
		reader := bufio.NewReader(response.Body)
		event, err := readProgressEvent(reader)
		first <- firstEvent{response, reader, event, err}
	}()
	childID := cancellationID(t, f.message(t))
	if _, err := fmt.Fprintln(f.stdout, progressNotification); err != nil {
		t.Fatal(err)
	}
	got := <-first
	if got.err != nil {
		t.Fatalf("progress was not flushed while final result was blocked: %v", got.err)
	}
	defer got.response.Body.Close()
	if got.response.StatusCode != http.StatusOK || got.response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("progress response = %d %v", got.response.StatusCode, got.response.Header)
	}
	if got.event != "event: message\ndata: "+progressNotification+"\n\n" {
		t.Fatalf("first event = %q", got.event)
	}
	// The child cannot produce a result until the HTTP consumer has read progress.
	f.reply(t, childID, `{"complete":true}`)
	result, err := readProgressEvent(got.reader)
	if err != nil || !strings.Contains(result, `"id":"call"`) || !strings.Contains(result, `"complete":true`) {
		t.Fatalf("final event = %q, %v", result, err)
	}
	if rest, err := io.ReadAll(got.reader); err != nil || len(rest) != 0 {
		t.Fatalf("stream did not end after result: %q, %v", rest, err)
	}
}

func readProgressEvent(reader *bufio.Reader) (string, error) {
	var event strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return event.String(), err
		}
		event.WriteString(line)
		if line == "\n" {
			return event.String(), nil
		}
	}
}

func progressPost(f *cancellationFixture, ctx context.Context, session, accept string, w http.ResponseWriter) <-chan struct{} {
	done := make(chan struct{})
	r := lifecycleRequest(ctx, `{"jsonrpc":"2.0","id":"call","method":"tools/call","params":{"name":"blocked","_meta":{"progressToken":"p"}}}`)
	r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	r.Header.Set("Mcp-Session-Id", session)
	r.Header.Set("Accept", accept)
	go func() {
		f.bridge.ServeHTTP(w, r)
		close(done)
	}()
	return done
}

func progressDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("progress handler did not release the child request")
	}
}

func TestBridgeLegacyProgressJSONFallback(t *testing.T) {
	for _, accept := range []string{"", "application/json", "*/*", "application/json, text/event-stream;q=0", "text/event-streaming", "text/event-stream;q=invalid"} {
		t.Run(accept, func(t *testing.T) {
			f := newCancellationFixture(t)
			w := httptest.NewRecorder()
			done := progressPost(f, f.ctx, "", accept, w)
			id := cancellationID(t, f.message(t))
			if _, err := fmt.Fprintln(f.stdout, progressNotification); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
				t.Fatal("JSON request completed before its result")
			default:
			}
			f.reply(t, id, `{"complete":true}`)
			progressDone(t, done)
			if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" || w.Flushed {
				t.Fatalf("JSON fallback changed: %d %v, flushed=%v", w.Code, w.Header(), w.Flushed)
			}
			if w.Body.String() != `{"id":"call","jsonrpc":"2.0","result":{"complete":true}}` {
				t.Fatalf("JSON response = %q", w.Body)
			}
		})
	}
}

// Capture individual flushes without retaining the full notification history.
type progressEventWriter struct {
	*httptest.ResponseRecorder
	events   chan string
	flushErr error
}

func newProgressEventWriter() *progressEventWriter {
	return &progressEventWriter{ResponseRecorder: httptest.NewRecorder(), events: make(chan string, 4)}
}

func (w *progressEventWriter) FlushError() error {
	w.ResponseRecorder.Flush()
	w.events <- w.Body.String()
	w.Body.Reset()
	return w.flushErr
}

func (w *progressEventWriter) event(t *testing.T) string {
	t.Helper()
	select {
	case event := <-w.events:
		return event
	case <-time.After(time.Second):
		t.Fatal("notification was not flushed")
		return ""
	}
}

func TestBridgeLegacyProgressLimitAndErrors(t *testing.T) {
	for _, failure := range []string{"notification limit", "child exit", "invalid JSON"} {
		t.Run(failure, func(t *testing.T) {
			f := newCancellationFixture(t)
			w := newProgressEventWriter()
			done := progressPost(f, f.ctx, "", "text/event-stream", w)
			_ = f.message(t)
			notification := progressNotification
			if failure == "notification limit" {
				notification = `{"jsonrpc":"2.0","method":"notifications/message","params":{"data":"` + strings.Repeat("x", MaxMessageSize/2) + `"}}`
			}
			if _, err := fmt.Fprintln(f.stdout, notification); err != nil {
				t.Fatal(err)
			}
			if event := w.event(t); event != "event: message\ndata: "+notification+"\n\n" {
				t.Fatalf("first notification has incorrect framing (%d bytes)", len(event))
			}
			want := ""
			switch failure {
			case "notification limit":
				want = "local MCP notifications are too large"
				_, _ = fmt.Fprintln(f.stdout, notification)
			case "child exit":
				want = "local MCP process exited"
				_ = f.stdout.Close()
			case "invalid JSON":
				want = "local MCP process wrote invalid JSON-RPC"
				_, _ = fmt.Fprintln(f.stdout, "invalid")
			}
			errorEvent := w.event(t)
			progressDone(t, done)
			if !strings.HasPrefix(errorEvent, "event: message\ndata: {") || !strings.Contains(errorEvent, `"id":"call"`) || !strings.Contains(errorEvent, want) {
				t.Fatalf("uncorrelated or non-SSE terminal error: %q", errorEvent)
			}
			if w.Header().Get("Content-Type") != "text/event-stream" || w.Code != http.StatusOK {
				t.Fatalf("stream changed media type or status after progress: %d %v", w.Code, w.Header())
			}
		})
	}
}

func TestBridgeLegacyProgressTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newCancellationFixture(t)
		f.bridge.requestTimeout = 50 * time.Millisecond
		w := newProgressEventWriter()
		done := progressPost(f, f.ctx, "", "text/event-stream", w)
		_ = f.message(t)
		_, _ = fmt.Fprintln(f.stdout, progressNotification)
		_ = w.event(t)
		errorEvent := w.event(t)
		progressDone(t, done)
		if !strings.HasPrefix(errorEvent, "event: message\ndata: {") || !strings.Contains(errorEvent, `"id":"call"`) || !strings.Contains(errorEvent, "local MCP request timed out") {
			t.Fatalf("timeout after progress = %q", errorEvent)
		}
	})
}

func TestBridgeLegacyProgressTimeoutHTTP(t *testing.T) {
	f := newCancellationFixture(t)
	session := f.session(t, true)
	f.bridge.requestTimeout = 100 * time.Millisecond
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.bridge.ServeHTTP(w, r)
		close(handlerDone)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, strings.NewReader(
		`{"jsonrpc":"2.0","id":"call","method":"tools/call","params":{"name":"blocked"}}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "text/event-stream")
	r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	r.Header.Set("Mcp-Session-Id", session)
	childDone := make(chan struct{})
	go func() {
		defer close(childDone)
		select {
		case <-f.messages:
			_, _ = fmt.Fprintln(f.stdout, progressNotification)
		case <-ctx.Done():
		}
	}()
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if event, err := readProgressEvent(reader); err != nil || event != "event: message\ndata: "+progressNotification+"\n\n" {
		t.Fatalf("first progress = %q, %v", event, err)
	}
	// The client stays connected while the child withholds its result.
	event, err := readProgressEvent(reader)
	if err != nil || !strings.HasPrefix(event, "event: message\ndata: {") || !strings.Contains(event, `"id":"call"`) || !strings.Contains(event, "local MCP request timed out") {
		t.Fatalf("terminal timeout event = %q, %v", event, err)
	}
	if rest, err := io.ReadAll(reader); err != nil || len(rest) != 0 {
		t.Fatalf("stream did not end cleanly after timeout: %q, %v", rest, err)
	}
	progressDone(t, childDone)
	progressDone(t, handlerDone)
	f.bridge.cancellationMu.Lock()
	active := f.bridge.cancellableRequest
	f.bridge.cancellationMu.Unlock()
	if active != nil {
		t.Fatal("timed out request retained its cancellation mapping")
	}
	gateCtx, stopGate := context.WithTimeout(f.ctx, time.Second)
	defer stopGate()
	if err := f.bridge.acquireRequest(gateCtx); err != nil {
		t.Fatalf("timed out request retained its request gate: %v", err)
	}
	<-f.bridge.requestGate
}

// Use real connection deadlines while withholding the peer's reads, including
// when progress was delivered but the terminal timeout write becomes blocked.
type progressDeadlineWriter struct {
	*progressEventWriter
	conn    net.Conn
	blockAt int
	writes  int
	started chan struct{}
}

func (w *progressDeadlineWriter) Write(message []byte) (int, error) {
	w.writes++
	if w.writes == w.blockAt {
		close(w.started)
		return w.conn.Write(message)
	}
	return w.progressEventWriter.Write(message)
}

func (w *progressDeadlineWriter) SetWriteDeadline(deadline time.Time) error {
	return w.conn.SetWriteDeadline(deadline)
}

func TestBridgeLegacyProgressTimeoutBlockedWriter(t *testing.T) {
	for _, phase := range []string{"progress", "terminal error"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newCancellationFixture(t)
				f.bridge.requestTimeout = 100 * time.Millisecond
				writer, peer := net.Pipe()
				defer writer.Close()
				defer peer.Close()
				w := &progressDeadlineWriter{progressEventWriter: newProgressEventWriter(), conn: writer, blockAt: 1, started: make(chan struct{})}
				if phase == "terminal error" {
					w.blockAt = 2
				}
				start := time.Now()
				done := progressPost(f, f.ctx, "", "text/event-stream", w)
				_ = f.message(t)
				_, _ = fmt.Fprintln(f.stdout, progressNotification)
				if phase == "terminal error" {
					_ = w.event(t)
				}
				progressDone(t, w.started)
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("blocked writer outlived the timeout delivery window")
				}
				if elapsed := time.Since(start); elapsed <= f.bridge.requestTimeout || elapsed > 2*time.Second {
					t.Fatalf("blocked writer cleanup took %s", elapsed)
				}
				gateCtx, cancel := context.WithTimeout(f.ctx, time.Second)
				defer cancel()
				if err := f.bridge.acquireRequest(gateCtx); err != nil {
					t.Fatalf("timed out writer retained the request gate: %v", err)
				}
				<-f.bridge.requestGate
			})
		})
	}
}

func TestBridgeLegacyProgressDisconnect(t *testing.T) {
	f := newCancellationFixture(t)
	session := f.session(t, true)
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.bridge.ServeHTTP(w, r)
		close(handlerDone)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, strings.NewReader(
		`{"jsonrpc":"2.0","id":"call","method":"tools/call","params":{"name":"blocked"}}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "text/event-stream")
	r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	r.Header.Set("Mcp-Session-Id", session)
	response := make(chan *http.Response, 1)
	errors := make(chan error, 1)
	go func() {
		w, err := server.Client().Do(r)
		if err != nil {
			errors <- err
			return
		}
		response <- w
	}()
	firstID := cancellationID(t, f.message(t))
	_, _ = fmt.Fprintln(f.stdout, progressNotification)
	select {
	case w := <-response:
		_, err := readProgressEvent(bufio.NewReader(w.Body))
		_ = w.Body.Close() // The final result is still blocked in the child.
		if err != nil {
			t.Fatal(err)
		}
	case err := <-errors:
		t.Fatal(err)
	}
	progressDone(t, handlerDone)
	f.bridge.cancellationMu.Lock()
	active := f.bridge.cancellableRequest
	f.bridge.cancellationMu.Unlock()
	if active != nil {
		t.Fatal("disconnected request retained its cancellation mapping")
	}
	// A late result cannot satisfy a later request, even with the same remote ID.
	w := httptest.NewRecorder()
	next := progressPost(f, f.ctx, session, "application/json", w)
	nextID := cancellationID(t, f.message(t))
	f.reply(t, firstID, `{"late":true}`)
	f.reply(t, nextID, `{"next":true}`)
	progressDone(t, next)
	if !strings.Contains(w.Body.String(), `"next":true`) || strings.Contains(w.Body.String(), "late") {
		t.Fatalf("next request consumed disconnected result: %s", w.Body)
	}
}

// Model a full HTTP send buffer. Only ResponseController's write deadline can
// unblock the writer, so context cancellation alone cannot hide a blocked Write.
type progressBlockedWriter struct {
	*httptest.ResponseRecorder
	started chan struct{}
	expired chan struct{}
	once    sync.Once
}

func (w *progressBlockedWriter) Write([]byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.expired
	return 0, context.DeadlineExceeded
}

func (w *progressBlockedWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		select {
		case <-w.expired:
		default:
			close(w.expired)
		}
	}
	return nil
}

func TestBridgeLegacyProgressBackpressureCleanup(t *testing.T) {
	f := newCancellationFixture(t)
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	w := &progressBlockedWriter{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), expired: make(chan struct{})}
	done := progressPost(f, ctx, "", "text/event-stream", w)
	_ = f.message(t)
	_, _ = fmt.Fprintln(f.stdout, progressNotification)
	progressDone(t, w.started)
	produced := make(chan struct{}, 16)
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		for i := 0; i < 16; i++ {
			if _, err := fmt.Fprintln(f.stdout, progressNotification); err != nil {
				return
			}
			produced <- struct{}{}
		}
	}()
	// readChild can queue one message and scan one more, then must stop reading
	// the child's pipe while the HTTP writer is stalled.
	for i := 0; i < cap(f.bridge.outputs)+1; i++ {
		select {
		case <-produced:
		case <-time.After(time.Second):
			t.Fatal("child pipeline did not fill")
		}
	}
	select {
	case <-produced:
		t.Fatal("stalled HTTP writer allowed unbounded child reads")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	progressDone(t, done)
	gateCtx, stopGate := context.WithTimeout(f.ctx, time.Second)
	defer stopGate()
	if err := f.bridge.acquireRequest(gateCtx); err != nil {
		t.Fatalf("stalled writer retained request gate: %v", err)
	}
	<-f.bridge.requestGate
	_ = f.stdout.Close()
	progressDone(t, producerDone)
}

func TestBridgeLegacyProgressFlushFailure(t *testing.T) {
	f := newCancellationFixture(t)
	w := newProgressEventWriter()
	w.flushErr = errors.New("consumer disconnected")
	done := progressPost(f, f.ctx, "", "text/event-stream", w)
	_ = f.message(t)
	_, _ = fmt.Fprintln(f.stdout, progressNotification)
	progressDone(t, done)
	if len(w.events) != 1 {
		t.Fatal("failed flush did not terminate delivery")
	}
}

func TestBridgeLegacyProgressCancellationAndChildRequests(t *testing.T) {
	f := newCancellationFixture(t)
	owner, other := f.session(t, true), f.session(t, false)
	w := newProgressEventWriter()
	done := progressPost(f, f.ctx, owner, "text/event-stream", w)
	id := cancellationID(t, f.message(t))
	_, _ = fmt.Fprintln(f.stdout, progressNotification)
	_ = w.event(t)
	for _, session := range []string{other, owner} {
		cancellation := f.post(f.ctx, session, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"call"}}`)
		cancellationResponse(t, cancellation, http.StatusAccepted)
	}
	var notification struct {
		Method string `json:"method"`
		Params struct {
			RequestID json.RawMessage `json:"requestId"`
		} `json:"params"`
	}
	if err := json.Unmarshal(f.message(t), &notification); err != nil || notification.Method != "notifications/cancelled" || !sameID(notification.Params.RequestID, id) {
		t.Fatalf("streaming cancellation lost the active child mapping: %+v, %v", notification, err)
	}
	_, _ = fmt.Fprintln(f.stdout, `{"jsonrpc":"2.0","id":"child-request","method":"sampling/createMessage","params":{}}`)
	rejection := string(f.message(t))
	if !strings.Contains(rejection, `"id":"child-request"`) || !strings.Contains(rejection, `"code":-32601`) {
		t.Fatalf("unsupported child request was not rejected: %s", rejection)
	}
	// A cancellation from the other session would be queued ahead of this
	// rejection, causing the assertions above to fail.
	f.reply(t, id, `{"cancelled":true}`)
	if result := w.event(t); !strings.Contains(result, `"id":"call"`) || !strings.Contains(result, `"cancelled":true`) {
		t.Fatalf("stream did not finish after cancellation: %s", result)
	}
	progressDone(t, done)
}

func TestBridgeProgressFiniteContracts(t *testing.T) {
	for _, mode := range []string{"initialize", "modern", "no notifications"} {
		t.Run(mode, func(t *testing.T) {
			f := newCancellationFixture(t)
			w := newProgressEventWriter()
			var done <-chan struct{}
			if mode == "no notifications" {
				done = progressPost(f, f.ctx, "", "text/event-stream", w)
			} else {
				body := `{"jsonrpc":"2.0","id":"call","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
				if mode == "modern" {
					_ = f.session(t, true)
					body = `{"jsonrpc":"2.0","id":"call","method":"tools/call","params":{"name":"blocked","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
				}
				r := lifecycleRequest(f.ctx, body)
				r.Header.Set("Accept", "text/event-stream")
				if mode == "modern" {
					r.Header.Set("Mcp-Protocol-Version", modernProtocolVersion)
					r.Header.Set("Mcp-Method", "tools/call")
					r.Header.Set("Mcp-Name", "blocked")
				}
				finished := make(chan struct{})
				done = finished
				go func() { f.bridge.ServeHTTP(w, r); close(finished) }()
			}
			id := cancellationID(t, f.message(t))
			if mode != "no notifications" {
				_, _ = fmt.Fprintln(f.stdout, progressNotification)
			}
			f.reply(t, id, `{"protocolVersion":"2025-11-25","capabilities":{}}`)
			progressDone(t, done)
			if len(w.events) != 0 {
				t.Fatal("finite contract started streaming")
			}
			if mode == "initialize" && !f.bridge.validSession(w.Header().Get("Mcp-Session-Id")) {
				t.Fatal("initialization committed headers before issuing its session")
			}
			if mode == "no notifications" {
				if w.Header().Get("Content-Type") != "application/json" {
					t.Fatalf("request without progress changed JSON response: %v", w.Header())
				}
			} else if strings.Count(w.Body.String(), "event: message") != 2 {
				t.Fatalf("finite SSE response changed: %s", w.Body)
			}
		})
	}
}
