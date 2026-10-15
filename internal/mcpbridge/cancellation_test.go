package mcpbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// The child reads requests independently of its response writer, so an active
// call can stay blocked until a cancellation notification reaches stdin.
type cancellationFixture struct {
	bridge   *Bridge
	ctx      context.Context
	messages chan []byte
	stdout   *io.PipeWriter
}

func newCancellationFixture(t *testing.T) *cancellationFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stdoutReader, stdoutWriter := io.Pipe()
	stdinReader, stdinWriter := io.Pipe()
	f := &cancellationFixture{
		bridge: FromStreams(ctx, stdoutReader, stdinWriter, Options{}),
		ctx:    ctx, messages: make(chan []byte, 16), stdout: stdoutWriter,
	}
	f.bridge.requestTimeout = 5 * time.Second
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(stdinReader)
		for scanner.Scan() {
			f.messages <- append([]byte(nil), scanner.Bytes()...)
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = stdoutWriter.Close()
		_ = stdoutReader.Close()
		_ = stdinReader.Close()
		<-f.bridge.Done()
		<-readDone
	})
	return f
}

func (f *cancellationFixture) post(ctx context.Context, session, body string) <-chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	r := lifecycleRequest(ctx, body)
	r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	r.Header.Set("Mcp-Session-Id", session)
	go func() {
		w := httptest.NewRecorder()
		f.bridge.ServeHTTP(w, r)
		done <- w
	}()
	return done
}

func cancellationResponse(t *testing.T, done <-chan *httptest.ResponseRecorder, status int) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case w := <-done:
		if w.Code != status {
			t.Fatalf("HTTP status = %d, want %d: %s", w.Code, status, w.Body)
		}
		return w
	case <-time.After(time.Second):
		t.Fatal("HTTP request blocked behind the active child call")
		return nil
	}
}

func (f *cancellationFixture) message(t *testing.T) []byte {
	t.Helper()
	select {
	case message := <-f.messages:
		return message
	case <-time.After(time.Second):
		t.Fatal("child did not receive a message promptly")
		return nil
	}
}

func (f *cancellationFixture) reply(t *testing.T, id json.RawMessage, result string) {
	t.Helper()
	if _, err := fmt.Fprintf(f.stdout, `{"jsonrpc":"2.0","id":%s,"result":%s}`+"\n", id, result); err != nil {
		t.Fatal(err)
	}
}

func cancellationID(t *testing.T, message []byte) json.RawMessage {
	t.Helper()
	var request envelope
	if err := json.Unmarshal(message, &request); err != nil {
		t.Fatal(err)
	}
	return request.ID
}

func (f *cancellationFixture) session(t *testing.T, first bool) string {
	t.Helper()
	done := f.post(f.ctx, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cancel-test","version":"1"}}}`)
	if first {
		id := cancellationID(t, f.message(t))
		f.reply(t, id, `{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"child","version":"1"}}`)
	}
	w := cancellationResponse(t, done, http.StatusOK)
	session := w.Header().Get("Mcp-Session-Id")
	if session == "" {
		t.Fatal("initialize did not create a session")
	}
	return session
}

func TestBridgeLegacyCancellationPrompt(t *testing.T) {
	for _, ids := range []struct{ call, cancellation string }{
		{`7`, `7`},
		{`"call-7"`, `"call-7"`},
		{`"call-\u0037"`, `"call-7"`},
		{`"call-7"`, `"call-\u0037"`},
		{`"a\/b"`, `"a/b"`},
		{`"\u00e9"`, `"é"`},
	} {
		t.Run(ids.call+"/"+ids.cancellation, func(t *testing.T) {
			remoteID := ids.call
			f := newCancellationFixture(t)
			session := f.session(t, true)
			call := f.post(f.ctx, session, `{"jsonrpc":"2.0","id":`+remoteID+`,"method":"tools/call","params":{"name":"blocked"}}`)
			childID := cancellationID(t, f.message(t))
			if sameID(childID, json.RawMessage(remoteID)) {
				t.Fatal("child call ID was not rewritten")
			}
			cancel := f.post(f.ctx, session, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":`+ids.cancellation+`,"reason":"stop this call"}}`)
			cancellationResponse(t, cancel, http.StatusAccepted)
			var notification struct {
				Method string `json:"method"`
				Params struct {
					RequestID json.RawMessage `json:"requestId"`
					Reason    string          `json:"reason"`
				} `json:"params"`
			}
			message := f.message(t)
			if err := json.Unmarshal(message, &notification); err != nil {
				t.Fatal(err)
			}
			if notification.Method != "notifications/cancelled" || !sameID(notification.Params.RequestID, childID) || notification.Params.Reason != "stop this call" {
				t.Fatalf("cancellation was not translated to the active child call: %s", message)
			}
			f.reply(t, childID, `{"cancelled":true}`)
			w := cancellationResponse(t, call, http.StatusOK)
			if !sameID(cancellationID(t, w.Body.Bytes()), json.RawMessage(remoteID)) {
				t.Fatalf("call response lost its remote ID: %s", w.Body)
			}
		})
	}
}

// Observe entry into an actual pipe write while leaving its read end idle.
type cancellationObservedPipe struct {
	*os.File
	started chan struct{}
}

func (p *cancellationObservedPipe) Write(message []byte) (int, error) {
	if len(message) >= 1024*1024 {
		close(p.started)
	}
	return p.File.Write(message)
}

func TestBridgeLegacyCancellationBackpressureReleasesGate(t *testing.T) {
	for _, finish := range []string{"cancel", "timeout", "response"} {
		t.Run(finish, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			pipe := &cancellationObservedPipe{File: writer, started: make(chan struct{})}
			f := &cancellationFixture{
				bridge: &Bridge{stdin: pipe, outputs: make(chan childOutput, 1), requestTimeout: 5 * time.Second},
				ctx:    context.Background(),
			}
			ctx, cancel := context.WithCancel(f.ctx)
			if finish == "timeout" {
				cancel()
				ctx, cancel = context.WithTimeout(f.ctx, time.Second)
			}
			defer cancel()
			call := f.post(ctx, "", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"blocked"}}`)
			if err := reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			message, err := bufio.NewReader(reader).ReadBytes('\n')
			if err != nil {
				t.Fatal(err)
			}
			childID := cancellationID(t, message)
			// Stop reading child stdin. The notification exceeds pipe capacity.
			notificationCtx, stopNotification := context.WithTimeout(f.ctx, 4*time.Second)
			defer stopNotification()
			notification := f.post(notificationCtx, "", `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"`+strings.Repeat("x", 1024*1024)+`"}}`)
			defer func() {
				_ = reader.Close()
				cancel()
				stopNotification()
				select {
				case <-notification:
				case <-time.After(time.Second):
					t.Error("cancellation handler did not finish during cleanup")
				}
			}()
			select {
			case <-pipe.started:
			case <-time.After(time.Second):
				t.Fatal("cancellation did not start its pipe write")
			}
			switch finish {
			case "cancel":
				cancel()
			case "response":
				f.bridge.outputs <- childOutput{message: []byte(`{"jsonrpc":"2.0","id":` + string(childID) + `,"result":{}}`)}
			}
			finishTimeout := 200 * time.Millisecond
			if finish == "timeout" {
				finishTimeout = 1500 * time.Millisecond
			}
			select {
			case w := <-call:
				want := http.StatusOK
				if finish == "timeout" {
					want = http.StatusGatewayTimeout
				}
				if w.Code != want {
					t.Fatalf("original call status = %d: %s", w.Code, w.Body)
				}
			case <-time.After(finishTimeout):
				t.Fatal("original handler retained requestGate behind the cancellation write")
			}
			gateCtx, stopGate := context.WithTimeout(f.ctx, 100*time.Millisecond)
			defer stopGate()
			if err := f.bridge.acquireRequest(gateCtx); err != nil {
				t.Fatalf("next request could not acquire the gate: %v", err)
			}
			<-f.bridge.requestGate
		})
	}
}

func TestBridgeLegacyCancellationSessionIsolation(t *testing.T) {
	f := newCancellationFixture(t)
	owner, other := f.session(t, true), f.session(t, false)
	call := f.post(f.ctx, owner, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"blocked"}}`)
	childID := cancellationID(t, f.message(t))
	for _, tt := range []struct {
		session, requestID string
		status             int
	}{
		{other, `7`, http.StatusAccepted},
		{owner, `"7"`, http.StatusAccepted},
		{owner, string(childID), http.StatusAccepted},
		{owner, `"unknown"`, http.StatusAccepted},
		{owner, `null`, http.StatusAccepted},
		{owner, `{}`, http.StatusAccepted},
		{"", `7`, http.StatusNotFound},
		{"unknown-session", `7`, http.StatusNotFound},
	} {
		done := f.post(f.ctx, tt.session, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":`+tt.requestID+`}}`)
		cancellationResponse(t, done, tt.status)
	}
	// The next child message must be the owner's valid cancellation; none of
	// the preceding notifications may reach the child's active work.
	done := f.post(f.ctx, owner, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"owner"}}`)
	cancellationResponse(t, done, http.StatusAccepted)
	var notification struct {
		Params struct {
			RequestID json.RawMessage `json:"requestId"`
			Reason    string          `json:"reason"`
		} `json:"params"`
	}
	message := f.message(t)
	if err := json.Unmarshal(message, &notification); err != nil {
		t.Fatal(err)
	}
	if !sameID(notification.Params.RequestID, childID) || notification.Params.Reason != "owner" {
		t.Fatalf("unrelated cancellation reached child: %s", message)
	}
	f.reply(t, childID, `{}`)
	cancellationResponse(t, call, http.StatusOK)
}

func TestBridgeLegacyCancellationLateIDReuse(t *testing.T) {
	for _, anotherSession := range []bool{false, true} {
		t.Run(fmt.Sprintf("another-session=%t", anotherSession), func(t *testing.T) {
			f := newCancellationFixture(t)
			firstSession := f.session(t, true)
			secondSession := firstSession
			if anotherSession {
				secondSession = f.session(t, false)
			}
			body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"blocked"}}`
			ctx, cancel := context.WithTimeout(f.ctx, 50*time.Millisecond)
			defer cancel()
			first := f.post(ctx, firstSession, body)
			firstID := cancellationID(t, f.message(t))
			cancellationResponse(t, first, http.StatusGatewayTimeout)

			// Late cancellation with no outstanding call must be discarded rather
			// than left queued to affect a later call that reuses the remote ID.
			cancellation := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}`
			cancellationResponse(t, f.post(f.ctx, firstSession, cancellation), http.StatusAccepted)
			second := f.post(f.ctx, secondSession, body)
			secondID := cancellationID(t, f.message(t))
			if !hasID(secondID) || sameID(firstID, secondID) {
				t.Fatal("late cancellation leaked or child call ID was reused")
			}
			if anotherSession {
				cancellationResponse(t, f.post(f.ctx, firstSession, cancellation), http.StatusAccepted)
			}
			// Even a guessed previous child ID cannot address current work.
			stale := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":` + string(firstID) + `}}`
			cancellationResponse(t, f.post(f.ctx, secondSession, stale), http.StatusAccepted)
			cancellationResponse(t, f.post(f.ctx, secondSession, cancellation), http.StatusAccepted)
			var notification struct {
				Params struct {
					RequestID json.RawMessage `json:"requestId"`
				} `json:"params"`
			}
			message := f.message(t)
			if err := json.Unmarshal(message, &notification); err != nil {
				t.Fatal(err)
			}
			if !sameID(notification.Params.RequestID, secondID) {
				t.Fatalf("reused remote ID cancelled the wrong child call: %s", message)
			}
			f.reply(t, firstID, `{"stale":true}`)
			f.reply(t, secondID, `{"fresh":true}`)
			w := cancellationResponse(t, second, http.StatusOK)
			if !sameID(cancellationID(t, w.Body.Bytes()), json.RawMessage(`7`)) || !bytes.Contains(w.Body.Bytes(), []byte(`"fresh":true`)) {
				t.Fatalf("reused ID received a stale response: %s", w.Body)
			}
			// A completed call also loses its cancellation mapping.
			cancellationResponse(t, f.post(f.ctx, secondSession, cancellation), http.StatusAccepted)
			third := f.post(f.ctx, secondSession, body)
			thirdID := cancellationID(t, f.message(t))
			if !hasID(thirdID) || sameID(secondID, thirdID) {
				t.Fatal("completed call retained its cancellation mapping")
			}
			f.reply(t, thirdID, `{}`)
			cancellationResponse(t, third, http.StatusOK)
		})
	}
}

func TestBridgeModernCancellationNotForwarded(t *testing.T) {
	f := newCancellationFixture(t)
	body := `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	r := lifecycleRequest(f.ctx, body)
	r.Header.Set("Mcp-Protocol-Version", modernProtocolVersion)
	r.Header.Set("Mcp-Method", "notifications/cancelled")
	w := httptest.NewRecorder()
	f.bridge.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("modern notification status = %d: %s", w.Code, w.Body)
	}
	// Starting a legacy session must see initialize as the first child message.
	// Forwarding the modern notification would make this initialization fail.
	f.session(t, true)
}
