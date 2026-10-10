package mcpbridge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBridgeIndependentLegacySessions(t *testing.T) {
	b := &Bridge{childInitialized: true, childInitializeResult: json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"test","version":"1"}}`)}
	newSession := func(id json.RawMessage) string {
		w := httptest.NewRecorder()
		b.writeCachedInitialize(w, id)
		if w.Code != 200 || w.Header().Get("Mcp-Session-Id") == "" {
			t.Fatalf("initialize: %d %s", w.Code, w.Body)
		}
		return w.Header().Get("Mcp-Session-Id")
	}
	first, second := newSession(json.RawMessage(`1`)), newSession(json.RawMessage(`2`))
	if first == second || !b.validSession(first) || !b.validSession(second) || b.validSession("") || b.validSession("unknown") {
		t.Fatal("legacy clients do not have distinct valid sessions")
	}
	r := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	r.Header.Set("Mcp-Session-Id", first)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 204 || b.validSession(first) || !b.validSession(second) {
		t.Fatal("DELETE did not invalidate only the requested session")
	}
	w = httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("deleted session was reusable")
	}
	b.sessionMu.Lock()
	b.sessions[second] = time.Now().Add(-time.Second)
	b.sessionMu.Unlock()
	if b.validSession(second) {
		t.Fatal("expired session accepted")
	}
}

func TestBridgeSecondLegacyClientCanInitialize(t *testing.T) {
	b := &Bridge{childInitialized: true, childInitializeResult: json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{}}`), requestTimeout: time.Second}
	var previous string
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		b.ServeHTTP(w, lifecycleRequest(t.Context(), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
		session := w.Header().Get("Mcp-Session-Id")
		if w.Code != 200 || session == "" || session == previous {
			t.Fatalf("second initialization: %d %s", w.Code, w.Body)
		}
		previous = session
	}
	w := httptest.NewRecorder()
	b.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if w.Code != 405 || w.Header().Get("Allow") != "POST, DELETE" {
		t.Fatal("optional GET stream must return 405")
	}
}
