package mcpbridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Observe the actual pipe writes without replacing the local stdio child or
// losing the pipe deadlines used by the bridge.
type boundaryStdin struct {
	io.WriteCloser
	mu       sync.Mutex
	messages [][]byte
}

func (s *boundaryStdin) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.messages = append(s.messages, append([]byte(nil), p...))
	s.mu.Unlock()
	return s.WriteCloser.Write(p)
}

func (s *boundaryStdin) SetWriteDeadline(deadline time.Time) error {
	return s.WriteCloser.(interface{ SetWriteDeadline(time.Time) error }).SetWriteDeadline(deadline)
}

func (s *boundaryStdin) snapshot() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.messages...)
}

func TestBridgeBatchBoundary(t *testing.T) {
	for _, modern := range []bool{false, true} {
		name := "legacy"
		if modern {
			name = "modern"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("GO_WANT_MCP_HELPER", "1")
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			bridge, err := StartStdioHandler(ctx, []string{os.Args[0]}, io.Discard, Options{})
			if err != nil {
				t.Fatal(err)
			}
			stdin := &boundaryStdin{WriteCloser: bridge.stdin}
			bridge.stdin = stdin
			t.Cleanup(func() {
				closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer closeCancel()
				if err := bridge.Close(closeCtx); err != nil {
					t.Errorf("close local stdio child: %v", err)
				}
				select {
				case <-bridge.Done(): // cmd.Wait has reaped the child.
					_ = bridge.Wait() // Cancellation may produce a nonzero exit.
				case <-closeCtx.Done():
					t.Error("orphan stdio child after Close")
				}
			})

			session := ""
			post := func(method, body string) *httptest.ResponseRecorder {
				t.Helper()
				requestCtx, requestCancel := context.WithTimeout(ctx, 3*time.Second)
				defer requestCancel()
				r := lifecycleRequest(requestCtx, body)
				r.Header.Set("Accept", "application/json")
				if modern {
					r.Header.Set("Mcp-Protocol-Version", modernProtocolVersion)
					r.Header.Set("Mcp-Method", method)
					if method == "tools/call" {
						r.Header.Set("Mcp-Name", "echo")
					}
				} else if session != "" {
					r.Header.Set("Mcp-Session-Id", session)
				}
				w := httptest.NewRecorder()
				bridge.ServeHTTP(w, r)
				return w
			}
			message := func(method, id string) string {
				params := map[string]any{}
				if modern {
					params["_meta"] = map[string]any{
						"io.modelcontextprotocol/protocolVersion":    modernProtocolVersion,
						"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "boundary-test", "version": "1"},
						"io.modelcontextprotocol/clientCapabilities": map[string]any{},
					}
				}
				if method == "tools/call" {
					params["name"] = "echo"
					params["arguments"] = map[string]string{"text": "hello"}
				}
				m := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
				if id != "" {
					m["id"] = json.RawMessage(id)
				}
				body, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				return string(body)
			}
			assertResult := func(w *httptest.ResponseRecorder, id, contains string) {
				t.Helper()
				if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
					t.Fatalf("valid request: status=%d headers=%v body=%s", w.Code, w.Header(), w.Body)
				}
				decoder := json.NewDecoder(w.Body)
				var reply struct {
					JSONRPC string          `json:"jsonrpc"`
					ID      json.RawMessage `json:"id"`
					Result  json.RawMessage `json:"result"`
				}
				if err := decoder.Decode(&reply); err != nil {
					t.Fatal(err)
				}
				if reply.JSONRPC != "2.0" || !sameID(reply.ID, json.RawMessage(id)) || !strings.Contains(string(reply.Result), contains) {
					t.Fatalf("wrong response: %+v", reply)
				}
				var extra any
				if err := decoder.Decode(&extra); err != io.EOF {
					t.Fatalf("expected exactly one response, extra=%v err=%v", extra, err)
				}
			}

			if modern {
				assertResult(post("tools/list", message("tools/list", `"setup"`)), `"setup"`, `"echo"`)
			} else {
				w := post("initialize", `{"jsonrpc":"2.0","id":"setup","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"boundary-test","version":"1"}}}`)
				session = w.Header().Get("Mcp-Session-Id")
				assertResult(w, `"setup"`, `"protocolVersion"`)
				if session == "" {
					t.Fatal("legacy initialize lost its session header")
				}
			}

			// All array forms are unsupported: never split a mixed batch or
			// forward even one member of an ambiguous duplicate-ID batch.
			for _, tc := range []struct{ name, body string }{
				{"empty batch", `[]`},
				{"mixed batch", `[` + message("notifications/initialized", "") + `,` + message("tools/call", `7`) + `]`},
				{"duplicate numeric IDs", `[` + message("tools/call", `7`) + `,` + message("tools/list", `7`) + `]`},
				{"duplicate string IDs", `[` + message("tools/call", `"reused"`) + `,` + message("tools/list", `"reused"`) + `]`},
				{"notification batch", `[` + message("notifications/initialized", "") + `]`},
				{"truncated JSON", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":`},
				{"concatenated objects", message("tools/call", `7`) + message("tools/list", `8`)},
				{"trailing garbage", message("tools/call", `7`) + ` garbage`},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before := len(stdin.snapshot())
					w := post("tools/call", tc.body)
					if w.Code != http.StatusBadRequest {
						t.Fatalf("invalid input: status=%d, want 400: %s", w.Code, w.Body)
					}
					if got := len(stdin.snapshot()); got != before {
						t.Fatalf("invalid input reached child: %d new writes", got-before)
					}
					// Reusing the rejected batch's ID must work, twice, with
					// one distinct child ID and one response for each valid call.
					for range 2 {
						assertResult(post("tools/call", message("tools/call", `7`)), `7`, `"hello"`)
					}
					assertResult(post("tools/list", message("tools/list", `7`)), `7`, `"echo"`)
					writes := stdin.snapshot()[before:]
					if len(writes) != 3 {
						t.Fatalf("valid requests produced %d child writes, want 3", len(writes))
					}
					seen := make(map[string]bool)
					for i, raw := range writes {
						var child envelope
						if err := json.Unmarshal(raw, &child); err != nil {
							t.Fatal(err)
						}
						want := "tools/call"
						if i == 2 {
							want = "tools/list"
						}
						if child.Method != want || !hasID(child.ID) || seen[string(child.ID)] {
							t.Fatalf("wrong or duplicate child dispatch: %s", raw)
						}
						seen[string(child.ID)] = true
					}
				})
			}

			before := len(stdin.snapshot())
			w := post("notifications/initialized", message("notifications/initialized", ""))
			if w.Code != http.StatusAccepted || w.Body.Len() != 0 {
				t.Fatalf("notification must have no response: status=%d body=%s", w.Code, w.Body)
			}
			wantWrites := 1 // Legacy notifications are preserved for the child.
			if modern {
				wantWrites = 0 // Modern notifications are acknowledged locally.
			}
			if writes := stdin.snapshot()[before:]; len(writes) != wantWrites {
				t.Fatalf("notification produced %d child writes, want %d", len(writes), wantWrites)
			} else if !modern && strings.TrimSpace(string(writes[0])) != message("notifications/initialized", "") {
				t.Fatalf("legacy notification changed: %s", writes[0])
			}
			assertResult(post("tools/list", message("tools/list", `"after-notification"`)), `"after-notification"`, `"echo"`)
		})
	}
}
