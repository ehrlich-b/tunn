package mcpbridge

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type lifecycleWriter struct{ bytes.Buffer }

func (*lifecycleWriter) Close() error { return nil }

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
