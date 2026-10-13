package mcpcheck

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func toolFixture(t *testing.T, change func(string, *http.Response)) (*Checker, *[]string) {
	t.Helper()
	methods := []string{}
	c := New(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != resourceURL || r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Fatal("token or resource binding lost")
		}
		var req struct {
			Method string
			ID     int
			Params json.RawMessage
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Fatal("bad request")
		}
		methods = append(methods, req.Method)
		if req.Method != "initialize" && (r.Header.Get("Mcp-Session-Id") != "fixture-session" || r.Header.Get("Mcp-Protocol-Version") != "2025-11-25") {
			t.Fatal("session/version binding lost")
		}
		body := `{}`
		switch req.Method {
		case "initialize":
			body = `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"echo","version":"1"}}`
		case "notifications/initialized":
			return response(202, ""), nil
		case "tools/list":
			body = `{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}`
		case "tools/call":
			body = `{"content":[{"type":"text","text":"secret-marker"}],"isError":false}`
		default:
			t.Fatal("unexpected method")
		}
		data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": json.RawMessage(body)})
		resp := response(200, string(data))
		resp.Header.Set("Mcp-Session-Id", "fixture-session")
		if change != nil {
			change(req.Method, resp)
		}
		return resp, nil
	}))
	return c, &methods
}
func TestConnectorToolContractAndOptIn(t *testing.T) {
	c, methods := toolFixture(t, nil)
	report, err := c.CheckTools(context.Background(), &Discovery{Resource: resourceURL}, "fixture-token", ToolOptions{Expected: []string{"echo"}})
	if err != nil || report.Called || report.Denied || len(*methods) != 3 {
		t.Fatalf("default called tool or contract failed: %v %v", err, methods)
	}
	c, _ = toolFixture(t, nil)
	report, err = c.CheckTools(context.Background(), &Discovery{Resource: resourceURL}, "fixture-token", ToolOptions{Expected: []string{"echo"}, Call: "echo", Arguments: json.RawMessage(`{"message":"hello"}`)})
	if err != nil || !report.Called {
		t.Fatalf("explicit call failed: %v", err)
	}
}
func TestConnectorToolFailures(t *testing.T) {
	for _, tt := range []struct {
		name, method, result, code string
		opts                       ToolOptions
	}{
		{"initialize error", "initialize", `{"error":{"code":-32603}}`, "rpc_error", ToolOptions{}},
		{"version", "initialize", `{"result":{"protocolVersion":"wrong","capabilities":{},"serverInfo":{"name":"echo","version":"1"}}}`, "protocol", ToolOptions{}},
		{"list error", "tools/list", `{"error":{"code":-32603}}`, "rpc_error", ToolOptions{}},
		{"schema", "tools/list", `{"result":{"tools":[{"name":"echo","inputSchema":{"type":"array"}}]}}`, "tool_schema", ToolOptions{}},
		{"duplicate", "tools/list", `{"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}},{"name":"echo","inputSchema":{"type":"object"}}]}}`, "tool_schema", ToolOptions{}},
		{"pagination", "tools/list", `{"result":{"tools":[],"nextCursor":"same"}}`, "pagination", ToolOptions{}},
		{"wrong tools", "", "", "tools_mismatch", ToolOptions{Expected: []string{}}},
		{"missing tool", "", "", "missing_tool", ToolOptions{Call: "missing"}},
		{"exposed denied tool", "", "", "tool_exposed", ToolOptions{Deny: "echo"}},
		{"call result error", "tools/call", `{"result":{"content":[],"isError":true}}`, "tool_error", ToolOptions{Call: "echo"}},
		{"call RPC error", "tools/call", `{"error":{"code":-32603}}`, "tool_error", ToolOptions{Call: "echo"}},
		{"unproven denial", "tools/call", `{"error":{"code":-32601}}`, "denial_unproven", ToolOptions{Deny: "hidden_echo"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := toolFixture(t, func(method string, r *http.Response) {
				if method != tt.method {
					return
				}
				var data map[string]json.RawMessage
				raw, _ := io.ReadAll(r.Body)
				json.Unmarshal(raw, &data)
				delete(data, "result")
				var patch map[string]json.RawMessage
				json.Unmarshal([]byte(tt.result), &patch)
				for k, v := range patch {
					data[k] = v
				}
				raw, _ = json.Marshal(data)
				r.Body = io.NopCloser(strings.NewReader(string(raw)))
			})
			_, err := c.CheckTools(context.Background(), &Discovery{Resource: resourceURL}, "fixture-token", tt.opts)
			requireProblem(t, err, tt.code)
		})
	}
}
