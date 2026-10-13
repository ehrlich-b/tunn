package mcpcheck

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"slices"
	"strings"
)

type ToolOptions struct {
	// Expected is an exact set. Nil skips the assertion; an empty non-nil set
	// asserts that no tools are exposed.
	Expected []string
	// Call and Deny are opt-in probes. Both must be harmless even if allowed.
	Call, Deny string
	Arguments  json.RawMessage
}
type ToolReport struct {
	Names          []string
	Called, Denied bool
}
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code int `json:"code"`
	} `json:"error"`
}

func rpcJSON(data []byte, resp *http.Response, id int, out *rpcResponse) error {
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return problem("tools", "content_type", "MCP POST responses must be JSON or finite SSE; check upstream transport.")
	}
	if mt == "text/event-stream" {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 4096), maxResponse)
		var event strings.Builder
		matches := 0
		dispatch := func() {
			if event.Len() == 0 {
				return
			}
			var candidate rpcResponse
			if decodeJSON([]byte(event.String()), &candidate) == nil && candidate.ID == id && candidate.JSONRPC == "2.0" {
				*out = candidate
				matches++
			}
			event.Reset()
		}
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				dispatch()
			} else if strings.HasPrefix(line, "data:") {
				if event.Len() > 0 {
					event.WriteByte('\n')
				}
				event.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
		}
		dispatch()
		if scanner.Err() != nil || matches != 1 {
			return problem("tools", "rpc", "Expected one matching JSON-RPC response in finite SSE; check upstream framing and IDs.")
		}
	} else if mt != "application/json" || decodeJSON(data, out) != nil {
		return problem("tools", "json", "Expected JSON-RPC JSON or finite SSE; check upstream, not an HTML login page.")
	}
	if out.JSONRPC != "2.0" || out.ID != id || (out.Error == nil) == (len(out.Result) == 0) {
		return problem("tools", "rpc", "MCP response ID/envelope does not match the request; correct upstream JSON-RPC.")
	}
	return nil
}
func (c *Checker) rpc(ctx context.Context, d *Discovery, token, session, version, method string, id int, params any) (*rpcResponse, string, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	headers := http.Header{}
	if session != "" {
		headers.Set("Mcp-Session-Id", session)
	}
	if version != "" {
		headers.Set("Mcp-Protocol-Version", version)
	}
	resp, data, err := c.request(ctx, method, "POST", d.Resource, "application/json", token, body, headers)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != 200 {
		return nil, "", statusProblem(method, resp.StatusCode)
	}
	var result rpcResponse
	if err := rpcJSON(data, resp, id, &result); err != nil {
		return nil, "", err
	}
	return &result, resp.Header.Get("Mcp-Session-Id"), nil
}
func (c *Checker) CheckTools(ctx context.Context, d *Discovery, token string, opts ToolOptions) (*ToolReport, error) {
	if token == "" || len(token) > 8192 || strings.ContainsAny(token, "\r\n\t ") {
		return nil, problem("tools", "credentials", "Use --oauth to obtain an in-memory token scoped to this connector.")
	}
	if opts.Call != "" && opts.Call == opts.Deny {
		return nil, problem("tools", "probe", "Allowed and denied probe names must differ.")
	}
	if len(opts.Arguments) > 0 {
		var args map[string]json.RawMessage
		if decodeJSON(opts.Arguments, &args) != nil || args == nil {
			return nil, problem("tools", "arguments", "--arguments must be one JSON object for the explicitly requested harmless tool call.")
		}
	}
	initialized, session, err := c.rpc(ctx, d, token, "", "", "initialize", 1, map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "tunn connector-check", "version": "1"}})
	if err != nil {
		return nil, err
	}
	if initialized.Error != nil {
		return nil, problem("initialize", "rpc_error", "Local MCP initialization failed; check child stderr and supported protocol versions.")
	}
	var init struct {
		Version      string                         `json:"protocolVersion"`
		Capabilities map[string]json.RawMessage     `json:"capabilities"`
		Server       struct{ Name, Version string } `json:"serverInfo"`
	}
	if decodeJSON(initialized.Result, &init) != nil || !slices.Contains([]string{"2025-11-25", "2025-06-18", "2025-03-26"}, init.Version) || init.Capabilities == nil || init.Server.Name == "" || init.Server.Version == "" {
		return nil, problem("initialize", "protocol", "Expected supported MCP initialize result, server identity and capabilities; update the upstream server.")
	}
	headers := http.Header{"Mcp-Protocol-Version": {init.Version}}
	if session != "" {
		headers.Set("Mcp-Session-Id", session)
	}
	resp, _, err := c.request(ctx, "initialized", "POST", d.Resource, "application/json", token, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), headers)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 202 && resp.StatusCode != 204 {
		return nil, statusProblem("initialized", resp.StatusCode)
	}
	report := &ToolReport{Names: []string{}}
	cursor := ""
	seen := map[string]bool{}
	// Pagination is bounded so a broken upstream cannot loop indefinitely.
	for page := 0; ; page++ {
		if page >= 16 {
			return nil, problem("tools/list", "pagination", "Tool pagination exceeded 16 pages; reduce metadata or fix repeated cursors.")
		}
		params := map[string]string{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		result, _, err := c.rpc(ctx, d, token, session, init.Version, "tools/list", 2+page, params)
		if err != nil {
			return nil, err
		}
		if result.Error != nil {
			return nil, problem("tools/list", "rpc_error", "Upstream rejected tools/list; verify it exposes tools and review child stderr.")
		}
		var listed struct {
			Tools []struct {
				Name   string                     `json:"name"`
				Schema map[string]json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
			Cursor string `json:"nextCursor"`
		}
		if decodeJSON(result.Result, &listed) != nil || listed.Tools == nil {
			return nil, problem("tools/list", "tool_schema", "Expected a tools array with names and inputSchema objects; fix upstream tool metadata.")
		}
		for _, tool := range listed.Tools {
			if tool.Name == "" || len(tool.Name) > 256 || strings.ContainsAny(tool.Name, "\r\n\t") || seen["tool:"+tool.Name] || tool.Schema == nil || string(tool.Schema["type"]) != `"object"` {
				return nil, problem("tools/list", "tool_schema", "Tool names must be unique and inputSchema must be an object schema; fix upstream metadata.")
			}
			seen["tool:"+tool.Name] = true
			report.Names = append(report.Names, tool.Name)
		}
		if listed.Cursor == "" {
			break
		}
		if len(listed.Cursor) > 4096 || seen["cursor:"+listed.Cursor] {
			return nil, problem("tools/list", "pagination", "Upstream repeated an invalid pagination cursor; fix tools/list.")
		}
		seen["cursor:"+listed.Cursor] = true
		cursor = listed.Cursor
	}
	slices.Sort(report.Names)
	if opts.Expected != nil {
		expected := slices.Clone(opts.Expected)
		slices.Sort(expected)
		if !slices.Equal(expected, report.Names) {
			return nil, problem("allow_list", "tools_mismatch", "Exposed tools differ from --expect-tools; check exact --tools names on the stdio publisher (HTTP upstreams enforce their own policy).")
		}
	}
	if opts.Call != "" {
		if !slices.Contains(report.Names, opts.Call) {
			return nil, problem("tools/call", "missing_tool", "Allowed probe is absent from tools/list; check the server and --tools names.")
		}
		args := opts.Arguments
		if len(args) == 0 {
			args = json.RawMessage(`{}`)
		}
		result, _, err := c.rpc(ctx, d, token, session, init.Version, "tools/call", 100, map[string]any{"name": opts.Call, "arguments": args})
		if err != nil {
			return nil, err
		}
		var called struct {
			Content []json.RawMessage `json:"content"`
			IsError bool              `json:"isError"`
		}
		if result.Error != nil || decodeJSON(result.Result, &called) != nil || called.IsError || called.Content == nil {
			return nil, problem("tools/call", "tool_error", "Harmless probe failed; check its input arguments and the local server's stderr.")
		}
		report.Called = true
	}
	if opts.Deny != "" {
		if slices.Contains(report.Names, opts.Deny) {
			return nil, problem("allow_list", "tool_exposed", "Denied probe appears in tools/list; restrict --tools before testing it.")
		}
		result, _, err := c.rpc(ctx, d, token, session, init.Version, "tools/call", 101, map[string]any{"name": opts.Deny, "arguments": map[string]any{}})
		if err != nil {
			return nil, err
		}
		if result.Error == nil || result.Error.Code != -32001 {
			return nil, problem("allow_list", "denial_unproven", "Expected tunn's -32001 tool policy denial; check stdio --tools. Other errors do not prove the allow-list.")
		}
		report.Denied = true
	}
	return report, nil
}
