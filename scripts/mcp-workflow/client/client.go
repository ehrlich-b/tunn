// Package client is a finite, secret-free MCP protocol consumer. It is separate
// from the server and does not import the server implementation or its SDK.
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

type Failure struct {
	Code        string `json:"code"`
	Status      int    `json:"httpStatus,omitempty"`
	Instruction string `json:"instruction"`
}

func (f *Failure) Error() string { return "mcp-workflow: " + f.Code }
func Fail(code string, status int) *Failure {
	hints := map[string]string{
		"service_unavailable": "Keep the local project reader and publisher running; retry only after publisher readiness.",
		"access_denied":       "Check the exact connector URL. Reconnect through consent after expiry or revocation; never fall back to a cookie or another endpoint.",
		"wrong_endpoint":      "Use the printed Connector URL ending in /mcp; do not use the platform or account URL.",
		"incomplete_response": "Discard this answer and its citations. Retry the whole finite call after transport recovery.",
		"protocol_error":      "Discard the answer; confirm the client and server negotiate the recorded MCP protocol.",
		"tool_error":          "Correct the tool name, path or bounded arguments and retry; this result is an error, not an empty answer.",
		"canceled":            "The caller canceled the task. Discard partial evidence; start a new call only if still wanted.",
	}
	return &Failure{code, status, hints[code]}
}

type Consumer struct {
	HTTP     *http.Client
	Endpoint string
	Bearer   string
}

// RPC never puts endpoint URLs, arguments, prompts, remote bodies or bearer
// values in errors. Bearer is used only for the outgoing Authorization header.
func (c Consumer) RPC(ctx context.Context, id int, method string, params any) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, Fail("protocol_error", 0)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, Fail("wrong_endpoint", 0)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	if c.HTTP == nil {
		return nil, Fail("service_unavailable", 0)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, Fail("canceled", 0)
		}
		return nil, Fail("service_unavailable", 0)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 401, 403:
		return nil, Fail("access_denied", resp.StatusCode)
	case 404:
		return nil, Fail("wrong_endpoint", resp.StatusCode)
	case 502, 503, 504:
		return nil, Fail("service_unavailable", resp.StatusCode)
	case 200:
	default:
		return nil, Fail("protocol_error", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, Fail("incomplete_response", resp.StatusCode)
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, Fail("protocol_error", resp.StatusCode)
	}
	if media == "text/event-stream" {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		var event bytes.Buffer
		var frames [][]byte
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				if event.Len() > 0 {
					frames = append(frames, bytes.TrimSuffix(append([]byte(nil), event.Bytes()...), []byte("\n")))
					event.Reset()
				}
				continue
			}
			if bytes.HasPrefix(line, []byte("data:")) {
				value := bytes.TrimPrefix(line, []byte("data:"))
				value = bytes.TrimPrefix(value, []byte(" "))
				event.Write(value)
				event.WriteByte('\n')
			}
		}
		if scanner.Err() != nil || event.Len() != 0 || len(frames) != 1 {
			return nil, Fail("incomplete_response", resp.StatusCode)
		}
		data = frames[0]
	} else if media != "application/json" {
		return nil, Fail("protocol_error", resp.StatusCode)
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, Fail("incomplete_response", resp.StatusCode)
	}
	expectedID, _ := json.Marshal(id)
	if envelope.JSONRPC != "2.0" || !bytes.Equal(envelope.ID, expectedID) {
		return nil, Fail("protocol_error", resp.StatusCode)
	}
	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		return nil, Fail("protocol_error", resp.StatusCode)
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return nil, Fail("incomplete_response", resp.StatusCode)
	}
	var tool struct {
		IsError bool `json:"isError"`
	}
	if json.Unmarshal(envelope.Result, &tool) != nil {
		return nil, Fail("protocol_error", resp.StatusCode)
	}
	if tool.IsError {
		return nil, Fail("tool_error", resp.StatusCode)
	}
	return envelope.Result, nil
}
func (c Consumer) Tool(ctx context.Context, id int, name string, args any) (json.RawMessage, error) {
	return c.RPC(ctx, id, "tools/call", map[string]any{"name": name, "arguments": args})
}
