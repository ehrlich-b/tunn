package mcpbridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

const modernProtocolVersion = "2026-07-28"

// validateProtocolRequest keeps the modern, sessionless HTTP contract separate
// from the older initialize/session contract served on the same URL.
func validateProtocolRequest(w http.ResponseWriter, r *http.Request, body []byte, request envelope) (modern, ok bool) {
	version := r.Header.Get("Mcp-Protocol-Version")
	if version == "" {
		var message struct {
			Params struct {
				Meta map[string]json.RawMessage `json:"_meta"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &message)
		if string(message.Params.Meta["io.modelcontextprotocol/protocolVersion"]) == `"`+modernProtocolVersion+`"` {
			writeRPCError(w, http.StatusBadRequest, request.ID, -32020, "MCP-Protocol-Version header is missing", nil)
			return false, false
		}
		return false, true
	}
	if version != modernProtocolVersion {
		if version == "2025-11-25" || version == "2025-06-18" || version == "2025-03-26" {
			return false, true
		}
		writeRPCError(w, http.StatusBadRequest, request.ID, -32022, "unsupported protocol version", map[string]any{
			"supported": []string{modernProtocolVersion, "2025-11-25"}, "requested": version,
		})
		return false, false
	}

	var message struct {
		Params map[string]json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(body, &message); err != nil || message.Params == nil {
		writeRPCError(w, http.StatusBadRequest, request.ID, -32600, "modern MCP requests require params", nil)
		return true, false
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(message.Params["_meta"], &meta); err != nil || meta == nil {
		writeRPCError(w, http.StatusBadRequest, request.ID, -32600, "modern MCP requests require params._meta", nil)
		return true, false
	}
	var bodyVersion string
	_ = json.Unmarshal(meta["io.modelcontextprotocol/protocolVersion"], &bodyVersion)
	if bodyVersion != version {
		writeRPCError(w, http.StatusBadRequest, request.ID, -32020, "protocol version header does not match body", nil)
		return true, false
	}
	var clientInfo map[string]json.RawMessage
	var capabilities map[string]json.RawMessage
	if json.Unmarshal(meta["io.modelcontextprotocol/clientInfo"], &clientInfo) != nil || clientInfo == nil ||
		json.Unmarshal(meta["io.modelcontextprotocol/clientCapabilities"], &capabilities) != nil || capabilities == nil {
		writeRPCError(w, http.StatusBadRequest, request.ID, -32600, "modern MCP requests require client identity and capabilities", nil)
		return true, false
	}
	if r.Header.Get("Mcp-Method") != request.Method || request.Method == "" {
		writeRPCError(w, http.StatusBadRequest, request.ID, -32020, "Mcp-Method header does not match body", nil)
		return true, false
	}
	var nameField string
	switch request.Method {
	case "tools/call", "prompts/get":
		nameField = "name"
	case "resources/read":
		nameField = "uri"
	}
	if nameField != "" {
		var name string
		if json.Unmarshal(message.Params[nameField], &name) != nil || name == "" {
			writeRPCError(w, http.StatusBadRequest, request.ID, -32600, "MCP request name is missing", nil)
			return true, false
		}
		headerName, err := decodeMCPHeader(r.Header.Get("Mcp-Name"))
		if err != nil || headerName != name {
			writeRPCError(w, http.StatusBadRequest, request.ID, -32020, "Mcp-Name header does not match body", nil)
			return true, false
		}
	}
	return true, true
}

func decodeMCPHeader(value string) (string, error) {
	if !strings.HasPrefix(value, "=?base64?") {
		return value, nil
	}
	if !strings.HasSuffix(value, "?=") {
		return "", errors.New("invalid base64 header sentinel")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(value, "=?base64?"), "?="))
	return string(decoded), err
}

// initializeChild negotiates the older stdio shape once, then serves modern
// remote requests without exposing a transport session to callers.
// Caller holds requestGate and supplies the shared request deadline.
func (b *Bridge) initializeChild(ctx context.Context) error {
	if b.childInitialized {
		return nil
	}
	initID := b.nextChildID()
	message := []byte(`{"jsonrpc":"2.0","id":` + string(initID) + `,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"tunn","version":"2"}}}`)
	if err := b.writeChild(ctx, message); err != nil {
		return err
	}
	for {
		select {
		case output := <-b.outputs:
			if output.err != nil {
				return output.err
			}
			var response envelope
			if json.Unmarshal(output.message, &response) != nil {
				return errors.New("invalid child initialization response")
			}
			if sameID(response.ID, initID) && response.Method == "" {
				b.cacheInitialize(output.message)
				if !b.childInitialized {
					return errors.New("child rejected legacy initialization")
				}
				if err := b.writeChild(ctx, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); err != nil {
					b.childInitialized = false
					return err
				}
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (b *Bridge) cacheInitialize(message []byte) {
	var response struct {
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(message, &response) == nil && len(response.Result) > 0 && !bytes.Equal(response.Result, []byte("null")) {
		b.childInitializeResult = append([]byte(nil), response.Result...)
		b.childInitialized = true
	}
}

func (b *Bridge) writeDiscover(w http.ResponseWriter, id json.RawMessage) {
	var initResult struct {
		Capabilities json.RawMessage `json:"capabilities"`
		ServerInfo   json.RawMessage `json:"serverInfo"`
		Instructions string          `json:"instructions"`
	}
	_ = json.Unmarshal(b.childInitializeResult, &initResult)
	if len(initResult.Capabilities) == 0 {
		initResult.Capabilities = json.RawMessage(`{}`)
	}
	if len(initResult.ServerInfo) == 0 {
		initResult.ServerInfo = json.RawMessage(`{"name":"tunn-stdio-bridge","version":"2"}`)
	}
	var childCapabilities map[string]json.RawMessage
	_ = json.Unmarshal(initResult.Capabilities, &childCapabilities)
	capabilities := make(map[string]any)
	for _, capability := range []string{"tools", "prompts", "resources"} {
		if _, ok := childCapabilities[capability]; ok {
			// Legacy list-change and subscription flags require delivery
			// machinery this bridge does not implement.
			capabilities[capability] = map[string]any{}
		}
	}
	result := map[string]any{
		"supportedVersions": []string{modernProtocolVersion},
		"capabilities":      capabilities,
		"_meta": map[string]any{
			"io.modelcontextprotocol/serverInfo": initResult.ServerInfo,
		},
	}
	if initResult.Instructions != "" {
		result["instructions"] = initResult.Instructions
	}
	writeRPCResult(w, id, result)
}

func (b *Bridge) writeCachedInitialize(w http.ResponseWriter, id json.RawMessage) {
	w.Header().Set("Mcp-Session-Id", b.ensureSessionID())
	writeRPCResult(w, id, b.childInitializeResult)
}

func methodNotFound(message []byte) bool {
	var response struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	return json.Unmarshal(message, &response) == nil && response.Error.Code == -32601
}

// Legacy stdio servers receive their familiar request shape. The transport
// metadata is for the remote, sessionless client and must not make a legacy
// child misidentify the request as a modern stdio request.
func legacyChildRequest(body []byte) []byte {
	var request map[string]json.RawMessage
	if json.Unmarshal(body, &request) != nil {
		return body
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(request["params"], &params) != nil {
		return body
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(params["_meta"], &meta) == nil {
		delete(meta, "io.modelcontextprotocol/protocolVersion")
		delete(meta, "io.modelcontextprotocol/clientInfo")
		delete(meta, "io.modelcontextprotocol/clientCapabilities")
		if len(meta) == 0 {
			delete(params, "_meta")
		} else {
			params["_meta"], _ = json.Marshal(meta)
		}
	}
	request["params"], _ = json.Marshal(params)
	encoded, err := json.Marshal(request)
	if err != nil {
		return body
	}
	return encoded
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	problem := map[string]any{"code": code, "message": message}
	if data != nil {
		problem["data"] = data
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": problem})
}
