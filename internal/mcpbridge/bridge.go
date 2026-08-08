// Package mcpbridge exposes a stdio MCP server as a loopback-only Streamable
// HTTP endpoint. The public ingress is provided separately by ServeClient.
package mcpbridge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// MaxMessageSize bounds both remote HTTP messages and messages emitted by
	// the child process. MCP messages should be much smaller in normal use.
	MaxMessageSize = 4 * 1024 * 1024

	defaultRequestTimeout = 25 * time.Second
)

// Bridge owns one stdio MCP child process and one loopback HTTP listener.
// The initial implementation intentionally supports one serialized MCP
// session. See docs/DESIGN-2.0.md for the compatibility boundary.
type Bridge struct {
	cancel context.CancelFunc
	stdin  io.WriteCloser

	listener   net.Listener
	httpServer *http.Server
	outputs    chan childOutput
	done       chan struct{}
	processMu  sync.Mutex
	processErr error

	writeMu   sync.Mutex
	requestMu sync.Mutex
	sessionMu sync.Mutex
	sessionID string

	requestTimeout time.Duration
	allowedTools   map[string]bool
	closeOnce      sync.Once
}

// Options controls local MCP policy. An empty AllowedTools list permits every
// tool exposed by the child process.
type Options struct {
	AllowedTools []string
}

type childOutput struct {
	message []byte
	err     error
}

type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
}

// Start launches command and returns a bridge listening only on 127.0.0.1.
// Child stderr is copied to stderr; stdout is reserved for MCP messages.
func Start(parent context.Context, command []string, stderr io.Writer) (*Bridge, error) {
	return StartWithOptions(parent, command, stderr, Options{})
}

// StartWithOptions launches a command with local MCP policy enforcement.
func StartWithOptions(parent context.Context, command []string, stderr io.Writer, options Options) (*Bridge, error) {
	if len(command) == 0 || strings.TrimSpace(command[0]) == "" {
		return nil, fmt.Errorf("MCP command is required")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for local MCP bridge: %w", err)
	}

	ctx, cancel := context.WithCancel(parent)
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stderr = stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		listener.Close()
		return nil, fmt.Errorf("open MCP command stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		listener.Close()
		return nil, fmt.Errorf("open MCP command stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		listener.Close()
		return nil, fmt.Errorf("start MCP command %q: %w", command[0], err)
	}

	allowedTools := make(map[string]bool, len(options.AllowedTools))
	for _, tool := range options.AllowedTools {
		if normalized := strings.TrimSpace(tool); normalized != "" {
			allowedTools[normalized] = true
		}
	}
	b := &Bridge{
		cancel:         cancel,
		stdin:          stdin,
		listener:       listener,
		outputs:        make(chan childOutput, 16),
		done:           make(chan struct{}),
		requestTimeout: defaultRequestTimeout,
		allowedTools:   allowedTools,
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", b)
	b.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go b.readChild(stdout)
	go func() {
		err := cmd.Wait()
		b.processMu.Lock()
		b.processErr = err
		b.processMu.Unlock()
		close(b.done)
	}()
	go func() {
		_ = b.httpServer.Serve(listener)
	}()

	return b, nil
}

// Done closes when the stdio child process exits.
func (b *Bridge) Done() <-chan struct{} {
	return b.done
}

// Wait waits for the child process and returns its exit status.
func (b *Bridge) Wait() error {
	<-b.done
	b.processMu.Lock()
	defer b.processMu.Unlock()
	return b.processErr
}

// URL is the loopback base URL. The MCP endpoint is URL()+"/mcp".
func (b *Bridge) URL() string {
	return "http://" + b.listener.Addr().String()
}

// Close stops accepting HTTP traffic and terminates the child process.
func (b *Bridge) Close(ctx context.Context) error {
	var closeErr error
	b.closeOnce.Do(func() {
		if err := b.httpServer.Shutdown(ctx); err != nil {
			closeErr = err
		}
		_ = b.stdin.Close()
		b.cancel()

		select {
		case <-b.done:
		case <-ctx.Done():
			if closeErr == nil {
				closeErr = ctx.Err()
			}
		}
	})
	return closeErr
}

func (b *Bridge) readChild(stdout io.Reader) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), MaxMessageSize)
	for scanner.Scan() {
		message := bytes.TrimSpace(scanner.Bytes())
		if len(message) == 0 {
			continue
		}
		copyOfMessage := append([]byte(nil), message...)
		b.outputs <- childOutput{message: copyOfMessage}
	}

	err := scanner.Err()
	if err == nil {
		err = io.EOF
	}
	b.outputs <- childOutput{err: err}
}

// ServeHTTP translates Streamable HTTP POSTs into newline-delimited stdio
// JSON-RPC. It buffers only a single finite response because tunn's current
// HTTP transport is request/response based.
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-transform")

	switch r.Method {
	case http.MethodPost:
		b.handlePOST(w, r)
	case http.MethodDelete:
		if !b.validSession(r.Header.Get("Mcp-Session-Id")) {
			http.Error(w, "unknown MCP session", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "this tunn MCP preview supports POST requests only", http.StatusMethodNotAllowed)
	}
}

func (b *Bridge) handlePOST(w http.ResponseWriter, r *http.Request) {
	mediaType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(mediaType), "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if !b.validSession(r.Header.Get("Mcp-Session-Id")) {
		http.Error(w, "unknown MCP session", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxMessageSize+1))
	if err != nil {
		http.Error(w, "failed to read MCP request", http.StatusBadRequest)
		return
	}
	if len(body) > MaxMessageSize {
		http.Error(w, "MCP request is too large", http.StatusRequestEntityTooLarge)
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] == '[' || !json.Valid(body) {
		http.Error(w, "expected one JSON-RPC object", http.StatusBadRequest)
		return
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		http.Error(w, "expected one JSON-RPC object", http.StatusBadRequest)
		return
	}
	body = compact.Bytes()

	var incoming envelope
	if err := json.Unmarshal(body, &incoming); err != nil || incoming.JSONRPC != "2.0" {
		http.Error(w, "expected a JSON-RPC 2.0 message", http.StatusBadRequest)
		return
	}
	if incoming.Method == "tools/call" && !b.toolCallAllowed(body) {
		writeToolDenied(w, incoming.ID)
		return
	}

	// Notifications and responses do not receive an HTTP response body.
	if !hasID(incoming.ID) || incoming.Method == "" {
		if err := b.writeChild(body); err != nil {
			writeBridgeError(w, http.StatusBadGateway, "local MCP process is unavailable")
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	b.requestMu.Lock()
	defer b.requestMu.Unlock()

	if err := b.writeChild(body); err != nil {
		writeBridgeError(w, http.StatusBadGateway, "local MCP process is unavailable")
		return
	}

	timer := time.NewTimer(b.requestTimeout)
	defer timer.Stop()

	var events [][]byte
	eventBytes := 0
	for {
		select {
		case output := <-b.outputs:
			if output.err != nil {
				writeBridgeError(w, http.StatusBadGateway, "local MCP process exited")
				return
			}

			var outgoing envelope
			if !json.Valid(output.message) || json.Unmarshal(output.message, &outgoing) != nil {
				writeBridgeError(w, http.StatusBadGateway, "local MCP process wrote invalid JSON-RPC")
				return
			}

			if outgoing.Method == "" && sameID(outgoing.ID, incoming.ID) {
				response := output.message
				if incoming.Method == "tools/list" {
					response = b.filterToolsList(response)
				}
				if incoming.Method == "initialize" {
					w.Header().Set("Mcp-Session-Id", b.ensureSessionID())
				}
				b.writeMCPResponse(w, r, events, response)
				return
			}

			if outgoing.Method != "" && hasID(outgoing.ID) {
				// The current tunn data path cannot deliver a server request and
				// receive the client's answer before the outer HTTP response ends.
				// Fail that capability explicitly so the child can continue and
				// potentially return an error for the original call.
				_ = b.rejectChildRequest(outgoing.ID)
				continue
			}

			// Preserve child notifications when the remote client accepts SSE.
			if outgoing.Method != "" {
				eventBytes += len(output.message)
				if eventBytes > MaxMessageSize {
					writeBridgeError(w, http.StatusBadGateway, "local MCP notifications are too large")
					return
				}
				events = append(events, output.message)
			}

		case <-timer.C:
			writeBridgeError(w, http.StatusGatewayTimeout, "local MCP request timed out")
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (b *Bridge) toolCallAllowed(message []byte) bool {
	if len(b.allowedTools) == 0 {
		return true
	}
	var call struct {
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(message, &call) != nil {
		return false
	}
	return b.allowedTools[call.Params.Name]
}

func (b *Bridge) filterToolsList(message []byte) []byte {
	if len(b.allowedTools) == 0 {
		return message
	}
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor json.RawMessage   `json:"nextCursor,omitempty"`
		} `json:"result"`
		Error json.RawMessage `json:"error,omitempty"`
	}
	if json.Unmarshal(message, &response) != nil || response.Error != nil {
		return message
	}
	filtered := response.Result.Tools[:0]
	for _, tool := range response.Result.Tools {
		var identity struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(tool, &identity) == nil && b.allowedTools[identity.Name] {
			filtered = append(filtered, tool)
		}
	}
	response.Result.Tools = filtered
	encoded, err := json.Marshal(response)
	if err != nil {
		return message
	}
	return encoded
}

func (b *Bridge) writeMCPResponse(w http.ResponseWriter, r *http.Request, events [][]byte, response []byte) {
	if len(events) > 0 && strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for _, event := range append(events, response) {
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", event)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func (b *Bridge) writeChild(message []byte) error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()

	if _, err := b.stdin.Write(message); err != nil {
		return err
	}
	_, err := b.stdin.Write([]byte("\n"))
	return err
}

func (b *Bridge) rejectChildRequest(id json.RawMessage) error {
	response := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"client-side MCP requests are not supported by this tunn preview"}}`,
		id,
	)
	return b.writeChild([]byte(response))
}

func (b *Bridge) validSession(got string) bool {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	return b.sessionID == "" || got == b.sessionID
}

func (b *Bridge) ensureSessionID() string {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if b.sessionID != "" {
		return b.sessionID
	}

	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		// rand.Read failures are extraordinarily rare. A timestamp still makes
		// accidental cross-session reuse unlikely without weakening ingress auth.
		b.sessionID = fmt.Sprintf("tunn-%d", time.Now().UnixNano())
	} else {
		b.sessionID = hex.EncodeToString(random)
	}
	return b.sessionID
}

func hasID(id json.RawMessage) bool {
	trimmed := bytes.TrimSpace(id)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func sameID(left, right json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(left), bytes.TrimSpace(right))
}

func writeBridgeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"error": map[string]any{
			"code":    -32603,
			"message": message,
		},
	})
}

func writeToolDenied(w http.ResponseWriter, id json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	idText := "null"
	if hasID(id) {
		idText = string(id)
	}
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32001,"message":"tool denied by local tunn policy"}}`, idText)
}
