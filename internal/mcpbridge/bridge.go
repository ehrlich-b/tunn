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
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// MaxMessageSize bounds both remote HTTP messages and messages emitted by
	// the child process. MCP messages should be much smaller in normal use.
	MaxMessageSize = 4 * 1024 * 1024

	defaultRequestTimeout = 25 * time.Second
	streamWriteGrace      = time.Second
)

// Bridge owns one stdio MCP child process and one loopback HTTP listener.
// Remote HTTP sessions share one serialized child process; each legacy client
// gets a distinct, expiring transport session.
type Bridge struct {
	cancel context.CancelFunc
	stdin  io.WriteCloser

	listener     net.Listener
	httpServer   *http.Server
	httpConnMu   sync.Mutex
	httpNewConns map[net.Conn]struct{}
	httpClosing  bool
	outputs      chan childOutput
	done         chan struct{}
	readerDone   chan struct{}
	processMu    sync.Mutex
	processErr   error

	writeMu               sync.Mutex
	requestGate           chan struct{}
	requestGateOnce       sync.Once
	sessionMu             sync.Mutex
	sessions              map[string]time.Time
	sessionStarted        bool
	childInitialized      bool            // guarded by requestGate
	childInitializeResult json.RawMessage // guarded by requestGate
	requestSequence       uint64          // guarded by requestGate
	cancellationMu        sync.Mutex
	cancellableRequest    *legacyRequest // guarded by cancellationMu

	requestTimeout time.Duration
	allowedTools   map[string]bool
	closeOnce      sync.Once
	streamContext  context.Context
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

// Only the single admitted legacy request can be cancelled. Never retain a
// remote ID after its handler returns, even if the child finishes late.
type legacyRequest struct {
	sessionID string
	remoteID  json.RawMessage
	childID   json.RawMessage
	ctx       context.Context
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
	b, err := StartStdioHandler(parent, command, stderr, options)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	b.listener = listener
	mux := http.NewServeMux()
	mux.Handle("/mcp", b)
	b.httpServer = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ConnState: b.trackHTTPConn}
	go func() { _ = b.httpServer.Serve(listener) }()
	return b, nil
}

// StartStdioHandler starts the same stdio adapter without opening an HTTP
// listener. Embedded callers can mount it on an existing HTTP server.
func StartStdioHandler(parent context.Context, command []string, stderr io.Writer, options Options) (*Bridge, error) {
	if len(command) == 0 || strings.TrimSpace(command[0]) == "" {
		return nil, fmt.Errorf("MCP command is required")
	}
	ctx, cancel := context.WithCancel(parent)
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stderr = stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open MCP command stdin: %w", err)
	}
	// Own the pipe so Wait cannot close stdout before the reader drains the
	// child's final response. StdoutPipe is closed by Wait as the child exits.
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open MCP command stdout: %w", err)
	}
	cmd.Stdout = stdoutWriter

	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stdoutWriter.Close()
		cancel()
		return nil, fmt.Errorf("start MCP command %q: %w", command[0], err)
	}
	_ = stdoutWriter.Close()

	allowedTools := make(map[string]bool, len(options.AllowedTools))
	for _, tool := range options.AllowedTools {
		if normalized := strings.TrimSpace(tool); normalized != "" {
			allowedTools[normalized] = true
		}
	}
	b := &Bridge{
		cancel:         cancel,
		stdin:          stdin,
		outputs:        make(chan childOutput, 16),
		done:           make(chan struct{}),
		readerDone:     make(chan struct{}),
		requestTimeout: defaultRequestTimeout,
		allowedTools:   allowedTools,
		streamContext:  ctx,
	}

	stopClosing := context.AfterFunc(ctx, func() { _ = stdout.Close() })
	go func() {
		defer close(b.readerDone)
		defer stdout.Close()
		defer stopClosing()
		b.readChild(stdout)
	}()
	go func() {
		err := cmd.Wait()
		b.processMu.Lock()
		b.processErr = err
		b.processMu.Unlock()
		close(b.done)
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
	if b.listener == nil {
		return ""
	}
	return "http://" + b.listener.Addr().String()
}

// net/http gives newly accepted, unused connections a five-second grace period
// during Shutdown. Speculative client dials must not hold bridge cleanup open.
func (b *Bridge) trackHTTPConn(conn net.Conn, state http.ConnState) {
	b.httpConnMu.Lock()
	defer b.httpConnMu.Unlock()
	if state != http.StateNew {
		delete(b.httpNewConns, conn)
		return
	}
	if b.httpClosing {
		_ = conn.Close()
		return
	}
	if b.httpNewConns == nil {
		b.httpNewConns = map[net.Conn]struct{}{}
	}
	b.httpNewConns[conn] = struct{}{}
}

func (b *Bridge) closeUnusedHTTPConns() {
	b.httpConnMu.Lock()
	b.httpClosing = true
	conns := b.httpNewConns
	b.httpNewConns = nil
	b.httpConnMu.Unlock()
	for conn := range conns {
		_ = conn.Close()
	}
}

// Close stops accepting HTTP traffic and terminates the child process.
func (b *Bridge) Close(ctx context.Context) error {
	var closeErr error
	b.closeOnce.Do(func() {
		if b.httpServer != nil {
			b.closeUnusedHTTPConns()
			if err := b.httpServer.Shutdown(ctx); err != nil {
				closeErr = fmt.Errorf("shutdown MCP HTTP server: %w", err)
				_ = b.httpServer.Close()
			}
		}
		_ = b.stdin.Close()
		b.cancel()

		select {
		case <-b.done:
		case <-ctx.Done():
			if closeErr == nil {
				closeErr = fmt.Errorf("wait for MCP child: %w", ctx.Err())
			}
		}
	})
	return closeErr
}

func (b *Bridge) readChild(stdout io.Reader) {
	ctx := context.Background()
	if b.streamContext != nil {
		ctx = b.streamContext
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), MaxMessageSize)
	for scanner.Scan() {
		message := bytes.TrimSpace(scanner.Bytes())
		if len(message) == 0 {
			continue
		}
		copyOfMessage := append([]byte(nil), message...)
		select {
		case b.outputs <- childOutput{message: copyOfMessage}:
		case <-ctx.Done():
			return
		}
	}

	err := scanner.Err()
	if err == nil {
		err = io.EOF
	}
	select {
	case b.outputs <- childOutput{err: err}:
	case <-ctx.Done():
	}
}

// ServeHTTP translates Streamable HTTP POSTs into newline-delimited stdio
// JSON-RPC. Legacy clients that accept SSE receive notifications as they arrive;
// other clients receive a single finite response.
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	// A browser Origin has no reason to reach this loopback bridge. Reject it
	// even when the request arrived through the public relay, so DNS rebinding
	// cannot turn a local MCP process into a browser-accessible capability.
	if r.Header.Get("Origin") != "" {
		http.Error(w, "browser origins are not allowed", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodPost:
		b.handlePOST(w, r)
	case http.MethodDelete:
		if !b.deleteSession(r.Header.Get("Mcp-Session-Id")) {
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
	modern, ok := validateProtocolRequest(w, r, body, incoming)
	if !ok {
		return
	}
	if !modern && (incoming.Method != "initialize" || r.Header.Get("Mcp-Session-Id") != "") && !b.validSession(r.Header.Get("Mcp-Session-Id")) {
		http.Error(w, "unknown MCP session", http.StatusNotFound)
		return
	}
	if incoming.Method == "tools/call" && !b.toolCallAllowed(body) {
		writeToolDenied(w, incoming.ID)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), b.requestTimeout)
	defer cancel()
	if !modern && !hasID(incoming.ID) && incoming.Method == "notifications/cancelled" {
		if err := b.cancelLegacyRequest(ctx, r.Header.Get("Mcp-Session-Id"), body); err != nil {
			writeRequestError(w, incoming.ID, err, "local MCP process is unavailable")
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err := b.acquireRequest(ctx); err != nil {
		writeRequestError(w, incoming.ID, err, "local MCP request could not start")
		return
	}
	defer func() { <-b.requestGate }()

	// Notifications and responses do not receive an HTTP response body.
	if !hasID(incoming.ID) || incoming.Method == "" {
		if modern {
			// The modern core has no client-to-server notifications. A
			// notification POST can still be acknowledged without handing
			// untrusted data to the local process.
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if err := b.writeChild(ctx, body); err != nil {
			writeRequestError(w, incoming.ID, err, "local MCP process is unavailable")
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if modern {
		if err := b.initializeChild(ctx); err != nil {
			writeRequestError(w, incoming.ID, err, "local MCP process could not initialize")
			return
		}
		if incoming.Method == "server/discover" {
			b.writeDiscover(w, incoming.ID)
			return
		}
	} else if incoming.Method == "initialize" && b.childInitialized {
		b.writeCachedInitialize(w, incoming.ID)
		return
	}
	if modern {
		body = legacyChildRequest(body)
	}
	// Remote callers may reuse IDs, including after a timeout. Give every
	// admitted child call a distinct ID so a late result cannot satisfy a
	// later caller's request.
	childID := b.nextChildID()
	body = replaceMessageID(body, childID)

	// Publish the mapping and write the request under the same lock used by
	// cancellation, so a notification cannot overtake its child request.
	b.cancellationMu.Lock()
	if !modern && incoming.Method != "initialize" {
		b.cancellableRequest = &legacyRequest{r.Header.Get("Mcp-Session-Id"), incoming.ID, childID, ctx}
	}
	err = b.writeChild(ctx, body)
	b.cancellationMu.Unlock()
	defer func() {
		// Stop any cancellation write before waiting for its lock, including
		// when the child completes while that write is backpressured.
		cancel()
		b.cancellationMu.Lock()
		b.cancellableRequest = nil
		b.cancellationMu.Unlock()
	}()
	if err != nil {
		writeRequestError(w, incoming.ID, err, "local MCP process is unavailable")
		return
	}

	// Initialization must retain its notifications until the session header is
	// available. Modern requests retain their existing finite response contract.
	acceptsSSE := acceptsEventStream(r)
	streamLegacy := !modern && incoming.Method != "initialize" && acceptsSSE
	streaming := false
	controller := http.NewResponseController(w)
	var stopWrite func()
	defer func() {
		if stopWrite != nil {
			stopWrite()
		}
	}()
	stream := func(message []byte) error {
		if !streaming {
			// Reserve a bounded window after the child request deadline for a
			// terminal timeout event. Expiring the writer at the request deadline
			// would prevent even a connected consumer from receiving that error.
			deadline, _ := ctx.Deadline()
			_ = controller.SetWriteDeadline(deadline.Add(streamWriteGrace))
			canceled := make(chan struct{})
			stop := context.AfterFunc(ctx, func() {
				// Disconnects still interrupt blocked writes immediately; a
				// timeout keeps the write deadline above for its terminal event.
				if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
					_ = controller.SetWriteDeadline(time.Now())
				}
				close(canceled)
			})
			stopWrite = func() {
				if !stop() {
					<-canceled
				}
				_ = controller.SetWriteDeadline(time.Time{})
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			streaming = true
		}
		if _, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", message); err != nil {
			return err
		}
		return controller.Flush()
	}
	writeError := func(status int, message string) {
		if streaming {
			_ = stream(bridgeErrorMessage(incoming.ID, message))
			return
		}
		writeBridgeError(w, status, incoming.ID, message)
	}
	var events [][]byte
	eventBytes := 0
	for {
		select {
		case output := <-b.outputs:
			if output.err != nil {
				writeError(http.StatusBadGateway, "local MCP process exited")
				return
			}

			var outgoing envelope
			if !json.Valid(output.message) || json.Unmarshal(output.message, &outgoing) != nil {
				writeError(http.StatusBadGateway, "local MCP process wrote invalid JSON-RPC")
				return
			}

			if outgoing.Method == "" && sameID(outgoing.ID, childID) {
				response := replaceMessageID(output.message, incoming.ID)
				if incoming.Method == "initialize" {
					b.cacheInitialize(response)
				}
				if incoming.Method == "tools/list" {
					response = b.filterToolsList(response)
				}
				if incoming.Method == "initialize" && b.childInitialized {
					if !b.setNewSession(w) {
						return
					}
				}
				if modern && methodNotFound(response) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write(response)
					return
				}
				if streaming {
					_ = stream(response)
				} else {
					b.writeMCPResponse(w, r, events, response)
				}
				return
			}

			if outgoing.Method != "" && hasID(outgoing.ID) {
				// The current tunn data path cannot deliver a server request and
				// receive the client's answer before the outer HTTP response ends.
				// Fail that capability explicitly so the child can continue and
				// potentially return an error for the original call.
				_ = b.rejectChildRequest(ctx, outgoing.ID)
				continue
			}

			// Preserve child notifications when the remote client accepts SSE.
			if outgoing.Method != "" {
				eventBytes += len(output.message)
				if eventBytes > MaxMessageSize {
					writeError(http.StatusBadGateway, "local MCP notifications are too large")
					return
				}
				if streamLegacy {
					if err := stream(output.message); err != nil {
						return
					}
				} else if acceptsSSE {
					events = append(events, output.message)
				}
			}

		case <-ctx.Done():
			if !streaming {
				writeRequestError(w, incoming.ID, ctx.Err(), "local MCP request failed")
			} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				writeError(http.StatusGatewayTimeout, "local MCP request timed out")
			}
			return
		}
	}
}

func (b *Bridge) cancelLegacyRequest(ctx context.Context, sessionID string, body []byte) error {
	var notification struct {
		Params map[string]json.RawMessage `json:"params"`
	}
	if json.Unmarshal(body, &notification) != nil {
		return nil
	}
	b.cancellationMu.Lock()
	defer b.cancellationMu.Unlock()
	request := b.cancellableRequest
	if request == nil || request.ctx.Err() != nil || request.sessionID != sessionID || !sameID(request.remoteID, notification.Params["requestId"]) {
		return nil
	}
	// Keep the mapping locked through the write. A late cancellation must not
	// wait on requestGate and then pick up a later call that reused the ID.
	notification.Params["requestId"] = request.childID
	var message map[string]json.RawMessage
	_ = json.Unmarshal(body, &message)
	message["params"], _ = json.Marshal(notification.Params)
	encoded, _ := json.Marshal(message)
	// The write belongs to both HTTP handlers. Ending the target request must
	// interrupt a blocked pipe write before its cleanup can release requestGate.
	writeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(request.ctx, cancel)
	defer stop()
	err := b.writeChild(writeCtx, encoded)
	if request.ctx.Err() != nil && ctx.Err() == nil {
		return nil
	}
	return err
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
	if len(events) > 0 && acceptsEventStream(r) {
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

// Only an explicit, nonzero SSE media range enables progress streaming.
func acceptsEventStream(r *http.Request) bool {
	for _, value := range r.Header.Values("Accept") {
		for _, part := range strings.Split(value, ",") {
			mediaType, params, err := mime.ParseMediaType(part)
			if err != nil || mediaType != "text/event-stream" {
				continue
			}
			if q, ok := params["q"]; ok {
				quality, err := strconv.ParseFloat(q, 64)
				if err != nil || !(quality > 0 && quality <= 1) {
					continue
				}
			}
			return true
		}
	}
	return false
}

func (b *Bridge) acquireRequest(ctx context.Context) error {
	b.requestGateOnce.Do(func() { b.requestGate = make(chan struct{}, 1) })
	select {
	case b.requestGate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-b.requestGate
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *Bridge) nextChildID() json.RawMessage {
	b.requestSequence++
	id, _ := json.Marshal(fmt.Sprintf("tunn-request-%d", b.requestSequence))
	return id
}

// Both callers supply validated JSON-RPC objects and valid JSON IDs.
func replaceMessageID(message []byte, id json.RawMessage) []byte {
	var object map[string]json.RawMessage
	_ = json.Unmarshal(message, &object)
	object["id"] = id
	encoded, _ := json.Marshal(object)
	return encoded
}

func (b *Bridge) writeChild(ctx context.Context, message []byte) error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	// StdinPipe is an os.File backed by a pollable pipe. Bound writes as well
	// as reads: a child that stops reading must not hold the queue indefinitely.
	if pipe, ok := b.stdin.(interface{ SetWriteDeadline(time.Time) error }); ok {
		deadline, _ := ctx.Deadline()
		if err := pipe.SetWriteDeadline(deadline); err != nil {
			return err
		}
		canceled := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			_ = pipe.SetWriteDeadline(time.Now())
			close(canceled)
		})
		defer func() {
			if !stop() {
				<-canceled
			}
			_ = pipe.SetWriteDeadline(time.Time{})
		}()
	}

	line := append(append([]byte(nil), message...), '\n')
	n, err := b.stdin.Write(line)
	if n > 0 && n < len(line) {
		// A partial JSON line cannot be safely resumed by a later request.
		_ = b.stdin.Close()
		if b.cancel != nil {
			b.cancel()
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (b *Bridge) rejectChildRequest(ctx context.Context, id json.RawMessage) error {
	response := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"client-side MCP requests are not supported by this tunn preview"}}`,
		id,
	)
	return b.writeChild(ctx, []byte(response))
}

func (b *Bridge) validSession(got string) bool {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if !b.sessionStarted && got == "" {
		return true
	}
	expires, exists := b.sessions[got]
	return exists && time.Now().Before(expires)
}

func (b *Bridge) setNewSession(w http.ResponseWriter) bool {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if b.sessions == nil {
		b.sessions = make(map[string]time.Time)
	}
	now := time.Now()
	for id, expires := range b.sessions {
		if !now.Before(expires) {
			delete(b.sessions, id)
		}
	}
	if len(b.sessions) >= 1024 {
		http.Error(w, "MCP session capacity reached", http.StatusServiceUnavailable)
		return false
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		http.Error(w, "Could not create MCP session", http.StatusInternalServerError)
		return false
	}
	id := hex.EncodeToString(random)
	b.sessions[id] = now.Add(time.Hour)
	b.sessionStarted = true
	w.Header().Set("Mcp-Session-Id", id)
	return true
}

func (b *Bridge) deleteSession(id string) bool {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	expires, exists := b.sessions[id]
	delete(b.sessions, id)
	return exists && time.Now().Before(expires)
}

func hasID(id json.RawMessage) bool {
	trimmed := bytes.TrimSpace(id)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func sameID(left, right json.RawMessage) bool {
	left, right = bytes.TrimSpace(left), bytes.TrimSpace(right)
	if len(left) > 0 && len(right) > 0 && left[0] == '"' && right[0] == '"' {
		var leftString, rightString string
		return json.Unmarshal(left, &leftString) == nil && json.Unmarshal(right, &rightString) == nil && leftString == rightString
	}
	return bytes.Equal(left, right)
}

func writeBridgeError(w http.ResponseWriter, status int, id json.RawMessage, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(bridgeErrorMessage(id, message), '\n'))
}

func bridgeErrorMessage(id json.RawMessage, message string) []byte {
	encoded, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    -32603,
			"message": message,
		},
	})
	return encoded
}

func writeRequestError(w http.ResponseWriter, id json.RawMessage, err error, message string) {
	if errors.Is(err, context.Canceled) {
		return
	}
	status := http.StatusBadGateway
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		status = http.StatusGatewayTimeout
		message = "local MCP request timed out"
	}
	writeBridgeError(w, status, id, message)
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

// FromStreams exposes a caller-owned stdio stream using the same MCP policy.
// No child process or socket is created, and remote input is never executable.
func FromStreams(parent context.Context, input io.Reader, output io.WriteCloser, options Options) *Bridge {
	ctx, cancel := context.WithCancel(parent)
	tools := make(map[string]bool)
	for _, tool := range options.AllowedTools {
		tools[tool] = true
	}
	b := &Bridge{cancel: cancel, stdin: output, outputs: make(chan childOutput, 1), done: make(chan struct{}), requestTimeout: defaultRequestTimeout, allowedTools: tools, streamContext: ctx}
	go func() { b.readChild(input); close(b.done) }()
	go func() { <-ctx.Done(); _ = output.Close() }()
	return b
}
