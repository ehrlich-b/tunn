package client

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "embed"

	"github.com/ehrlich-b/tunn/internal/inspection"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

const (
	inspectBodyLimit     = inspection.BodyLimit
	inspectEventLimit    = inspection.EventLimit
	inspectMetadataLimit = inspection.MetadataLimit
	inspectResponseLimit = 1024 * 1024
	redacted             = inspection.Redacted
)

// InspectionEvent is shared with the dashboard's metadata-only snapshots.
type InspectionEvent = inspection.Event

// InspectionMetrics has fixed keys, with no account, path, or credential labels.
// These observe publisher admissions; ingress denials stay in the relay ledger.
type InspectionMetrics struct {
	ActiveStreams    int64  `json:"active_streams"`
	Completed        uint64 `json:"completed"`
	DeniedAdmissions uint64 `json:"denied_admissions"`
	Reconnects       uint64 `json:"reconnects"`
	ExportDrops      uint64 `json:"export_drops"`
	HistoryEvictions uint64 `json:"history_evictions"`
	ReplayDispatches uint64 `json:"replay_dispatches"`
}

type replayAction struct {
	token      string
	used, busy bool
}

// Inspector retains at most 50 terminal events and one replay action per event.
// Its target is a configuration snapshot, independent of later client changes.
type Inspector struct {
	// OnEvent observes terminal metadata. Set before serving; callbacks may run concurrently.
	OnEvent      func(InspectionEvent, InspectionMetrics)
	mu           sync.RWMutex
	events       []InspectionEvent
	nextID       uint64
	target       *ServeClient
	captureBody  bool
	replayActive bool
	metrics      InspectionMetrics
	actions      map[uint64]replayAction
	host, token  string
}

func NewInspector(target *ServeClient) *Inspector { return NewInspectorWithBodyCapture(target, false) }
func NewInspectorWithBodyCapture(target *ServeClient, enabled bool) *Inspector {
	config := ServeClient{
		TargetURL: target.TargetURL, PublicPath: target.PublicPath,
		UpstreamPath: target.UpstreamPath, UpstreamRawQuery: target.UpstreamRawQuery,
		TargetNetwork: target.TargetNetwork, DialAddress: target.DialAddress,
		DialContext: target.DialContext, LocalDialContext: target.LocalDialContext,
		LocalTLSConfig: target.localTLSConfig(), HTTPTransport: target.HTTPTransport, HTTPTimeout: target.HTTPTimeout,
		SkipLocalTLSVerify: target.SkipLocalTLSVerify, RequireUpstreamAuth: target.RequireUpstreamAuth,
	}
	return &Inspector{target: &config, captureBody: enabled, actions: make(map[uint64]replayAction)}
}

func randomInspectorToken() (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(secret[:]), nil
}

// StartInspector uses a random literal loopback port; the fragment is never sent
// in HTTP requests. No captured application content is sent to the relay.
func (i *Inspector) StartInspector(ctx context.Context) (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	secret, err := randomInspectorToken()
	if err != nil {
		_ = listener.Close()
		return "", err
	}
	i.host, i.token = listener.Addr().String(), secret
	server := &http.Server{Handler: i, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() { _ = server.Serve(listener) }()
	return "http://" + i.host + "/#" + i.token, nil
}

// Only standard representation/negotiation headers retain values. Custom
// headers, signatures, credentials, cookies and forwarding identities redact.
// Platform credentials stay out of inspection even when an application echoes
// one in otherwise visible metadata or an explicitly captured body.
func inspectionCredential(value string) bool          { return inspection.Credential(value) }
func safeInspectionHeader(key string) bool            { return inspection.SafeHeader(key) }
func inspectionPath(path string) (string, bool, bool) { return inspection.Path(path) }

func (i *Inspector) begin(method, path string, headers map[string]string) *inspectionCapture {
	return i.beginConnection("", "http", method, path, headers)
}
func (i *Inspector) beginConnection(id, protocol, method, path string, headers map[string]string) *inspectionCapture {
	if protocol != "http" && protocol != "sse" && protocol != "websocket" && protocol != "tcp" {
		protocol = "unsupported"
	}
	if protocol == "http" {
		if method == http.MethodConnect {
			protocol = "tcp"
		} else {
			for key, value := range headers {
				if strings.EqualFold(key, "Upgrade") && value != "" {
					protocol = "unsupported"
					if strings.EqualFold(value, "websocket") {
						protocol = "websocket"
					}
					break
				}
			}
		}
	}
	event := inspection.Metadata(id, method, path, headers)
	event.At, event.Protocol = time.Now(), strings.Clone(protocol)
	event.BodyCaptured = i.captureBody && protocol == "http"
	i.mu.Lock()
	i.metrics.ActiveStreams++
	i.mu.Unlock()
	return &inspectionCapture{inspector: i, expectedBytes: -1, event: event}
}

// beginFields follows the wire representation selected by the HTTP decoder.
// Repeated fields cannot be reconstructed faithfully from the single-value
// inspection format, so retain sanitized metadata but disable reconstruction.
func (i *Inspector) beginFields(id, protocol, method, path string, legacy map[string]string, fields []*pb.HttpHeader) *inspectionCapture {
	if len(fields) == 0 {
		return i.beginConnection(id, protocol, method, path, legacy)
	}
	headers := make(map[string]string)
	incomplete := len(fields) > 64
	for _, field := range fields[:min(len(fields), 64)] {
		if field == nil {
			incomplete = true
			continue
		}
		key := http.CanonicalHeaderKey(field.Name)
		if _, exists := headers[key]; exists {
			incomplete = true
			continue
		}
		headers[key] = field.Value
	}
	capture := i.beginConnection(id, protocol, method, path, headers)
	capture.event.MetadataTruncated = capture.event.MetadataTruncated || incomplete
	return capture
}

type inspectionCapture struct {
	mu            sync.Mutex
	inspector     *Inspector
	event         InspectionEvent
	finished      bool
	expectedBytes int64
}

func (c *inspectionCapture) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished {
		return len(data), nil
	}
	c.event.RequestBytes += int64(len(data))
	// net/http treats zero ContentLength with a nonempty body as unknown.
	// Once bytes arrive, require EOF instead of treating zero as a body limit.
	if c.expectedBytes == 0 && len(data) > 0 {
		c.expectedBytes = -1
		c.event.BodyComplete = false
	}
	if c.expectedBytes >= 0 {
		c.event.BodyComplete = c.event.RequestBytes == c.expectedBytes
	}
	if c.event.BodyCaptured {
		space := inspectBodyLimit - len(c.event.Body)
		if space > 0 {
			c.event.Body = append(c.event.Body, data[:min(space, len(data))]...)
		}
	}
	c.event.Truncated = c.event.RequestBytes > inspectBodyLimit
	return len(data), nil
}

// A known HTTP Content-Length defines the whole body even when the target
// responds before the transport's asynchronous writer performs its EOF read.
func (c *inspectionCapture) expectLength(length int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if length >= 0 && !c.finished {
		c.expectedBytes = length
		c.event.BodyComplete = c.event.RequestBytes == length
	}
}
func (c *inspectionCapture) complete() {
	c.mu.Lock()
	if !c.finished {
		c.event.BodyComplete = c.expectedBytes < 0 || c.event.RequestBytes == c.expectedBytes
	}
	c.mu.Unlock()
}
func (c *inspectionCapture) response(n int) {
	c.mu.Lock()
	if !c.finished {
		c.event.ResponseBytes += int64(n)
	}
	c.mu.Unlock()
}
func (c *inspectionCapture) setProtocol(protocol string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if protocol == "sse" {
		c.event.Protocol = protocol
		c.event.Body = nil
		c.event.BodyCaptured = false
	}
}
func (c *inspectionCapture) finish(status int, responseBytes int64, failure string) {
	reason := "complete"
	if failure != "" {
		reason = "target_error"
	}
	c.finishReason(status, responseBytes, reason)
}
func (c *inspectionCapture) finishReason(status int, responseBytes int64, reason string) InspectionEvent {
	c.mu.Lock()
	if c.finished {
		c.mu.Unlock()
		return InspectionEvent{}
	}
	c.finished = true
	if inspectionCredential(string(c.event.Body)) {
		c.event.Body = nil
		c.event.BodyCaptured = false
	}
	event := c.event
	event.Body = append([]byte(nil), event.Body...)
	event.Status = status
	if responseBytes >= 0 {
		event.ResponseBytes = responseBytes
	}
	event.DurationMS = time.Since(event.At).Milliseconds()
	event.TerminalReason = reason
	if reason != "complete" && reason != "peer_closed" {
		event.Error = reason
	}
	event.Reconstructable = event.Protocol == "http" && event.Method != "CONNECT" && event.BodyComplete && !event.Truncated && !event.MetadataTruncated
	event.Replayable = event.Reconstructable && !event.QueryRedacted && len(event.RedactedHeaders) == 0 && (event.BodyCaptured || event.RequestBytes == 0)
	c.mu.Unlock()
	c.inspector.mu.Lock()
	c.inspector.metrics.ActiveStreams--
	c.inspector.mu.Unlock()
	return c.inspector.add(event)
}

type inspectionReader struct {
	reader   io.Reader
	capture  *inspectionCapture
	response bool
}

func (r *inspectionReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		if r.response {
			r.capture.response(n)
		} else {
			_, _ = r.capture.Write(p[:n])
		}
	}
	if err == io.EOF && !r.response {
		r.capture.complete()
	}
	return n, err
}
func (r *inspectionReader) Close() error {
	if closer, ok := r.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func cloneInspectionEvent(event InspectionEvent, body bool) InspectionEvent {
	event.Timing = event.Timing.Clone()
	clean := make(map[string]string, len(event.Headers))
	for k, v := range event.Headers {
		clean[k] = v
	}
	event.Headers = clean
	event.RedactedHeaders = append([]string(nil), event.RedactedHeaders...)
	if body {
		event.Body = append([]byte(nil), event.Body...)
	} else {
		event.Body = nil
		event.BodyCaptured = false
		event.Replayable = event.Replayable && event.RequestBytes == 0
	}
	return event
}
func (i *Inspector) add(event InspectionEvent) InspectionEvent {
	i.mu.Lock()

	i.nextID++
	event.ID = i.nextID
	i.metrics.Completed++
	event = cloneInspectionEvent(event, true)
	if len(i.events) == inspectEventLimit {
		delete(i.actions, i.events[0].ID)
		copy(i.events, i.events[1:])
		i.events[len(i.events)-1] = event
		i.metrics.HistoryEvictions++
	} else {
		i.events = append(i.events, event)
	}
	result := cloneInspectionEvent(event, true)
	metrics := i.metrics
	i.mu.Unlock()
	if i.OnEvent != nil {
		i.OnEvent(cloneInspectionEvent(result, false), metrics)
	}
	return result
}
func (i *Inspector) list() []InspectionEvent {
	i.mu.RLock()
	defer i.mu.RUnlock()
	events := make([]InspectionEvent, len(i.events))
	for j, event := range i.events {
		events[j] = cloneInspectionEvent(event, true)
	}
	return events
}
func (i *Inspector) snapshot() InspectionMetrics {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.metrics
}
func (i *Inspector) denied() {
	if i != nil {
		i.mu.Lock()
		i.metrics.DeniedAdmissions++
		i.mu.Unlock()
	}
}
func (i *Inspector) reconnected() {
	if i != nil {
		i.mu.Lock()
		i.metrics.Reconnects++
		i.mu.Unlock()
	}
}
func (i *Inspector) event(id uint64) (InspectionEvent, bool) {
	for _, event := range i.events {
		if event.ID == id {
			return cloneInspectionEvent(event, true), true
		}
	}
	return InspectionEvent{}, false
}

func (i *Inspector) prepare(id uint64) (string, error) {
	token, err := randomInspectorToken()
	if err != nil {
		return "", errors.New("unable to prepare replay")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	event, ok := i.event(id)
	if !ok || !event.Reconstructable {
		return "", errors.New("replay unavailable for this capture")
	}
	if i.replayActive || i.actions[id].busy {
		return "", errors.New("replay already in progress")
	}
	i.actions[id] = replayAction{token: token}
	return token, nil
}

type inspectionReplayInput struct {
	Action  string            `json:"action"`
	Path    *string           `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    *[]byte           `json:"body,omitempty"`
}

func reconstruction(original InspectionEvent, input inspectionReplayInput) (string, map[string]string, []byte, error) {
	return inspection.Reconstruct(original, inspection.Request{Path: input.Path, Headers: input.Headers, Body: input.Body})
}
func (i *Inspector) replay(ctx context.Context, id uint64, input inspectionReplayInput) (InspectionEvent, error) {
	if ctx.Err() != nil {
		return InspectionEvent{}, errors.New("replay canceled before dispatch")
	}
	i.mu.Lock()
	original, found := i.event(id)
	action := i.actions[id]
	if !found || !original.Reconstructable || input.Action == "" || action.token != input.Action || action.used || action.busy || i.replayActive {
		i.mu.Unlock()
		return InspectionEvent{}, errors.New("prepare a new deliberate replay action")
	}
	path, headers, body, err := reconstruction(original, input)
	if err != nil {
		i.mu.Unlock()
		return InspectionEvent{}, err
	}
	action.used = true
	action.busy = true
	i.replayActive = true
	i.actions[id] = action
	i.mu.Unlock()
	defer func() {
		i.mu.Lock()
		i.replayActive = false
		if current, ok := i.actions[id]; ok && current.token == action.token {
			current.busy = false
			i.actions[id] = current
		}
		i.mu.Unlock()
	}()
	capture := i.beginConnection("replay", "http", original.Method, path, headers)
	capture.event.ReplayOf = id
	_, _ = capture.Write(body)
	capture.complete()
	status, received, reason := 0, int64(0), "target_error"
	finish := func() InspectionEvent { return capture.finishReason(status, received, reason) }
	request, err := http.NewRequestWithContext(ctx, original.Method, i.target.targetURL(path), strings.NewReader(string(body)))
	if err != nil {
		return finish(), errors.New("failed to construct replay request")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	request.Host = request.Header.Get("Host")
	request.Header.Del("Host")
	if i.target.RequireUpstreamAuth && strings.TrimSpace(request.Header.Get("Authorization")) == "" {
		reason = "auth_required"
		return finish(), errors.New("upstream Authorization required")
	}
	transport := i.target.inspectionTransport()
	defer transport.CloseIdleConnections()
	timeout := i.target.HTTPTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	var roundTripper http.RoundTripper = transport
	if i.target.HTTPTransport != nil {
		roundTripper = i.target.HTTPTransport
	}
	client := &http.Client{Transport: roundTripper, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	i.mu.Lock()
	i.metrics.ReplayDispatches++
	i.mu.Unlock()
	response, err := client.Do(request)
	if err == nil {
		status = response.StatusCode
		if strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
			capture.setProtocol("sse")
		}
		received, err = io.Copy(io.Discard, io.LimitReader(response.Body, inspectResponseLimit+1))
		_ = response.Body.Close()
		reason = "complete"
		if received > inspectResponseLimit {
			reason = "response_limit"
			err = errors.New("replay response exceeds 1 MiB")
		} else if err != nil {
			reason = "response_error"
		}
	}
	if ctx.Err() != nil {
		reason = "canceled"
		err = ctx.Err()
	}
	result := finish()
	if err != nil {
		return result, errors.New("replay " + reason)
	}
	return result, nil
}
func (i *Inspector) authorized(r *http.Request) bool {
	return i.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Tunn-Inspector-Token")), []byte(i.token)) == 1 && (r.Header.Get("Origin") == "" || r.Header.Get("Origin") == "http://"+i.host)
}
func (i *Inspector) writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		i.mu.Lock()
		i.metrics.ExportDrops++
		i.mu.Unlock()
	}
}
func (i *Inspector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Host != i.host {
		http.Error(w, "invalid host", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-inspector'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		_, _ = io.WriteString(w, inspectorHTML)
		return
	}
	if !i.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/events":
		i.writeJSON(w, i.list())
	case r.Method == http.MethodGet && r.URL.Path == "/api/metrics":
		i.writeJSON(w, i.snapshot())
	case r.Method == http.MethodGet && r.URL.Path == "/api/export":
		events := i.list()
		for j := range events {
			events[j] = cloneInspectionEvent(events[j], false)
		}
		i.writeJSON(w, struct {
			Events  []InspectionEvent `json:"events"`
			Metrics InspectionMetrics `json:"metrics"`
		}{events, i.snapshot()})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/events/"):
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/events/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		id, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			http.Error(w, "invalid delivery ID", http.StatusBadRequest)
			return
		}
		if parts[1] == "prepare" {
			action, err := i.prepare(id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			i.writeJSON(w, struct {
				Action string `json:"action"`
			}{action})
			return
		}
		if parts[1] != "replay" {
			http.NotFound(w, r)
			return
		}
		var input inspectionReplayInput
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128*1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, "invalid replay reconstruction", http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			http.Error(w, "invalid replay reconstruction", http.StatusBadRequest)
			return
		}
		result, err := i.replay(r.Context(), id, input)
		if err != nil && result.ID == 0 {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		// A dispatched failure still returns its event, so the viewer can show it.
		i.writeJSON(w, result)
	default:
		http.NotFound(w, r)
	}
}

//go:embed inspector.html
var inspectorTemplate string

var inspectorHTML = strings.Replace(inspectorTemplate, "// REPLAY_VALIDATION", inspection.ReplayValidationJS, 1)

// Events returns sanitized snapshots for authenticated embedded owner interfaces.
func (i *Inspector) Events() []InspectionEvent { return i.list() }

// Replay performs one explicit action for a fully reconstructable captured request.
func (i *Inspector) Replay(ctx context.Context, id uint64) (InspectionEvent, error) {
	return i.ReplayWithRequest(ctx, id, InspectionReplayRequest{})
}

// InspectionReplayRequest supplies unavailable request data deliberately. Body
// uses JSON's base64 encoding for byte slices, matching the local inspection API.
type InspectionReplayRequest struct {
	Path    *string           `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    *[]byte           `json:"body,omitempty"`
}

// ReplayWithRequest applies the same reconstruction and credential checks as
// the local viewer, with a fresh one-use action for this owner command.
func (i *Inspector) ReplayWithRequest(ctx context.Context, id uint64, request InspectionReplayRequest) (InspectionEvent, error) {
	action, err := i.prepare(id)
	if err != nil {
		return InspectionEvent{}, err
	}
	return i.replay(ctx, id, inspectionReplayInput{Action: action, Path: request.Path, Headers: request.Headers, Body: request.Body})
}
