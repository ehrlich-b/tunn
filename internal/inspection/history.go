package inspection

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// History belongs to one live publisher connection, never to a reusable name.
// Only sanitized metadata enters it; payloads are counted and discarded.
type History struct {
	mu           sync.RWMutex
	session      string
	events       []Event
	nextID       uint64
	intents      map[uint64]intent
	replayActive bool
}
type intent struct {
	token, binding string
	expires        time.Time
	used           bool
}

func randomToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
func NewHistory() (*History, error) {
	session, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &History{session: session, intents: make(map[uint64]intent)}, nil
}
func (h *History) Session() string { return h.session }

func clone(event Event) Event {
	event.Timing = event.Timing.Clone()
	event.Body = nil
	event.BodyCaptured = false
	event.Headers = make(map[string]string, len(event.Headers))
	// Headers are assigned below by Snapshot/Event while holding the lock.
	return event
}
func snapshot(event Event) Event {
	headers := event.Headers
	event = clone(event)
	for k, v := range headers {
		event.Headers[k] = v
	}
	event.RedactedHeaders = append([]string(nil), event.RedactedHeaders...)
	return event
}
func (h *History) Snapshot() []Event {
	h.mu.RLock()
	defer h.mu.RUnlock()
	events := make([]Event, len(h.events))
	for j, event := range h.events {
		events[j] = snapshot(event)
	}
	return events
}
func (h *History) find(id uint64) (Event, bool) {
	for _, event := range h.events {
		if event.ID == id {
			return snapshot(event), true
		}
	}
	return Event{}, false
}
func (h *History) Event(id uint64) (Event, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.find(id)
}
func (h *History) add(event Event) Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	event.ID = h.nextID
	event = snapshot(event)
	if len(h.events) == EventLimit {
		delete(h.intents, h.events[0].ID)
		copy(h.events, h.events[1:])
		h.events[len(h.events)-1] = event
	} else {
		h.events = append(h.events, event)
	}
	return snapshot(event)
}

// Prepare creates at most one intent per retained event. Binding is a digest
// of the authenticated browser session, never the cookie itself.
func (h *History) Prepare(id uint64, binding string, now time.Time) (string, time.Time, error) {
	token, err := randomToken()
	if err != nil {
		return "", time.Time{}, errors.New("unable to prepare replay")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	event, ok := h.find(id)
	if !ok || !event.Reconstructable {
		return "", time.Time{}, errors.New("replay unavailable for this request")
	}
	if h.replayActive {
		return "", time.Time{}, errors.New("replay already in progress")
	}
	expires := now.Add(time.Minute)
	h.intents[id] = intent{token: token, binding: binding, expires: expires}
	return token, expires, nil
}

// BeginReplay validates reconstruction before consuming a one-use intent. The
// caller must recheck owner, origin and live publisher before calling it.
func (h *History) BeginReplay(id uint64, session, token, binding string, request Request, now time.Time) (Event, string, map[string]string, []byte, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	event, found := h.find(id)
	action := h.intents[id]
	if !found || !event.Reconstructable || session != h.session || token == "" ||
		subtle.ConstantTimeCompare([]byte(token), []byte(action.token)) != 1 ||
		action.binding != binding || action.used || !now.Before(action.expires) || h.replayActive {
		return Event{}, "", nil, nil, nil, errors.New("prepare a new replay; this intent is unavailable, expired or already used")
	}
	path, headers, body, err := Reconstruct(event, request)
	if err != nil {
		return Event{}, "", nil, nil, nil, err
	}
	action.used = true
	h.intents[id] = action
	h.replayActive = true
	var once sync.Once
	done := func() { once.Do(func() { h.mu.Lock(); h.replayActive = false; h.mu.Unlock() }) }
	return event, path, headers, body, done, nil
}

// Capture records HTTP body counts only. It retains no request/response data.
type Capture struct {
	mu               sync.Mutex
	history          *History
	event            Event
	expected         int64
	failed, finished bool
}

func (h *History) Begin(id, method, path string, headers map[string]string, length int64, replayOf uint64) *Capture {
	event := Metadata(id, method, path, headers)
	event.At, event.Protocol, event.ReplayOf = time.Now(), "http", replayOf
	event.BodyComplete = length == 0
	return &Capture{history: h, event: event, expected: length}
}
func (c *Capture) RequestRead(n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished {
		return
	}
	c.event.RequestBytes += int64(n)
	if c.expected == 0 && n > 0 {
		c.expected = -1
		c.event.BodyComplete = false
	}
	if c.expected >= 0 {
		c.event.BodyComplete = c.event.RequestBytes == c.expected
	}
	if err == io.EOF {
		c.event.BodyComplete = c.expected < 0 || c.event.RequestBytes == c.expected
	}
	if err != nil && err != io.EOF {
		c.failed = true
		c.event.BodyComplete = false
	}
	c.event.Truncated = c.event.RequestBytes > BodyLimit
}
func (c *Capture) SetTiming(timing *Timing) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.finished {
		c.event.Timing = timing.Clone()
	}
}

func (c *Capture) ResponseWrite(n int) {
	c.mu.Lock()
	if !c.finished {
		c.event.ResponseBytes += int64(n)
	}
	c.mu.Unlock()
}
func (c *Capture) Finish(status int, contentType, reason string) Event {
	c.mu.Lock()
	if c.finished {
		c.mu.Unlock()
		return Event{}
	}
	c.finished = true
	event := c.event
	event.Status, event.DurationMS, event.TerminalReason = status, time.Since(event.At).Milliseconds(), reason
	if strings.HasPrefix(strings.ToLower(contentType), "text/event-stream") {
		event.Protocol = "sse"
	}
	event.Reconstructable = event.Protocol == "http" && event.Method != http.MethodConnect && event.BodyComplete && !c.failed && !event.Truncated && !event.MetadataTruncated && reason == "complete"
	event.Replayable = event.Reconstructable && !event.QueryRedacted && len(event.RedactedHeaders) == 0 && event.RequestBytes == 0
	if reason != "complete" {
		event.Error = reason
	}
	c.mu.Unlock()
	return c.history.add(event)
}

type Body struct {
	io.ReadCloser
	Capture *Capture
}

func (b *Body) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.Capture.RequestRead(n, err)
	return n, err
}

// Unwrap preserves full-duplex/deadline control on HTTP/1 and HTTP/2. This
// writer is used only for ordinary HTTP, never a hijacked WebSocket or TCP.
type Response struct {
	http.ResponseWriter
	Capture     *Capture
	Status      int
	ContentType string
	committed   bool
}

func (w *Response) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *Response) WriteHeader(status int) {
	if !w.committed && status >= 200 {
		w.committed = true
		w.Status, w.ContentType = status, w.Header().Get("Content-Type")
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *Response) Write(p []byte) (int, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.Capture.ResponseWrite(n)
	return n, err
}
func (w *Response) Flush() {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
