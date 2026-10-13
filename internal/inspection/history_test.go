package inspection

import (
	"encoding/json"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func historyFixture(t *testing.T) (*History, Event) {
	t.Helper()
	h, err := NewHistory()
	if err != nil {
		t.Fatal(err)
	}
	c := h.Begin("connection", "POST", "/hooks?token=QUERY_SENTINEL", map[string]string{"Host": "api.example.test", "Content-Type": "application/json", "Authorization": "HEADER_SENTINEL", "X-Custom": "CUSTOM_SENTINEL"}, 4, 0)
	c.RequestRead(4, io.EOF)
	c.ResponseWrite(12)
	return h, c.Finish(202, "application/json", "complete")
}
func TestInspectionHistoryMetadataAndEviction(t *testing.T) {
	h, event := historyFixture(t)
	if !event.Reconstructable || event.Replayable || event.BodyCaptured || len(event.Body) != 0 || event.RequestBytes != 4 || event.ResponseBytes != 12 {
		t.Fatalf("unexpected event: %+v", event)
	}
	data, err := json.Marshal(h.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"QUERY_SENTINEL", "HEADER_SENTINEL", "CUSTOM_SENTINEL", `"body":`} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("retained forbidden data %q", forbidden)
		}
	}
	token, _, err := h.Prepare(event.ID, "owner-session", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for j := 0; j < EventLimit; j++ {
		h.Begin("c", "GET", "/", map[string]string{"Host": "api.example.test"}, 0, 0).Finish(200, "text/plain", "complete")
	}
	if len(h.Snapshot()) != EventLimit {
		t.Fatal("history limit changed")
	}
	if _, ok := h.Event(event.ID); ok {
		t.Fatal("oldest request retained")
	}
	if len(h.intents) != 0 {
		t.Fatal("evicted replay intent retained")
	}
	if _, _, _, _, _, err := h.BeginReplay(event.ID, h.Session(), token, "owner-session", Request{}, time.Now()); err == nil {
		t.Fatal("evicted request replayed")
	}
	copy := h.Snapshot()
	copy[0].Headers["Host"] = "changed"
	current, _ := h.Event(copy[0].ID)
	if current.Headers["Host"] == "changed" {
		t.Fatal("snapshot mutated history")
	}
	other, err := NewHistory()
	if err != nil {
		t.Fatal(err)
	}
	if h.Session() == other.Session() {
		t.Fatal("connection sessions reused")
	}
}
func TestInspectionHistoryIntentGuards(t *testing.T) {
	h, event := historyFixture(t)
	now := time.Now()
	token, _, err := h.Prepare(event.ID, "owner-session", now)
	if err != nil {
		t.Fatal(err)
	}
	path := "/hooks?token=restored"
	body := []byte("data")
	request := Request{Path: &path, Body: &body, Headers: map[string]string{"Host": "api.example.test", "Content-Type": "application/json", "Authorization": "explicit", "X-Custom": "explicit"}}
	cases := []struct {
		name, session, token, binding string
		at                            time.Time
		request                       Request
	}{
		{"another connection", "wrong", token, "owner-session", now, request},
		{"another action", h.Session(), "wrong", "owner-session", now, request},
		{"another session", h.Session(), token, "other-owner-session", now, request},
		{"expired", h.Session(), token, "owner-session", now.Add(time.Minute), request},
		{"missing replacements", h.Session(), token, "owner-session", now, Request{}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, _, _, err := h.BeginReplay(event.ID, test.session, test.token, test.binding, test.request, test.at); err == nil {
				t.Fatal("invalid intent accepted")
			}
		})
	}
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for j := 0; j < 8; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, _, _, done, err := h.BeginReplay(event.ID, h.Session(), token, "owner-session", request, now); err == nil {
				accepted.Add(1)
				done()
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("%d dispatches for one intent", accepted.Load())
	}
	if _, _, _, _, _, err := h.BeginReplay(event.ID, h.Session(), token, "owner-session", request, now); err == nil {
		t.Fatal("used action accepted")
	}
}
func TestInspectionHistoryReplayEligibility(t *testing.T) {
	cases := []struct {
		name                string
		expected            int64
		n                   int
		err                 error
		contentType, reason string
		eligible            bool
	}{
		{"complete", 4, 4, io.EOF, "application/json", "complete", true},
		{"declared length consumed", 4, 4, nil, "text/plain", "complete", true},
		{"unknown length complete", -1, 4, io.EOF, "text/plain", "complete", true},
		{"partial", 4, 3, nil, "text/plain", "complete", false},
		{"reader error", 4, 4, io.ErrUnexpectedEOF, "text/plain", "complete", false},
		{"body limit", BodyLimit + 1, BodyLimit + 1, io.EOF, "text/plain", "complete", false},
		{"SSE", 0, 0, io.EOF, "text/event-stream", "complete", false},
		{"delivery error", 0, 0, io.EOF, "text/plain", "proxy_error", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			h, err := NewHistory()
			if err != nil {
				t.Fatal(err)
			}
			c := h.Begin("c", "POST", "/", map[string]string{"Host": "api.example.test"}, test.expected, 0)
			c.RequestRead(test.n, test.err)
			event := c.Finish(200, test.contentType, test.reason)
			if event.Reconstructable != test.eligible {
				t.Fatalf("reconstructable=%t", event.Reconstructable)
			}
			if second := c.Finish(200, test.contentType, test.reason); second.ID != 0 || len(h.Snapshot()) != 1 {
				t.Fatal("duplicate terminal event")
			}
		})
	}
}
