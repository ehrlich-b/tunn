package terminal

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMachineOutputAndTerminalSafety(t *testing.T) {
	var out, errout bytes.Buffer
	o := New(&out, &errout, true)
	o.Color = true
	o.Route("https://app.example", "localhost:3000", "Only you")
	o.State("auth_expired", "Sign in again", "Tunnel stopped", "tunn login", 0)
	o.Request(Event{Method: "GET\x1b[2J", Path: "/hello\nnext", Status: 500, At: time.Now().Format(time.RFC3339Nano)})
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(e.Method+e.Path, "\x1b\n") {
			t.Fatal("terminal controls retained")
		}
	}
	if strings.Contains(out.String(), "\x1b") || errout.Len() == 0 {
		t.Fatal("mixed machine output")
	}
}
func TestNarrowFailureAndHistory(t *testing.T) {
	var out, errout bytes.Buffer
	o := New(&out, &errout, false)
	o.Width = 40
	o.Request(Event{Method: "POST", Path: "/hooks", Status: 500, At: "2026-10-13T13:42:15Z", DurationMS: 12})
	o.State("unreachable", "Local app unreachable", "Edge connected; localhost:3000 did not respond", "curl -I http://localhost:3000", 0)
	if !strings.Contains(out.String(), "[x]  500") || strings.Contains(out.String(), "[ok]") {
		t.Fatal(out.String())
	}
	if !strings.Contains(errout.String(), "curl -I http://localhost:3000") {
		t.Fatal(errout.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if len([]rune(line)) > 40 {
			t.Fatal("narrow output overflows", line)
		}
	}
}

func TestNarrowUnicodeAndLargeCounts(t *testing.T) {
	var out, errout bytes.Buffer
	o := New(&out, &errout, false)
	o.Width = 40
	o.Request(Event{At: "2026-10-13T13:42:15Z", Method: "GET", Path: "/日本語/very-long-path-that-does-not-fit", Status: 200, RequestBytes: 104857600, ResponseBytes: 104857600, DurationMS: 1200})
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if cells(line) > 40 {
			t.Fatal("display cells overflow", line)
		}
	}
}
