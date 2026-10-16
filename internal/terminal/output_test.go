package terminal

import (
	"bytes"
	"encoding/json"
	"github.com/ehrlich-b/tunn/internal/inspection"
	"strings"
	"testing"
	"time"
)

func TestMachineOutputAndTerminalSafety(t *testing.T) {
	var out, errout bytes.Buffer
	o := New(&out, &errout, true)
	o.Color = true
	o.Route("https://app.example", "localhost:3000", "private", false)
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
	if !strings.Contains(out.String(), "[x] 500") || strings.Contains(out.String(), "[ok]") {
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

func TestRequestSchemaRetainsZeroMeasurements(t *testing.T) {
	var out, errout bytes.Buffer
	o := New(&out, &errout, true)
	o.Route("https://app.example", "localhost:3000", "public", false)
	o.Request(Event{Method: "POST", Path: "/hooks", Status: 202})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var route, request map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &route); err != nil {
		t.Fatal(err)
	}
	if route["access"] != "public" {
		t.Fatal(route)
	}
	if err := json.Unmarshal([]byte(lines[1]), &request); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"status", "duration_ms", "request_bytes", "response_bytes", "active_streams"} {
		if _, ok := request[key]; !ok {
			t.Fatalf("missing %s: %v", key, request)
		}
		if _, ok := route[key]; ok {
			t.Fatalf("request field on route: %v", route)
		}
	}
}

func TestRedirectedReadingsDoNotDependOnColumns(t *testing.T) {
	var previous string
	for _, width := range []string{"40", "100"} {
		t.Setenv("COLUMNS", width)
		var out, errout bytes.Buffer
		o := New(&out, &errout, false)
		o.Route("https://app.example", "localhost:3000", "public", false)
		o.State("online", "Online", "", "", 0)
		o.Hint("Ctrl+C stops this tunnel")
		o.Request(Event{At: "2026-10-13T13:42:15Z", Method: "POST", Path: "/hooks", Status: 202})
		o.Summary()
		if strings.Contains(out.String(), "Ctrl+C") || strings.Contains(out.String(), "Online") || strings.Contains(out.String(), "Traffic") || strings.Contains(out.String(), "\x1b") {
			t.Fatal(out.String())
		}
		if !strings.Contains(errout.String(), "Ctrl+C") {
			t.Fatal(errout.String())
		}
		if previous != "" && previous != out.String() {
			t.Fatal("redirected output changed with COLUMNS")
		}
		previous = out.String()
	}
}

func TestFortyColumnRequestsUseOneRow(t *testing.T) {
	var out, errout bytes.Buffer
	o := New(&out, &errout, false)
	o.Width = 40
	o.TTY = true
	for _, code := range []int{200, 302, 403, 413, 500} {
		o.Request(Event{At: "2026-10-13T13:42:15Z", Method: "POST", Path: "/upload", Status: code, DurationMS: 18, ActiveStreams: 1})
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 7 || strings.TrimSpace(lines[5]) != "edge cap 100 MiB" {
		t.Fatalf("want heading, 5 rows and the 413 limit: %s", out.String())
	}
	column := strings.Index(lines[0], "RESULT")
	for _, line := range append(lines[1:5], lines[6]) {
		if strings.Index(line, "[") != column {
			t.Fatalf("row out of its columns: %s", out.String())
		}
	}
	for _, line := range lines {
		if cells(line) > 40 {
			t.Fatalf("overflow: %s", line)
		}
	}
	if !strings.Contains(out.String(), "[x] 413") || strings.Contains(out.String(), "open") {
		t.Fatal(out.String())
	}
}

func TestWideUnicodeAndLimitRowsStayWithinTerminal(t *testing.T) {
	for _, width := range []int{70, 100} {
		var out, errout bytes.Buffer
		o := New(&out, &errout, false)
		o.Width = width
		for _, status := range []int{200, 413} {
			o.Request(Event{At: "2026-10-13T13:42:15Z", Method: "GET", Path: "/" + strings.Repeat("日", 50), Status: status, DurationMS: 1200})
		}
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			if cells(line) > width {
				t.Fatalf("width %d overflow: %s", width, line)
			}
		}
	}
}

func TestFortyColumnPathsStayDistinct(t *testing.T) {
	var out, errout bytes.Buffer
	o := New(&out, &errout, false)
	o.Width = 40
	for _, path := range []string{"/api/items/7?token=[redacted]", "/api/items/11?token=[redacted]", "/api/organizations/acme/projects/42/builds/1001"} {
		o.Request(Event{At: "2026-10-13T13:42:15Z", Method: "GET", Path: path, Status: 200})
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for _, want := range []string{"/api/items/7?…", "/api/items/11?…", "…/builds/1001"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, out.String())
		}
	}
	for _, line := range lines {
		if cells(line) > 40 {
			t.Fatalf("overflow: %s", line)
		}
	}
}

func TestWrapKeepsWordsWhole(t *testing.T) {
	lines := Wrap("Private by default; visitors use tunn connect.", 39, 2)
	if len(lines) != 2 || lines[0] != "Private by default; visitors use tunn" || lines[1] != "  connect." {
		t.Fatal(lines)
	}
}

func TestRequestTimingLiveOutput(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		var out, errout bytes.Buffer
		o := New(&out, &errout, jsonOutput)
		o.TTY = true
		o.Width = 40
		o.Request(Event{Method: "GET", Path: "/slow", Status: 200, Timing: inspection.NewTiming(2600000, 2600000, 2640000, 2640000)})
		if jsonOutput {
			var event Event
			if err := json.Unmarshal(out.Bytes(), &event); err != nil {
				t.Fatal(err)
			}
			if event.Timing == nil || event.Timing.SlowSide != "app" {
				t.Fatal(out.String())
			}
		} else {
			for _, want := range []string{"app 2.6 s", "tunnel 40.0 ms", "app TTFB", "tunnel TTFB", "slow: app"} {
				if !strings.Contains(strings.Join(strings.Fields(out.String()), " "), want) {
					t.Fatalf("missing %q: %s", want, out.String())
				}
			}
			for _, line := range strings.Split(out.String(), "\n") {
				if cells(line) > 40 {
					t.Fatalf("overflow: %s", line)
				}
			}
		}
	}
}
