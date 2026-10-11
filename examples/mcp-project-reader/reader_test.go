package projectreader_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	reader "github.com/ehrlich-b/tunn/examples/mcp-project-reader"
	"github.com/ehrlich-b/tunn/scripts/mcp-workflow/client"
)

type memoryTransport struct{ handler http.Handler }

func (m memoryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	m.handler.ServeHTTP(w, r)
	return w.Result(), nil
}
func fixture(t *testing.T, day string) *reader.Reader {
	t.Helper()
	root, err := filepath.Abs("fixtures/harbor/" + day)
	if err != nil {
		t.Fatal(err)
	}
	r, err := reader.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func consumer(r *reader.Reader, sse bool) client.Consumer {
	return client.Consumer{HTTP: &http.Client{Transport: memoryTransport{r.Handler(!sse)}}, Endpoint: "https://reader.example.invalid/mcp"}
}
func call(t *testing.T, c client.Consumer, id int, name string, args any) reader.Result {
	t.Helper()
	raw, err := c.Tool(context.Background(), id, name, args)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		StructuredContent reader.Result `json:"structuredContent"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		t.Fatal("invalid result")
	}
	return envelope.StructuredContent
}
func validateSpan(t *testing.T, root string, s reader.Span) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(s.Path)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if s.SHA256 != hex.EncodeToString(digest[:]) || s.StartByte < 0 || s.EndByte > len(data) || string(data[s.StartByte:s.EndByte]) != s.Text {
		t.Fatalf("incorrect citation: %#v", s)
	}
	lines := strings.SplitAfter(string(data), "\n")
	start, end := 0, 0
	for i, line := range lines {
		if i+1 < s.FirstLine {
			start += len(line)
		}
		if i+1 <= s.LastLine {
			end += len(line)
		}
	}
	if start != s.StartByte || end != s.EndByte {
		t.Fatalf("line/byte mismatch: %#v", s)
	}
}

// This consumer derives the choice from full tool-returned files, independently
// of Reader.Call. It never consults an answer supplied by the server.
func choose(t *testing.T, text map[string]string) string {
	t.Helper()
	if !strings.Contains(text["README.md"], "Lower priority numbers come first") {
		t.Fatal("selection rule missing")
	}
	pattern := regexp.MustCompile(`(?m)^## (HN-[0-9]+) — [^\n]+\nStatus: ([a-z]+); Readiness: ([a-z]+); Priority: ([0-9]+)`)
	type issue struct {
		id               string
		priority, number int
	}
	var candidates []issue
	for _, m := range pattern.FindAllStringSubmatch(text["ISSUES.md"], -1) {
		if m[2] != "open" || m[3] != "ready" || strings.Contains(text["CHANGELOG.md"], "Shipped "+m[1]+":") {
			continue
		}
		priority, _ := strconv.Atoi(m[4])
		number, _ := strconv.Atoi(strings.TrimPrefix(m[1], "HN-"))
		candidates = append(candidates, issue{m[1], priority, number})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority < candidates[j].priority
		}
		return candidates[i].number < candidates[j].number
	})
	if len(candidates) == 0 {
		return "no_actionable_issue"
	}
	return candidates[0].id
}
func TestDirectProtocolIndependentOracle(t *testing.T) {
	for _, day := range []string{"day1", "day2"} {
		for _, sse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/sse=%v", day, sse), func(t *testing.T) {
				r := fixture(t, day)
				c := consumer(r, sse)
				initialized, err := c.RPC(context.Background(), 1, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "independent-consumer", "version": "1"}})
				if err != nil || !bytes.Contains(initialized, []byte("mcp-project-reader")) {
					t.Fatalf("initialize: %s %v", initialized, err)
				}
				if err := c.Initialized(context.Background()); err != nil {
					t.Fatal("initialized notification failed")
				}
				listed, err := c.RPC(context.Background(), 2, "tools/list", map[string]any{})
				if err != nil {
					t.Fatal(err)
				}
				var tools struct {
					Tools []struct {
						Name        string
						InputSchema map[string]any
						Annotations map[string]any
					}
				}
				if json.Unmarshal(listed, &tools) != nil || len(tools.Tools) != 3 {
					t.Fatalf("tool discovery: %s", listed)
				}
				for _, tool := range tools.Tools {
					if tool.Annotations["readOnlyHint"] != true {
						t.Fatal("read-only annotation missing")
					}
				}
				manifest := call(t, c, 3, "project_list", map[string]any{})
				if len(manifest.Files) != 3 {
					t.Fatal("manifest differs")
				}
				text := map[string]string{}
				root, _ := filepath.Abs("fixtures/harbor/" + day)
				for i, f := range manifest.Files {
					out := call(t, c, 4+i, "project_read", map[string]any{"path": f.Path, "firstLine": 1, "lastLine": f.Lines})
					if len(out.Spans) != 1 {
						t.Fatal("missing read")
					}
					validateSpan(t, root, out.Spans[0])
					text[f.Path] = out.Spans[0].Text
				}
				want := map[string]string{"day1": "HN-104", "day2": "HN-108"}[day]
				if got := choose(t, text); got != want {
					t.Fatalf("independent choice=%s want=%s", got, want)
				}
				search := call(t, c, 8, "project_search", map[string]any{"query": "Café 🌊"})
				if search.Status != "ok" || len(search.Spans) == 0 || search.Truncated {
					t.Fatal("unicode evidence missing")
				}
				for _, span := range search.Spans {
					validateSpan(t, root, span)
				}
				t.Logf("independent answer %s; %d files; %d Unicode citations checked", want, len(text), len(search.Spans))
			})
		}
	}
}
func TestPathArgumentsAndSnapshot(t *testing.T) {
	r := fixture(t, "day1")
	cases := []struct{ name, args string }{
		{"project_read", `{"path":"../README.md","firstLine":1,"lastLine":1}`},
		{"project_read", `{"path":"/etc/passwd","firstLine":1,"lastLine":1}`},
		{"project_read", `{"path":"x/../README.md","firstLine":1,"lastLine":1}`},
		{"project_read", `{"path":"README.md","firstLine":0,"lastLine":1}`},
		{"project_read", `{"path":"README.md","firstLine":1,"lastLine":999}`},
		{"project_read", `{"path":"README.md","firstLine":1.5,"lastLine":2}`},
		{"project_read", `{"path":"README.md","firstLine":1,"lastLine":1,"shell":"pwd"}`},
		{"project_read", `{"path":"README.md","path":"ISSUES.md","firstLine":1,"lastLine":1}`},
		{"project_read", `{"path":"README.md"}`},
		{"project_read", `{"path":"unknown.md","firstLine":1,"lastLine":1}`},
		{"project_search", `{"query":""}`}, {"project_search", `{"query":null}`},
		{"project_search", `{"query":"line\nbreak"}`}, {"project_list", `[]`},
		{"project_list", `{} {}`}, {"shell", `{}`},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if out, err := r.Call(context.Background(), tc.name, json.RawMessage(tc.args)); err == nil || out.Status == "ok" {
				t.Fatalf("invalid call accepted: %s", tc.args)
			}
		})
	}
	c := consumer(r, false)
	if _, err := c.Tool(context.Background(), 99, "project_read", map[string]any{"path": "../outside", "firstLine": 1, "lastLine": 1}); err == nil {
		t.Fatal("protocol path error appears successful")
	}
	root := t.TempDir()
	file := filepath.Join(root, "README.md")
	if os.WriteFile(file, []byte("Original\n"), 0600) != nil {
		t.Fatal("write fixture")
	}
	frozen, err := reader.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(file, []byte("Changed\n"), 0600) != nil {
		t.Fatal("write fixture")
	}
	out, err := frozen.Call(context.Background(), "project_read", json.RawMessage(`{"path":"README.md","firstLine":1,"lastLine":1}`))
	if err != nil || out.Spans[0].Text != "Original\n" {
		t.Fatal("snapshot changed")
	}
}
func TestSymlinkAndLimits(t *testing.T) {
	for _, target := range []string{"outside", "inside"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			file := filepath.Join(root, "ok.md")
			os.WriteFile(file, []byte("data"), 0600)
			destination := file
			if target == "outside" {
				destination = filepath.Join(t.TempDir(), "secret")
				os.WriteFile(destination, []byte("private"), 0600)
			}
			if err := os.Symlink(destination, filepath.Join(root, "link.md")); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Open(root); err == nil || !strings.Contains(err.Error(), "symlink_rejected") {
				t.Fatalf("symlink accepted: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		files int
		data  []byte
	}{
		{"files", 33, []byte("x")}, {"bytes", 1, bytes.Repeat([]byte("x"), 8193)},
		{"total", 17, bytes.Repeat([]byte("x"), 8192)}, {"lines", 1, bytes.Repeat([]byte("x\n"), 1025)},
		{"utf8", 1, []byte{0xff}}, {"nul", 1, []byte{'x', 0}}, {"empty", 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for i := 0; i < tc.files; i++ {
				if os.WriteFile(filepath.Join(root, fmt.Sprintf("%02d.md", i)), tc.data, 0600) != nil {
					t.Fatal("fixture write")
				}
			}
			if _, err := reader.Open(root); err == nil {
				t.Fatal("limit accepted")
			}
		})
	}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "repeats.md"), bytes.Repeat([]byte("needle\n"), 17), 0600)
	r, err := reader.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Call(context.Background(), "project_search", json.RawMessage(`{"query":"needle"}`))
	if err != nil || len(out.Spans) != 16 || !out.Truncated {
		t.Fatal("truncation missing")
	}
	out, err = r.Call(context.Background(), "project_search", json.RawMessage(`{"query":"absent"}`))
	if err != nil || out.Status != "no_matches" || out.Truncated {
		t.Fatal("no answer ambiguous")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.Call(canceled, "project_list", json.RawMessage(`{}`)); err == nil {
		t.Fatal("canceled call succeeded")
	}
}
func TestHTTPBoundary(t *testing.T) {
	r := fixture(t, "day1")
	h := r.Handler(true)
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/wrong", `{}`}, {"GET", "/mcp", ``}, {"POST", "/mcp", `{`},
		{"POST", "/mcp", strings.Repeat(" ", reader.MaxRequestBytes) + `{}`},
	} {
		req := httptest.NewRequest(tc.method, "https://reader.invalid"+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code == 200 {
			t.Fatalf("bad request succeeded: %s %d", tc.path, len(tc.body))
		}
		_ = w.Result().Body.Close()
	}
}

func TestSecondProjectDuplicatePathsUnicodeAndNoAnswer(t *testing.T) {
	root, err := filepath.Abs("fixtures/ridge")
	if err != nil {
		t.Fatal(err)
	}
	r, err := reader.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	c := consumer(r, true)
	manifest := call(t, c, 1, "project_list", map[string]any{})
	if len(manifest.Files) != 4 {
		t.Fatal("second-project manifest differs")
	}
	text := map[string]string{}
	for i, f := range manifest.Files {
		out := call(t, c, i+2, "project_read", map[string]any{"path": f.Path, "firstLine": 1, "lastLine": f.Lines})
		if len(out.Spans) != 1 {
			t.Fatal("missing source span")
		}
		validateSpan(t, root, out.Spans[0])
		text[f.Path] = out.Spans[0].Text
	}
	if text["README.md"] == text["docs/README.md"] || text["docs/README.md"] == "" {
		t.Fatal("duplicate basenames collided")
	}
	if choose(t, text) != "no_actionable_issue" {
		t.Fatal("absent answer was invented")
	}
	search := call(t, c, 7, "project_search", map[string]any{"query": "naïve café 🌲"})
	if len(search.Spans) != 2 || search.Spans[0].Path == search.Spans[1].Path {
		t.Fatal("unicode search conflated files")
	}
	for _, span := range search.Spans {
		validateSpan(t, root, span)
	}
	absent := call(t, c, 8, "project_search", map[string]any{"query": "Readiness: urgent"})
	if absent.Status != "no_matches" || absent.Truncated || len(absent.Spans) != 0 {
		t.Fatal("missing evidence not explicit")
	}
	t.Log("independent answer=no_actionable_issue; 4 files; duplicate paths and 2 Unicode spans checked")
}
