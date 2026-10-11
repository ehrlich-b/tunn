// Package projectreader exposes a bounded, immutable project fixture through MCP.
package projectreader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const Version = "1.0.0"
const MaxFiles = 32
const MaxFileBytes = 8192
const MaxTotalBytes = 128 * 1024
const MaxLines = 1024
const MaxReadLines = 32
const MaxMatches = 16
const MaxRequestBytes = 32 * 1024

type Error struct{ Code string }

func (e *Error) Error() string  { return "project-reader: " + e.Code }
func failure(code string) error { return &Error{Code: code} }

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	Lines  int    `json:"lines"`
}
type Span struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	FirstLine int    `json:"firstLine"`
	LastLine  int    `json:"lastLine"`
	StartByte int    `json:"startByte"`
	EndByte   int    `json:"endByte"`
	Text      string `json:"text"`
}
type Result struct {
	Status    string `json:"status"`
	Files     []File `json:"files,omitempty"`
	Spans     []Span `json:"spans,omitempty"`
	Truncated bool   `json:"truncated"`
	Code      string `json:"code,omitempty"`
}
type source struct {
	File
	data    []byte
	offsets []int
}
type Reader struct {
	files    map[string]source
	manifest []File
}

// Open canonicalizes the configured root once, then freezes its contents without
// following symbolic links inside the project. os.Root confines reads to that
// canonical root even if a source changes during startup. No handles survive.
func Open(root string) (*Reader, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, failure("invalid_root")
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, failure("invalid_root")
	}
	confined, err := os.OpenRoot(canonical)
	if err != nil {
		return nil, failure("invalid_root")
	}
	defer confined.Close()
	r := &Reader{files: make(map[string]source)}
	total := 0
	entries := 0
	err = fs.WalkDir(confined.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return failure("unreadable_fixture")
		}
		entries++
		if entries > 128 || len(name) > 256 || strings.Count(name, "/") > 8 {
			return failure("fixture_limit")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return failure("symlink_rejected")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || !validPath(name) {
			return failure("invalid_fixture_file")
		}
		if len(r.files) >= MaxFiles {
			return failure("fixture_limit")
		}
		f, err := confined.Open(name)
		if err != nil {
			return failure("unreadable_fixture")
		}
		stat, statErr := f.Stat()
		pathStat, pathErr := confined.Lstat(name)
		data, readErr := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
		closeErr := f.Close()
		if statErr != nil || pathErr != nil || !stat.Mode().IsRegular() || !pathStat.Mode().IsRegular() || !os.SameFile(stat, pathStat) || readErr != nil || closeErr != nil {
			return failure("unreadable_fixture")
		}
		if len(data) > MaxFileBytes || total+len(data) > MaxTotalBytes {
			return failure("fixture_limit")
		}
		if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return failure("invalid_utf8")
		}
		offsets := []int{0}
		for i, b := range data {
			if b == '\n' && i+1 < len(data) {
				offsets = append(offsets, i+1)
			}
		}
		if len(data) == 0 {
			offsets = nil
		}
		if len(offsets) > MaxLines {
			return failure("fixture_limit")
		}
		digest := sha256.Sum256(data)
		meta := File{Path: name, SHA256: hex.EncodeToString(digest[:]), Bytes: len(data), Lines: len(offsets)}
		r.files[name] = source{meta, data, append(offsets, len(data))}
		r.manifest = append(r.manifest, meta)
		total += len(data)
		return nil
	})
	if err != nil {
		var typed *Error
		if errors.As(err, &typed) {
			return nil, typed
		}
		return nil, failure("unreadable_fixture")
	}
	if len(r.files) == 0 {
		return nil, failure("empty_fixture")
	}
	sort.Slice(r.manifest, func(i, j int) bool { return r.manifest[i].Path < r.manifest[j].Path })
	return r, nil
}
func validPath(p string) bool {
	return p != "." && fs.ValidPath(p) && path.Clean(p) == p && !strings.ContainsAny(p, "\\:\x00")
}
func (r *Reader) Manifest() []File { return append([]File(nil), r.manifest...) }
func (s source) span(first, last int) Span {
	start, end := s.offsets[first-1], s.offsets[last]
	return Span{s.Path, s.SHA256, first, last, start, end, string(s.data[start:end])}
}
func strictArgs(raw json.RawMessage, into any) error {
	if !utf8.Valid(raw) {
		return failure("invalid_arguments")
	}
	// Reject duplicate keys as well as unknown fields and non-object input.
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return failure("invalid_arguments")
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return failure("invalid_arguments")
		}
		k, ok := key.(string)
		if !ok || seen[k] {
			return failure("invalid_arguments")
		}
		seen[k] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return failure("invalid_arguments")
		}
	}
	if _, err := d.Token(); err != nil {
		return failure("invalid_arguments")
	}
	if d.Decode(new(any)) != io.EOF {
		return failure("invalid_arguments")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil {
		return failure("invalid_arguments")
	}
	return nil
}
func (r *Reader) Call(ctx context.Context, name string, args json.RawMessage) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	switch name {
	case "project_list":
		var in struct{}
		if err := strictArgs(args, &in); err != nil {
			return Result{}, err
		}
		return Result{Status: "ok", Files: r.Manifest()}, nil
	case "project_read":
		var in struct {
			Path      string `json:"path"`
			FirstLine int    `json:"firstLine"`
			LastLine  int    `json:"lastLine"`
		}
		if err := strictArgs(args, &in); err != nil {
			return Result{}, err
		}
		if !validPath(in.Path) {
			return Result{}, failure("invalid_path")
		}
		s, ok := r.files[in.Path]
		if !ok {
			return Result{}, failure("file_not_allowed")
		}
		if in.FirstLine < 1 || in.LastLine < in.FirstLine || in.LastLine > s.Lines || in.LastLine-in.FirstLine+1 > MaxReadLines {
			return Result{}, failure("invalid_range")
		}
		return Result{Status: "ok", Spans: []Span{s.span(in.FirstLine, in.LastLine)}}, nil
	case "project_search":
		var in struct {
			Query string `json:"query"`
		}
		if err := strictArgs(args, &in); err != nil {
			return Result{}, err
		}
		if len(in.Query) == 0 || len(in.Query) > 128 || !utf8.ValidString(in.Query) || strings.ContainsAny(in.Query, "\x00\r\n") {
			return Result{}, failure("invalid_query")
		}
		out := Result{Status: "no_matches"}
		for _, f := range r.manifest {
			s := r.files[f.Path]
			for line := 1; line <= s.Lines; line++ {
				if err := ctx.Err(); err != nil {
					return Result{}, err
				}
				span := s.span(line, line)
				if strings.Contains(span.Text, in.Query) {
					if len(out.Spans) == MaxMatches {
						out.Truncated = true
						return out, nil
					}
					out.Status = "ok"
					out.Spans = append(out.Spans, span)
				}
			}
		}
		return out, nil
	default:
		return Result{}, failure("unknown_tool")
	}
}

func (r *Reader) Server() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "mcp-project-reader", Version: Version}, nil)
	schemas := map[string]map[string]any{
		"project_list":   {"type": "object", "properties": map[string]any{}, "additionalProperties": false},
		"project_read":   {"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}, "firstLine": map[string]any{"type": "integer", "minimum": 1}, "lastLine": map[string]any{"type": "integer", "minimum": 1}}, "required": []string{"path", "firstLine", "lastLine"}, "additionalProperties": false},
		"project_search": {"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string", "minLength": 1, "maxLength": 128}}, "required": []string{"query"}, "additionalProperties": false},
	}
	descriptions := map[string]string{"project_list": "List the allowed immutable project snapshot and full-file hashes.", "project_read": "Read an exact path and inclusive line range with UTF-8 byte citations.", "project_search": "Literal case-sensitive search. no_matches and truncated are explicit."}
	for _, name := range []string{"project_list", "project_read", "project_search"} {
		name := name
		server.AddTool(&mcp.Tool{Name: name, Description: descriptions[name], InputSchema: schemas[name], Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := r.Call(ctx, name, req.Params.Arguments)
			if err != nil {
				code := "call_failed"
				var e *Error
				if errors.As(err, &e) {
					code = e.Code
				} else if errors.Is(err, context.Canceled) {
					code = "canceled"
				}
				out = Result{Status: "error", Code: code}
			}
			data, _ := json.Marshal(out)
			return &mcp.CallToolResult{IsError: err != nil, StructuredContent: out, Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}, nil
		})
	}
	return server
}

// Handler uses the existing MCP SDK wire protocol. Stateless operation is
// appropriate for the immutable reader; initialization is still negotiated.
func (r *Reader) Handler(jsonResponse bool) http.Handler {
	server := r.Server()
	wire := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: jsonResponse})
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/mcp" {
			http.NotFound(w, req)
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, MaxRequestBytes)
		wire.ServeHTTP(w, req)
	})
}
