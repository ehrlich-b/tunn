package projectreader_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	reader "github.com/ehrlich-b/tunn/examples/mcp-project-reader"
	"github.com/ehrlich-b/tunn/scripts/mcp-workflow/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func regressionFixture(t *testing.T, files map[string]string) (string, *reader.Reader) {
	t.Helper()
	root := t.TempDir()
	for name, data := range files {
		file := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := reader.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, r
}

func initializeRegressionConsumer(t *testing.T, c client.Consumer) {
	t.Helper()
	if _, err := c.RPC(context.Background(), 1, "initialize", map[string]any{
		"protocolVersion": "2025-11-25", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "regression", "version": "1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Initialized(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestProjectListWithoutArguments(t *testing.T) {
	_, r := regressionFixture(t, map[string]string{"README.md": "readme\n"})
	t.Run("direct", func(t *testing.T) {
		out, err := r.Call(context.Background(), "project_list", nil)
		if err != nil || out.Status != "ok" || len(out.Files) != 1 || out.Files[0].Path != "README.md" {
			t.Fatalf("parameterless list: %+v, %v", out, err)
		}
	})
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%v", sse), func(t *testing.T) {
			c := consumer(r, sse)
			initializeRegressionConsumer(t, c)
			for _, params := range []map[string]any{{"name": "project_list"}, {"name": "project_list", "arguments": map[string]any{}}} {
				raw, err := c.RPC(context.Background(), 4, "tools/call", params)
				if err != nil {
					t.Fatalf("list with params %v: %v", params, err)
				}
				var out struct {
					StructuredContent reader.Result `json:"structuredContent"`
				}
				if err := json.Unmarshal(raw, &out); err != nil {
					t.Fatal(err)
				}
				if out.StructuredContent.Status != "ok" || len(out.StructuredContent.Files) != 1 || out.StructuredContent.Files[0].Path != "README.md" {
					t.Fatalf("parameterless list result: %s", raw)
				}
			}
		})
	}
	t.Run("newline-json", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		input, writer := io.Pipe()
		output, sink := io.Pipe()
		defer input.Close()
		defer writer.Close()
		defer output.Close()
		defer sink.Close()
		session, err := r.Server().Connect(ctx, &mcp.IOTransport{Reader: input, Writer: sink}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		decoder := json.NewDecoder(output)
		rpc := func(message string) json.RawMessage {
			t.Helper()
			if _, err := io.WriteString(writer, message+"\n"); err != nil {
				t.Fatal(err)
			}
			var out struct {
				Result json.RawMessage `json:"result"`
			}
			if err := decoder.Decode(&out); err != nil {
				t.Fatal(err)
			}
			return out.Result
		}
		rpc(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"regression","version":"1"}}}`)
		if _, err := io.WriteString(writer, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"); err != nil {
			t.Fatal(err)
		}
		raw := rpc(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"project_list"}}`)
		var out struct {
			IsError           bool          `json:"isError"`
			StructuredContent reader.Result `json:"structuredContent"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		if out.IsError || out.StructuredContent.Status != "ok" || len(out.StructuredContent.Files) != 1 || out.StructuredContent.Files[0].Path != "README.md" {
			t.Fatalf("parameterless stdio list: %s", raw)
		}
	})
}

func TestProjectArgumentsRejectCaseAliases(t *testing.T) {
	_, r := regressionFixture(t, map[string]string{"README.md": "readme\n", "ISSUES.md": "issues\n"})
	cases := []struct{ name, tool, args string }{
		{"path-overwrite", "project_read", `{"path":"README.md","PATH":"ISSUES.md","firstLine":1,"lastLine":1}`},
		{"alias-before-path", "project_read", `{"PATH":"ISSUES.md","path":"README.md","firstLine":1,"lastLine":1}`},
		{"uppercase-required", "project_read", `{"PATH":"README.md","FIRSTLINE":1,"LASTLINE":1}`},
		{"mixed-case-path", "project_read", `{"paTh":"README.md","firstLine":1,"lastLine":1}`},
		{"first-line-alias", "project_read", `{"path":"README.md","firstLine":1,"FIRSTLINE":1,"lastLine":1}`},
		{"last-line-alias", "project_read", `{"path":"README.md","firstLine":1,"lastLine":1,"LASTLINE":1}`},
		{"search-alias", "project_search", `{"query":"absent","QUERY":"issues"}`},
		{"uppercase-query", "project_search", `{"QUERY":"issues"}`},
		{"duplicate-path", "project_read", `{"path":"README.md","path":"ISSUES.md","firstLine":1,"lastLine":1}`},
		{"unknown-field", "project_read", `{"path":"README.md","firstLine":1,"lastLine":1,"extra":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := r.Call(context.Background(), tc.tool, json.RawMessage(tc.args))
			var typed *reader.Error
			if !errors.As(err, &typed) || typed.Code != "invalid_arguments" || len(out.Spans) != 0 {
				t.Errorf("undeclared argument accepted: %+v, %v", out, err)
			}
			for _, sse := range []bool{false, true} {
				t.Run(fmt.Sprintf("sse=%v", sse), func(t *testing.T) {
					c := consumer(r, sse)
					initializeRegressionConsumer(t, c)
					_, err := c.RPC(context.Background(), 7, "tools/call", map[string]any{"name": tc.tool, "arguments": json.RawMessage(tc.args)})
					var typed *client.Failure
					if !errors.As(err, &typed) || typed.Code != "tool_error" {
						t.Fatalf("wire call accepted undeclared argument: %v", err)
					}
				})
			}
		})
	}
}

func TestProjectTreeWithinPublishedBounds(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		dirs       int
	}{
		{"depth-8", strings.Repeat("d/", 8) + "README.md", 0},
		{"depth-9", strings.Repeat("d/", 9) + "README.md", 0},
		{"directories-126", "README.md", 126},
		{"directories-127", "README.md", 127},
		{"path-256-bytes", strings.Repeat("d", 120) + "/" + strings.Repeat("e", 135), 0},
		{"path-257-bytes", strings.Repeat("d", 120) + "/" + strings.Repeat("e", 136), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := regressionFixture(t, map[string]string{tc.path: "x\n"})
			for i := 0; i < tc.dirs; i++ {
				if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("d%03d", i)), 0700); err != nil {
					t.Fatal(err)
				}
			}
			r, err := reader.Open(root)
			if err != nil {
				t.Fatalf("one 2-byte, 1-line file below published bounds: %v", err)
			}
			files := r.Manifest()
			if len(files) != 1 || files[0].Path != tc.path || files[0].Bytes != 2 || files[0].Lines != 1 {
				t.Fatalf("tree manifest: %+v", files)
			}
			args, err := json.Marshal(map[string]any{"path": tc.path, "firstLine": 1, "lastLine": 1})
			if err != nil {
				t.Fatal(err)
			}
			out, err := r.Call(context.Background(), "project_read", args)
			if err != nil || len(out.Spans) != 1 || out.Spans[0].Text != "x\n" {
				t.Fatalf("read admitted tree: %+v, %v", out, err)
			}
			validateSpan(t, root, out.Spans[0])
		})
	}
}
