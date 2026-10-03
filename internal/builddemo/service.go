// Package builddemo exposes an in-memory, read-only MCP investigation fixture.
// It deliberately never opens files, invokes commands, or reads environment secrets.
package builddemo

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Line struct {
	Number int    `json:"number"`
	Text   string `json:"text"`
}

type Match struct {
	Path string `json:"path"`
	Line
}

type SearchInput struct {
	Query string `json:"query" jsonschema:"Literal case-insensitive text to find in the synthetic build workspace"`
}

type SearchOutput struct {
	Matches []Match `json:"matches"`
}

type ReadInput struct {
	Path string `json:"path" jsonschema:"Exact synthetic path returned by build.search"`
}

type ReadOutput struct {
	Path  string `json:"path"`
	Lines []Line `json:"lines"`
}

// Documents is a fresh copy of the synthetic workspace. It is useful in tests
// that need to alter evidence without changing the server or client protocol.
func Documents() map[string]string {
	return map[string]string{
		"logs/build-4821.log": `Synthetic CI run 4821, commit demo-7b4a
Step: npm ci
Dependencies installed successfully.
Step: npm run build
src/app.ts(1,31): error TS2307: Cannot find module './generated/schema'.
Build failed with exit code 2.
`,
		"package.json": `{
  "name": "synthetic-build-workspace",
  "scripts": {
    "generate:schema": "node scripts/generate-schema.mjs",
    "build": "tsc -p tsconfig.json"
  }
}
`,
		"ci/build.yml": `name: synthetic-build
steps:
  - run: npm ci
  - run: npm run build
`,
		"docs/build.md": `# Synthetic build setup
The schema is derived from checked-in schema/api.json.
Before compiling on a clean checkout, run npm run generate:schema.
That command creates src/generated/schema.ts.
Generated files are intentionally not checked in.
`,
		".gitignore": `node_modules/
src/generated/
dist/
`,
		"src/app.ts": `import { validateEvent } from './generated/schema';
export const acceptEvent = (event: unknown) => validateEvent(event);
`,
	}
}

// NewHandler returns a sessionless MCP server over the fixed synthetic corpus.
// Tunn supplies access control when this handler is published through a relay.
func NewHandler() http.Handler { return NewHandlerWithDocuments(Documents()) }

// NewHandlerWithDocuments copies its corpus before serving concurrent callers.
func NewHandlerWithDocuments(documents map[string]string) http.Handler {
	corpus := make(map[string]string, len(documents))
	for name, body := range documents {
		corpus[name] = body
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "tunn-synthetic-build", Version: "1"}, nil)
	closedWorld, nonDestructive := false, false
	annotations := &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &closedWorld, DestructiveHint: &nonDestructive}
	mcp.AddTool(server, &mcp.Tool{Name: "build.search", Description: "Search the synthetic build workspace and return exact path and line evidence.", Annotations: annotations},
		func(_ context.Context, _ *mcp.CallToolRequest, input SearchInput) (*mcp.CallToolResult, SearchOutput, error) {
			query := strings.TrimSpace(input.Query)
			if query == "" || len(query) > 256 {
				return nil, SearchOutput{}, fmt.Errorf("query must contain 1 to 256 characters")
			}
			output := SearchOutput{Matches: []Match{}}
			paths := make([]string, 0, len(corpus))
			for path := range corpus {
				paths = append(paths, path)
			}
			sort.Strings(paths)
			for _, path := range paths {
				for _, line := range numberedLines(corpus[path]) {
					if strings.Contains(strings.ToLower(line.Text), strings.ToLower(query)) {
						output.Matches = append(output.Matches, Match{Path: path, Line: line})
					}
				}
			}
			return nil, output, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "build.read", Description: "Read a synthetic workspace file with line numbers. No real filesystem access.", Annotations: annotations},
		func(_ context.Context, _ *mcp.CallToolRequest, input ReadInput) (*mcp.CallToolResult, ReadOutput, error) {
			body, ok := corpus[input.Path]
			if !ok {
				return nil, ReadOutput{}, fmt.Errorf("unknown synthetic path %q", input.Path)
			}
			return nil, ReadOutput{Path: input.Path, Lines: numberedLines(body)}, nil
		})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true,
	})
}

func numberedLines(body string) []Line {
	parts := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	lines := make([]Line, len(parts))
	for i, part := range parts {
		lines[i] = Line{Number: i + 1, Text: part}
	}
	return lines
}
