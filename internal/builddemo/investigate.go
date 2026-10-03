package builddemo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Evidence struct {
	Citation string `json:"citation"`
	Text     string `json:"text"`
}

// Report captures observed tool calls and evidence rather than merely proving
// discovery. The investigator is deterministic and makes no hosted model calls.
type Report struct {
	Client             string     `json:"client"`
	Protocol           string     `json:"protocol"`
	Diagnosis          string     `json:"diagnosis"`
	Recommendation     string     `json:"recommendation"`
	Evidence           []Evidence `json:"evidence"`
	ToolCalls          int        `json:"tool_calls"`
	FirstToolMillis    float64    `json:"first_tool_ms"`
	UsefulAnswerMillis float64    `json:"useful_answer_ms"`
	Investigator       string     `json:"investigator"`
}

type ClientOptions struct {
	Endpoint   string
	HTTPClient *http.Client
}

// Investigate uses the official Go SDK to search and read the remote corpus.
// It rejects missing or contradictory evidence instead of emitting a canned
// diagnosis whenever the transport happens to succeed.
func Investigate(ctx context.Context, options ClientOptions) (*Report, error) {
	start := time.Now()
	client := mcp.NewClient(&mcp.Implementation{Name: "tunn-build-investigator-go", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: options.Endpoint, HTTPClient: options.HTTPClient,
		DisableStandaloneSSE: true, MaxRetries: -1,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect official Go SDK: %w", err)
	}
	defer session.Close()
	report := &Report{Client: "official-go-sdk@v1.7.0", Protocol: session.InitializeResult().ProtocolVersion, Investigator: "deterministic evidence checks; no hosted model"}
	call := func(name string, args any, output any) error {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if result.IsError {
			return fmt.Errorf("%s returned a tool error: %v", name, result.Content)
		}
		report.ToolCalls++
		if report.ToolCalls == 1 {
			report.FirstToolMillis = float64(time.Since(start).Microseconds()) / 1000
		}
		data, err := json.Marshal(result.StructuredContent)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, output)
	}
	var failures SearchOutput
	if err := call("build.search", SearchInput{Query: "TS2307"}, &failures); err != nil {
		return nil, err
	}
	if len(failures.Matches) != 1 {
		return nil, fmt.Errorf("expected one missing-module failure, got %d", len(failures.Matches))
	}
	var failure ReadOutput
	if err := call("build.read", ReadInput{Path: failures.Matches[0].Path}, &failure); err != nil {
		return nil, err
	}
	var generation SearchOutput
	if err := call("build.search", SearchInput{Query: "generate:schema"}, &generation); err != nil {
		return nil, err
	}
	paths := map[string]bool{failure.Path: true, "ci/build.yml": true, ".gitignore": true}
	for _, match := range generation.Matches {
		paths[match.Path] = true
	}
	documents := map[string]ReadOutput{failure.Path: failure}
	orderedPaths := make([]string, 0, len(paths))
	for path := range paths {
		orderedPaths = append(orderedPaths, path)
	}
	sort.Strings(orderedPaths)
	for _, path := range orderedPaths {
		if _, ok := documents[path]; ok {
			continue
		}
		var document ReadOutput
		if err := call("build.read", ReadInput{Path: path}, &document); err != nil {
			return nil, err
		}
		documents[path] = document
	}
	evidence, err := diagnose(documents)
	if err != nil {
		return nil, err
	}
	report.Diagnosis = "The clean CI checkout never generates src/generated/schema.ts before TypeScript compilation."
	report.Recommendation = "Run npm run generate:schema after npm ci and before npm run build; keep generated files untracked."
	report.Evidence = evidence
	report.UsefulAnswerMillis = float64(time.Since(start).Microseconds()) / 1000
	return report, nil
}

func diagnose(documents map[string]ReadOutput) ([]Evidence, error) {
	var packageScripts struct {
		Scripts map[string]string `json:"scripts"`
	}
	var packageLines []string
	for _, line := range documents["package.json"].Lines {
		packageLines = append(packageLines, line.Text)
	}
	if err := json.Unmarshal([]byte(strings.Join(packageLines, "\n")), &packageScripts); err != nil {
		return nil, fmt.Errorf("package scripts evidence missing or invalid: %w", err)
	}
	if packageScripts.Scripts["generate:schema"] == "" || packageScripts.Scripts["build"] != "tsc -p tsconfig.json" || packageScripts.Scripts["prebuild"] != "" {
		return nil, fmt.Errorf("package scripts do not support a skipped-generation diagnosis")
	}
	for _, line := range documents["ci/build.yml"].Lines {
		if strings.Contains(line.Text, "generate:schema") {
			return nil, fmt.Errorf("CI already runs generation; skipped-generation diagnosis is unsupported")
		}
	}
	requirements := []struct{ path, text string }{
		{"logs/build-4821.log", "error TS2307: Cannot find module './generated/schema'"},
		{"package.json", `"generate:schema":`},
		{"package.json", `"build": "tsc -p tsconfig.json"`},
		{"ci/build.yml", "- run: npm run build"},
		{"docs/build.md", "Before compiling on a clean checkout, run npm run generate:schema."},
		{".gitignore", "src/generated/"},
	}
	evidence := make([]Evidence, 0, len(requirements))
	for _, requirement := range requirements {
		found := false
		for _, line := range documents[requirement.path].Lines {
			if strings.Contains(line.Text, requirement.text) {
				evidence = append(evidence, Evidence{Citation: fmt.Sprintf("%s:%d", requirement.path, line.Number), Text: line.Text})
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("missing evidence in %s for %q", requirement.path, requirement.text)
		}
	}
	return evidence, nil
}
