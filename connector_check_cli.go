package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ehrlich-b/tunn/internal/mcpcheck"
)

const connectorCheckUsage = `tunn connector-check - diagnose a private MCP connector

Usage:
  tunn connector-check [options] <https-connector-url/mcp>

Default: check the HTTPS challenge and OAuth/PKCE metadata without registering a client.
  --oauth                 Register a diagnostic client; print a browser consent link
  --expect-tools <names>  Assert the exact comma-separated exposed tool set (requires --oauth)
  --call-tool <name>      Invoke one explicitly chosen harmless tool (requires --oauth)
  --arguments <json>      JSON object for --call-tool (default {})
  --deny-tool <name>      Probe a harmless blocked tool; require tunn's -32001 denial
  --timeout <duration>    Total deadline including browser consent (default 3m, max 10m)
  --json                  Print a structured final report; consent link goes to stderr

Examples:
  tunn connector-check https://my-tools.tunn.to/mcp
  tunn connector-check --oauth --expect-tools echo --call-tool echo --arguments '{"message":"hello"}' https://my-tools.tunn.to/mcp

Both call probes must be harmless even if policy is broken. No tool is called by default.
OAuth tokens stay in memory. Disconnect “tunn connector-check” at /account/mcp afterward.
Guide: https://tunn.to/mcp-to-claude
`

type connectorCheckOptions struct {
	url         string
	oauth, json bool
	timeout     time.Duration
	tools       mcpcheck.ToolOptions
}

func parseConnectorCheckFlags(args []string) (*connectorCheckOptions, error) {
	fs := flag.NewFlagSet("connector-check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	opts := &connectorCheckOptions{}
	expected, arguments := "", ""
	fs.BoolVar(&opts.oauth, "oauth", false, "")
	fs.BoolVar(&opts.json, "json", false, "")
	fs.DurationVar(&opts.timeout, "timeout", 3*time.Minute, "")
	fs.StringVar(&expected, "expect-tools", "", "")
	fs.StringVar(&opts.tools.Call, "call-tool", "", "")
	fs.StringVar(&opts.tools.Deny, "deny-tool", "", "")
	fs.StringVar(&arguments, "arguments", "{}", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, flag.ErrHelp
		}
		return nil, fmt.Errorf("invalid connector-check options; use --help for supported flags and --timeout values such as 3m")
	}
	if fs.NArg() != 1 {
		return nil, fmt.Errorf("provide one printed HTTPS Connector URL ending in /mcp")
	}
	opts.url = fs.Arg(0)
	expectSet, argsSet := false, false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "expect-tools" {
			expectSet = true
		}
		if f.Name == "arguments" {
			argsSet = true
		}
	})
	if opts.timeout < time.Second || opts.timeout > 10*time.Minute {
		return nil, fmt.Errorf("--timeout must be between 1s and 10m")
	}
	if !opts.oauth && (expectSet || opts.tools.Call != "" || opts.tools.Deny != "" || argsSet) {
		return nil, fmt.Errorf("tool assertions/probes require --oauth")
	}
	if argsSet && opts.tools.Call == "" {
		return nil, fmt.Errorf("--arguments requires --call-tool")
	}
	if opts.tools.Call != "" && opts.tools.Call == opts.tools.Deny {
		return nil, fmt.Errorf("--call-tool and --deny-tool must differ")
	}
	if expectSet {
		opts.tools.Expected = []string{}
		if expected != "" {
			seen := map[string]bool{}
			for _, name := range strings.Split(expected, ",") {
				if strings.TrimSpace(name) != name || name == "" || seen[name] {
					return nil, fmt.Errorf("--expect-tools needs unique, exact comma-separated names")
				}
				seen[name] = true
				opts.tools.Expected = append(opts.tools.Expected, name)
			}
		}
	}
	var object map[string]json.RawMessage
	if json.Unmarshal([]byte(arguments), &object) != nil || object == nil {
		return nil, fmt.Errorf("--arguments must be one JSON object")
	}
	opts.tools.Arguments = json.RawMessage(arguments)
	return opts, nil
}

type connectorCheckReport struct {
	Status    string               `json:"status"`
	Discovery bool                 `json:"discovery"`
	OAuth     string               `json:"oauth"`
	Tools     *mcpcheck.ToolReport `json:"tools,omitempty"`
	Error     string               `json:"error,omitempty"`
	Hosted    string               `json:"hosted"`
}

func executeConnectorCheck(ctx context.Context, c *mcpcheck.Checker, opts *connectorCheckOptions, out, diagnostic io.Writer) error {
	report := connectorCheckReport{Status: "FAIL", OAuth: "REQUIRED-UNRUN", Hosted: "REQUIRED-UNRUN"}
	d, err := c.Discover(ctx, opts.url)
	if err == nil {
		report.Discovery = true
		if opts.oauth {
			var token string
			token, err = c.Authenticate(ctx, d, func(link string) {
				fmt.Fprintln(diagnostic, "Open this URL in your browser and approve this tunnel:")
				fmt.Fprintln(diagnostic, link)
			})
			if err == nil {
				report.OAuth = "PASS"
				report.Tools, err = c.CheckTools(ctx, d, token, opts.tools)
			}
		}
	}
	if err == nil {
		if opts.oauth {
			report.Status = "PASS"
		} else {
			report.Status = "DISCOVERY-PASS"
		}
	} else {
		report.Error = err.Error()
	}
	if opts.json {
		encodeErr := json.NewEncoder(out).Encode(report)
		if err == nil {
			err = encodeErr
		}
	} else {
		if report.Discovery {
			fmt.Fprintln(out, "PASS: HTTPS challenge, exact resource, OAuth metadata and S256 PKCE")
		}
		if report.Tools != nil {
			names, _ := json.Marshal(report.Tools.Names)
			fmt.Fprintf(out, "PASS: OAuth consent, initialize and tools/list %s\n", names)
			if opts.tools.Expected != nil {
				fmt.Fprintln(out, "PASS: exact tool allow-list")
			}
			if report.Tools.Called {
				fmt.Fprintln(out, "PASS: harmless allowed tool call")
			}
			if report.Tools.Denied {
				fmt.Fprintln(out, "PASS: blocked tool returned tunn policy denial")
			}
		}
		if err != nil {
			fmt.Fprintln(out, "FAIL:", err)
		} else if !opts.oauth {
			fmt.Fprintln(out, "REQUIRED-UNRUN: OAuth consent and tools; rerun with --oauth --expect-tools <names>")
		}
		if report.OAuth == "PASS" {
			fmt.Fprintln(out, "Disconnect the diagnostic client at the relay's /account/mcp when finished.")
		}
		fmt.Fprintln(out, "REQUIRED-UNRUN: real Claude.ai / ChatGPT account acceptance")
	}
	return err
}
func runConnectorCheck(args []string) {
	opts, err := parseConnectorCheckFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(os.Stdout, connectorCheckUsage)
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "connector-check:", err)
		fmt.Fprint(os.Stderr, connectorCheckUsage)
		os.Exit(1)
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, opts.timeout)
	defer cancel()
	if executeConnectorCheck(ctx, mcpcheck.New(nil), opts, os.Stdout, os.Stderr) != nil {
		os.Exit(1)
	}
}
