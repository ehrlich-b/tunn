package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/terminal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var version = "development build"

func firstRun(out io.Writer) {
	fmt.Fprintf(out, "tunn %s\n\nSign in\n  tunn login\n\nRun your app on port 3000, then\n  tunn http 3000\n\nAnyone with the link\n  tunn http 3000 --public\n\nAll commands\n  tunn --help\n", version)
}
func printHelp(out io.Writer) {
	text := fmt.Sprintf(`tunn %s

Start
  tunn login                  Sign in
  tunn http 3000              Only you and invited people
  tunn http 3000 --public     Anyone with the link
  tunn hosts                  List machines and tunnels
  tunn service status         Check the local service
  tunn http --help             HTTP options

Inspect
  tunn http 3000 --inspect    Open the local request inspector
  tunn hosts --json           Inventory JSON
  tunn http 3000 --json       Request events as JSON lines

Access
  tunn share NAME EMAIL       Invite a person
  tunn unshare NAME EMAIL     Remove a person
  tunn access NAME            List access
  tunn keys add|list|remove    Account SSH keys
  tunn token NAME             Endpoint token
  tunn ip-policy --help       IP rules
  tunn usage NAME             Usage and decisions
  tunn grant --help           Consumer tokens
  tunn policy --help          Headers and rate limits

More
  tunn mcp --help             Local MCP server
  tunn connector-check --help  Check an MCP connector
  tunn tcp --help             Raw TCP endpoint
  tunn unix --help            Unix socket endpoint
  tunn connect --help         Connect to a remote endpoint
  tunn domain --help          Custom domains
  tunn service --help         Persistent endpoints
  tunn openclaw --help        Phone setup
  tunn status --help          Service probe collector (operators)
  tunn admin --help           Account controls (operators)

Targets
  tunn http localhost:3000
  tunn http https://localhost:8443
  tunn 3000

Global options go before the command
  --verbosity none|error|request|trace
  --dev                       Local development configuration
  --insecure                  Skip relay TLS verification
  --version                   Print version
`, version)
	writeCLIHelp(out, text)
}

func shellURL(value string) string {
	if strings.ContainsAny(value, " ;&|$`'\"()<>\t\r\n") {
		return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	return value
}
func validateCLIURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(value, "\r\n\x1b") {
		return errors.New("invalid public URL")
	}
	return nil
}
func accountURL(server string) string {
	return "https://" + strings.TrimSuffix(server, ":443") + "/account"
}
func localReading(target string) (string, string, string) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "local app", "", ""
	}
	host := u.Host
	address := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		address = net.JoinHostPort(u.Hostname(), port)
	}
	check := u.Scheme + "://" + u.Host
	return host, address, "curl -I " + shellURL(check)
}

var tunnelLimit = regexp.MustCompile(`tunnel limit reached \(([0-9]+)/([0-9]+)\)`)

func showTunnelError(o *terminal.Output, err error, server string) {
	if client.AuthenticationFailure(err) || status.Code(err) == codes.Unauthenticated {
		o.State("auth_expired", "Sign in again", "Tunnel stopped", "tunn login", 0)
		return
	}
	text := strings.ToLower(err.Error())
	if status.Code(err) == codes.PermissionDenied {
		o.State("error", "Access denied", "Check your account access", "tunn login", 0)
		return
	}
	if status.Code(err) == codes.ResourceExhausted && strings.Contains(text, "larger than max") {
		o.State("error", "Tunnel message too large", "Check the installed version", "tunn --version", 0)
		return
	}
	if match := tunnelLimit.FindStringSubmatch(text); len(match) == 3 {
		o.State("limit", "Limit reached", match[1]+" / "+match[2]+" tunnels. Stop one, then retry.", accountURL(server), 0)
		return
	}
	if status.Code(err) == codes.ResourceExhausted || strings.Contains(text, "quota") || strings.Contains(text, "limit reached") {
		o.State("limit", "Limit reached", "Tunnel stopped. Check usage and reset time.", accountURL(server), 0)
		return
	}
	if client.ClassifyFailure(err) == client.FailureRegistration {
		if strings.Contains(text, "already in use") || strings.Contains(text, "reserved") {
			o.State("error", "Tunnel name unavailable", "Choose another name", "tunn http 3000 --name my-app", 0)
		} else {
			o.State("error", "Tunnel rejected", "Check your account access", "tunn login", 0)
		}
		return
	}
	if client.ClassifyFailure(err) == client.FailureProtocol {
		o.State("error", "Relay cannot start this tunnel", "Check the installed version", "tunn --version", 0)
		return
	}
	o.State("offline", "Cannot reach tunn", "Tunnel stopped. Check your network.", "tunn hosts --json", 0)
}

// cliSession owns the human health reading. A relay alone cannot mark it Online.
type cliSession struct {
	mu             sync.Mutex
	out            *terminal.Output
	target, check  string
	ready, started bool
	retryAdvice    bool
	lastRequest    time.Time
	publicURL      string
	serve          *client.ServeClient
}

func attachCLI(ctx context.Context, s *client.ServeClient, o *terminal.Output, viewerActive ...bool) *cliSession {
	target, _, check := localReading(s.TargetURL)
	c := &cliSession{out: o, target: target, check: check, serve: s}
	s.Quiet = true
	if commonTrace() {
		s.SafeLogs = true
	} else {
		s.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s.OnLifecycle = func(e client.LifecycleEvent) {
		c.mu.Lock()
		defer c.mu.Unlock()
		switch e.State {
		case client.StateConnecting:
			if !c.started {
				o.State("starting", "Starting tunnel…", "", "", 0)
				c.started = true
			}
		case client.StateReady:
			c.ready = true
			c.retryAdvice = false
			scope := "Only you and invited people"
			if len(s.AccessTokenSHA256) > 0 {
				scope = "Private · Sign in or use an endpoint token"
			}
			if s.Public {
				scope = "Public · Anyone with the link"
			}
			first := c.publicURL == ""
			if !first && len(viewerActive) > 0 && viewerActive[0] {
				o.Hint("Inspector history cleared after reconnect")
			}
			if c.publicURL != e.PublicURL {
				o.Route(e.PublicURL, target, scope)
				c.publicURL = e.PublicURL
			}
			o.State("checking", "Checking local app…", "HTTPS route created", "", 0)
			c.probeLocked(ctx)
			if first {
				o.Hint("Ctrl+C stops this tunnel")
				o.Waiting(e.PublicURL)
			}
		case client.StateReconnecting:
			c.ready = false
			if !c.retryAdvice {
				detail := "Check your network."
				if !c.lastRequest.IsZero() {
					detail = "Last request " + c.lastRequest.Local().Format("15:04:05")
				}
				o.State("offline", "Cannot reach tunn", detail, "tunn hosts --json", 0)
				c.retryAdvice = true
			}
			o.State("reconnecting", fmt.Sprintf("Retrying in %s", e.RetryDelay.Round(time.Millisecond)), "", "", e.RetryDelay)
		}
	}
	if s.Inspector == nil {
		s.Inspector = client.NewInspector(s)
	}
	s.Inspector.OnEvent = func(e client.InspectionEvent, m client.InspectionMetrics) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if e.At.After(c.lastRequest) {
			c.lastRequest = e.At
		}
		if c.ready && ctx.Err() == nil {
			if e.TerminalReason == "target_error" {
				o.State("unreachable", "Local app unreachable", "Edge connected", check, 0)
			} else if e.TerminalReason == "complete" {
				o.State("online", "Online", "", "", 0)
			}
		}
		state, message := "", ""
		if e.TerminalReason != "complete" && e.TerminalReason != "peer_closed" {
			state = "error"
			switch e.TerminalReason {
			case "canceled":
				message = "Request canceled"
			case "target_error":
			case "auth_required":
				message = "Local app requires Authorization"
			default:
				message = "Request did not complete"
			}
		}
		o.Request(terminal.Event{At: e.At.Format(time.RFC3339Nano), Method: e.Method, Path: e.Path, Status: e.Status, DurationMS: e.DurationMS, RequestBytes: e.RequestBytes, ResponseBytes: e.ResponseBytes, ActiveStreams: m.ActiveStreams, State: state, Message: message})
	}
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.mu.Lock()
				if c.ready {
					c.probeLocked(ctx)
				}
				c.mu.Unlock()
			}
		}
	}()
	return c
}
func (c *cliSession) probeLocked(ctx context.Context) {
	err := probeLocalApp(ctx, c.serve)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		c.out.State("unreachable", "Local app unreachable", "Edge connected", c.check, 0)
		return
	}
	c.out.State("online", "Online", "", "", 0)
}

func commonTrace() bool { return *verbosity == "trace" }
func reportCLIError(title, detail, command string, jsonOutput bool) {
	terminal.New(os.Stderr, os.Stderr, jsonOutput).State("error", title, detail, command, 0)
}
func stoppedNormally(err error) bool {
	return err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

var helpColumns = regexp.MustCompile(`^\s*((?:tunn |--).+?) {2,}(.+)$`)

func writeCLIHelp(out io.Writer, text string) {
	if terminal.New(out, out, false).Width >= 70 {
		_, _ = io.WriteString(out, text)
		return
	}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		match := helpColumns.FindStringSubmatch(line)
		if len(match) == 3 {
			fmt.Fprintln(out, match[2])
			fmt.Fprintln(out, "  "+match[1])
			fmt.Fprintln(out)
		} else {
			fmt.Fprintln(out, line)
		}
	}
}
