package main

import (
	"context"
	"crypto/tls"
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
	"syscall"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/terminal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// productHeading names the release; development builds print no heading.
func productHeading() string {
	if version == "development build" || version == "" {
		return ""
	}
	return "tunn " + version + "\n\n"
}
func firstRun(out io.Writer) {
	writeCLIHelp(out, productHeading()+"Sign in\n  tunn login\n\nChoose who gets in to port 3000\n")
	commandLadder(out)
	fmt.Fprintln(out, "\nAll commands\n  tunn --help")
}
func commandLadder(out io.Writer) {
	writeCLIHelp(out, `  tunn 3000                         Only you
  tunn 3000 --allow=alex@example.com  You and Alex
  tunn 3000 --allow=@example.com     You and that email domain
  tunn 3000 --public                Anyone with the link
`)
}
func printHelp(out io.Writer) {
	fmt.Fprint(out, productHeading())
	writeCLIHelp(out, "Start\n  tunn login                        Sign in\n\nChoose who gets in\n")
	commandLadder(out)
	writeCLIHelp(out, `
Inspect
  tunn 3000 --inspect               Local request inspector
  tunn 3000 --json                  Request events as JSON lines
  tunn hosts --json                 List machines and tunnels as JSON

Access
  tunn share NAME EMAIL             Invite to a running tunnel
  tunn unshare NAME EMAIL           Remove access
  tunn access NAME                  List access
  tunn keys --help                  Manage your SSH keys
  tunn token NAME                   Show a tunnel's access token
  tunn ip-policy --help             Allow or block IP addresses
  tunn usage NAME                   See traffic used this month
  tunn grant --help                 Give someone a time-limited token
  tunn policy --help                Headers and rate limits

More
  tunn http --help                  HTTP options
  tunn status                       Check account tunnels
  tunn list                         List account tunnels
  tunn hosts                        List machines and tunnels
  tunn service --help               Run tunnels in the background
  tunn service status               Check the local service
  tunn mcp --help                   Run a local MCP server
  tunn connector-check --help       Check an MCP connector
  tunn tcp --help                   Share a TCP port
  tunn unix --help                  Share a Unix socket
  tunn connect --help               Connect to a remote endpoint
  tunn domain --help                Custom domains
  tunn version                      Print the build version

Compare · diff tunn ngrok
  Choose visitor emails with --allow
  https://tunn.to/ngrok-alternative

Global options go before the command
  --verbosity none|error|request|trace
    Choose the log detail
  --version
    Print version
`)
}

func shellURL(value string) string {
	if strings.ContainsAny(value, " \\;&|$`'\"()<>[]*?{}~#\t\r\n") {
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
	return relayOrigin(server) + "/account"
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

// relayOrigin drops credentials, paths and queries before printing a relay URL.
func relayOrigin(server string) string {
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" || strings.ContainsAny(u.Host, "\r\n\x1b") {
		return "https://tunn.to"
	}
	return "https://" + strings.TrimSuffix(u.Host, ":443")
}
func relayCheck(server string) string {
	return "curl --connect-timeout 5 -I " + shellURL(relayOrigin(server))
}
func loginCommand() string {
	if dir := os.Getenv("TUNN_CONFIG_DIR"); dir != "" {
		return "TUNN_CONFIG_DIR=" + shellURL(dir) + " tunn login"
	}
	return "tunn login"
}
func loginCause(err error) string {
	if errors.Is(err, client.ErrNotLoggedIn) {
		return "No saved login on this machine"
	}
	if client.LoginRequired(err) || client.AuthenticationFailure(err) {
		return "Login expired or revoked"
	}
	return "Sign-in failed"
}

func savedLoginCause(err error) string {
	if client.LoginRequired(err) || client.AuthenticationFailure(err) {
		return loginCause(err)
	}
	if strings.Contains(err.Error(), "saved login belongs to a different server") {
		return "Saved login is for a different server"
	}
	return "Saved login file is unreadable"
}

func loginRelayFailure(err error) bool {
	var network net.Error
	var response *client.DeviceCodeHTTPError
	var certificate *tls.CertificateVerificationError
	return errors.As(err, &certificate) || client.RetryableCredentialError(err) || errors.As(err, &network) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &response) && response.StatusCode >= 500 && response.StatusCode <= 599)
}
func showHTTPLoginRequired(o *terminal.Output, err error) bool {
	if !client.LoginRequired(err) {
		return false
	}
	cause := loginCause(err)
	state := "auth_expired"
	if errors.Is(err, client.ErrNotLoggedIn) {
		state = "auth_missing"
	}
	if o.JSON {
		o.State(state, "Sign in required", cause, loginCommand(), 0)
	} else {
		// Services keep one log line and the exit status that prevents restart loops.
		o.Diagnostic(client.LoginRequiredMessage())
	}
	return true
}
func relayCause(err error) string {
	var response *client.DeviceCodeHTTPError
	if errors.As(err, &response) && response.StatusCode >= 500 && response.StatusCode <= 599 {
		return fmt.Sprintf("Relay returned HTTP %d", response.StatusCode)
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return "Relay TLS certificate verification failed"
	}
	if client.RetryableCredentialError(err) {
		return "Login server unavailable"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "Relay DNS lookup failed"
	}
	if relayRefused(err) {
		return "Relay connection refused"
	}
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return "Relay connection timed out"
	}
	return "Relay connection failed"
}
func relayRecovery(err error) string {
	var response *client.DeviceCodeHTTPError
	if errors.As(err, &response) && response.StatusCode >= 500 && response.StatusCode <= 599 {
		return "Retry when the relay is reachable"
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return "Check the relay certificate"
	}
	if relayRefused(err) {
		return "Relay is down or the address is wrong"
	}
	return "Restore your connection"
}
func relayRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	// gRPC reports dial failures as status text without the original net error.
	return status.Code(err) == codes.Unavailable && strings.Contains(strings.ToLower(err.Error()), "connection refused")
}
func showTunnelError(o *terminal.Output, err error, server string) {
	if client.AuthenticationFailure(err) || status.Code(err) == codes.Unauthenticated {
		o.State("auth_expired", "Sign in again", "Login expired or rejected", loginCommand(), 0)
		return
	}
	text := strings.ToLower(err.Error())
	if status.Code(err) == codes.PermissionDenied {
		o.State("error", "Access denied", "Relay denied this account access", accountURL(server), 0)
		return
	}
	if status.Code(err) == codes.ResourceExhausted && strings.Contains(text, "larger than max") {
		o.State("error", "Tunnel message too large", "Check the installed version", "tunn --version", 0)
		return
	}
	if match := tunnelLimit.FindStringSubmatch(text); len(match) == 3 {
		o.State("limit", "Tunnel limit reached", match[1]+" / "+match[2]+" tunnels in use. Stop a running tunnel.", accountURL(server), 0)
		return
	}
	if status.Code(err) == codes.ResourceExhausted || strings.Contains(text, "quota") || strings.Contains(text, "limit reached") {
		o.State("limit", "Limit reached", "Relay usage limit reached. Check the reset time.", accountURL(server), 0)
		return
	}
	if client.ClassifyFailure(err) == client.FailureRegistration {
		if strings.Contains(text, "already in use") || strings.Contains(text, "reserved") {
			o.State("error", "Tunnel name unavailable", "Choose another name", "tunn 3000 --name my-app", 0)
		} else {
			o.State("error", "Tunnel rejected", "Relay rejected this account or tunnel", accountURL(server), 0)
		}
		return
	}
	if client.ClassifyFailure(err) == client.FailureProtocol {
		o.State("error", "Relay cannot start this tunnel", "Check the installed version", "tunn --version", 0)
		return
	}
	o.State("offline", "Cannot reach tunn", relayCause(err)+". "+relayRecovery(err)+".", relayCheck(server), 0)
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
	health         string
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
			c.health = ""
			c.retryAdvice = false
			first := c.publicURL == ""
			if !first && len(viewerActive) > 0 && viewerActive[0] {
				o.Hint("Inspector history cleared after reconnect")
			}
			if c.publicURL != e.PublicURL {
				access := "private"
				if s.Public {
					access = "public"
				}
				o.Route(e.PublicURL, target, access, len(s.AccessTokenSHA256) > 0, s.AllowedEmails...)
				c.publicURL = e.PublicURL
			}
			o.State("checking", "Checking local app…", "HTTPS route created", "", 0)
			if !first {
				o.State("reconnected", "Reconnected", "", "", 0)
			}
			c.probeLocked(ctx)
			if first {
				o.Hint("Ctrl+C stops this tunnel")
				if !s.Public && len(s.AllowedEmails) == 0 && s.TunnelID != "" {
					o.Hint("Invite someone:")
					o.Hint("tunn share " + shellURL(s.TunnelID) + " alex@example.com")
				}
			}
		case client.StateReconnecting:
			c.ready = false
			if !c.retryAdvice {
				detail := relayCause(e.Err) + ". " + relayRecovery(e.Err) + "; tunn retries automatically."
				if !c.lastRequest.IsZero() {
					detail += " Last request " + c.lastRequest.Local().Format("15:04:05")
				}
				o.State("offline", "Cannot reach tunn", detail, relayCheck(s.ServerAddr), 0)
				c.retryAdvice = true
			}
			o.State("reconnecting", fmt.Sprintf("Retrying in %.1f s", e.RetryDelay.Seconds()), "", "", e.RetryDelay)
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
				c.unreachable(nil)
			} else if e.TerminalReason == "complete" {
				c.health = "online"
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
		if e.Status == 413 {
			message = "Body rejected; edge limit is 100 MiB"
		}
		o.Request(terminal.Event{At: e.At.Format(time.RFC3339Nano), Method: e.Method, Path: e.Path, Status: e.Status, DurationMS: e.DurationMS, Timing: e.Timing, RequestBytes: e.RequestBytes, ResponseBytes: e.ResponseBytes, ActiveStreams: m.ActiveStreams, State: state, Message: message})
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
		c.unreachable(err)
		return
	}
	c.health = "online"
	c.out.State("online", "Online", "", "", 0)
}

func (c *cliSession) unreachable(err error) {
	if c.health == "unreachable" {
		return
	}
	c.health = "unreachable"
	detail := "Local app did not respond"
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		detail = "Connection refused"
	}
	c.out.RouteCheck("unreachable", "Local app unreachable", []terminal.Check{
		{Label: "browser", State: "unknown", Text: "not checked"},
		{Label: "edge", State: "online", Text: "connected"},
		{Label: "tunn on laptop", State: "online", Text: "connected"},
		{Label: c.target, State: "error", Text: strings.ToLower(detail) + "; start your app here"},
	}, c.check)
}

func commonTrace() bool { return *verbosity == "trace" }
func reportCLIError(title, detail, command string, jsonOutput bool) {
	terminal.New(os.Stderr, os.Stderr, jsonOutput).State("error", title, detail, command, 0)
}
func stoppedNormally(err error) bool {
	return err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

var helpColumns = regexp.MustCompile(`^\s*((?:tunn |--).+?) {2,}(.+)$`)

var helpWidth = func(out io.Writer) int { return terminal.New(out, out, false).Width }

func writeCLIHelp(out io.Writer, text string) {
	width := helpWidth(out)
	if width >= 70 {
		for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			match := helpColumns.FindStringSubmatch(line)
			if len(match) == 3 {
				fmt.Fprintf(out, "  %-34s  %s\n", match[1], match[2])
			} else {
				fmt.Fprintln(out, line)
			}
		}
		return
	}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		match := helpColumns.FindStringSubmatch(line)
		if len(match) == 3 {
			fmt.Fprintln(out, "  "+match[1])
			fmt.Fprintln(out, "    "+match[2])
			fmt.Fprintln(out)
		} else {
			indent := len(line) - len(strings.TrimLeft(line, " "))
			for _, wrapped := range terminal.Wrap(line, width-1, indent+2) {
				fmt.Fprintln(out, wrapped)
			}
		}
	}
}

func printRawHelp(out io.Writer, kind string) {
	switch kind {
	case "tcp":
		writeCLIHelp(out, `Usage: tunn tcp HOST:PORT [options]

Publish a TCP service through tunn.
Private by default.
Visitors run tunn connect.

Example
  tunn tcp localhost:5432 --name db \
    --allow=alex@example.com

Options
  --name NAME     Choose the endpoint name
  --allow EMAILS  People or email domains
  --public        Anyone with the link
`)
	case "unix":
		writeCLIHelp(out, `Usage: tunn unix PATH [options]

Publish a Unix socket through tunn.
Private by default.
Visitors run tunn connect.

Example
  tunn unix ./app.sock --name app \
    --allow=alex@example.com

Options
  --name NAME     Choose the endpoint name
  --allow EMAILS  People or email domains
  --public        Anyone with the link
  --adapter http  Forward HTTP to the socket
`)
	case "connect":
		writeCLIHelp(out, `Usage: tunn connect ENDPOINT [options]

Forward an endpoint to a local port.
Use account access or an endpoint token.

Example
  tunn connect db --account \
    --listen 127.0.0.1:15432

Options
  --account          Use your signed-in account
  --token-file FILE  Read an endpoint token
  --listen ADDRESS   Local loopback address
  --stdio            Forward standard input/output
  --public           Connect without credentials
`)
	}
}
