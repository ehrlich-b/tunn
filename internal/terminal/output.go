// Package terminal renders terminal-native readings without cursor rewriting.
package terminal

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mattn/go-isatty"
	textwidth "golang.org/x/text/width"
)

// Event is one JSON line. Existing inventory JSON has its own unchanged schema.
// Durations use milliseconds; traffic counts use bytes.
type Event struct {
	Type          string   `json:"type"`
	URL           string   `json:"url,omitempty"`
	Target        string   `json:"target,omitempty"`
	Access        string   `json:"access,omitempty"`
	EndpointToken bool     `json:"endpoint_token,omitempty"`
	AllowedEmails []string `json:"requested_emails,omitempty"`
	State         string   `json:"state,omitempty"`
	At            string   `json:"at,omitempty"`
	Method        string   `json:"method,omitempty"`
	Path          string   `json:"path,omitempty"`
	Status        int      `json:"status"`
	DurationMS    int64    `json:"duration_ms"`
	RequestBytes  int64    `json:"request_bytes"`
	ResponseBytes int64    `json:"response_bytes"`
	ActiveStreams int64    `json:"active_streams"`
	RetryDelayMS  int64    `json:"retry_delay_ms,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	Message       string   `json:"message,omitempty"`
	Command       string   `json:"command,omitempty"`
}

type Output struct {
	mu                          sync.Mutex
	Out, Err                    io.Writer
	JSON, Color, TTY            bool
	Width                       int
	lastState                   string
	rows                        bool
	requestBytes, responseBytes int64
	requestCount                uint64
}

func New(out, errout io.Writer, jsonOutput bool) *Output {
	width := 100
	color, tty := false, false
	if f, ok := out.(*os.File); ok && isatty.IsTerminal(f.Fd()) {
		tty = true
		width = terminalWidth(f)
		_, noColor := os.LookupEnv("NO_COLOR")
		color = !noColor && os.Getenv("TERM") != "dumb"
	}
	return &Output{Out: out, Err: errout, JSON: jsonOutput, Color: color, TTY: tty, Width: width}
}

// Safe prevents terminal control sequences in remote or application data.
func Safe(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, value)
}
func (o *Output) paint(code, value string) string {
	if o.Color && !o.JSON {
		return "\x1b[" + code + "m" + value + "\x1b[0m"
	}
	return value
}
func (o *Output) line(w io.Writer, value string) { fmt.Fprintln(w, value) }
func (e Event) MarshalJSON() ([]byte, error) {
	type plain Event
	data, err := json.Marshal(plain(e))
	if err != nil || e.Type == "request" {
		return data, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for _, key := range []string{"status", "duration_ms", "request_bytes", "response_bytes", "active_streams"} {
		delete(fields, key)
	}
	return json.Marshal(fields)
}
func (o *Output) event(e Event) { _ = json.NewEncoder(o.Out).Encode(e) }

func (o *Output) marker(state string) string {
	switch state {
	case "online":
		return o.paint("32", "[ok]")
	case "error", "offline", "unreachable", "auth_expired":
		return o.paint("31", "[x]")
	case "reconnecting", "limit":
		return o.paint("33", "[!]")
	case "unknown", "stopped":
		return "[o]"
	default:
		return o.paint("34", "[i]")
	}
}
func (o *Output) Route(url, target, access string, endpointToken bool, allowed ...string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	url, target, access = Safe(url), Safe(target), Safe(access)
	if o.JSON {
		o.event(Event{Type: "route", URL: url, Target: target, Access: access, EndpointToken: endpointToken, AllowedEmails: allowed})
		return
	}
	o.line(o.Out, "url  "+o.accent(url))
	o.line(o.Out, "to   "+target)
	if access == "public" {
		o.line(o.Out, "Public · Anyone with the link")
	} else {
		if endpointToken {
			o.line(o.Out, "Private · Sign in or use an endpoint token")
		} else {
			o.line(o.Out, "Private · Only you and invited people")
		}
		if len(allowed) > 0 {
			o.line(o.Out, "requested  "+Safe(strings.Join(allowed, ", "))+" and you")
		}
	}
	o.rows = false
}
func (o *Output) State(state, title, detail, command string, delay time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	key := state + title + detail + command + delay.String()
	if o.lastState == key {
		return
	}
	o.lastState = key
	title, detail, command = Safe(title), Safe(detail), Safe(command)
	if o.JSON {
		e := Event{Type: "state", State: state, At: time.Now().Format(time.RFC3339Nano), Message: title, Detail: detail, Command: command, RetryDelayMS: delay.Milliseconds()}
		if state == "error" || state == "offline" || state == "unreachable" || state == "auth_expired" || state == "limit" {
			_ = json.NewEncoder(o.Err).Encode(e)
		} else {
			o.event(e)
		}
		return
	}
	w := o.Out
	if !o.TTY {
		w = o.Err
	}
	if state == "error" || state == "offline" || state == "unreachable" || state == "auth_expired" || state == "limit" {
		w = o.Err
	}
	if state == "stopped" {
		o.line(w, "")
	}
	if state == "error" || state == "offline" || state == "unreachable" || state == "auth_expired" {
		title = o.paint("31", title)
	}
	o.line(w, time.Now().Format("15:04:05")+"  "+o.marker(state)+" "+title)
	if detail != "" {
		o.line(w, detail)
	}
	if command != "" {
		o.line(w, command)
	}
}
func (o *Output) Hint(text string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.JSON {
		w := o.Out
		if !o.TTY {
			w = o.Err
		}
		o.line(w, Safe(text))
	}
}
func runeCells(r rune) int {
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
		return 0
	}
	kind := textwidth.LookupRune(r).Kind()
	if kind == textwidth.EastAsianWide || kind == textwidth.EastAsianFullwidth || (r >= 0x1f300 && r <= 0x1faff) {
		return 2
	}
	return 1
}
func cells(value string) int {
	n := 0
	for _, r := range value {
		n += runeCells(r)
	}
	return n
}
func clip(value string, budget int) string {
	value = Safe(value)
	if cells(value) <= budget {
		return value
	}
	if budget < 1 {
		return ""
	}
	var result strings.Builder
	used := 0
	for _, r := range value {
		n := runeCells(r)
		if used+n > budget-1 {
			break
		}
		result.WriteRune(r)
		used += n
	}
	return result.String() + "~"
}

func column(value string, budget int) string {
	return value + strings.Repeat(" ", max(0, budget-cells(value)))
}
func (o *Output) accent(value string) string {
	// Use truecolor only when the terminal reports a background; otherwise
	// preserve its native palette.
	if os.Getenv("COLORTERM") == "truecolor" {
		switch os.Getenv("COLORFGBG") {
		case "15;0":
			return o.paint("1;38;2;255;79;18", value)
		case "0;15":
			return o.paint("1;38;2;173;48;0", value)
		}
	}
	return o.paint("1;33", value)
}

func (o *Output) Request(e Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	e.Type = "request"
	e.Method, e.Path = Safe(e.Method), Safe(e.Path)
	o.requestCount++
	o.requestBytes += e.RequestBytes
	o.responseBytes += e.ResponseBytes
	if o.JSON {
		o.event(e)
		return
	}
	e.Path = strings.ReplaceAll(e.Path, "%5Bredacted%5D", "[redacted]")
	result, state := strconv.Itoa(e.Status), "online"
	if e.Status == 0 {
		result, state = "unknown", "unknown"
	} else if e.Status >= 400 || e.State == "error" {
		state = "error"
	} else if (e.Status >= 100 && e.Status < 200) || e.Status >= 300 {
		state = "info"
	}
	stamp := Safe(e.At)
	if at, err := time.Parse(time.RFC3339Nano, e.At); err == nil {
		stamp = at.Local().Format("15:04:05")
	}
	duration := fmt.Sprintf("%dms", e.DurationMS)
	if e.DurationMS >= 1000 {
		duration = fmt.Sprintf("%.1fs", float64(e.DurationMS)/1000)
	}
	if e.DurationMS == 0 {
		duration = "<1ms"
	}
	width := max(40, o.Width)
	methodWidth, pathWidth := 7, width-65
	if width < 70 {
		methodWidth, pathWidth = 4, width-33
	}
	if !o.rows {
		o.line(o.Out, "")
		o.line(o.Out, fmt.Sprintf("%-8s %-*s %-*s %-7s %s", "AT", methodWidth, "METHOD"[:min(6, methodWidth)], pathWidth, "PATH", "RESULT", "ELAPSED"))
		o.rows = true
	}
	if e.Status == 413 && width < 70 {
		// Preserve the full limit at narrow widths rather than wrapping a request.
		o.line(o.Out, fmt.Sprintf("%s %s %s 413; edge cap 100 MiB", clip(e.Method, 4), clip(e.Path, 7), o.marker("error")))
	} else {
		mark := o.marker(state)
		if state == "online" {
			mark = o.paint("32", "[+]")
		}
		if state == "unknown" {
			result = "?"
		}
		row := fmt.Sprintf("%-8s %s %s %s %-3s %s", stamp, column(clip(e.Method, methodWidth), methodWidth), column(clip(e.Path, pathWidth), pathWidth), mark, result, clip(duration, 6))
		if width >= 70 && e.Status == 413 {
			row += "  edge cap: 100 MiB"
		}
		o.line(o.Out, row)
	}
	if e.Message != "" && e.Status != 413 {
		o.line(o.Err, o.marker("error")+" "+Safe(e.Message))
	}
}

func (o *Output) Summary() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.JSON {
		return
	}
	w := o.Out
	if !o.TTY {
		w = o.Err
	}
	o.line(w, fmt.Sprintf("Requests  %d", o.requestCount))
	o.line(w, fmt.Sprintf("Traffic  %d B in / %d B out", o.requestBytes, o.responseBytes))
}

func (o *Output) URL(value string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.JSON {
		o.line(o.Out, o.paint("36", Safe(value)))
	}
}

// Diagnostic is human guidance; redirected stdout retains only readings.
func (o *Output) Diagnostic(text string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.JSON {
		o.line(o.Err, Safe(text))
	}
}

// Reading is inventory data and stays on stdout even when redirected.
func (o *Output) Reading(text string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.JSON {
		o.line(o.Out, Safe(text))
	}
}
