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
)

// Event is one JSON line. Existing inventory JSON has its own unchanged schema.
// Durations use milliseconds; traffic counts use bytes.
type Event struct {
	Type          string `json:"type"`
	URL           string `json:"url,omitempty"`
	Target        string `json:"target,omitempty"`
	Access        string `json:"access,omitempty"`
	State         string `json:"state,omitempty"`
	At            string `json:"at,omitempty"`
	Method        string `json:"method,omitempty"`
	Path          string `json:"path,omitempty"`
	Status        int    `json:"status,omitempty"`
	DurationMS    int64  `json:"duration_ms,omitempty"`
	RequestBytes  int64  `json:"request_bytes,omitempty"`
	ResponseBytes int64  `json:"response_bytes,omitempty"`
	ActiveStreams int64  `json:"active_streams,omitempty"`
	RetryDelayMS  int64  `json:"retry_delay_ms,omitempty"`
	Message       string `json:"message,omitempty"`
	Command       string `json:"command,omitempty"`
}

type Output struct {
	mu                          sync.Mutex
	Out, Err                    io.Writer
	JSON, Color                 bool
	Width                       int
	lastState                   string
	rows                        bool
	requestBytes, responseBytes int64
}

func New(out, errout io.Writer, jsonOutput bool) *Output {
	width := 100
	color := false
	if f, ok := out.(*os.File); ok && isatty.IsTerminal(f.Fd()) {
		width = terminalWidth(f)
		_, noColor := os.LookupEnv("NO_COLOR")
		color = !noColor && os.Getenv("TERM") != "dumb"
	}
	return &Output{Out: out, Err: errout, JSON: jsonOutput, Color: color, Width: width}
}

// Safe prevents terminal control sequences in remote or application data.
func Safe(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
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
func (o *Output) event(e Event)                  { _ = json.NewEncoder(o.Out).Encode(e) }
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
func (o *Output) Route(url, target, access string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	url, target, access = Safe(url), Safe(target), Safe(access)
	if o.JSON {
		o.event(Event{Type: "route", URL: url, Target: target, Access: access})
		return
	}
	o.line(o.Out, o.paint("36", url))
	o.line(o.Out, "  -> "+target)
	o.line(o.Out, access)
	o.rows = false
}
func (o *Output) State(state, title, detail, command string, delay time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lastState == state {
		return
	}
	o.lastState = state
	title, detail, command = Safe(title), Safe(detail), Safe(command)
	if o.JSON {
		o.event(Event{Type: "state", State: state, Message: title, Command: command, RetryDelayMS: delay.Milliseconds()})
		return
	}
	w := o.Out
	if state == "error" || state == "offline" || state == "unreachable" || state == "auth_expired" || state == "limit" {
		w = o.Err
	}
	o.line(w, o.marker(state)+" "+title)
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
		o.line(o.Out, Safe(text))
	}
}
func clip(value string, width int) string {
	r := []rune(Safe(value))
	if len(r) > width {
		if width < 1 {
			return ""
		}
		return string(r[:width-1]) + "~"
	}
	return string(r)
}
func (o *Output) Request(e Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	e.Type = "request"
	e.Method, e.Path = Safe(e.Method), Safe(e.Path)
	o.requestBytes += e.RequestBytes
	o.responseBytes += e.ResponseBytes
	if o.JSON {
		o.event(e)
		return
	}
	result, state := strconv.Itoa(e.Status), "online"
	if e.Status == 0 {
		result, state = "unknown", "unknown"
	} else if e.Status >= 400 || e.State == "error" {
		state = "error"
	} else if e.Status >= 300 {
		state = "info"
	}
	stamp := e.At
	if at, err := time.Parse(time.RFC3339Nano, e.At); err == nil {
		stamp = at.Local().Format("15:04:05")
	}
	duration := fmt.Sprintf("%dms", e.DurationMS)
	width := o.Width
	if width < 40 {
		width = 40
	}
	if !o.rows {
		o.line(o.Out, "")
		if width < 70 {
			o.line(o.Out, "METHOD  PATH")
			o.line(o.Out, "TIME      RESULT      TIME")
		} else {
			o.line(o.Out, fmt.Sprintf("%-8s  %-7s  %-*s  %-8s  %s", "TIME", "METHOD", width-45, "PATH", "RESULT", "TIME"))
		}
		o.rows = true
	}
	if width < 70 {
		o.line(o.Out, fmt.Sprintf("%-7s %s", clip(e.Method, 7), clip(e.Path, width-8)))
		o.line(o.Out, fmt.Sprintf("%-8s  %s %-7s %s", stamp, o.marker(state), result, duration))
	} else {
		o.line(o.Out, fmt.Sprintf("%-8s  %-7s  %-*s  %s %-3s  %s", stamp, clip(e.Method, 7), width-45, clip(e.Path, width-45), o.marker(state), result, duration))
	}
	if e.Message != "" {
		o.line(o.Err, o.marker("error")+" "+Safe(e.Message))
	}
}
func (o *Output) Summary() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.JSON {
		return
	}
	o.line(o.Out, fmt.Sprintf("Traffic  %d B in / %d B out", o.requestBytes, o.responseBytes))
}
