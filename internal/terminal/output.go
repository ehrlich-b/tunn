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
	Detail        string `json:"detail,omitempty"`
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
	requestCount                uint64
	active                      int64
}

func New(out, errout io.Writer, jsonOutput bool) *Output {
	width := 100
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n > 0 {
		width = n
	}
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
		o.line(o.Out, Safe(text))
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
func byteReading(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%dB", n)
	}
	value := float64(n)
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	for _, unit := range units {
		value /= 1000
		if value < 999.5 {
			if value >= 9.95 {
				return fmt.Sprintf("%.0f%s", value, unit)
			}
			return fmt.Sprintf("%.1f%s", value, unit)
		}
	}
	return fmt.Sprintf("%.0fEB", value)
}

func (o *Output) Request(e Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	e.Type = "request"
	e.Method, e.Path = Safe(e.Method), Safe(e.Path)
	o.requestCount++
	o.active = e.ActiveStreams
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
	mark := o.marker(state)
	if state != "online" {
		mark += " "
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
	width := o.Width
	if width < 40 {
		width = 40
	}
	if !o.rows {

		o.line(o.Out, "")
		if width < 90 {
			o.line(o.Out, "METHOD  PATH")
			o.line(o.Out, "TIME      RESULT      TIME")
		} else {
			o.line(o.Out, fmt.Sprintf("%-8s  %-7s  %-*s  %-8s  %-7s %-11s %s", "TIME", "METHOD", width-65, "PATH", "RESULT", "TIME", "IN/OUT", "OPEN"))
		}
		o.rows = true
	}
	if width < 90 {
		o.line(o.Out, fmt.Sprintf("%s %s", column(clip(e.Method, 7), 7), clip(e.Path, width-8)))
		o.line(o.Out, fmt.Sprintf("%-8s  %s %-7s %s", stamp, mark, result, duration))
		o.line(o.Out, fmt.Sprintf("%s in / %s out · %d open", byteReading(e.RequestBytes), byteReading(e.ResponseBytes), e.ActiveStreams))
	} else {
		o.line(o.Out, fmt.Sprintf("%-8s  %s  %s  %s %-3s  %-7s %-11s %d", stamp, column(clip(e.Method, 7), 7), column(clip(e.Path, width-65), width-65), mark, result, duration, byteReading(e.RequestBytes)+"/"+byteReading(e.ResponseBytes), e.ActiveStreams))
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
	o.line(o.Out, fmt.Sprintf("Requests  %d · %d open", o.requestCount, o.active))
	o.line(o.Out, fmt.Sprintf("Traffic  %d B in / %d B out", o.requestBytes, o.responseBytes))
}

func (o *Output) URL(value string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.JSON {
		o.line(o.Out, o.paint("36", Safe(value)))
	}
}

func (o *Output) Waiting(url string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.JSON {
		return
	}
	o.line(o.Out, "")
	o.line(o.Out, "Requests forwarded to your app")
	o.line(o.Out, time.Now().Format("15:04:05")+"  No requests yet")
	o.line(o.Out, "curl "+Safe(url))
}
