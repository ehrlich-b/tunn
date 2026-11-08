// Package terminal renders terminal-native readings without cursor rewriting.
package terminal

import (
	"encoding/json"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/inspection"
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
	Type          string             `json:"type"`
	Code          string             `json:"code,omitempty"`
	URL           string             `json:"url,omitempty"`
	Target        string             `json:"target,omitempty"`
	Access        string             `json:"access,omitempty"`
	EndpointToken bool               `json:"endpoint_token,omitempty"`
	AllowedEmails []string           `json:"requested_emails,omitempty"`
	State         string             `json:"state,omitempty"`
	At            string             `json:"at,omitempty"`
	Method        string             `json:"method,omitempty"`
	Path          string             `json:"path,omitempty"`
	Status        int                `json:"status"`
	Timing        *inspection.Timing `json:"timing,omitempty"`
	DurationMS    int64              `json:"duration_ms"`
	RequestBytes  int64              `json:"request_bytes"`
	ResponseBytes int64              `json:"response_bytes"`
	ActiveStreams int64              `json:"active_streams"`
	RetryDelayMS  int64              `json:"retry_delay_ms,omitempty"`
	Detail        string             `json:"detail,omitempty"`
	Message       string             `json:"message,omitempty"`
	Command       string             `json:"command,omitempty"`
	Cause         string             `json:"cause,omitempty"`
	NextAction    string             `json:"next_action,omitempty"`
	HTTPStatus    int                `json:"http_status,omitempty"`
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
	text := markerText(state)
	switch text {
	case "[ok]":
		return o.paint("32", text)
	case "[x]":
		return o.paint("31", text)
	case "[!]":
		return o.paint("33", text)
	case "[o]":
		return text
	}
	return o.paint("2", text)
}
func (o *Output) Route(url, target, access string, endpointToken bool, allowed ...string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	url, target, access = Safe(url), Safe(target), Safe(access)
	if o.JSON {
		o.event(Event{Type: "route", URL: url, Target: target, Access: access, EndpointToken: endpointToken, AllowedEmails: allowed})
		return
	}
	o.reading("url", o.accent(url))
	o.reading("to", target)
	switch {
	case access == "public":
		o.reading("allowed", "anyone with the link")
	case len(allowed) > 0:
		o.reading("allowed", Safe(strings.Join(allowed, ", "))+" and you")
	default:
		o.reading("allowed", "only you")
	}
	if access != "public" {
		if endpointToken {
			o.reading("token", "endpoint token holders")
		}
		o.reading("others", "403 at the edge")
	}
	o.rows = false
}

// reading prints one aligned label/value line of the route block.
func (o *Output) reading(label, value string) {
	for i, line := range o.wrap(value, 9) {
		if i == 0 {
			o.line(o.Out, column(label, 9)+line)
		} else {
			o.line(o.Out, strings.Repeat(" ", 9)+line)
		}
	}
}

// Wrap breaks text at spaces so no word is split across terminal lines.
// Continuation lines are indented by indent cells.
func Wrap(text string, width, indent int) []string {
	if width < 20 || cells(text) <= width {
		return []string{text}
	}
	var lines []string
	current := ""
	for _, word := range strings.Split(text, " ") {
		budget := width
		if len(lines) > 0 {
			budget = width - indent
		}
		if current != "" && cells(current)+1+cells(word) > budget {
			lines = append(lines, current)
			current = word
			continue
		}
		if current == "" {
			current = word
		} else {
			current += " " + word
		}
	}
	lines = append(lines, current)
	for i := 1; i < len(lines); i++ {
		lines[i] = strings.Repeat(" ", indent) + lines[i]
	}
	return lines
}

// wrap fits text after a prefix of the given cells; only terminals wrap.
func (o *Output) wrap(text string, prefix int) []string {
	if !o.TTY {
		return []string{text}
	}
	lines := Wrap(text, o.Width-1-prefix, 2)
	return lines
}

func (o *Output) wrapped(w io.Writer, text string) {
	for _, line := range o.wrap(text, 0) {
		o.line(w, line)
	}
}

// Check is one hop of the route check printed when the local app fails.
type Check struct{ Label, State, Text string }

// RouteCheck reports a failed route as aligned hops, then the next command.
func (o *Output) RouteCheck(state, title string, checks []Check, command string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	key := state + title + command
	for _, c := range checks {
		key += c.Label + c.State + c.Text
	}
	if o.lastState == key {
		return
	}
	o.lastState = key
	if o.JSON {
		detail := ""
		if len(checks) > 0 {
			last := checks[len(checks)-1]
			detail = Safe(last.Label) + " · " + Safe(last.Text)
		}
		_ = json.NewEncoder(o.Err).Encode(Event{Type: "state", State: state, At: time.Now().Format(time.RFC3339Nano), Message: Safe(title), Detail: detail, Command: Safe(command), Cause: detail, NextAction: Safe(command)})
		return
	}
	labelWidth := 0
	for _, c := range checks {
		labelWidth = max(labelWidth, cells(Safe(c.Label)))
	}
	o.line(o.Err, o.paint("2", time.Now().Format("15:04:05"))+"  "+o.marker(state)+" "+o.paint("1", Safe(title)))
	for _, c := range checks {
		mark := o.marker(c.State)
		pad := 5 - cells(markerText(c.State))
		o.line(o.Err, column(Safe(c.Label), labelWidth+2)+mark+strings.Repeat(" ", pad)+Safe(c.Text))
	}
	if command != "" {
		o.line(o.Err, Safe(command))
	}
}

func markerText(state string) string {
	switch state {
	case "online":
		return "[ok]"
	case "error", "offline", "unreachable", "auth_expired", "auth_missing":
		return "[x]"
	case "reconnecting", "limit":
		return "[!]"
	case "unknown", "stopped":
		return "[o]"
	}
	return "[i]"
}

func (o *Output) State(state, title, detail, command string, delay time.Duration, httpStatus ...int) {
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
		if len(httpStatus) > 0 {
			e.HTTPStatus = httpStatus[0]
		}
		if command != "" {
			e.Cause, e.NextAction = detail, command
			if e.Cause == "" {
				e.Cause = title
			}
		}
		if state == "error" || state == "offline" || state == "unreachable" || state == "auth_expired" || state == "auth_missing" || state == "limit" {
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
	if state == "error" || state == "offline" || state == "unreachable" || state == "auth_expired" || state == "auth_missing" || state == "limit" {
		w = o.Err
	}
	if state == "stopped" {
		o.line(w, "")
	}
	if state == "error" || state == "offline" || state == "unreachable" || state == "auth_expired" || state == "auth_missing" {
		title = o.paint("1", title)
	}
	o.line(w, o.paint("2", time.Now().Format("15:04:05"))+"  "+o.marker(state)+" "+title)
	if detail != "" {
		o.wrapped(w, detail)
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
		o.wrapped(w, Safe(text))
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

// shortPath keeps the part of a path that tells requests apart: the query
// collapses first, then the middle of the path.
func shortPath(value string, budget int) string {
	value = Safe(value)
	if cells(value) <= budget {
		return value
	}
	if i := strings.IndexByte(value, '?'); i >= 0 && cells(value[:i])+2 <= budget {
		return value[:i] + "?…"
	}
	if budget < 8 {
		return clip(value, budget)
	}
	// Keep the longest run of trailing segments that leaves room for a head.
	tail := ""
	for i := len(value) - 1; i > 0; i-- {
		if value[i] == '/' && cells(value[i:]) <= budget-5 {
			tail = value[i:]
		}
	}
	if tail == "" {
		runes := []rune(value)
		for len(runes) > 0 && cells(string(runes)) > budget/2 {
			runes = runes[1:]
		}
		tail = string(runes)
	}
	head := strings.TrimSuffix(clip(value, budget-cells(tail)), "~")
	return head + "…" + tail
}

func column(value string, budget int) string {
	return value + strings.Repeat(" ", max(0, budget-cells(value)))
}

// accent is the one link color; it uses the terminal's own cyan so it reads
// in 16-color palettes, light or dark.
func (o *Output) accent(value string) string { return o.paint("36", value) }

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
	// Rows print when a request finishes, so stamp the finish time to keep
	// the column in order.
	if at, err := time.Parse(time.RFC3339Nano, e.At); err == nil {
		stamp = at.Add(time.Duration(e.DurationMS) * time.Millisecond).Local().Format("15:04:05")
	}
	duration := fmt.Sprintf("%dms", e.DurationMS)
	if e.DurationMS >= 1000 {
		duration = fmt.Sprintf("%.1fs", float64(e.DurationMS)/1000)
	}
	if e.DurationMS == 0 {
		duration = "<1ms"
	}
	width := max(40, o.Width)
	// Narrow terminals drop the AT column and give its cells to PATH.
	narrow := width < 70
	methodWidth, pathWidth := 7, width-65
	if narrow {
		methodWidth, pathWidth = 4, width-23
	}
	if !o.rows {
		o.line(o.Out, "")
		heading := fmt.Sprintf("%-*s %-*s %-7s %s", methodWidth, "METHOD"[:min(6, methodWidth)], pathWidth, "PATH", "RESULT", "ELAPSED")
		if !narrow {
			heading = fmt.Sprintf("%-8s ", "AT") + heading
		}
		o.line(o.Out, o.paint("2", heading))
		o.rows = true
	}
	mark := o.marker(state)
	if state == "online" {
		mark = o.paint("32", "[+]")
	}
	if state == "unknown" {
		result = "?"
	}
	row := fmt.Sprintf("%s %s %s %-3s %s", column(clip(e.Method, methodWidth), methodWidth), column(shortPath(e.Path, pathWidth), pathWidth), mark, result, clip(duration, 6))
	if !narrow {
		row = o.paint("2", fmt.Sprintf("%-8s", stamp)) + " " + row
	}
	if e.Status == 413 && !narrow {
		row += "  edge cap: 100 MiB"
	}
	o.line(o.Out, row)
	if e.Timing != nil {
		// Use a separate wrapping line so narrow terminals retain all four values.
		o.wrapped(o.Out, "  "+e.Timing.Summary())
	}
	if e.Status == 413 && narrow {
		o.line(o.Out, strings.Repeat(" ", methodWidth+1)+"edge cap 100 MiB")
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
	o.line(w, column("requests", 9)+fmt.Sprint(o.requestCount))
	o.line(w, column("traffic", 9)+byteSize(o.requestBytes)+" in · "+byteSize(o.responseBytes)+" out")
}

func byteSize(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
}

func (o *Output) URL(value string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.JSON {
		o.line(o.Out, o.accent(Safe(value)))
	}
}

// Diagnostic is human guidance; redirected stdout retains only readings.
func (o *Output) Diagnostic(text string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.JSON {
		o.wrapped(o.Err, Safe(text))
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

// PlanMessage preserves relay guidance in both terminal and JSON output.
func (o *Output) PlanMessage(kind, code, message string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	message = Safe(message)
	if o.JSON {
		o.event(Event{Type: kind, Code: Safe(code), Message: message})
		return
	}
	o.line(o.Err, message)
}
