package common

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// LogLevel represents the verbosity level
type LogLevel int

const (
	LogLevelNone LogLevel = iota
	LogLevelError
	LogLevelRequest
	LogLevelTrace
)

// ParseLogLevel parses a string into a LogLevel
func ParseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "none":
		return LogLevelNone
	case "error":
		return LogLevelError
	case "request":
		return LogLevelRequest
	case "trace":
		return LogLevelTrace
	default:
		return LogLevelError
	}
}

var currentLogLevel LogLevel = LogLevelError

// GetCurrentLogLevel returns the current log level (useful for testing)
func GetCurrentLogLevel() LogLevel {
	return currentLogLevel
}

// SetLogLevel sets the global log level and configures slog
func SetLogLevel(level LogLevel) {
	currentLogLevel = level

	var slogLevel slog.Level
	switch level {
	case LogLevelNone:
		slogLevel = slog.Level(100) // Very high level to suppress all logs
	case LogLevelError:
		slogLevel = slog.LevelError
	case LogLevelRequest:
		slogLevel = slog.LevelInfo
	case LogLevelTrace:
		slogLevel = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: slogLevel,
	}
	handler := slog.NewTextHandler(os.Stderr, opts)
	slog.SetDefault(slog.New(handler))
}

// LogError logs at error level
func LogError(msg string, args ...any) {
	slog.Error(msg, args...)
}

// LogInfo logs at info level
func LogInfo(msg string, args ...any) {
	slog.Info(msg, args...)
}

// LogDebug logs at debug level
func LogDebug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

// LogAuthTransport wraps http.RoundTripper with logging
type LogAuthTransport struct {
	Transport http.RoundTripper
	Token     string
}

func (t *LogAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.Token)
	LogDebug("sending request", "url", req.URL, "method", req.Method)

	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		LogError("request failed", "url", req.URL, "error", err)
		return resp, err
	}

	LogDebug("response received", "url", req.URL, "status", resp.Status)
	if resp.StatusCode == http.StatusUnauthorized {
		LogError("authentication failure", "url", req.URL)
	}

	return resp, err
}

// CancelRequest implements the requestCanceler interface, which is needed
// for the http.Client to properly handle request cancellation.
func (t *LogAuthTransport) CancelRequest(req *http.Request) {
	type canceler interface {
		CancelRequest(*http.Request)
	}
	if cr, ok := t.Transport.(canceler); ok {
		cr.CancelRequest(req)
	}
}
