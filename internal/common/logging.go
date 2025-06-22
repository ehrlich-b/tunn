package common

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"
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

// LogError logs at error level (always shown unless none)
func LogError(msg string, args ...any) {
	if currentLogLevel >= LogLevelError {
		slog.Error(msg, args...)
	}
}

// LogInfo logs at info level (shown at request and trace levels)
func LogInfo(msg string, args ...any) {
	if currentLogLevel >= LogLevelRequest {
		slog.Info(msg, args...)
	}
}

// LogDebug logs at debug level (shown only at trace level)
func LogDebug(msg string, args ...any) {
	if currentLogLevel >= LogLevelTrace {
		slog.Debug(msg, args...)
	}
}

// HTTPLoggingMiddleware logs HTTP requests based on the current log level
func HTTPLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if currentLogLevel < LogLevelRequest {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		
		// Capture request details for trace level
		var requestDump []byte
		if currentLogLevel >= LogLevelTrace {
			if dump, err := httputil.DumpRequest(r, true); err == nil {
				requestDump = dump
			}
		}

		// Wrap the response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
		
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		
		// Log based on level
		if currentLogLevel >= LogLevelTrace && len(requestDump) > 0 {
			LogDebug("HTTP request trace",
				"method", r.Method,
				"url", r.URL.String(),
				"remote_addr", r.RemoteAddr,
				"status", wrapped.statusCode,
				"duration", duration,
				"request_dump", string(requestDump),
			)
		} else if currentLogLevel >= LogLevelRequest {
			LogInfo("HTTP request",
				"method", r.Method,
				"url", r.URL.String(),
				"remote_addr", r.RemoteAddr,
				"status", wrapped.statusCode,
				"duration", duration,
			)
		}
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// LogAuthTransport wraps http.RoundTripper with logging
type LogAuthTransport struct {
	Transport http.RoundTripper
	Token     string
}

func (t *LogAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.Token)
	
	// Log at trace level
	if currentLogLevel >= LogLevelTrace {
		if dump, err := httputil.DumpRequestOut(req, true); err == nil {
			LogDebug("outgoing request", "dump", string(dump))
		}
	}
	
	LogDebug("sending request", "url", req.URL, "method", req.Method)
	
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		LogError("request failed", "url", req.URL, "error", err)
	} else {
		LogDebug("response received", "url", req.URL, "status", resp.Status)
		if resp.StatusCode == http.StatusUnauthorized {
			LogError("authentication failure", "url", req.URL)
		}
		
		// Log response at trace level
		if currentLogLevel >= LogLevelTrace {
			if dump, err := httputil.DumpResponse(resp, true); err == nil {
				// Create a copy of the response body for logging
				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				LogDebug("response trace", "dump", string(dump))
			}
		}
	}
	
	return resp, err
}