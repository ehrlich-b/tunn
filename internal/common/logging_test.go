package common

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"none", LogLevelNone},
		{"error", LogLevelError},
		{"request", LogLevelRequest},
		{"trace", LogLevelTrace},
		{"NONE", LogLevelNone},
		{"ERROR", LogLevelError},
		{"REQUEST", LogLevelRequest},
		{"TRACE", LogLevelTrace},
		{"invalid", LogLevelError}, // defaults to error
		{"", LogLevelError},        // defaults to error
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseLogLevel(tt.input)
			if result != tt.expected {
				t.Errorf("ParseLogLevel(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSetLogLevel(t *testing.T) {
	// Save original state
	originalLevel := currentLogLevel
	defer func() {
		currentLogLevel = originalLevel
	}()

	tests := []LogLevel{
		LogLevelNone,
		LogLevelError,
		LogLevelRequest,
		LogLevelTrace,
	}

	for _, level := range tests {
		t.Run(level.String(), func(t *testing.T) {
			SetLogLevel(level)
			if currentLogLevel != level {
				t.Errorf("SetLogLevel(%v) did not set currentLogLevel correctly", level)
			}
		})
	}
}

func TestLogFunctions(t *testing.T) {
	// Save original state
	originalLevel := currentLogLevel
	defer func() {
		currentLogLevel = originalLevel
	}()

	// Capture log output
	var buf bytes.Buffer
	originalLogger := slog.Default()
	defer slog.SetDefault(originalLogger)

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Test at trace level (should show all logs)
	currentLogLevel = LogLevelTrace // Set level directly to avoid creating new handler
	buf.Reset()

	LogError("test error", "key", "value")
	LogInfo("test info", "key", "value")
	LogDebug("test debug", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "test error") {
		t.Error("LogError not working at trace level")
	}
	if !strings.Contains(output, "test info") {
		t.Error("LogInfo not working at trace level")
	}
	if !strings.Contains(output, "test debug") {
		t.Error("LogDebug not working at trace level")
	}

	// Test at error level (should only show errors)
	currentLogLevel = LogLevelError
	buf.Reset()

	LogError("test error", "key", "value")
	LogInfo("test info", "key", "value")
	LogDebug("test debug", "key", "value")

	output = buf.String()
	if !strings.Contains(output, "test error") {
		t.Error("LogError not working at error level")
	}
	if strings.Contains(output, "test info") {
		t.Error("LogInfo should not show at error level")
	}
	if strings.Contains(output, "test debug") {
		t.Error("LogDebug should not show at error level")
	}

	// Test at none level (should show nothing)
	currentLogLevel = LogLevelNone
	buf.Reset()

	LogError("test error", "key", "value")
	LogInfo("test info", "key", "value")
	LogDebug("test debug", "key", "value")

	output = buf.String()
	if output != "" {
		t.Error("No logs should show at none level, got:", output)
	}
}

func TestHTTPLoggingMiddleware(t *testing.T) {
	// Save original state
	originalLevel := currentLogLevel
	defer func() {
		currentLogLevel = originalLevel
	}()

	// Capture log output
	var buf bytes.Buffer
	originalLogger := slog.Default()
	defer slog.SetDefault(originalLogger)

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slog.SetDefault(slog.New(handler))

	// Test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Test at request level
	currentLogLevel = LogLevelRequest
	buf.Reset()

	middleware := HTTPLoggingMiddleware(testHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	output := buf.String()
	if !strings.Contains(output, "HTTP request") {
		t.Error("HTTP request logging not working")
	}
	if !strings.Contains(output, "GET") {
		t.Error("HTTP method not logged")
	}
	if !strings.Contains(output, "/test") {
		t.Error("HTTP URL not logged")
	}
	if !strings.Contains(output, "200") {
		t.Error("HTTP status not logged")
	}

	// Test at none level (should not log)
	currentLogLevel = LogLevelNone
	buf.Reset()

	middleware.ServeHTTP(w, req)

	output = buf.String()
	if output != "" {
		t.Error("HTTP logging should not occur at none level")
	}
}

func TestResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

	// Test default status code
	if wrapped.statusCode != 200 {
		t.Errorf("Default status code should be 200, got %d", wrapped.statusCode)
	}

	// Test setting status code
	wrapped.WriteHeader(404)
	if wrapped.statusCode != 404 {
		t.Errorf("Status code should be 404 after WriteHeader, got %d", wrapped.statusCode)
	}

	// Test writing data
	data := []byte("test data")
	n, err := wrapped.Write(data)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned %d bytes, expected %d", n, len(data))
	}
}

// Helper method for LogLevel to make tests more readable
func (l LogLevel) String() string {
	switch l {
	case LogLevelNone:
		return "none"
	case LogLevelError:
		return "error"
	case LogLevelRequest:
		return "request"
	case LogLevelTrace:
		return "trace"
	default:
		return "unknown"
	}
}