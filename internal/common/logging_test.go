package common

import (
	"bytes"
	"log/slog"
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
	// Test that log functions work (now they just call slog directly)
	var buf bytes.Buffer
	originalLogger := slog.Default()
	defer slog.SetDefault(originalLogger)

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slog.SetDefault(slog.New(handler))

	LogError("test error", "key", "value")
	LogInfo("test info", "key", "value")
	LogDebug("test debug", "key", "value")

	output := buf.String()
	if !strings.Contains(output, "test error") {
		t.Error("LogError not working")
	}
	if !strings.Contains(output, "test info") {
		t.Error("LogInfo not working")
	}
	if !strings.Contains(output, "test debug") {
		t.Error("LogDebug not working")
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