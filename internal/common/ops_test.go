package common

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestOpsStructuredLogAttributes(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	LogError("database unavailable", "component", "store", "retryable", false)
	LogInfo("listeners bound", "component", "host", "port", 443)
	LogDebug("route chosen", "component", "host", "tunnel_id", "fixture")
	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	levels := []string{"ERROR", "INFO", "DEBUG"}
	for _, level := range levels {
		if !scanner.Scan() {
			t.Fatal("missing log record")
		}
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if record["level"] != level || record["component"] == nil || record["time"] == nil || record["msg"] == nil {
			t.Fatalf("lost structured fields: %v", record)
		}
	}
	if scanner.Scan() || scanner.Err() != nil {
		t.Fatal("unexpected log records")
	}
	if !strings.Contains(output.String(), `"retryable":false`) || !strings.Contains(output.String(), `"port":443`) {
		t.Fatal("typed fields were flattened to text")
	}
}

func TestOpsLogLevelFiltering(t *testing.T) {
	previous, level, stderr := slog.Default(), GetCurrentLogLevel(), os.Stderr
	defer func() { os.Stderr = stderr; SetLogLevel(level); slog.SetDefault(previous) }()
	for _, test := range []struct {
		level    LogLevel
		messages int
	}{{LogLevelNone, 0}, {LogLevelError, 1}, {LogLevelRequest, 2}, {LogLevelTrace, 3}} {
		file, err := os.CreateTemp(t.TempDir(), "logs")
		if err != nil {
			t.Fatal(err)
		}
		os.Stderr = file
		SetLogLevel(test.level)
		LogError("fixture error", "field", "value with spaces")
		LogInfo("fixture info")
		LogDebug("fixture debug")
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		if got := bytes.Count(contents, []byte("\n")); got != test.messages {
			t.Fatalf("level %d emitted %d records instead of %d", test.level, got, test.messages)
		}
		if test.messages > 0 && !bytes.Contains(contents, []byte(`field="value with spaces"`)) {
			t.Fatal("structured text field lost quoting")
		}
	}
}

func TestOpsConcurrentLogReconfiguration(t *testing.T) {
	previous, level := slog.Default(), GetCurrentLogLevel()
	defer func() { SetLogLevel(level); slog.SetDefault(previous) }()
	SetLogLevel(LogLevelNone)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 20; j++ {
				SetLogLevel(LogLevelNone)
				if GetCurrentLogLevel() != LogLevelNone {
					t.Error("log level changed unexpectedly")
				}
				LogInfo("concurrent fixture", "iteration", j)
			}
		}()
	}
	close(start)
	wg.Wait()
}
