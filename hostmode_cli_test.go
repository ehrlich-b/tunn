package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostCLIPreview(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nmachine: gpu-box\ntunnels:\n  - name: gpu-http\n    kind: http\n    target: \"8080\"\n    allow: [owner@example.com]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"darwin", "linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			var out, stderr bytes.Buffer
			if err := hostCommand(context.Background(), "service", []string{"install", "--dry-run", "--os", platform, "--config", path}, &out, &stderr); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "service") || !strings.Contains(out.String(), "host.yaml") {
				t.Fatalf("invalid unit preview: %s", out.String())
			}
			if strings.Contains(out.String(), "owner@example.com") {
				t.Fatal("unit leaked the manifest allow-list")
			}
		})
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatal("dry-run created a service artifact")
	}
}

func TestHostCLIRejectsInvalidActions(t *testing.T) {
	for _, args := range [][]string{{}, {"replace"}, {"install", "--unknown"}, {"install", "extra"}} {
		var out, stderr bytes.Buffer
		if err := hostCommand(context.Background(), "service", args, &out, &stderr); err == nil {
			t.Fatalf("invalid command accepted: %v", args)
		}
	}
}
