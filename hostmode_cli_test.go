package main

import (
	"bytes"
	"context"
	"errors"
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

func TestHostCLIConfigErrorDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.yaml")
	if err := os.WriteFile(path, []byte("version: 2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"check", "install"} {
		t.Run(action, func(t *testing.T) {
			args := []string{action, "--config", path, "--dry-run"}
			var out, stderr bytes.Buffer
			err := hostCommand(context.Background(), "service", args, &out, &stderr)
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			writeHostError(&out, &stderr, err, args)
			if !strings.HasSuffix(stderr.String(), "Command failed\nhost config version must be 1\ntunn --help\n") {
				t.Fatalf("missing ordered diagnostic: %s", stderr.String())
			}
			if out.Len() != 0 {
				t.Fatal("diagnostic on stdout")
			}
		})
	}
}

func TestHostCLICredentialErrorsStayRedacted(t *testing.T) {
	for _, token := range []string{"", "private-token-secret\ninvalid", "eyJprivate-token-secret"} {
		t.Run(token, func(t *testing.T) {
			dir := t.TempDir()
			tokenPath := filepath.Join(dir, "private-token-secret")
			// The missing-file error includes the private path in its cause.
			if token != "" {
				if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, "host.yaml")
			manifest := "version: 1\nmachine: fixture\ntoken_file: " + tokenPath + "\ntunnels:\n  - name: fixture-http\n    kind: http\n    target: \"8080\"\n    allow: [owner@example.test]\n"
			if err := os.WriteFile(path, []byte(manifest), 0600); err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{"check", "install", "restart"} {
				t.Run(action, func(t *testing.T) {
					// Install and restart must run without --dry-run to check credentials.
					args := []string{action, "--config", path}
					var out, stderr bytes.Buffer
					err := hostCommand(context.Background(), "service", args, &out, &stderr)
					if err == nil {
						t.Fatal("invalid credential accepted")
					}
					if token == "" {
						var pathErr *os.PathError
						if !errors.As(err, &pathErr) || pathErr.Path != tokenPath || !os.IsNotExist(pathErr) {
							t.Fatalf("expected missing credential error containing the private path, got %v", err)
						}
					}
					writeHostError(&out, &stderr, err, args)
					if out.Len() != 0 || strings.Contains(stderr.String(), "private-token-secret") {
						t.Fatalf("credential information printed: stdout=%q stderr=%q", out.String(), stderr.String())
					}
					if !strings.HasSuffix(stderr.String(), "Command failed\nCheck command options\ntunn --help\n") {
						t.Fatalf("credential diagnostic changed: %s", stderr.String())
					}
				})
			}
		})
	}
}
