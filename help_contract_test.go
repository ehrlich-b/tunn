package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestCLIHelpMatchesInstallerMarker(t *testing.T) {
	if os.Getenv("TUNN_HELP_CONTRACT_CHILD") == "1" {
		os.Args = []string{"tunn", "--help"}
		main()
		t.Fatal("tunn --help returned instead of exiting")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Read the actual bytes used by the installer, without duplicating its
	// banner or importing Python source into the production Go binary.
	readMarker := exec.CommandContext(ctx, "python3", "-B", "-c",
		`import runpy, sys; sys.stdout.buffer.write(runpy.run_path(sys.argv[1])["HELP_MARKER"])`,
		"deploy/install/artifacts.py")
	var markerErrors bytes.Buffer
	readMarker.Stderr = &markerErrors
	marker, err := readMarker.Output()
	if err != nil {
		t.Fatalf("read installer HELP_MARKER: %v\n%s", err, &markerErrors)
	}
	if len(marker) == 0 {
		t.Fatal("installer HELP_MARKER is empty")
	}

	ctx, cancelHelp := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelHelp()
	// main's flag parser handles --help and exits, so run it in a child.
	// Capture both streams just as Installation.install does.
	help := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIHelpMatchesInstallerMarker$")
	help.Env = append(os.Environ(), "TUNN_HELP_CONTRACT_CHILD=1")
	output, err := help.CombinedOutput()
	if err != nil {
		t.Fatalf("tunn --help: %v\n%s", err, output)
	}
	// The installer only examines the first 64 KiB; a later match cannot
	// make a candidate installable.
	if len(output) > 65536 {
		output = output[:65536]
	}
	if !bytes.Contains(output, marker) {
		t.Fatalf("tunn --help does not contain installer HELP_MARKER %q\n%s", marker, output)
	}
}
