package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	statuspage "github.com/ehrlich-b/tunn/internal/status"
)

func TestStatusCLIIncidentJourneyAndErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.db")
	var out, errOut bytes.Buffer
	run := func(args ...string) error { return executeStatus(context.Background(), args, &out, &errOut) }
	if err := run("incident", "--db", path, "--title", "Fixture incident", "--note", "Investigating"); err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(out.String())
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		t.Fatal(out.String())
	}
	if err := run("resolve", "--db", path, "--note", "Recovered", id); err != nil {
		t.Fatal(err)
	}
	s, err := statuspage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Snapshot(context.Background(), time.Now())
	_ = s.Close()
	if err != nil || len(v.Incidents) != 1 || v.Incidents[0].ResolvedAt == nil || v.Incidents[0].Note != "Recovered" {
		t.Fatal(v, err)
	}
	for _, args := range [][]string{nil, {"unknown"}, {"serve", "--probe", "https://relay.example/path"}, {"serve", "--probe", "http://relay.example"}, {"serve", "--probe", "http://127.0.0.1:8091"}, {"serve", "--probe", "http://relay.example", "--allow-http-loopback"}, {"serve", "extra"}, {"incident", "--db", path}, {"incident", "--db", path, "extra"}, {"resolve", "--db", path}, {"resolve", "--db", path, "-1"}, {"resolve", "--db", path, "--note", "x", "999"}, {"serve", "--unknown"}} {
		if err := run(args...); err == nil {
			t.Fatal("invalid CLI accepted", args)
		}
	}
	if err := run("serve", "--help"); !errors.Is(err, flag.ErrHelp) {
		t.Fatal("help", err)
	}
}
func TestStatusCLIServeShutdownAndPersistentHistory(t *testing.T) {
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer probe.Close()
	path := filepath.Join(t.TempDir(), "status.db")
	// Reserve an ephemeral address and release it just before starting the server.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- executeStatus(ctx, []string{"serve", "--db", path, "--listen", addr, "--probe", probe.URL, "--allow-http-loopback"}, &bytes.Buffer{}, &bytes.Buffer{})
	}()
	client := statuspage.ProbeClient(time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://" + addr + "/status.json")
		if err == nil {
			var snapshot statuspage.Snapshot
			decodeErr := json.NewDecoder(resp.Body).Decode(&snapshot)
			resp.Body.Close()
			// Serving HTTP can precede the collector's first persisted sample.
			// Wait for that sample before cancelling the collector under test.
			if resp.StatusCode == 200 && decodeErr == nil && snapshot.Observed == 1 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("collector did not start", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not shut down")
	}
	s, err := statuspage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, err := s.Snapshot(context.Background(), time.Now())
	if err != nil || v.Observed != 1 {
		t.Fatal(v, err)
	}
}

func TestStatusCLIOfflineObserver(t *testing.T) {
	var hits atomic.Int64
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer probe.Close()
	root := t.TempDir()
	raw := filepath.Join(root, "raw")
	if err := os.Mkdir(raw, 0700); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("scripts/status-observer/testdata/synthetic/raw/2026-10-01.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(raw, "2026-10-01.jsonl")
	if err := os.WriteFile(input, bytes.ReplaceAll(fixture, []byte("https://tunn.to"), []byte(probe.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(root, "imported.db")
	cmd := exec.Command("python3", "scripts/status-observer/import_status.py", "--data-dir", root, "--db", db, "--origin", probe.URL, "--synthetic", "--now", "2026-10-01T12:02:10Z")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(output))
	}
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- executeStatus(ctx, []string{"serve", "--offline", "--db", db, "--listen", addr, "--probe", probe.URL, "--allow-http-loopback"}, &bytes.Buffer{}, &bytes.Buffer{})
	}()
	client := statuspage.ProbeClient(time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://" + addr + "/status.json")
		if err == nil {
			var got statuspage.Snapshot
			decodeErr := json.NewDecoder(resp.Body).Decode(&got)
			resp.Body.Close()
			if decodeErr != nil || resp.StatusCode != 200 || got.State != "unknown" {
				t.Fatal(got, decodeErr)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("offline server failed to start", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(db)
	if err != nil || !bytes.Equal(before, after) || hits.Load() != 0 {
		t.Fatal("offline history changed or probes sent", err, hits.Load())
	}
	for _, listen := range []string{"0.0.0.0:8091", "localhost:8091"} {
		if err := executeStatus(context.Background(), []string{"serve", "--offline", "--db", db, "--listen", listen}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatal("nonliteral loopback accepted", listen)
		}
	}
	t.Log("SYNTHETIC: offline CLI served unknown, made zero probes and preserved database bytes")
}
