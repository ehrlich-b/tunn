package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
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
	for _, args := range [][]string{nil, {"unknown"}, {"serve", "--probe", "https://relay.example/path"}, {"serve", "extra"}, {"incident", "--db", path}, {"incident", "--db", path, "extra"}, {"resolve", "--db", path}, {"resolve", "--db", path, "-1"}, {"resolve", "--db", path, "--note", "x", "999"}, {"serve", "--unknown"}} {
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
		done <- executeStatus(ctx, []string{"serve", "--db", path, "--listen", addr, "--probe", probe.URL}, &bytes.Buffer{}, &bytes.Buffer{})
	}()
	client := statuspage.ProbeClient(time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://" + addr + "/status.json")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
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
