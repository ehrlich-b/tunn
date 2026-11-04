package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReportPayloadAndDryRun(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	var out bytes.Buffer
	if err := executeReport([]string{"hello"}, &out, server.Client(), server.URL); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), string(received)+"\n") || !strings.Contains(string(received), `"text":"hello"`) {
		t.Fatalf("output %q payload %q", out.String(), received)
	}
	received = nil
	out.Reset()
	if err := executeReport([]string{"--dry-run", "hello"}, &out, server.Client(), server.URL); err != nil {
		t.Fatal(err)
	}
	if received != nil {
		t.Fatal("dry run sent a request")
	}
	if err := executeReport([]string{strings.Repeat("x", 4001)}, &out, server.Client(), server.URL); err == nil {
		t.Fatal("accepted oversized report")
	}
}
