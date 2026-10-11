package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestConnectReportsAccountCutoffTrailer(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	data := make(chan string, 1)
	go func() { bytes, _ := io.ReadAll(b); data <- string(bytes) }()
	hc := &http.Client{Transport: meteringTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != "CONNECT" || r.Header.Get("Tunn-Authorization") != "Bearer endpoint-token" {
			t.Error("CONNECT credential missing")
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Trailer: http.Header{"Tunn-Limit-Reason": {"owner_byte_budget"}}, Body: io.NopCloser(strings.NewReader("prefix")), Request: r}, nil
	})}
	c := &ConnectClient{EndpointURL: "https://work.relay.test", Token: "endpoint-token"}
	if err := c.handleConnection(context.Background(), hc, a); err == nil || !strings.Contains(err.Error(), "owner_byte_budget") {
		t.Fatal("cutoff reported as normal EOF", err)
	}
	if received := <-data; received != "prefix" {
		t.Fatal(received)
	}
}
