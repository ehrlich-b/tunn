package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
)

type connectWriteCloser struct{ io.Writer }

func (connectWriteCloser) Close() error { return nil }

func TestConnectStdioFullDuplexAndInputEOF(t *testing.T) {
	input, applicationInput := io.Pipe()
	output, applicationOutput := io.Pipe()
	defer func() { _ = applicationInput.Close(); _ = output.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	observed := make(chan string, 1)
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodConnect || r.URL.Path != common.TCPConnectPath || r.Header.Get(common.TCPConnectHeader) != common.TCPConnectValue || r.Header.Get("Tunn-Authorization") != "Bearer account-jwt" {
			t.Errorf("invalid CONNECT request: %s %s %v", r.Method, r.URL, r.Header)
		}
		response, target := io.Pipe()
		go func() {
			// Send the server banner before reading any client data. A pump
			// that waits for stdin EOF before downloading would deadlock here.
			if _, err := target.Write([]byte("SSH-2.0-forge\r\n")); err != nil {
				_ = target.CloseWithError(err)
				return
			}
			body, err := io.ReadAll(r.Body)
			observed <- string(body)
			if err == nil {
				_, err = target.Write([]byte("after-input-eof"))
			}
			_ = target.CloseWithError(err)
		}()
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: response}, nil
	})
	var status bytes.Buffer
	c := &ConnectClient{EndpointURL: "https://forge-ssh.tunn.to" + common.TCPConnectPath, Token: "account-jwt", HTTPClient: &http.Client{Transport: transport}, Output: &status}
	done := make(chan error, 1)
	go func() { done <- c.RunStdio(ctx, input, applicationOutput) }()
	banner := make([]byte, len("SSH-2.0-forge\r\n"))
	if _, err := io.ReadFull(output, banner); err != nil || string(banner) != "SSH-2.0-forge\r\n" {
		t.Fatalf("server-first banner = %q, %v", banner, err)
	}
	if _, err := applicationInput.Write([]byte("SSH-2.0-laptop\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = applicationInput.Close()
	body, err := io.ReadAll(output)
	if err != nil || string(body) != "after-input-eof" {
		t.Fatalf("response after input EOF = %q, %v", body, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := <-observed; got != "SSH-2.0-laptop\r\n" {
		t.Fatalf("uploaded bytes = %q", got)
	}
	if status.Len() != 0 {
		t.Fatalf("stdio emitted status output: %q", status.String())
	}
}

func TestConnectStdioDenialsNeverReachStdout(t *testing.T) {
	for _, status := range []int{401, 403, 503, 307} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			requests := 0
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Location": {"https://attacker.test"}}, Body: io.NopCloser(strings.NewReader("denied")), Request: r}, nil
			})
			input, peer := io.Pipe() // Stalled stdin must also be closed on denial.
			defer func() { _ = peer.Close() }()
			var stdout bytes.Buffer
			c := &ConnectClient{EndpointURL: "https://forge-ssh.tunn.to", Token: "account-jwt", HTTPClient: &http.Client{Transport: transport}}
			if err := c.RunStdio(context.Background(), input, connectWriteCloser{&stdout}); err == nil {
				t.Fatal("denied connection returned success")
			}
			if stdout.Len() != 0 || requests != 1 {
				t.Fatalf("denial wrote stdout or followed a redirect: stdout=%q requests=%d", stdout.String(), requests)
			}
		})
	}
}

func TestConnectStdioCancellationUnblocksIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input, inputPeer := io.Pipe()
	response, responsePeer := io.Pipe()
	defer func() { _ = inputPeer.Close(); _ = responsePeer.Close() }()
	opened := make(chan struct{})
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(opened)
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: response}, nil
	})
	c := &ConnectClient{EndpointURL: "https://forge-ssh.tunn.to", HTTPClient: &http.Client{Transport: transport}}
	done := make(chan error, 1)
	go func() { done <- c.RunStdio(ctx, input, connectWriteCloser{io.Discard}) }()
	<-opened
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled stream returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation retained blocked stdin or response")
	}
	if _, err := inputPeer.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("stdin left open after cancellation: %v", err)
	}
}

func TestConnectStdioReportsCutoff(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Trailer: http.Header{"Tunn-Limit-Reason": {"owner_byte_budget"}}, Body: io.NopCloser(strings.NewReader("prefix"))}, nil
	})
	var stdout bytes.Buffer
	c := &ConnectClient{EndpointURL: "https://forge-ssh.tunn.to", HTTPClient: &http.Client{Transport: transport}}
	err := c.RunStdio(context.Background(), io.NopCloser(strings.NewReader("client")), connectWriteCloser{&stdout})
	if err == nil || !strings.Contains(err.Error(), "owner_byte_budget") || stdout.String() != "prefix" {
		t.Fatalf("cutoff = %q, %v", stdout.String(), err)
	}
}
