package sshfront

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/testnet"
	"golang.org/x/crypto/ssh"
)

func startupClient(t *testing.T, cfg Config) *ssh.Client {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cfg.HostKey = key
	cfg.Resolve = func(context.Context, string) (string, error) { return "", nil }
	cfg.Establish = func(context.Context, Identity, *Stream) error { return nil }
	server, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	raw, peer := testnet.Pair()
	t.Cleanup(func() { _ = raw.Close() })
	go server.ServeConn(ctx, peer)
	conn, channels, requests, err := ssh.NewClientConn(raw, "memory:443", &ssh.ClientConfig{
		User: "tunn", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(key.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestIdleSSHStartupDeadline(t *testing.T) {
	for _, pty := range []bool{false, true} {
		t.Run(map[bool]string{false: "no session", true: "PTY without command"}[pty], func(t *testing.T) {
			client := startupClient(t, Config{StartupTimeout: 100 * time.Millisecond})
			if pty {
				session, err := client.NewSession()
				if err != nil {
					t.Fatal(err)
				}
				if err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { done <- client.Wait() }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("idle client retained an SSH session slot")
			}
		})
	}
}

func TestSSHHelpPTYLineEndings(t *testing.T) {
	client := startupClient(t, Config{StartupTimeout: time.Second})
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	output, err := session.CombinedOutput("help")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte("\r\n")) || strings.Contains(strings.ReplaceAll(string(output), "\r\n", ""), "\n") {
		t.Fatalf("terminal output did not return to the start of each line: %q", output)
	}
}

func TestSSHCommandOutlivesStartupDeadline(t *testing.T) {
	client := startupClient(t, Config{StartupTimeout: 100 * time.Millisecond,
		Command: func(ctx context.Context, _ Identity, _ []string, _ io.Reader, out io.Writer) error {
			timer := time.NewTimer(300 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
				_, err := io.WriteString(out, "completed\n")
				return err
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.CombinedOutput("hosts")
	if err != nil || string(output) != "completed\n" {
		t.Fatalf("started command=%q, %v", output, err)
	}
}
