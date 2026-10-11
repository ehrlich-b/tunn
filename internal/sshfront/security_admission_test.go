package sshfront

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/testnet"
	"golang.org/x/crypto/ssh"
)

// Pin the selected dependency, rather than just text in go.mod, and exercise
// ordinary rejection separately in TestReviewOuterAgentAndUnixForwardingDenied.
func TestReviewSSHDependencyPatched(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-json", "golang.org/x/crypto").Output()
	if err != nil {
		t.Fatal(err)
	}
	var module struct {
		Version string
		Replace *struct{ Version string }
	}
	if err := json.Unmarshal(out, &module); err != nil {
		t.Fatal(err)
	}
	var major, minor, patch int
	if _, err := fmt.Sscanf(module.Version, "v%d.%d.%d", &major, &minor, &patch); err != nil {
		t.Fatal(err)
	}
	if module.Replace != nil || major == 0 && minor < 56 || strings.Contains(module.Version, "-") {
		t.Fatalf("selected SSH dependency %s is not a patched release (minimum v0.56.0)", module.Version)
	}
	t.Logf("selected golang.org/x/crypto %s", module.Version)
}

func reviewForwardClient(t *testing.T, seed func(*Server, Identity)) (*ssh.Client, *Server, Identity) {
	t.Helper()
	cfg := Config{StartupTimeout: 100 * time.Millisecond}
	signer := reviewSigner(t)
	id := Identity{Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), Email: "alice@example.com", IP: "127.0.0.1"}
	cfg.HostKey = signer
	cfg.Resolve = func(context.Context, string) (string, error) { return id.Email, nil }
	cfg.Establish = func(context.Context, Identity, *Stream) error { return nil }
	cfg.Connect = func(context.Context, Identity, string) (net.Conn, error) {
		local, peer := net.Pipe()
		go func() { defer peer.Close(); io.Copy(peer, peer) }()
		return reviewHalfOpenOrigin{local}, nil
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if seed != nil {
		seed(s, id)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	raw, peer := testnet.Pair()
	t.Cleanup(func() { raw.Close(); peer.Close() })
	go s.ServeConn(ctx, peer)
	conn, ch, req, err := ssh.NewClientConn(raw, "memory:443", &ssh.ClientConfig{User: "tunn", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	c := ssh.NewClient(conn, ch, req)
	t.Cleanup(func() { c.Close() })
	return c, s, id
}

func TestReviewDirectForwardIdentityBudgets(t *testing.T) {
	for _, kind := range []string{"key", "ip", "account"} {
		t.Run(kind, func(t *testing.T) {
			c, _, _ := reviewForwardClient(t, func(s *Server, id Identity) {
				limit := 10
				if kind == "ip" {
					limit = 30
				}
				if kind == "account" {
					limit = 20
				}
				for n := 0; n < limit; n++ {
					other := id
					if kind != "key" {
						other.Fingerprint = fmt.Sprint(n)
					}
					if kind != "ip" {
						other.IP = fmt.Sprint(n)
					}
					if kind != "account" {
						other.Email = fmt.Sprint(n) + "@example.com"
					}
					release, err := s.acquire(other)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(release)
				}
			})
			stream, err := c.Dial("tcp", "private:22")
			if err == nil {
				stream.Close()
				t.Fatalf("direct forwarding bypassed the per-%s budget", kind)
			}
		})
	}
}

func TestReviewDirectForwardIdleExpiryAndRelease(t *testing.T) {
	c, s, id := reviewForwardClient(t, nil)
	stream, err := c.Dial("tcp", "private:22")
	if err != nil {
		t.Fatal(err)
	}
	// Active forwarding outlives startup expiry and carries real bytes.
	time.Sleep(150 * time.Millisecond)
	if _, err := stream.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(stream, b); err != nil {
		t.Fatal(err)
	}
	second, err := c.Dial("tcp", "private:22")
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	// Closing one multiplexed channel must not start idle expiry while another
	// is still forwarding.
	time.Sleep(150 * time.Millisecond)
	if _, err := second.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(second, b); err != nil {
		t.Fatal(err)
	}
	second.Close()
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle consumer transport retained its session slot after forwarding ended")
	}
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		active := 0
		for _, k := range []string{"key:" + id.Fingerprint, "ip:" + id.IP, "account:" + id.Email, "transport:key:" + id.Fingerprint, "transport:ip:" + id.IP, "transport:account:" + id.Email} {
			if b := s.budgets[k]; b != nil {
				active += b.active
			}
		}
		s.mu.Unlock()
		if active == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("closed transport retained identity budget", active)
		}
		time.Sleep(time.Millisecond)
	}
}

func reviewSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// Model an origin that keeps producing output after an input half-close.
// Closing the SSH channel entirely must still release its forwarding budget.
type reviewHalfOpenOrigin struct{ net.Conn }

func (c reviewHalfOpenOrigin) CloseWrite() error { return nil }
