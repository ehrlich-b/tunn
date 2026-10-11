package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/sshfront"
	"golang.org/x/crypto/ssh"
)

// Coordinator-only acceptance: requires loopback listeners and permission to
// execute native OpenSSH. The offline edge gate compiles but never runs it.
func TestLoopbackEdgeOpenSSHAndHTTPSSharePort(t *testing.T) {
	sshBinary, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal("required native OpenSSH executable unavailable", err)
	}
	p, _, _ := sshRelay(t, true)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.sshKeys.Add(context.Background(), "owner@example.com", string(ssh.MarshalAuthorizedKey(clientKey.PublicKey()))); err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "edge-loopback-fixture")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	keyFile := filepath.Join(root, "client_key")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	hostKey := sshSigner(t)
	server, err := sshfront.New(sshfront.Config{
		HostKey: hostKey, Resolve: p.sshKeys.Owner, Establish: p.establishSSH,
		RenderQR: func(_ context.Context, url string, out io.Writer) error {
			_, err := fmt.Fprintf(out, "fixture QR: %s\n", url)
			return err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("required shared-port loopback listener unavailable", err)
	}
	shared := sshfront.Share(ctx, raw, server.ServeConn)
	t.Cleanup(func() { _ = shared.Close() })
	certFile, tlsKeyFile, pool := edgeTLSFiles(t)
	certificate, err := tls.LoadX509KeyPair(certFile, tlsKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	publicHTTP := &http.Server{Handler: p.createHandler(), ReadHeaderTimeout: time.Second}
	go func() {
		_ = publicHTTP.Serve(tls.NewListener(shared, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}}))
	}()
	t.Cleanup(func() { _ = publicHTTP.Close() })
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("required local target loopback listener unavailable", err)
	}
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "native SSH %s", r.URL.RequestURI())
	})}
	go func() { _ = upstream.Serve(origin) }()
	t.Cleanup(func() { _ = upstream.Close() })
	_, port, _ := net.SplitHostPort(raw.Addr().String())
	_, originPort, _ := net.SplitHostPort(origin.Addr().String())
	knownHosts := filepath.Join(root, "known_hosts")
	if err := os.WriteFile(knownHosts, append([]byte("[127.0.0.1]:"+port+" "), ssh.MarshalAuthorizedKey(hostKey.PublicKey())...), 0600); err != nil {
		t.Fatal(err)
	}
	// All authentication/forwarding options are supplied by this fixture;
	// machine-wide SSH config must not alter its local acceptance contract.
	command := exec.CommandContext(ctx, sshBinary, "-F", "/dev/null", "-T", "-p", port, "-i", keyFile,
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile="+knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null", "-o", "ExitOnForwardFailure=yes",
		"-R", "0:127.0.0.1:"+originPort, "tunn@127.0.0.1", "--",
		"--name", "openssh-fixture", "--public", "--qr", "--expire=30s")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
			if t.Failed() {
				t.Logf("native SSH diagnostic: %s", stderr.String())
			}
		case <-time.After(3 * time.Second):
			t.Error("native SSH did not stop after cancellation")
		}
	})
	output := bufio.NewReader(stdout)
	if line := sshLine(t, output); line != "https://openssh-fixture.tunn.test\n" {
		t.Fatal("native remote forwarding did not publish endpoint", line)
	}
	for lines := 0; lines < 4; lines++ {
		if line := sshLine(t, output); strings.HasPrefix(line, "fixture QR:") {
			break
		} else if lines == 3 {
			t.Fatal("native SSH --qr flag did not reach renderer")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "tunn.test", RootCAs: pool}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for _, tc := range []struct{ host, path, body string }{
		{"tunn.test", "/health", "ok"},
		{"openssh-fixture.tunn.test", "/probe?value=1", "native SSH /probe?value=1"},
	} {
		request, err := http.NewRequestWithContext(ctx, "GET", "https://"+raw.Addr().String()+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = tc.host
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("HTTPS request on active SSH port failed", err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != 200 || string(body) != tc.body {
			t.Fatalf("shared native SSH/TLS: %d %q %v", response.StatusCode, body, err)
		}
	}
}
