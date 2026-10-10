package sshfront

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/testnet"
	"golang.org/x/crypto/ssh"
)

func TestSniffSSHAndTLS(t *testing.T) {
	l := testnet.NewListener()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 1)
	shared := Share(ctx, l, func(_ context.Context, c net.Conn) {
		defer func() { _ = c.Close() }()
		b := make([]byte, 8)
		_, e := io.ReadFull(c, b)
		if e == nil {
			got <- string(b)
		}
	})
	defer func() { _ = shared.Close() }()
	s, err := l.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	_, _ = s.Write([]byte("SSH-2.0-client\r\n"))
	select {
	case banner := <-got:
		if banner != "SSH-2.0-" {
			t.Fatal(banner)
		}
	case <-time.After(time.Second):
		t.Fatal("SSH sniff timeout")
	}
	tls, err := l.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tls.Close() }()
	_, _ = tls.Write([]byte{0x16, 3, 1, 0, 1, 0})
	conn, err := shared.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	b := make([]byte, 6)
	if _, err := io.ReadFull(conn, b); err != nil {
		t.Fatal(err)
	}
	if b[0] != 0x16 || b[5] != 0 {
		t.Fatalf("ClientHello corrupted: %v", b)
	}
	cancel()
	if _, err := shared.Accept(); err == nil {
		t.Fatal("closed listener accepted")
	}
}

func TestSniffRealSSHAndTLSHandshakesOnOneListener(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{HostKey: hostKey, Resolve: func(context.Context, string) (string, error) { return "", nil }, Establish: func(context.Context, Identity, *Stream) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := testnet.NewListener()
	shared := Share(ctx, l, s.ServeConn)
	defer func() { _ = shared.Close() }()
	raw, err := l.Dial()
	if err != nil {
		t.Fatal(err)
	}
	conn, channels, requests, err := ssh.NewClientConn(raw, "memory:443", &ssh.ClientConfig{User: "tunn", Auth: []ssh.AuthMethod{ssh.PublicKeys(hostKey)}, HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	c := ssh.NewClient(conn, channels, requests)
	defer func() { _ = c.Close() }()
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.CombinedOutput("help")
	if err != nil || len(output) == 0 {
		t.Fatalf("shared SSH=%s %v", output, err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"memory.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	tlsListener := tls.NewListener(shared, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}})
	done := make(chan error, 1)
	go func() {
		c, err := tlsListener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = c.Close() }()
		data := make([]byte, 4)
		_, err = io.ReadFull(c, data)
		if err == nil {
			_, err = c.Write(data)
		}
		done <- err
	}()
	raw, err = l.Dial()
	if err != nil {
		t.Fatal(err)
	}
	tlsClient := tls.Client(raw, &tls.Config{ServerName: "memory.test", RootCAs: pool})
	defer func() { _ = tlsClient.Close() }()
	_ = tlsClient.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := tlsClient.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4)
	if _, err := io.ReadFull(tlsClient, data); err != nil || string(data) != "ping" {
		t.Fatalf("shared TLS=%s %v", data, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSniffHTTPSIsNotStarvedBySSHSessionSlots(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := testnet.NewListener()
	started := make(chan struct{}, 128)
	shared := Share(ctx, l, func(ctx context.Context, c net.Conn) {
		defer func() { _ = c.Close() }()
		started <- struct{}{}
		<-ctx.Done()
	})
	defer func() { _ = shared.Close() }()
	for range 128 {
		raw, err := l.Dial()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = raw.Close() }()
		if _, err := raw.Write([]byte("SSH-2.0-client\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	for range 128 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("SSH classification stalled")
		}
	}
	raw, err := l.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	_, _ = raw.Write([]byte{0x16, 3, 1, 0, 1, 0})
	done := make(chan error, 1)
	go func() {
		c, err := shared.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = c.Close() }()
		data := make([]byte, 6)
		_, err = io.ReadFull(c, data)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSH sessions starved HTTPS")
	}
}
