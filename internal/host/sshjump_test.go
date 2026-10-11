package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/sshfront"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"golang.org/x/crypto/ssh"
)

type jumpPublisherStream struct{ *durableControlStream }

type jumpMailCapture struct{ delivered chan [2]string }

func (s jumpMailCapture) SendMagicLink(to, link string) error {
	s.delivered <- [2]string{to, link}
	return nil
}

func (s jumpPublisherStream) Send(m *pb.TunnelMessage) error {
	select {
	case s.incoming <- m:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s jumpPublisherStream) Recv() (*pb.TunnelMessage, error) {
	select {
	case m := <-s.outgoing:
		return m, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

// Runs registration and the real publisher's TCP adapter without a consumer
// binary or token. Only the control-stream transport is in process.
func jumpPublish(t *testing.T, p *ProxyServer, target string, allowed []string) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &durableControlStream{ctx: ctx, incoming: make(chan *pb.TunnelMessage, 32), outgoing: make(chan *pb.TunnelMessage, 32)}
	token, err := p.generateJWT("owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	stream.incoming <- &pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: &pb.RegisterClient{TunnelId: "forge-ssh", TargetUrl: "tcp", EndpointProtocol: "tcp", AuthToken: token, TunnelKey: p.config.WellKnownKey, AllowedEmails: allowed, Capabilities: []string{common.CapabilityConnectionStreamV1}}}}
	hostDone := make(chan struct{})
	go func() { defer close(hostDone); _ = p.tunnelServer.EstablishTunnel(stream) }()
	select {
	case m := <-stream.outgoing:
		if !m.GetRegisterResponse().Success {
			t.Fatal(m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("registration timeout")
	}
	publisher := &client.ServeClient{TargetURL: target, EndpointProtocol: "tcp"}
	clientDone := make(chan struct{})
	go func() { defer close(clientDone); _ = publisher.ServeMessages(ctx, jumpPublisherStream{stream}) }()
	stop := func() { cancel(); <-hostDone; <-clientDone }
	t.Cleanup(stop)
	return stop
}

func jumpKey(t *testing.T, path string) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "native jump fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestLoopbackNativeSSHJump(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal(err)
	}
	sftpBin, err := exec.LookPath("sftp")
	if err != nil {
		t.Fatal(err)
	}
	sshdBin := "/usr/sbin/sshd"
	if _, err := os.Stat(sshdBin); err != nil {
		t.Fatal("native jump acceptance requires openssh-server", err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	p, _, _ := sshRelay(t, true)
	root := t.TempDir()
	recipient := filepath.Join(root, "recipient")
	if err := os.Mkdir(recipient, 0700); err != nil {
		t.Fatal(err)
	}
	aliceFile := filepath.Join(recipient, "id_ed25519")
	alice := jumpKey(t, aliceFile)
	alicePub := string(ssh.MarshalAuthorizedKey(alice.PublicKey()))
	if _, err := p.storage.FindOrCreateByEmails(context.Background(), []string{"alice@example.com"}, "test"); err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(root, "authorized_keys")
	if err := os.WriteFile(authorized, []byte(alicePub), 0600); err != nil {
		t.Fatal(err)
	}
	originKeyFile := filepath.Join(root, "origin_host_key")
	originKey := jumpKey(t, originKeyFile)
	originCfg := filepath.Join(root, "sshd_config")
	config := fmt.Sprintf("HostKey %s\nAuthorizedKeysFile %s\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nAllowUsers %s\nSubsystem sftp internal-sftp\nLogLevel ERROR\n", originKeyFile, authorized, current.Username)
	if err := os.WriteFile(originCfg, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	// sshd inetd mode inherits each accepted socket and remains unprivileged.
	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				file, err := conn.(*net.TCPConn).File()
				if err != nil {
					return
				}
				defer file.Close()
				command := exec.CommandContext(ctx, sshdBin, "-i", "-e", "-f", originCfg)
				command.Stdin = file
				command.Stdout = file
				_ = command.Run()
			}()
		}
	}()
	stopPublisher := jumpPublish(t, p, origin.Addr().String(), []string{"alice@example.com"})
	relayKey := sshSigner(t)
	front, err := sshfront.New(sshfront.Config{HostKey: relayKey, Resolve: p.sshKeys.Owner, Establish: p.establishSSH, Command: p.sshCommand, Connect: p.sshConnect})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	go func() { _ = front.Serve(ctx, relay) }()
	_, relayPort, _ := net.SplitHostPort(relay.Addr().String())
	known := filepath.Join(recipient, "known_hosts")
	writePins := func(originPin, relayPin ssh.PublicKey) {
		data := append([]byte("forge-ssh "), ssh.MarshalAuthorizedKey(originPin)...)
		data = append(data, []byte("[127.0.0.1]:"+relayPort+" ")...)
		data = append(data, ssh.MarshalAuthorizedKey(relayPin)...)
		if err := os.WriteFile(known, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writePins(originKey.PublicKey(), relayKey.PublicKey())
	cfgFile := filepath.Join(recipient, "config")
	cfg := fmt.Sprintf("Host pilot-relay\n HostName 127.0.0.1\n Port %s\nHost *\n IdentityFile %s\n IdentitiesOnly yes\n IdentityAgent none\n BatchMode yes\n StrictHostKeyChecking yes\n UserKnownHostsFile %s\n GlobalKnownHostsFile /dev/null\n ConnectTimeout 3\n", relayPort, aliceFile, known)
	if err := os.WriteFile(cfgFile, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	attempt := 1
	selectedKey := aliceFile
	prepare := func() {
		attempt++
		if err := os.WriteFile(cfgFile, []byte(fmt.Sprintf("Host pilot-relay\n BindAddress 127.0.0.%d\n", attempt)+strings.ReplaceAll(cfg, aliceFile, selectedKey)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(bin string, args ...string) ([]byte, error) {
		// Independent source addresses keep this matrix from exhausting the
		// production per-IP handshake budget (five attempts per minute).
		prepare()
		command := exec.CommandContext(ctx, bin, args...)
		command.Env = append(os.Environ(), "HOME="+recipient, "SSH_AUTH_SOCK=", "PATH=/usr/bin:/bin")
		return command.CombinedOutput()
	}
	native := func(login, resource string) ([]byte, error) {
		return run(sshBin, "-F", cfgFile, "-J", "tunn@pilot-relay", login+"@"+resource, "printf native-jump-ok")
	}
	// The registered key and origin-authorized key are distinct decisions.
	// Exercise native SSH enrollment with a captured email and the real browser
	// handlers; no email is sent outside the fixture.
	mail := jumpMailCapture{delivered: make(chan [2]string, 1)}
	p.emailSender = mail
	enrollmentStart := time.Now()
	loginOutput, err := run(sshBin, "-F", cfgFile, "-T", "tunn@pilot-relay", "login", "--email", "alice@example.com")
	if err != nil {
		t.Fatalf("native enrollment: %s %v", loginOutput, err)
	}
	var delivery [2]string
	select {
	case delivery = <-mail.delivered:
	case <-time.After(time.Second):
		t.Fatal("enrollment email missing")
	}
	if delivery[0] != "alice@example.com" {
		t.Fatal("wrong email recipient", delivery[0])
	}
	linkURL, err := url.Parse(delivery[1])
	if err != nil {
		t.Fatal(err)
	}
	link := linkURL.Query().Get("token")
	if link == "" || bytes.Contains(loginOutput, []byte(link)) {
		t.Fatal("email proof leaked to key owner")
	}
	page := httptest.NewRecorder()
	p.handleSSHKeyLink(page, httptest.NewRequest("GET", delivery[1], nil))
	if page.Code != 200 {
		t.Fatal(page.Code, page.Body.String())
	}
	cookie := page.Result().Cookies()[0]
	confirmation := httptest.NewRequest("POST", delivery[1], strings.NewReader(url.Values{"csrf": {cookie.Value}}.Encode()))
	confirmation.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	confirmation.AddCookie(cookie)
	result := httptest.NewRecorder()
	p.handleSSHKeyLink(result, confirmation)
	if result.Code != 200 {
		t.Fatal(result.Code, result.Body.String())
	}
	t.Logf("automated native enrollment and confirmation: %s", time.Since(enrollmentStart))
	for _, session := range []string{"first", "second"} {
		start := time.Now()
		output, err := native(current.Username, "forge-ssh")
		if err != nil || string(output) != "native-jump-ok" {
			t.Fatalf("%s session: %s %v", session, output, err)
		}
		t.Logf("%s native session: %s", session, time.Since(start))
	}
	strangerFile := filepath.Join(recipient, "stranger_key")
	stranger := jumpKey(t, strangerFile)
	selectedKey = strangerFile
	output, err := native(current.Username, "forge-ssh")
	if err == nil || !bytes.Contains(output, []byte("SSH endpoint access denied")) {
		t.Fatalf("unknown key admitted: %s %v", output, err)
	}
	if _, err := p.sshKeys.Add(context.Background(), "stranger@example.com", string(ssh.MarshalAuthorizedKey(stranger.PublicKey()))); err != nil {
		t.Fatal(err)
	}
	output, err = native(current.Username, "forge-ssh")
	if err == nil || !bytes.Contains(output, []byte("SSH endpoint access denied")) {
		t.Fatalf("registered stranger admitted: %s %v", output, err)
	}
	selectedKey = aliceFile
	for _, tc := range []struct{ name, resource, login string }{
		{"wrong resource", "missing-resource", current.Username}, {"wrong origin user", "forge-ssh", "not-a-real-origin-user"}, {"relay loopback", "127.0.0.1", current.Username},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if output, err := native(tc.login, tc.resource); err == nil {
				t.Fatalf("unauthorized connection: %s", output)
			}
		})
	}
	for _, tc := range []struct {
		name          string
		origin, relay ssh.PublicKey
	}{
		{"substituted origin key", sshSigner(t).PublicKey(), relayKey.PublicKey()},
		{"substituted relay key", originKey.PublicKey(), sshSigner(t).PublicKey()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writePins(tc.origin, tc.relay)
			output, err := native(current.Username, "forge-ssh")
			if err == nil || !bytes.Contains(output, []byte("Host key verification failed")) {
				t.Fatalf("host substitution: %s %v", output, err)
			}
			writePins(originKey.PublicKey(), relayKey.PublicKey())
		})
	}
	binary := make([]byte, 65536)
	if _, err := rand.Read(binary); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "binary.dat")
	destination := filepath.Join(recipient, "download.dat")
	if err := os.WriteFile(source, binary, 0600); err != nil {
		t.Fatal(err)
	}
	batch := filepath.Join(recipient, "batch")
	if err := os.WriteFile(batch, []byte(fmt.Sprintf("get %s %s\n", source, destination)), 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	output, err = run(sftpBin, "-F", cfgFile, "-J", "tunn@pilot-relay", "-b", batch, current.Username+"@forge-ssh")
	if err != nil {
		t.Fatalf("sftp: %s %v", output, err)
	}
	downloaded, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(binary, downloaded) {
		t.Fatal("binary transfer corrupted", err)
	}
	t.Logf("64 KiB sftp transfer: %s", time.Since(start))
	// A relay grant cannot supply missing origin authorization.
	if err := os.WriteFile(authorized, nil, 0600); err != nil {
		t.Fatal(err)
	}
	output, err = native(current.Username, "forge-ssh")
	if err == nil || !bytes.Contains(output, []byte("Permission denied")) {
		t.Fatalf("relay-only shell grant: %s %v", output, err)
	}
	if err := os.WriteFile(authorized, []byte(alicePub), 0600); err != nil {
		t.Fatal(err)
	}
	prepare()
	active := exec.CommandContext(ctx, sshBin, "-F", cfgFile, "-J", "tunn@pilot-relay", current.Username+"@forge-ssh", "printf ready; cat")
	stdout, err := active.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := active.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := active.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan error, 1)
	go func() {
		b := make([]byte, 5)
		_, err := io.ReadFull(stdout, b)
		if err == nil && string(b) != "ready" {
			err = fmt.Errorf("unexpected shell response %q", b)
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("active origin shell not ready")
	}
	finished := make(chan error, 1)
	go func() { finished <- active.Wait() }()
	// Publisher restart with the recipient removed denies the next session.
	start = time.Now()
	stopPublisher()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("revoked origin session exited successfully")
		}
		t.Logf("active person revocation via publisher stop: %s", time.Since(start))
	case <-time.After(5 * time.Second):
		t.Fatal("removed person retained origin session")
	}
	jumpPublish(t, p, origin.Addr().String(), []string{"owner@example.com"})
	if output, err := native(current.Username, "forge-ssh"); err == nil || !bytes.Contains(output, []byte("SSH endpoint access denied")) {
		t.Fatalf("removed person: %s %v", output, err)
	}
	entries, err := os.ReadDir(recipient)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "tunn") || strings.Contains(entry.Name(), "token") {
			t.Fatal("recipient requires tunn artifact", entry.Name())
		}
	}
}

func TestSSHKeyLinkRequiresDeliberateConfirmation(t *testing.T) {
	p, _, _ := sshRelay(t, false)
	pub := string(ssh.MarshalAuthorizedKey(sshSigner(t).PublicKey()))
	key, _ := sshfront.ParseKey(pub)
	token, err := p.sshKeys.BeginLink(context.Background(), pub, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	path := "https://tunn.test/auth/ssh-key?token=" + token
	page := httptest.NewRecorder()
	p.handleSSHKeyLink(page, httptest.NewRequest("GET", path, nil))
	cookie := page.Result().Cookies()[0]
	for _, tc := range []struct {
		name, method, csrf string
		cookie             bool
		status             int
	}{
		{"scanner revisit", "GET", "", false, 200}, {"no browser confirmation", "POST", "", false, 403}, {"wrong confirmation", "POST", "wrong", true, 403}, {"unsupported method", "PUT", "", false, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, path, strings.NewReader(url.Values{"csrf": {tc.csrf}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.cookie {
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			p.handleSSHKeyLink(w, r)
			if w.Code != tc.status {
				t.Fatal(w.Code, w.Body.String())
			}
			if owner, _ := p.sshKeys.Owner(context.Background(), key.Fingerprint); owner != "" {
				t.Fatal("unconfirmed key enrolled")
			}
		})
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe confirmation cookie")
	}
}

func TestSSHJumpLiveKeyRevocationAndReusedTransport(t *testing.T) {
	p, c, _ := sshRelay(t, true)
	l, err := c.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start("tcp --name forge-ssh"); err != nil {
		t.Fatal(err)
	}
	_ = sshLine(t, bufio.NewReader(stdout))
	stream, err := c.Dial("tcp", "forge-ssh:22")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 2)
	if _, err := io.ReadFull(stream, data); err != nil {
		t.Fatal(err)
	}
	keys, err := p.sshKeys.List(context.Background(), []string{"owner@example.com"})
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	start := time.Now()
	if err := p.sshKeys.Remove(context.Background(), []string{"owner@example.com"}, keys[0].Fingerprint); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := stream.Read(data); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revoked stream readable")
		}
		t.Logf("active key revocation: %s", time.Since(start))
	case <-time.After(5 * time.Second):
		t.Fatal("revoked stream survived")
	}
	if _, err := c.Dial("tcp", "forge-ssh:22"); err == nil {
		t.Fatal("removed key opened channel on reused transport")
	}
	for _, target := range []string{"forge-ssh:23", "forge-ssh:443", "127.0.0.1:22", "localhost:22"} {
		if _, err := c.Dial("tcp", target); err == nil {
			t.Fatal("arbitrary target allowed", target)
		}
	}
}

func TestSSHJumpPinsResourceGeneration(t *testing.T) {
	p, c, _ := sshRelay(t, true)
	stop := jumpPublish(t, p, "127.0.0.1:1", []string{"owner@example.com"})
	original, _ := p.tunnelServer.GetTunnel("forge-ssh")
	keys, err := p.sshKeys.List(context.Background(), []string{"owner@example.com"})
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	id := sshfront.Identity{Fingerprint: keys[0].Fingerprint, Email: "owner@example.com"}
	if _, err := p.sshConnectIdentity(context.Background(), id, original); err != nil {
		t.Fatal(err)
	}
	// Simulate a name being reused after authorization and before local ingress.
	replacement := &TunnelConnection{TunnelID: "forge-ssh", EndpointProtocol: "tcp"}
	p.tunnelServer.mu.Lock()
	p.tunnelServer.tunnels["forge-ssh"] = replacement
	p.tunnelServer.mu.Unlock()
	r := httptest.NewRequest(http.MethodConnect, "https://forge-ssh.tunn.test/", nil)
	r = r.WithContext(context.WithValue(r.Context(), sshConnectTunnelKey{}, original))
	w := httptest.NewRecorder()
	_ = p.proxyToLocal(w, r, "forge-ssh")
	if w.Code != http.StatusForbidden {
		t.Fatal("resource generation not pinned", w.Code, w.Body.String())
	}
	if _, err := p.sshConnectIdentity(context.Background(), id, original); err == nil {
		t.Fatal("old generation still authorized")
	}
	// Restore the original publisher for orderly teardown.
	p.tunnelServer.mu.Lock()
	p.tunnelServer.tunnels["forge-ssh"] = original
	p.tunnelServer.mu.Unlock()
	for _, target := range []string{"forge-ssh:23", "forge-ssh:443", "forge-ssh:65535", "127.0.0.1:22", "localhost:22"} {
		if conn, err := c.Dial("tcp", target); err == nil {
			_ = conn.Close()
			t.Fatal("arbitrary destination admitted", target)
		}
	}
	stop()
}

func TestSSHJumpAdmissionRequiresPersonGrant(t *testing.T) {
	p, _, _ := sshRelay(t, true)
	jumpPublish(t, p, "127.0.0.1:1", nil) // Even a public raw endpoint is not a jump grant.
	tunnel, _ := p.tunnelServer.GetTunnel("forge-ssh")
	stranger := sshSigner(t)
	pub := string(ssh.MarshalAuthorizedKey(stranger.PublicKey()))
	key, err := p.sshKeys.Add(context.Background(), "stranger@example.com", pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []sshfront.Identity{
		{Fingerprint: key.Fingerprint, Email: "stranger@example.com"},
		{Fingerprint: key.Fingerprint, Email: "owner@example.com"},
		{Fingerprint: "unknown", Email: "owner@example.com"},
	} {
		if _, err := p.sshConnectIdentity(context.Background(), id, tunnel); err == nil {
			t.Fatal("missing or mismatched person grant admitted", id)
		}
	}
	// A tunnel with no account authority fails closed instead of becoming public.
	keys, err := p.sshKeys.List(context.Background(), []string{"owner@example.com"})
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	id := sshfront.Identity{Fingerprint: keys[0].Fingerprint, Email: "owner@example.com"}
	tunnel.accountQuotaExempt = true
	if _, err := p.sshConnectIdentity(context.Background(), id, tunnel); err == nil {
		t.Fatal("missing endpoint owner admitted")
	}
	tunnel.accountQuotaExempt = false
}
