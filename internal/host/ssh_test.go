package host

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/ehrlich-b/tunn/internal/testnet"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/sshfront"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	"golang.org/x/crypto/ssh"
)

func sshSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
func sshRelay(t *testing.T, known bool) (*ProxyServer, *ssh.Client, func() *ssh.Client) {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st := storage.NewLocalStorage(db)
	cfg := &config.Config{Domain: "tunn.test", PublicAddr: "tunn.test", LoginNode: true, JWTSecret: "ssh-test-secret", WellKnownKey: "creation"}
	account, err := st.FindOrCreateByEmails(context.Background(), []string{"owner@example.com"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := sshfront.NewRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	signer := sshSigner(t)
	if known {
		if _, err := keys.Add(context.Background(), account.PrimaryEmail, string(ssh.MarshalAuthorizedKey(signer.PublicKey()))); err != nil {
			t.Fatal(err)
		}
	}
	s := NewTunnelServer(cfg, nil, st.AccountStore(), st)
	ledger, err := metering.New(db)
	if err != nil {
		t.Fatal(err)
	}
	p := &ProxyServer{Domain: cfg.Domain, config: cfg, tunnelServer: s, storage: st, meter: ledger, sshKeys: keys, quotaCache: NewQuotaCache(time.Minute), usageBuffer: NewUsageBuffer(), tunnelCache: map[string]string{}}
	hostKey := sshSigner(t)
	server, err := sshfront.New(sshfront.Config{HostKey: hostKey, Resolve: keys.Owner, Establish: p.establishSSH, Command: p.sshCommand, RotateToken: p.rotateSSHToken, Connect: p.sshConnect})
	if err != nil {
		t.Fatal(err)
	}
	p.sshServer = server
	l := testnet.NewListener()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Serve(ctx, l) }()
	dial := func() *ssh.Client {
		raw, err := l.Dial()
		if err != nil {
			t.Fatal(err)
		}
		conn, channels, requests, err := ssh.NewClientConn(raw, l.Addr().String(), &ssh.ClientConfig{User: "tunn", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()), Timeout: 3 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		client := ssh.NewClient(conn, channels, requests)
		t.Cleanup(func() { _ = client.Close() })
		return client
	}
	return p, dial(), dial
}

func sshForward(t *testing.T, c *ssh.Client, command string, handler http.Handler) (*ssh.Session, *bufio.Reader) {
	t.Helper()
	l, err := c.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = upstream.Serve(l) }()
	t.Cleanup(func() { _ = upstream.Close() })
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start(command); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, bufio.NewReader(out)
}
func sshLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	result := make(chan string, 1)
	go func() {
		s, e := r.ReadString('\n')
		if e != nil {
			s = "ERROR: " + e.Error() + ": " + s
		}
		result <- s
	}()
	select {
	case s := <-result:
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("SSH session output timeout")
		return ""
	}
}

func TestSSHForwardHTTPSAccessFilteringAndMetering(t *testing.T) {
	p, c, _ := sshRelay(t, true)
	target := make(chan *http.Request, 4)
	session, out := sshForward(t, c, "-- --name ssh-http --allow alice@example.com --bearer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target <- r.Clone(context.Background())
		w.Header().Set("Set-Cookie", "app=ok; Path=/, tunn_auth=stolen; Path=/")
		_, _ = io.WriteString(w, "ssh response "+r.URL.RequestURI())
	}))
	if line := sshLine(t, out); line != "https://ssh-http.tunn.test\n" {
		t.Fatal(line)
	}
	tunnel, ok := p.tunnelServer.GetTunnel("ssh-http")
	if !ok || tunnel.TargetURL != "http" || tunnel.AccountID == "" || len(tunnel.accessTokenDigest()) != 32 {
		t.Fatalf("ordinary tunnel not registered: %#v", tunnel)
	}
	client, relayURL := sshHTTPS(t, p.createHandler())
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request := func(token string) *http.Response {
		t.Helper()
		r, err := http.NewRequest("GET", relayURL+"/hello?from=ssh", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "ssh-http.tunn.test"
		if token != "" {
			r.Header.Set("Tunn-Authorization", "Bearer "+token)
			r.Header.Set("Authorization", "Bearer application-secret")
		}
		r.AddCookie(&http.Cookie{Name: "tunn_auth", Value: "invalid-platform-cookie"})
		r.AddCookie(&http.Cookie{Name: "app", Value: "local-cookie"})
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := request("")
	_ = resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("anonymous access=%d", resp.StatusCode)
	}
	stranger, err := p.generateJWT("stranger@example.com")
	if err != nil {
		t.Fatal(err)
	}
	resp = request(stranger)
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("stranger access=%d", resp.StatusCode)
	}
	alice, err := p.generateJWT("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	resp = request(alice)
	data, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(data) != "ssh response /hello?from=ssh" {
		t.Fatalf("response=%d %q %v", resp.StatusCode, data, err)
	}
	r := <-target
	if r.Header.Get("Tunn-Authorization") != "" || r.Header.Get("Authorization") != "Bearer application-secret" || strings.Contains(r.Header.Get("Cookie"), "tunn_auth") {
		t.Fatalf("platform credentials forwarded: %v", r.Header)
	}
	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) != 1 || !strings.HasPrefix(cookies[0], "app=") {
		t.Fatalf("platform response cookie leaked: %v", cookies)
	}
	if resp.Header.Get("Tunn-Request-ID") == "" {
		t.Fatal("SSH bypassed ingress meter")
	}
	if err := session.Signal(ssh.SIGINT); err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := p.tunnelServer.GetTunnel("ssh-http"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Ctrl-C left tunnel registered")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSSHAnonymousRequiresAllowListAndConservativeLimits(t *testing.T) {
	p, c, _ := sshRelay(t, false)
	session, out := sshForward(t, c, "-- --name ssh-anon --allow alice@example.com --expire 2h", http.NotFoundHandler())
	if line := sshLine(t, out); line != "https://ssh-anon.tunn.test\n" {
		t.Fatal(line)
	}
	_ = sshLine(t, out)
	if line := sshLine(t, out); !strings.Contains(line, "30m0s") {
		t.Fatal(line)
	}
	tunnel, ok := p.tunnelServer.GetTunnel("ssh-anon")
	if !ok || !tunnel.anonymousSSH || tunnel.accountQuotaExempt || tunnel.rateLimiter.Limit() != 125000 {
		t.Fatalf("anonymous limits=%#v", tunnel)
	}
	tunnel.updateBandwidthPlan("pro")
	if tunnel.rateLimiter.Limit() != 125000 {
		t.Fatal("account plan reset anonymous rate")
	}
	_ = session.Signal(ssh.SIGINT)
	_ = session.Wait()
	_, other, _ := sshRelay(t, false)
	rejected, out := sshForward(t, other, "-- --public", http.NotFoundHandler())
	if line := sshLine(t, out); !strings.Contains(line, "anonymous SSH requires") {
		t.Fatal(line)
	}
	if err := rejected.Wait(); err == nil {
		t.Fatal("anonymous public tunnel accepted")
	}
}

func TestSSHEmailLinkAndOwnerKeyAPI(t *testing.T) {
	p, c, _ := sshRelay(t, false)
	ctx := context.Background()
	pub := string(ssh.MarshalAuthorizedKey(sshSigner(t).PublicKey()))
	token, err := p.sshKeys.BeginLink(ctx, pub, "linked@example.com")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://tunn.test/auth/ssh-key?token="+token, nil)
	p.handleSSHKeyLink(w, r)
	if w.Code != 200 {
		t.Fatalf("link=%d %s", w.Code, w.Body.String())
	}
	key, _ := sshfront.ParseKey(pub)
	if owner, err := p.sshKeys.Owner(ctx, key.Fingerprint); err != nil || owner != "linked@example.com" {
		t.Fatalf("owner=%q %v", owner, err)
	}
	w = httptest.NewRecorder()
	p.handleSSHKeyLink(w, r)
	if w.Code != 400 {
		t.Fatalf("link replay=%d", w.Code)
	}
	// An unknown key cannot list or add account keys through the SSH command API.
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.CombinedOutput("keys list")
	if err == nil || !strings.Contains(string(output), "link an SSH key first") {
		t.Fatalf("anonymous keys=%q %v", output, err)
	}
	ownerToken, err := p.generateJWT("linked@example.com")
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("GET", "https://tunn.test/api/ssh/keys", nil)
	r.Header.Set("Authorization", "Bearer "+ownerToken)
	w = httptest.NewRecorder()
	p.handleSSHKeys(w, r)
	var keys []sshfront.Key
	if err := json.Unmarshal(w.Body.Bytes(), &keys); err != nil || len(keys) != 1 {
		t.Fatalf("keys=%s %v", w.Body.String(), err)
	}
}

func sshHTTPS(t *testing.T, handler http.Handler) (*http.Client, string) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"relay.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	l := testnet.NewListener()
	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{certificate}}))
	}()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(context.Context, string, string) (net.Conn, error) { return l.Dial() }}
	t.Cleanup(func() { transport.CloseIdleConnections(); _ = server.Close(); _ = l.Close() })
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}, "https://relay.test"
}

func sshOwnerCommand(t *testing.T, dial func() *ssh.Client, command string) []byte {
	t.Helper()
	c := dial()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	data, err := s.CombinedOutput(command)
	if err != nil {
		t.Fatalf("%s: %s (%v)", command, data, err)
	}
	return data
}

func TestSSHOwnerTokenInspectionAndReplay(t *testing.T) {
	p, c, dial := sshRelay(t, true)
	var requests atomic.Int32
	_, out := sshForward(t, c, "--name ssh-owner --bearer --inspect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	_ = sshLine(t, out)
	_ = sshLine(t, out)
	oldToken := strings.TrimSpace(strings.TrimPrefix(sshLine(t, out), "Endpoint token: "))
	request := func(token string) int {
		r := httptest.NewRequest("POST", "https://ssh-owner.tunn.test/action", strings.NewReader("replay-body"))
		r.Header.Set("Tunn-Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		p.handleWebProxy(w, r)
		return w.Code
	}
	if status := request(oldToken); status != 200 {
		t.Fatal(status)
	}
	newToken := strings.TrimSpace(string(sshOwnerCommand(t, dial, "token --rotate ssh-owner")))
	if newToken == oldToken || !strings.HasPrefix(newToken, "tunn_ep_") {
		t.Fatal("rotation did not issue a fresh token")
	}
	if status := request(oldToken); status != 401 {
		t.Fatalf("old token still accepted: %d", status)
	}
	if status := request(newToken); status != 200 {
		t.Fatal(status)
	}
	data := sshOwnerCommand(t, dial, "inspect ssh-owner")
	var events []map[string]any
	if err := json.Unmarshal(data, &events); err != nil || len(events) != 2 {
		t.Fatalf("inspection=%s %v", data, err)
	}
	_ = sshOwnerCommand(t, dial, "replay ssh-owner 1")
	if requests.Load() != 3 {
		t.Fatalf("replay target requests=%d", requests.Load())
	}
	data = sshOwnerCommand(t, dial, "usage ssh-owner")
	if !json.Valid(data) || !strings.Contains(string(data), "ssh-owner") {
		t.Fatalf("usage=%s", data)
	}
}

func TestSSHConsumerGrantsUseOrdinaryIngress(t *testing.T) {
	p, c, dial := sshRelay(t, true)
	_, out := sshForward(t, c, "--name ssh-grant", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Tunn-Authorization") != "" {
			t.Error("grant credential reached target")
		}
		_, _ = io.WriteString(w, "allowed")
	}))
	_ = sshLine(t, out)
	data := sshOwnerCommand(t, dial, "grant create ssh-grant --for visitor --expires 1h --monthly-requests 1")
	var result struct {
		Token string `json:"token"`
		Grant struct {
			ID string `json:"id"`
		} `json:"grant"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.Token == "" || result.Grant.ID == "" {
		t.Fatalf("grant=%s %v", data, err)
	}
	r := httptest.NewRequest("GET", "https://ssh-grant.tunn.test/", nil)
	r.Header.Set("Tunn-Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	p.handleWebProxy(w, r)
	if w.Code != 200 || w.Body.String() != "allowed" {
		t.Fatalf("grant ingress=%d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	p.handleWebProxy(w, r)
	if w.Code != 429 {
		t.Fatalf("grant budget=%d", w.Code)
	}
	_ = sshOwnerCommand(t, dial, "grant revoke ssh-grant "+result.Grant.ID)
}

func TestSSHRawForwardAndNamedConnectHalfClose(t *testing.T) {
	p, c, _ := sshRelay(t, true)
	l, err := c.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		upstream, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = upstream.Close() }()
		data, err := io.ReadAll(upstream)
		if err == nil {
			_, _ = io.WriteString(upstream, "echo:"+string(data))
		}
	}()
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start("tcp --name ssh-raw"); err != nil {
		t.Fatal(err)
	}
	if line := sshLine(t, bufio.NewReader(out)); line != "https://ssh-raw.tunn.test\n" {
		t.Fatal(line)
	}
	stream, err := c.Dial("tcp", "ssh-raw:80")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	_, err = io.WriteString(stream, "payload")
	if err != nil {
		t.Fatal(err)
	}
	half, ok := stream.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("SSH TCP stream does not support half-close")
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result := make(chan string, 1)
	go func() {
		data, err := io.ReadAll(stream)
		if err != nil {
			result <- err.Error()
		} else {
			result <- string(data)
		}
	}()
	select {
	case data := <-result:
		if data != "echo:payload" {
			t.Fatal(data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("raw half-close did not return a response")
	}
	if tunnel, ok := p.tunnelServer.GetTunnel("ssh-raw"); !ok || tunnel.EndpointProtocol != "tcp" {
		t.Fatal("not an ordinary raw tunnel")
	}
	if _, err := c.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Fatal("SSH connect exposed host network")
	}
	_ = session.Signal(ssh.SIGINT)
	_ = session.Wait()
}

func TestSSHStdioMCPNeedsNoLocalTunnelBinary(t *testing.T) {
	p, c, _ := sshRelay(t, true)
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	input, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	rpc, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	info, err := session.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start("mcp --stdio --tools read_file --name ssh-mcp"); err != nil {
		t.Fatal(err)
	}
	if line := sshLine(t, bufio.NewReader(info)); line != "https://ssh-mcp.tunn.test/mcp\n" {
		t.Fatal(line)
	}
	var childToolCalls atomic.Int32
	go func() {
		scan := bufio.NewScanner(rpc)
		for scan.Scan() {
			var message map[string]any
			if json.Unmarshal(scan.Bytes(), &message) != nil {
				continue
			}
			if message["method"] == "tools/call" {
				childToolCalls.Add(1)
			}
			if id, ok := message["id"]; ok {
				response := map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "stdio-fixture", "version": "1"}}}
				_ = json.NewEncoder(input).Encode(response)
			}
		}
	}()
	owner, _ := p.generateJWT("owner@example.com")
	r := httptest.NewRequest("POST", "https://ssh-mcp.tunn.test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
	r.Header.Set("Authorization", "Bearer "+owner)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleWebProxy(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "stdio-fixture") {
		t.Fatalf("stdio MCP=%d %s", w.Code, w.Body.String())
	}
	streamSession := w.Header().Get("Mcp-Session-Id")
	r = httptest.NewRequest("POST", "https://ssh-mcp.tunn.test/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file"}}`))
	r.Header.Set("Authorization", "Bearer "+owner)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Mcp-Session-Id", streamSession)
	w = httptest.NewRecorder()
	p.handleWebProxy(w, r)
	var denied struct {
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &denied) != nil || denied.Error.Code != -32001 || childToolCalls.Load() != 0 {
		t.Fatalf("stdio tool policy=%d %s", w.Code, w.Body.String())
	}
	_ = session.Signal(ssh.SIGINT)
	_ = session.Wait()
}

func TestSSHExpiryClosesForward(t *testing.T) {
	p, c, _ := sshRelay(t, true)
	session, out := sshForward(t, c, "--name ssh-short --expire 100ms", http.NotFoundHandler())
	_ = sshLine(t, out)
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expiry did not close the session")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := p.tunnelServer.GetTunnel("ssh-short"); !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("expired tunnel remains online")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSSHNamedForwardCancellationAndAccountNameOwnership(t *testing.T) {
	p, c, dial := sshRelay(t, true)
	channels := c.HandleChannelOpen("forwarded-tcpip")
	spec := struct {
		Address string
		Port    uint32
	}{"named-demo", 80}
	ok, _, err := c.SendRequest("tcpip-forward", true, ssh.Marshal(spec))
	if err != nil || !ok {
		t.Fatalf("named forward=%v %v", ok, err)
	}
	go func() {
		newChannel := <-channels
		if newChannel == nil {
			return
		}
		ch, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		defer func() { _ = ch.Close() }()
		go ssh.DiscardRequests(requests)
		r, err := http.ReadRequest(bufio.NewReader(ch))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		_, _ = io.WriteString(ch, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nnamed")
	}()
	session, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Start("--public"); err != nil {
		t.Fatal(err)
	}
	if line := sshLine(t, bufio.NewReader(out)); line != "https://named-demo.tunn.test\n" {
		t.Fatal(line)
	}
	w := httptest.NewRecorder()
	p.handleWebProxy(w, httptest.NewRequest("GET", "https://named-demo.tunn.test/", nil))
	if w.Code != 200 || w.Body.String() != "named" {
		t.Fatalf("named request=%d %s", w.Code, w.Body.String())
	}
	ok, _, err = c.SendRequest("cancel-tcpip-forward", true, ssh.Marshal(spec))
	if err != nil || !ok {
		t.Fatalf("cancel=%v %v", ok, err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.tunnelServer.GetTunnel("named-demo"); ok {
		t.Fatal("cancelled forward remains online")
	}
	// Anonymous publishers cannot take a subdomain reserved by a real account.
	owner, err := p.storage.GetAccountByEmail(context.Background(), "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.tunnelServer.accounts.UpdatePlan(owner.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	if err := p.tunnelServer.accounts.ReserveSubdomain(owner.ID, "reserved-demo"); err != nil {
		t.Fatal(err)
	}
	keys, err := p.sshKeys.List(context.Background(), []string{owner.PrimaryEmail})
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%v %v", keys, err)
	}
	if err := p.sshKeys.Remove(context.Background(), []string{owner.PrimaryEmail}, keys[0].Fingerprint); err != nil {
		t.Fatal(err)
	}
	anonymous := dial()
	rejected, output := sshForward(t, anonymous, "--name reserved-demo --allow alice@example.com", http.NotFoundHandler())
	if line := sshLine(t, output); strings.TrimSpace(line) != "subdomain is reserved by another user" {
		t.Fatal(line)
	}
	if err := rejected.Wait(); err == nil {
		t.Fatal("anonymous key claimed another account's reserved name")
	}

}
