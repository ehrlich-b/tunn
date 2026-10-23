package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ehrlich-b/tunn/internal/testnet"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/metering"
	"github.com/ehrlich-b/tunn/internal/sshfront"
	"github.com/ehrlich-b/tunn/internal/storage"
	"github.com/ehrlich-b/tunn/internal/store"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
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
	return sshRelayWithClock(t, known, time.Now)
}

func sshRelayWithClock(t *testing.T, known bool, now func() time.Time) (*ProxyServer, *ssh.Client, func() *ssh.Client) {
	p, c, dial, _ := sshRelayWithSchedule(t, known, now, nil, false)
	return p, c, dial
}

func sshRelayWithSchedule(t *testing.T, known bool, now func() time.Time, schedule *sshInspectionSchedule, inspection bool) (*ProxyServer, *ssh.Client, func() *ssh.Client, func(context.Context) (*ssh.Client, error)) {
	t.Helper()
	db, err := store.InitForTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st := storage.NewLocalStorageWithClock(db, now)
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
	server, err := sshfront.New(sshfront.Config{HostKey: hostKey, Resolve: keys.Owner, ResolveAccount: keys.AccountID, CanonicalAccount: keys.CanonicalAccountID, Establish: func(ctx context.Context, id sshfront.Identity, stream *sshfront.Stream) error {
		if schedule != nil {
			stream = schedule.bridge(ctx, stream)
		}
		return p.establishSSH(ctx, id, stream)
	}, Command: p.sshCommand, RotateToken: p.rotateSSHToken, Connect: p.sshConnect})
	if err != nil {
		t.Fatal(err)
	}
	p.sshServer = server
	l := testnet.NewListener()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var listener net.Listener = l
	if inspection {
		listener = &sshInspectionListener{Listener: l}
	}
	go func() { _ = server.Serve(ctx, listener) }()
	dialContext := func(ctx context.Context) (*ssh.Client, error) {
		raw, err := l.Dial()
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		defer stop()
		if deadline, ok := ctx.Deadline(); ok {
			_ = raw.SetDeadline(deadline)
		}
		conn, channels, requests, err := ssh.NewClientConn(raw, l.Addr().String(), &ssh.ClientConfig{User: "tunn", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()), Timeout: 3 * time.Second})
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		_ = raw.SetDeadline(time.Time{})
		client := ssh.NewClient(conn, channels, requests)
		t.Cleanup(func() { _ = client.Close() })
		return client, nil
	}
	dial := func() *ssh.Client {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := dialContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	return p, dial(), dial, dialContext
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
	if owner, err := p.sshKeys.Owner(ctx, key.Fingerprint); err != nil || owner != "" {
		t.Fatalf("GET enrolled key: owner=%q %v", owner, err)
	}
	if !strings.Contains(w.Body.String(), key.Fingerprint) {
		t.Fatal("confirmation omitted key fingerprint")
	}
	cookie := w.Result().Cookies()[0]
	r = httptest.NewRequest("POST", "https://tunn.test/auth/ssh-key?token="+token, strings.NewReader(url.Values{"csrf": {cookie.Value}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	p.handleSSHKeyLink(w, r)
	if w.Code != 200 {
		t.Fatalf("confirmation=%d %s", w.Code, w.Body.String())
	}
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
	testSSHOwnerTokenInspection(t, "normal")
}

func testSSHOwnerTokenInspection(t *testing.T, mode string) {
	t.Helper()
	var schedule *sshInspectionSchedule
	if mode == "delayed_second_capture" || mode == "never_completing_capture" {
		schedule = &sshInspectionSchedule{held: make(chan struct{}), release: make(chan struct{})}
	}
	p, c, dial, dialContext := sshRelayWithSchedule(t, true, time.Now, schedule, true)
	var requests atomic.Int32
	_, out := sshForward(t, c, "--name ssh-owner --bearer --inspect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "replay-body" || r.Header.Get("X-Replay-Original") != "owner-value" {
			t.Errorf("original request not preserved: body=%q headers=%v error=%v", body, r.Header, err)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	_ = sshLine(t, out)
	_ = sshLine(t, out)
	oldToken := strings.TrimSpace(strings.TrimPrefix(sshLine(t, out), "Endpoint token: "))
	var originalHeaders map[string]string
	request := func(token string) int {
		r := httptest.NewRequest("POST", "https://ssh-owner.tunn.test/action", strings.NewReader("replay-body"))
		r.Header.Set("Tunn-Authorization", "Bearer "+token)
		r.Header.Set("X-Replay-Original", "owner-value")
		originalHeaders = p.forwardedHTTPHeaders(r)
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
	// The response can arrive before the publisher commits its terminal
	// inspection record. The scheduled fixture holds its completion signal.
	if schedule != nil {
		select {
		case <-schedule.held:
		case <-time.After(3 * time.Second):
			t.Fatal("second completion was not held")
		}
	}
	read := func(ctx context.Context) ([]byte, error) {
		inspectionConnection, err := dialContext(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = inspectionConnection.Close() }()
		stop := context.AfterFunc(ctx, func() { _ = inspectionConnection.Close() })
		defer stop()
		session, err := inspectionConnection.NewSession()
		if err != nil {
			return nil, err
		}
		defer func() { _ = session.Close() }()
		data, err := session.CombinedOutput("inspect ssh-owner")
		if schedule != nil && mode == "delayed_second_capture" {
			// Release only after an observable one-event snapshot. The next poll
			// must see the real second capture, rather than a manufactured event.
			var events []client.InspectionEvent
			if json.Unmarshal(data, &events) == nil && len(events) == 1 {
				select {
				case <-schedule.release:
				default:
					close(schedule.release)
				}
			}
		}
		return data, err
	}
	if mode == "excess_capture" {
		if status := request(newToken); status != 200 {
			t.Fatal(status)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := sshWaitInspection(ctx, 3, read); err != nil {
			t.Fatal(err)
		}
	}
	timeout := 3 * time.Second
	if mode == "never_completing_capture" {
		timeout = 100 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	events, err := sshWaitInspection(ctx, 2, read)
	if mode == "never_completing_capture" {
		if !errors.Is(err, context.DeadlineExceeded) || len(events) != 1 {
			t.Fatalf("never-completing capture: events=%v error=%v", events, err)
		}
		if requests.Load() != 2 {
			t.Fatalf("partial capture dispatched replay: %d", requests.Load())
		}
		return
	}
	if mode == "excess_capture" {
		if err == nil || !strings.Contains(err.Error(), "excess capture") || len(events) != 3 {
			t.Fatalf("excess capture: events=%v error=%v", events, err)
		}
		if requests.Load() != 3 {
			t.Fatalf("excess capture dispatched replay: %d", requests.Load())
		}
		return
	}
	if err != nil {
		t.Fatalf("inspection missing capture: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("inspection count=%d", len(events))
	}
	// Metadata capture cannot silently substitute an empty body or redacted
	// forwarding headers; the owner reconstructs the original request explicitly.
	ownerConnection := dial()
	session, err := ownerConnection.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	replayBody := []byte("replay-body")
	payload, err := json.Marshal(client.InspectionReplayRequest{Headers: originalHeaders, Body: &replayBody})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	session.Stdin = bytes.NewReader(payload)
	if data, err := session.CombinedOutput("replay ssh-owner 1 --request -"); err != nil {
		t.Fatalf("explicit replay=%s %v", data, err)
	}
	if requests.Load() != 3 {
		t.Fatalf("replay target requests=%d", requests.Load())
	}
	data := sshOwnerCommand(t, dial, "usage ssh-owner")
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
	keys, err := p.sshKeys.List(context.Background(), sshTestAccountID(t, p, owner.PrimaryEmail))
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys=%v %v", keys, err)
	}
	if err := p.sshKeys.Remove(context.Background(), sshTestAccountID(t, p, owner.PrimaryEmail), keys[0].Fingerprint); err != nil {
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

func TestSSHPublishAfterPrimarySwitchOnExistingConnection(t *testing.T) {
	p, connection, _ := sshRelay(t, true)
	ctx := context.Background()
	account, err := p.storage.GetAccountByEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	emails := p.storage.(storage.AccountEmailStorage)
	if _, err := emails.MutateAccountEmail(ctx, account.ID, "new-primary@example.com", "link"); err != nil {
		t.Fatal(err)
	}
	if _, err := emails.MutateAccountEmail(ctx, account.ID, "new-primary@example.com", "primary"); err != nil {
		t.Fatal(err)
	}
	_, output := sshForward(t, connection, "--name primary-switch --public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "still connected") }))
	if line := sshLine(t, output); line != "https://primary-switch.tunn.test\n" {
		t.Fatal(line)
	}
	tunnel, ok := p.tunnelServer.GetTunnel("primary-switch")
	if !ok || tunnel.AccountID != account.ID || tunnel.CreatorEmail != "new-primary@example.com" {
		t.Fatalf("wrong tunnel owner: %+v", tunnel)
	}
	request := httptest.NewRequest("GET", "https://primary-switch.tunn.test/", nil)
	response := httptest.NewRecorder()
	p.handleWebProxy(response, request)
	if response.Code != 200 || response.Body.String() != "still connected" {
		t.Fatal(response.Code, response.Body)
	}
}

// sshWaitInspection waits for exactly the expected terminal captures. Each read
// must honor ctx, including SSH command execution; a partial list is never success.
func sshWaitInspection(ctx context.Context, expected int, read func(context.Context) ([]byte, error)) ([]client.InspectionEvent, error) {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	var events []client.InspectionEvent
	for {
		if err := ctx.Err(); err != nil {
			return events, fmt.Errorf("capture timeout: got %d, want %d: %w", len(events), expected, err)
		}
		data, err := read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				// A connection's deadline can fire before the context timer
				// publishes its error. Both enforce the same capture deadline.
				err = context.DeadlineExceeded
			}
			return events, fmt.Errorf("inspection command: %w", err)
		}
		if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '[' {
			return nil, fmt.Errorf("malformed inspection: %q", data)
		}
		if err := json.Unmarshal(data, &events); err != nil {
			return nil, fmt.Errorf("malformed inspection: %w", err)
		}
		if len(events) > expected {
			return events, fmt.Errorf("excess capture: got %d, want %d", len(events), expected)
		}
		for i, event := range events {
			if event.ID != uint64(i+1) || event.TerminalReason != "complete" || !event.BodyComplete || !event.Reconstructable || event.Status != http.StatusOK || event.Method != "POST" || event.Path != "/action" {
				return events, fmt.Errorf("malformed completed capture: %+v", event)
			}
		}
		if err := ctx.Err(); err != nil {
			return events, fmt.Errorf("capture timeout: %w", err)
		}
		if len(events) == expected {
			return events, nil
		}
		select {
		case <-ctx.Done():
			return events, fmt.Errorf("capture timeout: got %d, want %d: %w", len(events), expected, ctx.Err())
		case <-ticker.C:
		}
	}
}

// sshInspectionSchedule holds the second relay completion, after the response
// has been delivered but before the publisher can commit its capture. Both
// directions still use real SSH streams and the ordinary admission callback.
type sshInspectionSchedule struct {
	held    chan struct{}
	release chan struct{}
}

func (s *sshInspectionSchedule) bridge(ctx context.Context, original *sshfront.Stream) *sshfront.Stream {
	host, messages := sshfront.NewStream(ctx)
	go func() {
		for {
			message, err := original.Recv()
			if err != nil {
				return
			}
			if err := messages.Send(message); err != nil {
				return
			}
		}
	}()
	go func() {
		completed := 0
		for {
			message, err := messages.Recv()
			if err != nil {
				return
			}
			if closeMessage := message.GetConnectionClose(); closeMessage != nil {
				completed++
				if completed == 2 {
					close(s.held)
					select {
					case <-s.release:
					case <-ctx.Done():
						return
					}
				}
			}
			message = proto.Clone(message).(*pb.TunnelMessage)
			if open := message.GetConnectionOpen(); open != nil {
				// Opt this fixture into the existing timing-completion handshake so
				// terminal capture can be held deterministically after response EOF.
				// The ordinary regression above retains SSH's default capabilities.
				open.RequestTiming = true
			}
			if err := original.Send(message); err != nil {
				return
			}
		}
	}()
	return host
}

func TestSSHOwnerTokenInspectionSchedules(t *testing.T) {
	for _, mode := range []string{"normal", "delayed_second_capture", "never_completing_capture", "excess_capture"} {
		t.Run(mode, func(t *testing.T) { testSSHOwnerTokenInspection(t, mode) })
	}
	for _, output := range []string{`null`, `{}`, `[{}]`, `[`, `["event"]`} {
		t.Run("malformed_"+output, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			_, err := sshWaitInspection(ctx, 2, func(context.Context) ([]byte, error) { calls++; return []byte(output), nil })
			if err == nil || !strings.Contains(err.Error(), "malformed") || calls != 1 {
				t.Fatalf("malformed output retried or accepted: calls=%d error=%v", calls, err)
			}
		})
	}
	t.Run("command_deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := sshWaitInspection(ctx, 2, func(ctx context.Context) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() })
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("command exceeded deadline: %v", err)
		}
	})
	t.Run("command_deadline_before_context_notification", func(t *testing.T) {
		// Model the socket deadline firing while the context timer's
		// notification is still pending; Err is deliberately still nil.
		ctx := sshInspectionPendingDeadline{Context: context.Background(), deadline: time.Now()}
		calls := 0
		events, err := sshWaitInspection(ctx, 2, func(context.Context) ([]byte, error) {
			calls++
			return nil, errors.New("ssh: handshake failed: i/o timeout")
		})
		if !errors.Is(err, context.DeadlineExceeded) || len(events) != 0 || calls != 1 {
			t.Fatalf("expired command deadline: events=%v calls=%d error=%v", events, calls, err)
		}
	})
	t.Run("command_error_before_deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		commandErr := errors.New("inspection failed")
		calls := 0
		_, err := sshWaitInspection(ctx, 2, func(context.Context) ([]byte, error) {
			calls++
			return nil, commandErr
		})
		if !errors.Is(err, commandErr) || errors.Is(err, context.DeadlineExceeded) || calls != 1 {
			t.Fatalf("command error retried or masked: calls=%d error=%v", calls, err)
		}
	})
}

type sshInspectionPendingDeadline struct {
	context.Context
	deadline time.Time
}

func (c sshInspectionPendingDeadline) Deadline() (time.Time, bool) { return c.deadline, true }

// Inspection polling opens one session per connection, as required by SSH.
// Give each synthetic peer its own documentation-only address so repeated
// observation does not exhaust the per-IP handshake admission budget.
type sshInspectionListener struct {
	net.Listener
	peers atomic.Uint64
}

func (l *sshInspectionListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &sshInspectionPeer{Conn: c, address: &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("2001:db8::%x", l.peers.Add(1))), Port: 1234}}, nil
}

type sshInspectionPeer struct {
	net.Conn
	address net.Addr
}

func (c *sshInspectionPeer) RemoteAddr() net.Addr { return c.address }
