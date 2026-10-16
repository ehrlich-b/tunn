package host

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/sshfront"
	"github.com/ehrlich-b/tunn/internal/storage"
	"golang.org/x/crypto/ssh"
)

func TestSSHIdentityContinuityAcrossPrimaryFormAndProviderMerge(t *testing.T) {
	p, _, _ := sshRelay(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	local := p.storage.(*storage.LocalStorage)
	owner, err := local.GetAccountByEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	signer := sshSigner(t)
	public := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	key, err := p.sshKeys.Add(ctx, owner.PrimaryEmail, public)
	if err != nil {
		t.Fatal(err)
	}
	cached := sshfront.Identity{Fingerprint: key.Fingerprint, PublicKey: public, Email: owner.PrimaryEmail, AccountID: owner.ID}

	// Use actual loopback sockets for both SSH transports and the TCP origin.
	hostKey := sshSigner(t)
	server, err := sshfront.New(sshfront.Config{HostKey: hostKey, Resolve: p.sshKeys.Owner, ResolveAccount: p.sshKeys.AccountID, CanonicalAccount: p.sshKeys.CanonicalAccountID, Establish: p.establishSSH, Command: p.sshCommand, Connect: p.sshConnect})
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ctx, relay) }()
	t.Cleanup(func() { _ = relay.Close() })
	dial := func(signer ssh.Signer) *ssh.Client {
		t.Helper()
		c, err := ssh.Dial("tcp", relay.Addr().String(), &ssh.ClientConfig{User: "tunn", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()), Timeout: 3 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		// Authentication completes before the server caches account ownership.
		if _, _, err := c.SendRequest("identity-test-barrier", true, nil); err != nil {
			t.Fatal(err)
		}
		return c
	}
	jump, publish := dial(signer), dial(signer)
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	jumpPublish(t, p, origin.Addr().String(), []string{owner.PrimaryEmail})
	active, err := jump.Dial("tcp", "build-host-ssh:22")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = active.Close() })
	echo := func(c net.Conn, message string) {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			if _, err := io.WriteString(c, message); err != nil {
				done <- err
				return
			}
			got := make([]byte, len(message))
			_, err := io.ReadFull(c, got)
			if err == nil && string(got) != message {
				err = fmt.Errorf("echo = %q", got)
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("TCP jump stopped working:", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("TCP jump stalled")
		}
	}
	echo(active, "before changes")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "still published") })
	_, output := sshForward(t, publish, "--public", handler)
	firstURL := strings.TrimSpace(sshLine(t, output))
	if !strings.HasPrefix(firstURL, "https://") {
		t.Fatal(firstURL)
	}
	_ = sshLine(t, output) // Allow-list line.
	_ = sshLine(t, output) // Public access line.
	fetch := func(target string) {
		t.Helper()
		w := httptest.NewRecorder()
		p.handleWebProxy(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 200 || w.Body.String() != "still published" {
			t.Fatal(target, w.Code, w.Body)
		}
	}
	fetch(firstURL)

	stranger, err := local.FindOrCreateByEmails(ctx, []string{"stranger@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	otherSigner := sshSigner(t)
	if _, err := p.sshKeys.Add(ctx, stranger.PrimaryEmail, string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))); err != nil {
		t.Fatal(err)
	}
	other := dial(otherSigner)
	refused := func() {
		t.Helper()
		if c, err := other.Dial("tcp", "build-host-ssh:22"); err == nil {
			_ = c.Close()
			t.Fatal("different account credential admitted")
		}
		if _, err := p.sshOwnerAccount(ctx, sshfront.Identity{Fingerprint: ssh.FingerprintSHA256(otherSigner.PublicKey()), Email: cached.Email, AccountID: cached.AccountID}); err == nil {
			t.Fatal("different account credential accepted cached owner UUID")
		}
	}
	refused()

	// Keep a real enrollment proof pending across both identity changes as well.
	proofSigner := sshSigner(t)
	proofPublic := string(ssh.MarshalAuthorizedKey(proofSigner.PublicKey()))
	proof, err := p.sshKeys.BeginProof(ctx, proofPublic, owner.PrimaryEmail, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	proofSignature, err := proofSigner.Sign(rand.Reader, sshfront.ProofMessage(owner.PrimaryEmail, proof))
	if err != nil {
		t.Fatal(err)
	}

	check := func(stage string) {
		t.Helper()
		// Keep exchanging bytes beyond the one-second live ownership monitor.
		until := time.Now().Add(1250 * time.Millisecond)
		for time.Now().Before(until) {
			echo(active, stage)
			time.Sleep(100 * time.Millisecond)
		}
		next, err := jump.Dial("tcp", "build-host-ssh:22")
		if err != nil {
			t.Fatal("new channel on existing jump transport:", err)
		}
		echo(next, stage+" new channel")
		_ = next.Close()
		fetch(firstURL)
		// A new publication on the original authenticated publish connection checks
		// transport ownership and host admission again without reconnecting.
		listener, err := publish.Listen("tcp", stage+":0")
		if err != nil {
			t.Fatal("new publication on existing transport:", err)
		}
		upstream := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
		go func() { _ = upstream.Serve(listener) }()
		t.Cleanup(func() { _ = upstream.Close() })
		for {
			got := sshLine(t, output)
			if strings.HasPrefix(got, "GET ") || strings.HasPrefix(got, "<- ") {
				continue
			} // Adapter request log from fetch(firstURL).
			if got != "https://"+stage+".tunn.test\n" {
				t.Fatal(got)
			}
			break
		}
		_ = sshLine(t, output)
		_ = sshLine(t, output)
		fetch("https://" + stage + ".tunn.test/")
		if _, err := p.sshOwnerAccount(ctx, cached); err != nil {
			t.Fatal("owner commands:", err)
		}
		if _, err := p.sshOwnerRequest(ctx, cached, "POST", "/api/ssh/keys", strings.NewReader(fmt.Sprintf(`{"public_key":%q}`, public))); err != nil {
			t.Fatal("authenticated key confirmation:", err)
		}
		refused()
	}

	// Add, verify, and change primary through the production form handlers.
	sink := &accountsMailCapture{}
	p.emailSender = sink
	fixture := &mcpOAuthFixture{p: p}
	cookie := emailSession(t, p, owner.PrimaryEmail)
	if w := emailAction(t, fixture, cookie, url.Values{"action": {"add"}, "email": {"new-jump@example.com"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	link, err := url.Parse(sink.link)
	if err != nil {
		t.Fatal(err)
	}
	if w := emailAction(t, fixture, cookie, url.Values{"token": {link.Query().Get("token")}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	w := emailAction(t, fixture, cookie, url.Values{"action": {"primary"}, "email": {sink.to}})
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body)
	}
	assertAccountsSessionCookie(t, p, w, sink.to)
	check("after-primary")

	survivor, err := local.FindOrCreateByEmails(ctx, []string{"survivor@example.com"}, "magic_link")
	if err != nil {
		t.Fatal(err)
	}
	// A paid fixture account wins the authorized merge, exercising an obsolete UUID.
	if err := local.AccountStore().UpdatePlan(survivor.ID, "pro"); err != nil {
		t.Fatal(err)
	}
	p.config.GitHubClientID, p.config.GitHubClientSecret = "fixture-client", "fixture-secret"
	calls := 0
	installAccountsHTTPFake(t, func(r *http.Request) (*http.Response, error) {
		calls++
		switch r.URL.String() {
		case githubTokenURL:
			if r.ParseForm() != nil || r.PostForm.Get("code") != "authorized-merge-code" {
				t.Error("wrong provider authorization code")
			}
			return accountsProviderResponse(r, 200, `{"access_token":"fixture-provider-token","token_type":"bearer","scope":"user:email"}`), nil
		case githubEmailsURL:
			if r.Header.Get("Authorization") != "Bearer fixture-provider-token" {
				t.Error("missing provider authentication")
			}
			return accountsProviderResponse(r, 200, `[{"email":"owner@example.com","verified":true,"primary":false},{"email":"new-jump@example.com","verified":true,"primary":true},{"email":"survivor@example.com","verified":true,"primary":false}]`), nil
		default:
			return nil, fmt.Errorf("unexpected external request: %s", r.URL)
		}
	})
	state, browserCookie := accountsGitHubBrowserStart(t, p, url.Values{})
	if w := accountsGitHubCallback(p, state, "authorized-merge-code", browserCookie); w.Code != 302 || calls != 2 {
		t.Fatal("provider merge:", w.Code, w.Body, calls)
	}
	merged, err := local.GetAccount(ctx, owner.ID)
	if err != nil || merged.ID != survivor.ID || merged.ID == owner.ID {
		t.Fatal("merge did not retire cached UUID:", merged, err)
	}
	check("after-merge")
	if _, err := p.sshKeys.CompleteProof(ctx, owner.ID, owner.PrimaryEmail, proofPublic, proof, proofSignature); err != nil {
		t.Fatal("pending enrollment across merge:", err)
	}
	if _, err := p.sshKeys.ConfirmSessionKey(ctx, strings.ToUpper(owner.ID), public); err != nil {
		t.Fatal("cached merged UUID confirmation:", err)
	}
	if keys, err := p.sshKeys.List(ctx, owner.ID); err != nil || len(keys) < 2 {
		t.Fatal("cached merged UUID listing:", keys, err)
	}
	if err := p.sshKeys.Remove(ctx, stranger.ID, key.Fingerprint); err == nil {
		t.Fatal("different account removed owner's credential")
	}
	if err := p.sshKeys.Remove(ctx, owner.ID, ssh.FingerprintSHA256(proofSigner.PublicKey())); err != nil {
		t.Fatal("cached merged UUID removal:", err)
	}
}
