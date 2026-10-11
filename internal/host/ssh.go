package host

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/cliopts"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/hostmode"
	"github.com/ehrlich-b/tunn/internal/sshfront"
	"golang.org/x/crypto/ssh"
	"time"
)

type sshPublisherContextKey struct{}
type sshPublisher struct {
	email     string
	anonymous bool
}
type sshHostStream struct {
	*sshfront.Stream
	ctx context.Context
}

func (s sshHostStream) Context() context.Context { return s.ctx }

func (p *ProxyServer) enableSSH(db *sql.DB) error {
	key, err := os.ReadFile(p.config.SSHHostKeyFile)
	if err != nil {
		return fmt.Errorf("read SSH host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("parse SSH host key: %w", err)
	}
	p.sshKeys, err = sshfront.NewRegistry(db)
	if err != nil {
		return err
	}
	p.sshServer, err = sshfront.New(sshfront.Config{HostKey: signer, Resolve: p.sshKeys.Owner, Establish: p.establishSSH, Command: p.sshCommand, RotateToken: p.rotateSSHToken, Connect: p.sshConnect, RenderQR: func(ctx context.Context, u string, w io.Writer) error { return hostmode.RenderQR(ctx, u, w, "") }})
	return err
}

func (p *ProxyServer) establishSSH(ctx context.Context, id sshfront.Identity, stream *sshfront.Stream) error {
	email, err := p.sshKeys.Owner(ctx, id.Fingerprint)
	if err != nil {
		return err
	}
	// Re-resolve the key at admission. A removed key never authenticates a new
	// forward through an SSH connection that was established before removal.
	if email != id.Email {
		return fmt.Errorf("SSH key ownership changed; reconnect")
	}
	anonymous := email == ""
	if anonymous {
		digest := sha256.Sum256([]byte(id.Fingerprint))
		email = hex.EncodeToString(digest[:]) + "@ssh-anonymous.invalid"
	}
	if p.storage == nil || !p.storage.Available() {
		return fmt.Errorf("account service unavailable")
	}
	if anonymous {
		if _, err = p.storage.FindOrCreateByEmails(ctx, []string{email}, "ssh_anonymous"); err != nil {
			return err
		}
	}
	trusted := context.WithValue(ctx, sshPublisherContextKey{}, sshPublisher{email: email, anonymous: anonymous})
	return p.tunnelServer.EstablishTunnel(sshHostStream{stream, trusted})
}

func (p *ProxyServer) sshOwnerRequest(ctx context.Context, id sshfront.Identity, method, path string, body io.Reader) (*httptest.ResponseRecorder, error) {
	email, err := p.sshKeys.Owner(ctx, id.Fingerprint)
	if err != nil {
		return nil, err
	}
	if email == "" {
		return nil, fmt.Errorf("link an SSH key first: login --email you@example.com")
	}
	token, err := p.generateJWT(email)
	if err != nil {
		return nil, err
	}
	r := httptest.NewRequest(method, "https://"+p.Domain+path, body).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.createHandler().ServeHTTP(w, r)
	if w.Code >= 400 {
		return nil, fmt.Errorf("%s", strings.TrimSpace(w.Body.String()))
	}
	return w, nil
}

func (p *ProxyServer) sshCommand(ctx context.Context, id sshfront.Identity, args []string, in io.Reader, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("SSH command required")
	}
	switch args[0] {
	case "keys":
		if len(args) < 2 {
			return fmt.Errorf("keys add [PUBLIC_KEY] | list | remove FINGERPRINT")
		}
		method, path, body := http.MethodGet, "/api/ssh/keys", io.Reader(nil)
		switch args[1] {
		case "list":
			if len(args) != 2 {
				return fmt.Errorf("keys list takes no operands")
			}
		case "add":
			public := id.PublicKey
			if len(args) > 2 {
				public = strings.Join(args[2:], " ")
			}
			data, _ := json.Marshal(map[string]string{"public_key": public})
			method = http.MethodPost
			body = strings.NewReader(string(data))
		case "remove":
			if len(args) != 3 {
				return fmt.Errorf("keys remove requires a fingerprint")
			}
			method = http.MethodDelete
			path += "?fingerprint=" + url.QueryEscape(args[2])
		default:
			return fmt.Errorf("unknown keys action")
		}
		w, err := p.sshOwnerRequest(ctx, id, method, path, body)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, w.Body)
		return err
	case "login", "magic-link":
		if len(args) != 3 || args[1] != "--email" {
			return fmt.Errorf("login --email you@example.com")
		}
		return p.requestSSHKeyLink(ctx, id, args[2], out)
	case "hosts":
		if len(args) > 2 || len(args) == 2 && args[1] != "--json" {
			return fmt.Errorf("hosts [--json]")
		}
		w, err := p.sshOwnerRequest(ctx, id, "GET", "/api/hosts", nil)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, w.Body)
		return err
	case "connect":
		if len(args) != 2 || !isValidDNSLabel(args[1]) {
			return fmt.Errorf("connect NAME; use ssh -N -L LOCALPORT:NAME:80 tunn.to")
		}
		_, _ = fmt.Fprintf(out, "ssh -N -p 443 -L 127.0.0.1:15432:%s:80 %s\n", args[1], p.Domain)
		return nil
	case "service":
		return sshfront.ServicePlan(args[1:], in, p.Domain, out)
	case "openclaw":
		fs := flag.NewFlagSet("openclaw", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		name := fs.String("name", "home-openclaw", "endpoint name")
		gateway := fs.String("gateway", "http://127.0.0.1:18789", "local gateway URL")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("openclaw --name NAME --gateway URL")
		}
		if !hostmode.ValidName(*name) {
			return fmt.Errorf("invalid endpoint name")
		}
		// Local gateway probing is done by the SSH forward, never by dialing the
		// relay's loopback network in response to a remote command.
		_, _ = fmt.Fprintf(out, "Preview URL: https://%s.%s\nExpose the gateway with: ssh -T -p 443 -R0:localhost:18789 %s -- --name %s --bearer --require-upstream-auth --qr\nAuthenticate to tunn and approve the device in OpenClaw; keep gateway authentication enabled.\n", *name, p.Domain, p.Domain, *name)
		return hostmode.OpenClaw(ctx, hostmode.OpenClawOptions{Name: *name, Domain: p.Domain, Gateway: *gateway, Probe: func(context.Context, string) error { return fmt.Errorf("probe through a local SSH forward") }, RenderQR: func(ctx context.Context, u string, w io.Writer, _ string) error {
			if p.sshServer == nil {
				return fmt.Errorf("SSH disabled")
			}
			return hostmode.RenderQR(ctx, u, out, "")
		}}, io.Discard)
	case "usage", "grant":
		opts, err := cliopts.ParseMetering(args[0], args[1:], time.Now())
		if err != nil {
			return err
		}
		if opts.Server != "" || opts.OwnerFile != "" || opts.Insecure {
			return fmt.Errorf("SSH owner commands use this relay and the authenticated key")
		}
		email, err := p.sshKeys.Owner(ctx, id.Fingerprint)
		if err != nil || email == "" {
			return fmt.Errorf("link an SSH key first")
		}
		token, err := p.generateJWT(email)
		if err != nil {
			return err
		}
		transport := sshOwnerTransport{handler: p.createHandler()}
		c := &client.ManagementClient{ServerURL: "https://" + p.Domain, OwnerToken: token, HTTPClient: &http.Client{Transport: transport}}
		return client.ExecuteMetering(ctx, opts, c, out)
	default:
		return fmt.Errorf("SSH command %q is unavailable on this relay", args[0])
	}
}

func (p *ProxyServer) rotateSSHToken(ctx context.Context, id sshfront.Identity, name string, digest []byte) error {
	email, err := p.sshKeys.Owner(ctx, id.Fingerprint)
	if err != nil || email == "" {
		return fmt.Errorf("linked key required")
	}
	owner, err := p.storage.GetAccountByEmail(ctx, email)
	if err != nil || owner == nil {
		return fmt.Errorf("account unavailable")
	}
	tunnel, ok := p.tunnelServer.GetTunnel(name)
	if !ok {
		return fmt.Errorf("endpoint offline")
	}
	account, err := p.currentTunnelAccount(ctx, tunnel)
	if err != nil || account == nil || account.ID != owner.ID {
		return fmt.Errorf("only the endpoint owner can manage its token")
	}
	if digest != nil {
		if len(digest) != sha256.Size {
			return fmt.Errorf("invalid token digest")
		}
		tunnel.updateAccessTokenDigest(digest)
	}
	return nil
}

// sshConnect feeds an authenticated HTTP CONNECT through ordinary ingress. It
// never dials a hostname supplied by an SSH client on the host's network.
func (p *ProxyServer) sshConnect(ctx context.Context, id sshfront.Identity, name string) (net.Conn, error) {
	if !isValidDNSLabel(name) {
		return nil, fmt.Errorf("invalid endpoint name")
	}
	tunnel, ok := p.tunnelServer.GetTunnel(name)
	if !ok || tunnel.EndpointProtocol != "tcp" {
		return nil, fmt.Errorf("raw endpoint is not online on this SSH relay")
	}
	email, err := p.sshKeys.Owner(ctx, id.Fingerprint)
	if err != nil || email == "" {
		return nil, fmt.Errorf("linked key required for SSH connect")
	}
	token, err := p.generateJWT(email)
	if err != nil {
		return nil, err
	}
	local, remote := net.Pipe()
	input, output := io.Pipe()
	connection := &sshConnectConn{Conn: local, input: input, output: output}
	ready := make(chan error, 1)
	r := httptest.NewRequest(http.MethodConnect, "https://"+name+"."+p.Domain+common.TCPConnectPath, input).WithContext(ctx)
	r.Host = name + "." + p.Domain
	r.URL.Path = common.TCPConnectPath
	r.RemoteAddr = net.JoinHostPort(id.IP, "1")
	r.ContentLength = -1
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set(common.TCPConnectHeader, common.TCPConnectValue)
	w := &sshConnectWriter{headers: make(http.Header), writer: remote, ready: ready}
	go func() { defer func() { _ = input.Close(); _ = remote.Close() }(); p.handleWebProxy(w, r) }()
	select {
	case err := <-ready:
		if err != nil {
			_ = connection.Close()
			return nil, err
		}
		return connection, nil
	case <-ctx.Done():
		_ = connection.Close()
		return nil, ctx.Err()
	}
}

type sshConnectConn struct {
	net.Conn
	input  *io.PipeReader
	output *io.PipeWriter
}

func (c *sshConnectConn) Write(p []byte) (int, error) { return c.output.Write(p) }
func (c *sshConnectConn) CloseWrite() error           { return c.output.Close() }
func (c *sshConnectConn) Close() error {
	_ = c.output.Close()
	_ = c.input.Close()
	return c.Conn.Close()
}

type sshConnectWriter struct {
	headers http.Header
	writer  io.Writer
	ready   chan error
	once    sync.Once
}

func (w *sshConnectWriter) Header() http.Header { return w.headers }
func (w *sshConnectWriter) WriteHeader(status int) {
	w.once.Do(func() {
		var err error
		if status != http.StatusOK {
			err = fmt.Errorf("SSH endpoint access denied (HTTP %d)", status)
		}
		w.ready <- err
	})
}
func (w *sshConnectWriter) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.writer.Write(p)
}
func (w *sshConnectWriter) Flush()                  {}
func (w *sshConnectWriter) EnableFullDuplex() error { return nil }

func (p *ProxyServer) requestSSHKeyLink(ctx context.Context, id sshfront.Identity, email string, out io.Writer) error {
	email = common.NormalizeEmail(email)
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return fmt.Errorf("provide one email address")
	}
	if p.emailSender == nil {
		return fmt.Errorf("email linking unavailable: SMTP is not configured")
	}
	if !p.checkDeviceCodeRateLimit("ssh-link:"+id.IP) || !p.checkDeviceCodeRateLimit("ssh-key:"+id.Fingerprint) {
		return fmt.Errorf("SSH linking rate limited")
	}
	allowed, _, _, err := p.storage.CheckMagicLinkRateLimit(ctx, email)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("email linking rate limited")
	}
	token, err := p.sshKeys.BeginLink(ctx, id.PublicKey, email)
	if err != nil {
		return err
	}
	u := "https://" + p.config.PublicAddr + "/auth/ssh-key?token=" + url.QueryEscape(token)
	if err = p.emailSender.SendMagicLink(email, u); err != nil {
		return err
	}
	// The email proof never appears in the SSH session. Printing the actual
	// bearer link here would let a key owner claim an arbitrary victim account.
	_, _ = fmt.Fprintf(out, "Link requested for %s (%s). Open the magic link in your email within 5 minutes, then reconnect.\nAccount: https://%s/account\n", email, id.Fingerprint, p.config.PublicAddr)
	return nil
}

func (p *ProxyServer) handleSSHKeyLink(w http.ResponseWriter, r *http.Request) {
	if extractTunnelID(r.Host, p.Domain) != "" {
		p.handleWebProxy(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if p.sshKeys == nil {
		http.Error(w, "SSH key linking is disabled", http.StatusNotFound)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.URL.Query().Get("token")
	email, err := p.sshKeys.LinkEmail(r.Context(), token)
	if err != nil {
		http.Error(w, "Invalid or expired SSH link", http.StatusBadRequest)
		return
	}
	if _, err = p.storage.FindOrCreateByEmails(r.Context(), []string{email}, "magic_link"); err != nil {
		http.Error(w, "Account service unavailable", http.StatusServiceUnavailable)
		return
	}
	if err = p.sshKeys.CompleteLink(r.Context(), token); err != nil {
		http.Error(w, "SSH link already used or key belongs to another identity", http.StatusBadRequest)
		return
	}
	if err = p.setAuthCookie(w, email); err != nil {
		http.Error(w, "Could not complete login", http.StatusInternalServerError)
		return
	}
	_, _ = fmt.Fprintln(w, "SSH key linked. Reconnect with the same key to use your account.")
}

func (p *ProxyServer) handleSSHKeys(w http.ResponseWriter, r *http.Request) {
	if extractTunnelID(r.Host, p.Domain) != "" {
		p.handleWebProxy(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if p.sshKeys == nil {
		http.Error(w, "SSH API disabled on this node", http.StatusNotFound)
		return
	}
	email, _, capability, ok := p.getAuthFromTunnelBearer(r, &TunnelConnection{})
	if !ok || capability {
		http.Error(w, "Owner authentication required", http.StatusUnauthorized)
		return
	}
	account, err := p.storage.GetAccountByEmail(r.Context(), common.NormalizeEmail(email))
	if err != nil || account == nil {
		http.Error(w, "Account service unavailable", http.StatusServiceUnavailable)
		return
	}
	emails := []string{account.PrimaryEmail}
	for _, e := range account.Emails {
		if e.Email != account.PrimaryEmail {
			emails = append(emails, e.Email)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		keys, err := p.sshKeys.List(r.Context(), emails)
		if err != nil {
			http.Error(w, "Could not list SSH keys", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(keys)
	case http.MethodPost:
		var req struct {
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
			http.Error(w, "Invalid key", http.StatusBadRequest)
			return
		}
		key, err := sshfront.ParseKey(req.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ownerEmail := account.PrimaryEmail
		previousOwner, err := p.sshKeys.Owner(r.Context(), key.Fingerprint)
		if err != nil {
			http.Error(w, "Key service unavailable", http.StatusServiceUnavailable)
			return
		}
		for _, email := range emails {
			if email == previousOwner {
				ownerEmail = email
			}
		}
		key, err = p.sshKeys.Add(r.Context(), ownerEmail, req.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(key)
	case http.MethodDelete:
		if err := p.sshKeys.Remove(r.Context(), emails, r.URL.Query().Get("fingerprint")); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintln(w, `{"removed":true}`)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type sshOwnerTransport struct{ handler http.Handler }

func (t sshOwnerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.handler.ServeHTTP(w, r)
	return w.Result(), nil
}
