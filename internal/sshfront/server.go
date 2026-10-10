// Package sshfront provides OpenSSH remote forwarding without opening host-side
// target sockets or executing client commands on the relay.
package sshfront

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/cliopts"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/mcpbridge"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
	"golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"
)

const AnonymousExpiry = 30 * time.Minute
const AnonymousBytes int64 = 10 << 20

type Identity struct{ Fingerprint, PublicKey, Email, IP string }
type Config struct {
	HostKey        ssh.Signer
	Resolve        func(context.Context, string) (string, error)
	Establish      func(context.Context, Identity, *Stream) error
	Command        func(context.Context, Identity, []string, io.Reader, io.Writer) error
	RenderQR       func(context.Context, string, io.Writer) error
	RotateToken    func(context.Context, Identity, string, []byte) error
	Connect        func(context.Context, Identity, string) (net.Conn, error)
	StartupTimeout time.Duration
}
type budget struct {
	active  int
	used    int64
	since   time.Time
	limiter *rate.Limiter
}
type Server struct {
	cfg       Config
	mu        sync.Mutex
	budgets   map[string]*budget
	handshake map[string]*budget
	port      atomic.Uint32
	tokens    map[string]string
	endpoints map[string]*forward
	sessions  chan struct{}
}

func New(cfg Config) (*Server, error) {
	if cfg.HostKey == nil || cfg.Establish == nil || cfg.Resolve == nil {
		return nil, fmt.Errorf("SSH host key, identity resolver and tunnel callback required")
	}
	s := &Server{cfg: cfg, budgets: map[string]*budget{}, handshake: map[string]*budget{}, tokens: map[string]string{}, endpoints: map[string]*forward{}, sessions: make(chan struct{}, 128)}
	s.port.Store(1023)
	return s, nil
}

func (s *Server) allowHandshake(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, b := range s.handshake {
		if now.Sub(b.since) > 5*time.Minute {
			delete(s.handshake, k)
		}
	}
	b := s.handshake[ip]
	if b == nil {
		if len(s.handshake) >= 4096 {
			return false
		}
		b = &budget{since: now, limiter: rate.NewLimiter(rate.Every(time.Minute), 5)}
		s.handshake[ip] = b
	}
	return b.limiter.Allow()
}
func (s *Server) acquire(id Identity) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, b := range s.budgets {
		if b.active == 0 && now.Sub(b.since) > AnonymousExpiry {
			delete(s.budgets, k)
		}
	}
	if len(s.budgets) > 8192 {
		return nil, fmt.Errorf("SSH admission busy")
	}
	keys := []string{"key:" + id.Fingerprint, "ip:" + id.IP}
	max := []int{10, 30}
	if id.Email == "" {
		max = []int{1, 3}
	}
	for i, k := range keys {
		b := s.budgets[k]
		if b == nil {
			b = &budget{since: now}
			s.budgets[k] = b
		}
		if b.active >= max[i] || id.Email == "" && b.used >= AnonymousBytes {
			return nil, fmt.Errorf("SSH key or IP limit reached")
		}
	}
	for _, k := range keys {
		s.budgets[k].active++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, k := range keys {
				s.budgets[k].active--
			}
		})
	}, nil
}
func (s *Server) charge(id Identity, n int) bool {
	if id.Email != "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range []string{"key:" + id.Fingerprint, "ip:" + id.IP} {
		b := s.budgets[k]
		if b == nil || b.used+int64(n) > AnonymousBytes {
			return false
		}
	}
	for _, k := range []string{"key:" + id.Fingerprint, "ip:" + id.IP} {
		s.budgets[k].used += int64(n)
	}
	return true
}

func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { _ = l.Close() }()
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		go s.ServeConn(ctx, c)
	}
}
func (s *Server) ServeConn(parent context.Context, raw net.Conn) {
	defer func() { _ = raw.Close() }()
	if parent.Err() != nil {
		return
	}
	stopParent := context.AfterFunc(parent, func() { _ = raw.Close() })
	defer stopParent()
	select {
	case s.sessions <- struct{}{}:
		defer func() { <-s.sessions }()
	default:
		return
	}
	ip, _, err := net.SplitHostPort(raw.RemoteAddr().String())
	if err != nil {
		ip = raw.RemoteAddr().String()
	}
	if !s.allowHandshake(ip) {
		return
	}
	config := &ssh.ServerConfig{MaxAuthTries: 3, PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return &ssh.Permissions{Extensions: map[string]string{"fingerprint": ssh.FingerprintSHA256(key), "public": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))}}, nil
	}}
	config.AddHostKey(s.cfg.HostKey)
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn, channels, requests, err := ssh.NewServerConn(raw, config)
	if err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	id := Identity{Fingerprint: conn.Permissions.Extensions["fingerprint"], PublicKey: conn.Permissions.Extensions["public"], IP: ip}
	state := &connection{server: s, ssh: conn, ctx: ctx, id: id, forwards: map[forwardSpec]*forward{}, cancel: cancel, directSlots: make(chan struct{}, 32), sessionDone: make(chan struct{})}
	startupTimeout := s.cfg.StartupTimeout
	if startupTimeout <= 0 {
		startupTimeout = 15 * time.Second
	}
	startup := time.AfterFunc(startupTimeout, cancel)
	defer startup.Stop()
	state.started = func() { startup.Stop() }
	go func() {
		<-ctx.Done()
		select {
		case <-parent.Done():
		case <-state.sessionDone:
		case <-time.After(time.Second):
		}
		_ = conn.Close()
	}()
	go state.requests(requests)
	for channel := range channels {
		if channel.ChannelType() == "direct-tcpip" && s.cfg.Connect != nil {
			select {
			case state.directSlots <- struct{}{}:
				go func() { defer func() { <-state.directSlots }(); state.direct(channel) }()
			default:
				_ = channel.Reject(ssh.ResourceShortage, "SSH connection limit reached")
			}
			continue
		}
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.Prohibited, "only session channels are supported")
			continue
		}
		state.mu.Lock()
		if state.output != nil {
			state.mu.Unlock()
			_ = channel.Reject(ssh.Prohibited, "one session per SSH connection")
			continue
		}
		ch, rs, e := channel.Accept()
		if e != nil {
			state.mu.Unlock()
			continue
		}
		state.output = &sessionOutput{channel: ch}
		state.mu.Unlock()
		go state.session(ch, rs)
	}
}

type forwardSpec struct {
	Address string
	Port    uint32
}
type forward struct {
	spec      forwardSpec
	cancel    context.CancelFunc
	done      chan struct{}
	name      string
	adapter   *client.ServeClient
	inspector *client.Inspector
	digest    []byte
	token     string
}
type connection struct {
	sessionDone chan struct{}
	directSlots chan struct{}
	server      *Server
	ssh         *ssh.ServerConn
	ctx         context.Context
	cancel      context.CancelFunc
	id          Identity
	mu          sync.Mutex
	forwards    map[forwardSpec]*forward
	options     *cliopts.Serve
	protocol    string
	kind        string
	output      *sessionOutput
	bridge      *mcpbridge.Bridge
	started     func()
}
type sessionOutput struct {
	mu      sync.Mutex
	channel io.Writer
	pty     bool
}

func (o *sessionOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.pty {
		_, err := o.channel.Write([]byte(strings.ReplaceAll(string(p), "\n", "\r\n")))
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return o.channel.Write(p)
}
func (c *connection) requests(requests <-chan *ssh.Request) {
	defer c.cancel()
	for req := range requests {
		var spec forwardSpec
		if (req.Type != "tcpip-forward" && req.Type != "cancel-tcpip-forward") || ssh.Unmarshal(req.Payload, &spec) != nil {
			_ = req.Reply(false, nil)
			continue
		}
		if spec.Port > 65535 || len(spec.Address) > 253 {
			_ = req.Reply(false, nil)
			continue
		}
		c.mu.Lock()
		if req.Type == "cancel-tcpip-forward" {
			f := c.forwards[spec]
			if f != nil {
				delete(c.forwards, spec)
				if f.cancel != nil {
					f.cancel()
				}
			}
			c.mu.Unlock()
			if f != nil && f.done != nil {
				<-f.done
			}
			_ = req.Reply(f != nil, nil)
			c.mu.Lock()
			empty := len(c.forwards) == 0 && c.options != nil
			c.mu.Unlock()
			if f != nil && empty {
				c.cancel()
			}
			continue
		}
		if len(c.forwards) >= 10 {
			c.mu.Unlock()
			_ = req.Reply(false, nil)
			continue
		}
		allocated := spec.Port == 0
		if allocated {
			spec.Port = 1024 + (c.server.port.Add(1)-1024)%60000
		}
		if _, exists := c.forwards[spec]; exists {
			c.mu.Unlock()
			_ = req.Reply(false, nil)
			continue
		}
		f := &forward{spec: spec}
		c.forwards[spec] = f
		err := error(nil)
		if c.options != nil {
			err = c.start(f)
		}
		if err != nil {
			delete(c.forwards, spec)
		}
		c.mu.Unlock()
		if err != nil {
			_ = req.Reply(false, nil)
			fmt.Fprintln(c.output, err)
			continue
		}
		var reply []byte
		if allocated {
			reply = ssh.Marshal(struct{ Port uint32 }{spec.Port})
		}
		_ = req.Reply(true, reply)
	}
}

func (c *connection) session(ch ssh.Channel, requests <-chan *ssh.Request) {
	defer func() { _ = ch.Close(); close(c.sessionDone); c.cancel() }()
	for req := range requests {
		switch req.Type {
		case "pty-req", "window-change":
			if req.Type == "pty-req" {
				c.output.mu.Lock()
				c.output.pty = true
				c.output.mu.Unlock()
			}
			_ = req.Reply(true, nil)
		case "signal":
			_ = req.Reply(true, nil)
			return
		case "shell", "exec":
			args := []string{}
			if req.Type == "exec" {
				var command struct{ Command string }
				if ssh.Unmarshal(req.Payload, &command) != nil {
					_ = req.Reply(false, nil)
					continue
				}
				var err error
				args, err = SplitCommand(command.Command)
				if err != nil {
					_ = req.Reply(false, nil)
					fmt.Fprintln(c.output, err)
					return
				}
			}
			_ = req.Reply(true, nil)
			c.started()
			// Exec owns the session until the tunnel ends; keep receiving control
			// requests so OpenSSH signals are effective while run is blocked.
			go func() {
				for control := range requests {
					if control.Type == "signal" {
						_ = control.Reply(true, nil)
						c.cancel()
						return
					}
					_ = control.Reply(control.Type == "window-change", nil)
				}
				c.cancel()
			}()
			err := c.run(args, ch)
			code := uint32(0)
			if err != nil {
				code = 1
				fmt.Fprintln(c.output, err)
			}
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func (c *connection) run(args []string, in ssh.Channel) error {
	for len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) > 0 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(c.output, "SSH API: ssh -T -p 443 -R0:localhost:8080 tunn.to -- [serve|tcp|unix|mcp] [flags]\nCommands: help, keys add/list/remove, login --email EMAIL, hosts, usage, grant, token, inspect, replay, connect\nLocal plans: service install/uninstall/status/run; openclaw preview.\nMCP: mcp --stdio bridges JSON-RPC on stdin/stdout; --tools restricts tools.")
		if len(args) > 1 && (args[1] == "grant" || args[1] == "usage") {
			fmt.Fprint(c.output, cliopts.MeteringUsage)
		} else {
			cliopts.Usage(c.output)
		}
		return nil
	}
	email, err := c.server.cfg.Resolve(c.ctx, c.id.Fingerprint)
	if err != nil {
		return err
	}
	c.id.Email = email
	protocol := "http"
	kind := "serve"
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			args = args[1:]
		case "tcp", "unix":
			kind = args[0]
			protocol = "tcp"
			args = args[1:]
		case "mcp":
			kind = "mcp"
			args = args[1:]
		case "inspect", "replay":
			return c.server.inspection(c.ctx, c.id, args, c.output)
		case "token":
			return c.server.token(c.ctx, c.id, args[1:], c.output)
		case "keys", "login", "hosts", "usage", "grant", "service", "openclaw", "connect", "magic-link":
			if c.server.cfg.Command == nil {
				return fmt.Errorf("command unavailable")
			}
			ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, func() { _ = in.Close(); c.cancel() })
			defer stop()
			return c.server.cfg.Command(ctx, c.id, args, in, c.output)
		}
	}
	userArgs, err := UsernameArgs(c.ssh.User())
	if err != nil {
		return err
	}
	opts, err := cliopts.ParseSSHPublication(append(userArgs, args...), kind)
	if err != nil {
		return err
	}
	if opts.Secret != "" || opts.TunnelKey != "" {
		return fmt.Errorf("SSH authenticates with your public key; do not send secrets in commands")
	}
	if opts.Target != "" {
		u, e := url.Parse(opts.Target)
		if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Scheme != "http" && u.Scheme != "https" || protocol == "tcp" {
			return fmt.Errorf("--target must be an HTTP(S) URL without credentials")
		}
	}
	if c.id.Email == "" {
		if opts.Public || len(opts.AllowedEmails) == 0 {
			return fmt.Errorf("anonymous SSH requires --allow or --allow-domain; --public requires a linked key (ssh tunn.to -- login --email you@example.com)")
		}
		if opts.Expire == 0 || opts.Expire > AnonymousExpiry {
			opts.Expire = AnonymousExpiry
		}
	} else if !opts.Public {
		opts.AllowedEmails = append(opts.AllowedEmails, c.id.Email)
	}
	if protocol == "tcp" && opts.Public {
		return fmt.Errorf("raw endpoints must be private")
	}
	if kind == "unix" && opts.Adapter == "http" {
		protocol = "http"
		if opts.Public {
			return fmt.Errorf("HTTP-over-Unix endpoints cannot be public")
		}
	}
	c.mu.Lock()
	if opts.Stdio {
		if len(c.forwards) != 0 {
			c.mu.Unlock()
			return fmt.Errorf("mcp --stdio uses stdin/stdout; omit -R")
		}
		c.output = &sessionOutput{channel: in.Stderr()}
		c.bridge = mcpbridge.FromStreams(c.ctx, in, &stdioOutput{Channel: in, cancel: c.cancel}, mcpbridge.Options{AllowedTools: opts.Tools})
		c.forwards[forwardSpec{Address: "localhost", Port: 80}] = &forward{spec: forwardSpec{Address: "localhost", Port: 80}}
	}
	c.options = opts
	c.protocol = protocol
	c.kind = kind
	if len(c.forwards) == 0 {
		c.mu.Unlock()
		return fmt.Errorf("supply an OpenSSH remote forward: -R0:localhost:8080")
	}
	if opts.Name != "" && len(c.forwards) > 1 {
		c.mu.Unlock()
		return fmt.Errorf("--name requires one forward; use -R name:80:localhost:PORT for multiple names")
	}
	for _, f := range c.forwards {
		if err = c.start(f); err != nil {
			break
		}
	}
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if opts.Stdio {
		select {
		case <-c.ctx.Done():
		case <-c.bridge.Done():
		}
		return nil
	}
	// stdin delivers Ctrl-C in non-PTY sessions too. A closed stdin (-n) keeps
	// the tunnel alive until the SSH connection, a signal, or expiry closes it.
	go func() {
		buf := make([]byte, 256)
		for {
			n, e := in.Read(buf)
			for _, b := range buf[:n] {
				if b == 3 || b == 4 {
					c.cancel()
					return
				}
			}
			if e != nil {
				return
			}
		}
	}()
	<-c.ctx.Done()
	return nil
}

func (c *connection) start(f *forward) error {
	email, err := c.server.cfg.Resolve(c.ctx, c.id.Fingerprint)
	if err != nil {
		return err
	}
	if email != c.id.Email {
		return fmt.Errorf("SSH key ownership changed; reconnect")
	}
	id := c.id
	o := *c.options
	o.AllowedEmails = append([]string(nil), o.AllowedEmails...)
	name := o.Name
	if name == "" && f.spec.Address != "localhost" && f.spec.Address != "127.0.0.1" && f.spec.Address != "0.0.0.0" && f.spec.Address != "::" && f.spec.Address != "" && f.spec.Address != "*" {
		name = f.spec.Address
	}
	if name == "" {
		name = common.RandID(12)
	}
	release, err := c.server.acquire(id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(c.ctx)
	if o.Expire > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, o.Expire)
		old := cancel
		cancel = func() { stop(); old() }
	}
	f.cancel = cancel
	f.done = make(chan struct{})
	f.name = name
	stream, messages := NewStream(ctx)
	hostDone := make(chan error, 1)
	go func() {
		defer close(f.done)
		defer release()
		err := c.server.cfg.Establish(ctx, id, stream)
		cancel()
		hostDone <- err
	}()
	var token string
	var digest []byte
	if o.Bearer || c.protocol == "tcp" {
		token, digest, err = client.GenerateEndpointToken()
		if err != nil {
			cancel()
			return err
		}
		f.digest = digest
		f.token = token
	}
	reg := &pb.RegisterClient{TunnelId: name, TargetUrl: c.protocol, AllowedEmails: o.AllowedEmails, AccessTokenSha256: digest, EndpointProtocol: c.protocol, Capabilities: []string{common.CapabilityHTTPStreamV1, common.CapabilityConnectionStreamV1, common.CapabilityWebSocketV1}}
	if err = messages.Send(&pb.TunnelMessage{Message: &pb.TunnelMessage_RegisterClient{RegisterClient: reg}}); err != nil {
		cancel()
		return err
	}
	msg, err := messages.Recv()
	if err != nil {
		cancel()
		select {
		case e := <-hostDone:
			if e != nil {
				return e
			}
		default:
		}
		return fmt.Errorf("SSH registration interrupted")
	}
	r := msg.GetRegisterResponse()
	if r == nil || !r.Success {
		cancel()
		if r != nil {
			return fmt.Errorf("%s", r.ErrorMessage)
		}
		return fmt.Errorf("invalid relay registration reply")
	}
	messages.Observe = func(m *pb.TunnelMessage) {
		if o.Stdio {
			if data := m.GetConnectionData(); data != nil && !c.server.charge(id, len(data.Data)) {
				cancel()
			}
		}
		if open := m.GetConnectionOpen(); open != nil && open.HttpRequest != nil {
			fmt.Fprintf(c.output, "%s %s\n", open.HttpRequest.Method, terminalText(open.HttpRequest.Path))
		}
		if accept := m.GetConnectionAccept(); accept != nil && accept.HttpResponse != nil {
			fmt.Fprintf(c.output, "<- %d\n", accept.HttpResponse.StatusCode)
		}
	}
	adapter := &client.ServeClient{TargetURL: "http://ssh-forward", EndpointProtocol: c.protocol, RequireUpstreamAuth: o.RequireUpstreamAuth, SkipLocalTLSVerify: o.SkipLocalTLSVerify, WebSocket: &o.WebSocket}
	if o.Target != "" {
		adapter.TargetURL = o.Target
	}
	if c.bridge != nil || c.kind == "mcp" {
		u, _ := url.Parse(adapter.TargetURL)
		adapter.TargetURL = u.Scheme + "://" + u.Host
		adapter.PublicPath = "/mcp"
		adapter.UpstreamPath = u.Path
		adapter.UpstreamRawQuery = u.RawQuery
		if adapter.UpstreamPath == "" {
			adapter.UpstreamPath = "/mcp"
		}
	}
	if c.protocol == "tcp" {
		adapter.TargetURL = "ssh-forward:80"
	}
	adapter.DialContext = func(callCtx context.Context, _, _ string) (net.Conn, error) {
		type opened struct {
			ch   ssh.Channel
			reqs <-chan *ssh.Request
			err  error
		}
		result := make(chan opened)
		go func() {
			ch, reqs, err := c.ssh.OpenChannel("forwarded-tcpip", ssh.Marshal(struct {
				Address    string
				Port       uint32
				Origin     string
				OriginPort uint32
			}{f.spec.Address, f.spec.Port, "127.0.0.1", 1}))
			select {
			case result <- opened{ch, reqs, err}:
			case <-callCtx.Done():
				if ch != nil {
					_ = ch.Close()
				}
			}
		}()
		select {
		case r := <-result:
			if r.err != nil {
				common.LogDebug("SSH forward channel failed", "error", r.err)
				return nil, r.err
			}
			go ssh.DiscardRequests(r.reqs)
			return &channelConn{Channel: r.ch, server: c.server, id: id, cancel: cancel}, nil
		case <-callCtx.Done():
			return nil, callCtx.Err()
		}
	}
	f.adapter = adapter
	if o.Stdio {
		adapter.HTTPTransport = handlerTransport{handler: c.bridge}
	}
	if o.Inspect {
		f.inspector = client.NewInspector(adapter)
		adapter.Inspector = f.inspector
	}
	c.server.mu.Lock()
	if ctx.Err() != nil {
		c.server.mu.Unlock()
		cancel()
		return fmt.Errorf("SSH registration expired")
	}
	c.server.endpoints[name] = f
	if token != "" {
		c.server.tokens[name] = token
	}
	c.server.mu.Unlock()
	publicURL := r.PublicUrl
	if c.kind == "mcp" {
		publicURL += "/mcp"
	}
	fmt.Fprintf(c.output, "%s\nAccess: %s\n", publicURL, strings.Join(o.AllowedEmails, ", "))
	if o.Public {
		fmt.Fprintln(c.output, "Access: public")
	}
	if o.Expire > 0 {
		fmt.Fprintf(c.output, "Expires after: %s\n", o.Expire)
	}
	if token != "" {
		fmt.Fprintf(c.output, "Endpoint token: %s\n", token)
	}
	if o.QR {
		if c.server.cfg.RenderQR == nil {
			fmt.Fprintln(c.output, "QR unavailable: install qrencode on the relay")
		} else if err := c.server.cfg.RenderQR(ctx, publicURL, c.output); err != nil {
			fmt.Fprintln(c.output, err)
		}
	}
	go func() { _ = adapter.ServeMessages(ctx, messages); cancel() }()
	go func() {
		<-ctx.Done()
		cancel()
		c.server.mu.Lock()
		if c.server.endpoints[name] == f {
			delete(c.server.tokens, name)
			delete(c.server.endpoints, name)
		}
		c.server.mu.Unlock()
		c.mu.Lock()
		removed := c.forwards[f.spec] == f
		if removed {
			delete(c.forwards, f.spec)
		}
		empty := len(c.forwards) == 0
		c.mu.Unlock()
		if removed && empty {
			c.cancel()
		}
	}()
	return nil
}

type stdioOutput struct {
	ssh.Channel
	mu     sync.Mutex
	timer  *time.Timer
	cancel context.CancelFunc
}

func (s *stdioOutput) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	if !t.IsZero() {
		s.timer = time.AfterFunc(max(time.Until(t), 0), func() { _ = s.Channel.Close(); s.cancel() })
	}
	return nil
}

func (s *stdioOutput) Close() error {
	_ = s.SetWriteDeadline(time.Time{})
	return s.Channel.CloseWrite()
}

type handlerTransport struct{ handler http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.handler.ServeHTTP(w, r)
	return w.Result(), nil
}
func (s *Server) inspection(ctx context.Context, id Identity, args []string, out io.Writer) error {
	if len(args) < 2 || len(args) > 3 || args[0] == "inspect" && len(args) != 2 || args[0] == "replay" && len(args) != 3 {
		return fmt.Errorf("inspect NAME | replay NAME DELIVERY_ID")
	}
	if s.cfg.RotateToken == nil {
		return fmt.Errorf("owner interface unavailable")
	}
	if err := s.cfg.RotateToken(ctx, id, args[1], nil); err != nil {
		return err
	}
	s.mu.Lock()
	f := s.endpoints[args[1]]
	s.mu.Unlock()
	if f == nil || f.inspector == nil {
		return fmt.Errorf("endpoint was not started with --inspect")
	}
	if args[0] == "inspect" {
		return json.NewEncoder(out).Encode(f.inspector.Events())
	}
	n, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid delivery ID")
	}
	event, err := f.inspector.Replay(ctx, n)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(event)
}

func (s *Server) token(ctx context.Context, id Identity, args []string, out io.Writer) error {
	rotate := false
	var name string
	for _, a := range args {
		if a == "--rotate" {
			rotate = true
		} else if name == "" {
			name = a
		} else {
			return fmt.Errorf("token [--rotate] NAME")
		}
	}
	if name == "" || s.cfg.RotateToken == nil {
		return fmt.Errorf("token [--rotate] NAME")
	}
	// The host checks the current account UUID, including merges and revoked keys.
	if err := s.cfg.RotateToken(ctx, id, name, nil); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	token := s.tokens[name]
	if token == "" {
		return fmt.Errorf("endpoint has no SSH-managed token")
	}
	if rotate {
		var digest []byte
		var err error
		token, digest, err = client.GenerateEndpointToken()
		if err != nil {
			return err
		}
		if err = s.cfg.RotateToken(ctx, id, name, digest); err != nil {
			return err
		}
		s.tokens[name] = token
	}
	_, err := fmt.Fprintln(out, token)
	return err
}

func (c *connection) direct(channel ssh.NewChannel) {
	var spec struct {
		Address    string
		Port       uint32
		Origin     string
		OriginPort uint32
	}
	if ssh.Unmarshal(channel.ExtraData(), &spec) != nil || spec.Port != 80 || len(spec.Address) > 63 {
		_ = channel.Reject(ssh.Prohibited, "use -L LOCALPORT:TUNNEL:80 for a named raw endpoint")
		return
	}
	ctx, cancel := context.WithCancel(c.ctx)
	timer := time.AfterFunc(10*time.Second, cancel)
	defer timer.Stop()
	upstream, err := c.server.cfg.Connect(ctx, c.id, spec.Address)
	if err != nil {
		cancel()
		_ = channel.Reject(ssh.Prohibited, err.Error())
		return
	}
	c.started()
	timer.Stop()
	// Admission has its own timeout. The data path lives for the SSH session.
	ch, requests, err := channel.Accept()
	if err != nil {
		cancel()
		_ = upstream.Close()
		return
	}
	go ssh.DiscardRequests(requests)
	defer cancel()
	defer func() { _ = ch.Close(); _ = upstream.Close() }()
	done := make(chan struct{})
	go func() {
		select {
		case <-c.ctx.Done():
			_ = ch.Close()
			_ = upstream.Close()
		case <-done:
		}
	}()
	defer close(done)
	go func() {
		_, _ = io.Copy(upstream, ch)
		if half, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
	}()
	_, _ = io.Copy(ch, upstream)
}

type channelConn struct {
	ssh.Channel
	server *Server
	id     Identity
	cancel context.CancelFunc
}

func (c *channelConn) Read(p []byte) (int, error) {
	n, e := c.Channel.Read(p)
	if n > 0 && !c.server.charge(c.id, n) {
		c.cancel()
		return 0, fmt.Errorf("anonymous SSH bandwidth budget exhausted")
	}
	return n, e
}
func (c *channelConn) Write(p []byte) (int, error) {
	if !c.server.charge(c.id, len(p)) {
		c.cancel()
		return 0, fmt.Errorf("anonymous SSH bandwidth budget exhausted")
	}
	return c.Channel.Write(p)
}
func (c *channelConn) LocalAddr() net.Addr              { return channelAddr("ssh-relay") }
func (c *channelConn) RemoteAddr() net.Addr             { return channelAddr("ssh-forward") }
func (c *channelConn) SetDeadline(time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(time.Time) error { return nil }
func (c *channelConn) CloseWrite() error                { return c.Channel.CloseWrite() }

type channelAddr string

func (a channelAddr) Network() string { return "ssh" }
func (a channelAddr) String() string  { return string(a) }
func terminalText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}

func UsernameArgs(user string) ([]string, error) {
	if user == "" || user == "tunn" || user == "anonymous" {
		return nil, nil
	}
	parts := strings.Split(user, "+")
	var args []string
	for i := 0; i < len(parts); i++ {
		switch parts[i] {
		case "qr", "public", "inspect", "bearer":
			args = append(args, "--"+parts[i])
		case "allow", "allow-domain", "name", "expire":
			if i+1 >= len(parts) {
				return nil, fmt.Errorf("missing username option value")
			}
			args = append(args, "--"+parts[i], parts[i+1])
			i++
		default:
			if len(parts) == 1 {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown username option %q", parts[i])
		}
	}
	return args, nil
}

// SplitCommand recognizes shell quoting only. It never expands variables,
// invokes a shell, or executes a command supplied by the SSH client.
func SplitCommand(s string) ([]string, error) {
	if len(s) > 8192 {
		return nil, fmt.Errorf("SSH command too long")
	}
	var out []string
	var b strings.Builder
	quote := rune(0)
	escaped, started := false, false
	for _, r := range s {
		if escaped {
			b.WriteRune(r)
			escaped = false
			started = true
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			started = true
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			started = true
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' {
			if started {
				out = append(out, b.String())
				b.Reset()
				started = false
			}
			continue
		}
		b.WriteRune(r)
		started = true
	}
	if escaped || quote != 0 {
		return nil, fmt.Errorf("unterminated SSH command quote")
	}
	if started {
		out = append(out, b.String())
	}
	return out, nil
}
