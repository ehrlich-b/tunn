// Package tunn embeds tunn's HTTP publisher in a Go application. It uses the
// same registration, authorization and HTTP/WebSocket transport as the CLI.
// See docs/go-sdk.md for lifecycle and unsupported features.
package tunn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/common"
)

// Credentials are supplied by the caller. The SDK never reads or writes an
// account cache and never launches a login flow. Empty values follow the
// relay's publisher authentication configuration; they do not bypass it.
type Credentials struct {
	AuthToken     string // tunn login JWT or self-hosted client secret/per-user token
	TunnelKey     string // relay's tunnel creation key
	EndpointToken string // optional existing endpoint bearer token; only its digest is sent
}

func (Credentials) String() string     { return "tunn.Credentials{[redacted]}" }
func (c Credentials) GoString() string { return c.String() }

// ReconnectPolicy bounds consecutive retry attempts. A nil policy uses five
// retries, with equal jitter from 0.5–1s initially and a maximum delay of 30s.
// MaxAttempts=0 disables retries. Backoff resets after a connection lasts 30s.
type ReconnectPolicy struct {
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration
}

// WebSocketOptions controls the existing WebSocket transport. Nil selects
// 5-minute idle expiry, 30-second keepalive and an 8 MiB message limit.
type WebSocketOptions struct {
	IdleTimeout       time.Duration
	KeepaliveInterval time.Duration
	MaxMessageSize    int64
}

// Options specifies one HTTP publisher. Values and TLS configs are copied at
// startup; do not mutate a TLS config concurrently with Publish.
type Options struct {
	Origin              string // http(s)://host[:port], without credentials, path or query
	Name                string // blank generates a name once, retained through reconnects
	ServerAddr          string // host:port; blank uses tunn.to:443
	Credentials         Credentials
	Public              bool          // Explicit anonymous HTTP exposure; defaults to owner-only.
	AllowedEmails       []string      // existing relay allow-list semantics, including @domain
	TLSConfig           *tls.Config   // relay TLS; nil uses verified system trust
	OriginTLSConfig     *tls.Config   // HTTPS origin TLS; nil uses verified system trust
	ConnectTimeout      time.Duration // connection and registration deadline; default 10s
	HTTPTimeout         time.Duration // default 30s: buffered request deadline / streaming response-header deadline
	Reconnect           *ReconnectPolicy
	WebSocket           *WebSocketOptions
	RequireUpstreamAuth bool         // keep application Authorization separate from tunn auth
	Logger              *slog.Logger // nil discards SDK logs; only static messages are logged
}

type State string

const (
	Connecting   State = "connecting"
	Ready        State = "ready"
	Reconnecting State = "reconnecting"
	Failed       State = "failed"
	Closed       State = "closed"
)

// Event contains public lifecycle data only. Closed occurs exactly once, last,
// and includes the terminal result even when earlier events were evicted.
type Event struct {
	State      State
	URL        string
	Err        error
	RetryDelay time.Duration
}

type ErrorCode string

const (
	InvalidOptions       ErrorCode = "invalid_options"
	ConnectionFailed     ErrorCode = "connection_failed"
	RegistrationRejected ErrorCode = "registration_rejected"
	ProtocolViolation    ErrorCode = "protocol_violation"
)

// Error reports a stable category. Remote error strings and underlying
// transport errors are deliberately excluded because they can echo secrets.
type Error struct {
	Code    ErrorCode
	message string
}

func (e *Error) Error() string { return "tunn: " + e.message }

var errClosed = errors.New("SDK Close")

const eventCapacity = 16

// Tunnel owns one publisher's connection, forwarding workers and, when used,
// its handler transport. Use only values returned by Publish/PublishHandler.
// All methods are safe for concurrent use; Events is a single-consumer stream.
type Tunnel struct {
	name     string
	cancel   context.CancelCauseFunc
	done     chan struct{}
	ready    chan struct{}
	events   chan Event
	mu       sync.RWMutex
	status   Event
	url      string
	readyURL string
	err      error
}

// Publish starts asynchronously. Invalid options fail synchronously; use
// WaitReady or Events for connection/registration results. The caller's
// context governs the entire tunnel lifetime, including reconnects.
func Publish(ctx context.Context, options Options) (*Tunnel, error) {
	return publish(ctx, options, nil)
}

func publish(ctx context.Context, options Options, origin *handlerOrigin) (*Tunnel, error) {
	core, name, err := publisher(options)
	if err != nil {
		return nil, err
	}
	return startTunnel(ctx, options, core, name, origin)
}

func startTunnel(ctx context.Context, options Options, core *client.ServeClient, name string, origin *handlerOrigin) (*Tunnel, error) {
	if ctx == nil {
		return nil, invalid("a context is required")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancelCause(ctx)
	t := &Tunnel{name: name, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{}), events: make(chan Event, eventCapacity)}
	core.OnLifecycle = func(event client.LifecycleEvent) {
		t.emit(Event{State: State(event.State), URL: event.PublicURL, Err: publicError(event.Err), RetryDelay: event.RetryDelay})
	}
	core.ValidatePublicURL = func(value string) error {
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil ||
			u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") ||
			!strings.HasPrefix(u.Hostname(), name+".") {
			return errors.New("invalid registration URL or tunnel identity")
		}
		for _, secret := range []string{options.Credentials.AuthToken, options.Credentials.TunnelKey, options.Credentials.EndpointToken} {
			if secret != "" && strings.Contains(value, secret) {
				return errors.New("registration URL contains private credentials")
			}
		}
		t.mu.RLock()
		previous := t.url
		t.mu.RUnlock()
		if previous != "" && previous != value {
			return errors.New("registration URL changed on reconnect")
		}
		return nil
	}
	if origin != nil {
		core.LocalDialContext = origin.dial
		origin.start(ctx)
	}
	go func() {
		err := core.Run(ctx)
		if origin != nil {
			origin.close()
		}
		// Core.Run returns the lifetime context error directly on cancellation.
		// A completed protocol/registration failure remains the result even if
		// Close races with this cleanup. Never replace it with a later cancel.
		if err == context.Canceled || err == context.DeadlineExceeded {
			if errors.Is(context.Cause(ctx), errClosed) {
				err = nil
			}
		} else {
			err = publicError(err)
		}
		cancel(errClosed)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.emit(Event{State: Failed, Err: err})
		}
		t.mu.Lock()
		t.err = err
		t.mu.Unlock()
		t.emit(Event{State: Closed, Err: err})
		close(t.events)
		close(t.done)
	}()
	return t, nil
}

// Name returns the requested/generated identity, stable across reconnects.
func (t *Tunnel) Name() string { return t.name }

// Events is bounded to 16 entries. A slow reader loses the oldest intermediate
// events. Delivery never blocks the publisher; the final Closed event is kept.
// WaitReady and Wait retain results independently of event consumption.
func (t *Tunnel) Events() <-chan Event { return t.events }

// Done closes after the final event and all SDK-owned forwarding resources stop.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Status returns the most recently emitted event, without consuming Events.
func (t *Tunnel) Status() Event { t.mu.RLock(); defer t.mu.RUnlock(); return t.status }

// URL returns the last confirmed public URL; use Status to check connectivity.
func (t *Tunnel) URL() string { t.mu.RLock(); defer t.mu.RUnlock(); return t.url }

// WaitReady waits for the first registration. Its context bounds only this
// wait; cancel the context passed to Publish to stop the publisher.
func (t *Tunnel) WaitReady(ctx context.Context) (string, error) {
	select {
	case <-t.ready:
		t.mu.RLock()
		defer t.mu.RUnlock()
		return t.readyURL, nil
	case <-t.done:
		t.mu.RLock()
		firstURL := t.readyURL
		t.mu.RUnlock()
		if firstURL != "" {
			return firstURL, nil
		}
		if err := t.Wait(); err != nil {
			return "", err
		}
		return "", context.Canceled
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Wait returns the same terminal result to every caller. Explicit Close is
// successful (nil); caller cancellation/deadline returns the context error.
func (t *Tunnel) Wait() error { <-t.done; t.mu.RLock(); defer t.mu.RUnlock(); return t.err }

// Close cancels and joins this tunnel's resources. Repeated/concurrent calls
// are safe. It never closes a caller's origin server or cancels its context.
func (t *Tunnel) Close() error { t.cancel(errClosed); return t.Wait() }

func (t *Tunnel) emit(event Event) {
	t.mu.Lock()
	t.status = event
	if event.State == Ready {
		t.url = event.URL
		if t.readyURL == "" {
			t.readyURL = event.URL
			close(t.ready)
		}
	}
	t.mu.Unlock()
	select {
	case t.events <- event:
	default:
		select {
		case <-t.events:
		default:
		}
		t.events <- event // one producer; the eviction guarantees capacity
	}
}

func publisher(o Options) (*client.ServeClient, string, error) {
	if o.Public && (len(o.AllowedEmails) > 0 || o.Credentials.EndpointToken != "") {
		return nil, "", invalid("public exposure cannot be combined with private access credentials")
	}
	u, err := url.Parse(o.Origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, "", invalid("origin must be an HTTP(S) origin without credentials, path, query or fragment")
	}
	if o.ServerAddr == "" {
		o.ServerAddr = "tunn.to:443"
	}
	host, port, err := net.SplitHostPort(o.ServerAddr)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || host == "" || portErr != nil || portNumber < 1 || portNumber > 65535 || strings.ContainsAny(host, "/@?# \t\r\n") {
		return nil, "", invalid("server address must be host:port")
	}
	if o.Name == "" {
		var random [6]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", invalid("could not generate tunnel identity")
		}
		o.Name = hex.EncodeToString(random[:])
	}
	if !validName(o.Name) {
		return nil, "", invalid("name must be 1–63 lowercase letters, digits or interior hyphens")
	}
	if o.ConnectTimeout < 0 || o.HTTPTimeout < 0 {
		return nil, "", invalid("timeouts must be positive or zero for defaults")
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = 10 * time.Second
	}
	if o.HTTPTimeout == 0 {
		o.HTTPTimeout = 30 * time.Second
	}
	retry := ReconnectPolicy{MaxAttempts: 5, InitialDelay: time.Second, MaxDelay: 30 * time.Second}
	if o.Reconnect != nil {
		retry = *o.Reconnect
		if retry.MaxAttempts < 0 || retry.InitialDelay < 0 || retry.MaxDelay < 0 {
			return nil, "", invalid("reconnect values must be nonnegative")
		}
		if retry.InitialDelay == 0 {
			retry.InitialDelay = time.Second
		}
		if retry.MaxDelay == 0 {
			retry.MaxDelay = 30 * time.Second
		}
		if retry.InitialDelay > retry.MaxDelay {
			return nil, "", invalid("initial reconnect delay exceeds maximum")
		}
	}
	ws := common.DefaultWebSocketOptions()
	if o.WebSocket != nil {
		ws = common.WebSocketOptions{IdleTimeout: o.WebSocket.IdleTimeout, KeepaliveInterval: o.WebSocket.KeepaliveInterval, MaxMessageSize: o.WebSocket.MaxMessageSize}
	}
	if ws.Validate() != nil {
		return nil, "", invalid("invalid WebSocket limits")
	}
	logger := o.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	var digest []byte
	if o.Credentials.EndpointToken != "" {
		if !strings.HasPrefix(o.Credentials.EndpointToken, "tunn_ep_") {
			return nil, "", invalid("endpoint token must use the tunn_ep_ format")
		}
		hash := sha256.Sum256([]byte(o.Credentials.EndpointToken))
		digest = hash[:]
	}
	return &client.ServeClient{
		Public: o.Public, RequireSharing: o.Public || len(o.AllowedEmails) == 0 && len(digest) == 0,
		TunnelID: o.Name, TargetURL: strings.TrimSuffix(o.Origin, "/"), ServerAddr: o.ServerAddr,
		AuthToken: o.Credentials.AuthToken, TunnelKey: o.Credentials.TunnelKey, AccessTokenSHA256: digest,
		AllowedEmails: append([]string(nil), o.AllowedEmails...), RelayTLSConfig: cloneTLS(o.TLSConfig), LocalTLSConfig: cloneTLS(o.OriginTLSConfig),
		ConnectTimeout: o.ConnectTimeout, HTTPTimeout: o.HTTPTimeout, InitialDelay: retry.InitialDelay, MaxReconnectDelay: retry.MaxDelay, ReconnectLimit: &retry.MaxAttempts,
		WebSocket: &ws, RequireUpstreamAuth: o.RequireUpstreamAuth, Quiet: true, Persistent: true, Logger: logger, SafeLogs: true,
	}, o.Name, nil
}

func validName(name string) bool {
	if len(name) < 1 || len(name) > 63 {
		return false
	}
	for i, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && (c != '-' || i <= 0 || i >= len(name)-1) {
			return false
		}
	}
	return true
}

func cloneTLS(config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}
	copy := config.Clone()
	if copy.RootCAs != nil {
		copy.RootCAs = copy.RootCAs.Clone()
	}
	return copy
}

func invalid(message string) error { return &Error{Code: InvalidOptions, message: message} }

func publicError(err error) error {
	if err == nil {
		return nil
	}
	switch client.ClassifyFailure(err) {
	case client.FailureRegistration:
		return &Error{Code: RegistrationRejected, message: "registration rejected by relay"}
	case client.FailureProtocol:
		return &Error{Code: ProtocolViolation, message: "relay violated the publisher protocol"}
	default:
		return &Error{Code: ConnectionFailed, message: "relay connection failed"}
	}
}
