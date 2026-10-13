// Command tunn-python-bridge owns one Go SDK publisher for the Python binding.
// Its versioned stdin/stdout protocol is private to this repository revision.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	tunn "github.com/ehrlich-b/tunn/sdk"
)

type tlsOptions struct {
	RootCAPEM  string `json:"root_ca_pem"`
	ServerName string `json:"server_name"`
}
type retryOptions struct {
	MaxAttempts  int     `json:"max_attempts"`
	InitialDelay float64 `json:"initial_delay"`
	MaxDelay     float64 `json:"max_delay"`
}
type wsOptions struct {
	IdleTimeout       float64 `json:"idle_timeout"`
	KeepaliveInterval float64 `json:"keepalive_interval"`
	MaxMessageSize    int64   `json:"max_message_size"`
}
type options struct {
	Origin      string `json:"origin"`
	Name        string `json:"name"`
	ServerAddr  string `json:"server_addr"`
	Credentials struct {
		AuthToken     string `json:"auth_token"`
		TunnelKey     string `json:"tunnel_key"`
		EndpointToken string `json:"endpoint_token"`
	} `json:"credentials"`
	Public              bool          `json:"public"`
	AllowedEmails       []string      `json:"allowed_emails"`
	RelayTLS            *tlsOptions   `json:"relay_tls"`
	OriginTLS           *tlsOptions   `json:"origin_tls"`
	ConnectTimeout      float64       `json:"connect_timeout"`
	HTTPTimeout         float64       `json:"http_timeout"`
	Reconnect           *retryOptions `json:"reconnect"`
	WebSocket           *wsOptions    `json:"websocket"`
	RequireUpstreamAuth bool          `json:"require_upstream_auth"`
}
type command struct {
	Op      string  `json:"op"`
	Version int     `json:"version"`
	Options options `json:"options"`
}
type event struct {
	Kind       string  `json:"kind"`
	Version    int     `json:"version,omitempty"`
	Name       string  `json:"name,omitempty"`
	State      string  `json:"state,omitempty"`
	URL        string  `json:"url,omitempty"`
	Code       string  `json:"code,omitempty"`
	RetryDelay float64 `json:"retry_delay,omitempty"`
}

func publicCode(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	var e *tunn.Error
	if errors.As(err, &e) {
		return string(e.Code)
	}
	return "connection_failed"
}
func tlsConfig(o *tlsOptions) (*tls.Config, error) {
	if o == nil {
		return nil, nil
	}
	c := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.ServerName}
	if o.RootCAPEM != "" {
		c.RootCAs = x509.NewCertPool()
		if !c.RootCAs.AppendCertsFromPEM([]byte(o.RootCAPEM)) {
			return nil, errors.New("invalid CA certificate")
		}
	}
	return c, nil
}
func convert(o options) (tunn.Options, error) {
	relayTLS, err := tlsConfig(o.RelayTLS)
	if err != nil {
		return tunn.Options{}, err
	}
	originTLS, err := tlsConfig(o.OriginTLS)
	if err != nil {
		return tunn.Options{}, err
	}
	result := tunn.Options{Origin: o.Origin, Name: o.Name, ServerAddr: o.ServerAddr,
		Credentials: tunn.Credentials{AuthToken: o.Credentials.AuthToken, TunnelKey: o.Credentials.TunnelKey, EndpointToken: o.Credentials.EndpointToken},
		Public:      o.Public, AllowedEmails: o.AllowedEmails, TLSConfig: relayTLS, OriginTLSConfig: originTLS,
		ConnectTimeout: time.Duration(o.ConnectTimeout * float64(time.Second)), HTTPTimeout: time.Duration(o.HTTPTimeout * float64(time.Second)),
		RequireUpstreamAuth: o.RequireUpstreamAuth}
	if o.Reconnect != nil {
		result.Reconnect = &tunn.ReconnectPolicy{MaxAttempts: o.Reconnect.MaxAttempts,
			InitialDelay: time.Duration(o.Reconnect.InitialDelay * float64(time.Second)), MaxDelay: time.Duration(o.Reconnect.MaxDelay * float64(time.Second))}
	}
	if o.WebSocket != nil {
		result.WebSocket = &tunn.WebSocketOptions{IdleTimeout: time.Duration(o.WebSocket.IdleTimeout * float64(time.Second)),
			KeepaliveInterval: time.Duration(o.WebSocket.KeepaliveInterval * float64(time.Second)), MaxMessageSize: o.WebSocket.MaxMessageSize}
	}
	return result, nil
}
func run(in io.Reader, out io.Writer) {
	encoder := json.NewEncoder(out)
	send := func(e event) bool { return encoder.Encode(e) == nil }
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var first command
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &first) != nil || first.Op != "start" || first.Version != 1 {
		send(event{Kind: "error", Code: "invalid_options"})
		return
	}
	opts, err := convert(first.Options)
	if err != nil {
		send(event{Kind: "error", Code: "invalid_options"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tunnel, err := tunn.Publish(ctx, opts)
	if err != nil {
		send(event{Kind: "error", Code: publicCode(err)})
		return
	}
	defer tunnel.Close()
	if !send(event{Kind: "started", Version: 1, Name: tunnel.Name()}) {
		return
	}
	// EOF cancels the tunnel, including when the parent exits unexpectedly.
	go func() {
		for scanner.Scan() {
			var c command
			if json.Unmarshal(scanner.Bytes(), &c) != nil {
				cancel()
				return
			}
			switch c.Op {
			case "close":
				_ = tunnel.Close()
				return
			case "cancel":
				cancel()
				return
			default:
				cancel()
				return
			}
		}
		cancel()
	}()
	for e := range tunnel.Events() {
		if !send(event{Kind: "event", State: string(e.State), URL: e.URL, Code: publicCode(e.Err), RetryDelay: e.RetryDelay.Seconds()}) {
			return
		}
	}
}
func main() { run(os.Stdin, os.Stdout) }
