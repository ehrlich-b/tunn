// Package cliopts owns flag definitions shared by the CLI and SSH API.
package cliopts

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
)

type Serve struct {
	Target, Name, Namespace, TunnelKey, Secret                                        string
	AllowedEmails                                                                     []string
	SkipLocalTLSVerify, Inspect, InspectBody, Bearer, RequireUpstreamAuth, Public, QR bool
	Expire                                                                            time.Duration
	WebSocket                                                                         common.WebSocketOptions
	Stdio                                                                             bool
	Tools                                                                             []string
	Adapter                                                                           string
}

// PublicationFlags defines identity, naming and sharing options for every publisher.
func PublicationFlags(fs *flag.FlagSet, o *Serve) {
	fs.StringVar(&o.Name, "id", "", "tunnel ID (blank generates one)")
	fs.StringVar(&o.Name, "name", "", "endpoint name (alias for --id)")
	fs.StringVar(&o.Name, "subdomain", "", "reserved subdomain (alias for --id)")
	fs.Func("allow", "comma-separated email or @domain allow-list", func(s string) error {
		for _, email := range strings.Split(s, ",") {
			if email = strings.TrimSpace(email); email != "" {
				o.AllowedEmails = append(o.AllowedEmails, email)
			}
		}
		return nil
	})
	fs.Func("allow-domain", "comma-separated email domains allowed to log in", func(s string) error {
		for _, domain := range strings.Split(s, ",") {
			domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "@")
			if domain == "" || strings.ContainsAny(domain, " @/:\r\n") || !strings.Contains(domain, ".") {
				return fmt.Errorf("invalid email domain")
			}
			o.AllowedEmails = append(o.AllowedEmails, "@"+domain)
		}
		return nil
	})
	fs.StringVar(&o.TunnelKey, "tunnel-key", "", "tunnel creation authorization key")
	fs.StringVar(&o.Secret, "secret", "", "self-hosted authentication secret (or TUNN_SECRET)")
	fs.BoolVar(&o.Public, "public", false, "allow unauthenticated internet access")

}

// MCPToolFlag defines the tool policy in both transports.
func MCPToolFlag(fs *flag.FlagSet, tools *[]string) {
	fs.Func("tools", "comma-separated exact tool allow-list", func(s string) error {
		for _, t := range strings.Split(s, ",") {
			if t = strings.TrimSpace(t); t != "" {
				*tools = append(*tools, t)
			}
		}
		return nil
	})
}

func ServeFlags(fs *flag.FlagSet, o *Serve) {
	o.WebSocket = common.DefaultWebSocketOptions()
	PublicationFlags(fs, o)
	fs.StringVar(&o.Target, "target", "", "HTTP upstream URL (SSH dials it through -R)")
	fs.BoolVar(&o.SkipLocalTLSVerify, "skip-local-tls-verify", false, "skip local HTTPS certificate verification")
	fs.BoolVar(&o.Inspect, "inspect", false, "inspect request metadata")
	fs.BoolVar(&o.InspectBody, "inspect-body", false, "explicitly retain request bodies up to 64 KiB; requires --inspect")
	fs.BoolVar(&o.Bearer, "bearer", false, "enable private endpoint-token access")
	fs.BoolVar(&o.RequireUpstreamAuth, "require-upstream-auth", false, "require upstream Authorization after tunn authentication")
	fs.BoolVar(&o.QR, "qr", false, "print a QR code for the URL")
	fs.DurationVar(&o.Expire, "expire", 0, "close the tunnel after a duration")
	fs.DurationVar(&o.WebSocket.IdleTimeout, "ws-idle-timeout", o.WebSocket.IdleTimeout, "WebSocket inactivity timeout (0 disables)")
	fs.DurationVar(&o.WebSocket.KeepaliveInterval, "ws-keepalive", o.WebSocket.KeepaliveInterval, "WebSocket ping interval (0 disables)")
	fs.Int64Var(&o.WebSocket.MaxMessageSize, "ws-max-message-size", o.WebSocket.MaxMessageSize, "maximum WebSocket message bytes")
}

// ParseInterspersed accepts flags before or after operands without interpreting a shell.
func ParseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, targets []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			targets = append(targets, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			targets = append(targets, arg)
			continue
		}
		flags = append(flags, arg)
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		definition := fs.Lookup(name)
		if definition == nil || hasValue {
			continue
		}
		boolean, isBoolean := definition.Value.(interface{ IsBoolFlag() bool })
		if isBoolean && boolean.IsBoolFlag() {
			continue
		}
		if i+1 >= len(args) {
			return nil, fmt.Errorf("flag --%s requires a value", name)
		}
		i++
		flags = append(flags, args[i])
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return targets, nil
}

func ParseServe(args []string, requireTarget bool) (*Serve, error) {
	return parseServe(args, requireTarget, "serve")
}

func ParseSSHPublication(args []string, kind string) (*Serve, error) {
	return parseServe(args, false, kind)
}
func parseServe(args []string, requireTarget bool, kind string) (*Serve, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := new(Serve)
	ServeFlags(fs, o)
	if requireTarget {
		fs.StringVar(&o.Namespace, "namespace", "", "verified custom namespace (for example apps.example.com); requires --name")
	}
	if kind == "mcp" {
		fs.BoolVar(&o.Stdio, "stdio", false, "bridge JSON-RPC on SSH stdin/stdout")
		MCPToolFlag(fs, &o.Tools)
	}
	if kind == "unix" || kind == "tcp" {
		fs.StringVar(&o.Adapter, "as", "raw", "adapter: raw or http (Unix sockets)")
	}
	targets, err := ParseInterspersed(fs, args)
	if err != nil {
		return nil, err
	}
	if requireTarget && (len(targets) != 1 && (len(targets) != 0 || o.Target == "")) || !requireTarget && len(targets) > 0 || len(targets) > 0 && o.Target != "" {
		return nil, fmt.Errorf("provide one target for the CLI; SSH targets come from -R")
	}
	if len(targets) == 1 {
		o.Target = targets[0]
	}
	if o.Public && (len(o.AllowedEmails) > 0 || o.Bearer) {
		return nil, fmt.Errorf("--public cannot be combined with --allow, --allow-domain or --bearer")
	}
	if o.InspectBody && !o.Inspect {
		return nil, fmt.Errorf("--inspect-body requires --inspect")
	}
	if o.Expire < 0 {
		return nil, fmt.Errorf("--expire must be nonnegative")
	}
	if len(o.Tools) > 0 && !o.Stdio {
		return nil, fmt.Errorf("--tools applies only to stdio MCP")
	}
	if kind == "tcp" && o.Adapter != "raw" || kind == "unix" && o.Adapter != "raw" && o.Adapter != "http" {
		return nil, fmt.Errorf("invalid --as adapter")
	}
	if err := o.WebSocket.Validate(); err != nil {
		return nil, err
	}
	return o, nil
}

func Usage(w io.Writer) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(w)
	ServeFlags(fs, new(Serve))
	fs.PrintDefaults()
}
