package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/domains"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
)

const domainUsage = `Usage:
  tunn domain add <domain> --tunnel <reserved-name>
  tunn domain verify <domain>
  tunn domain list
  tunn domain delete <domain>
Owner options: --server, --owner-token-file, --insecure
Add requires Pro and returns a unique cname_target. Set your DNS CNAME to
that exact target, then run verify to provision HTTPS. Publish the reserved
name with tunn serve --name <reserved-name> <target>. List shows DNS and
certificate state. Delete removes the domain; the tunnel name stays reserved.
`

type domainOptions struct {
	action, name, tunnel, server, ownerFile string
	insecure                                bool
}

func parseDomainOptions(args []string) (*domainOptions, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("domain action required")
	}
	if args[0] == "--help" || args[0] == "-h" {
		return nil, flag.ErrHelp
	}
	o := &domainOptions{action: args[0]}
	if o.action != "add" && o.action != "verify" && o.action != "list" && o.action != "delete" {
		return nil, fmt.Errorf("unknown domain action")
	}
	fs := flag.NewFlagSet("domain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.server, "server", "", "relay HTTPS origin")
	fs.StringVar(&o.ownerFile, "owner-token-file", "", "owner JWT file")
	fs.BoolVar(&o.insecure, "insecure", false, "skip TLS verification")
	if o.action == "add" {
		fs.StringVar(&o.tunnel, "tunnel", "", "reserved tunnel name")
	}
	var flags, names []string
	args = args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			names = append(names, arg)
			continue
		}
		flags = append(flags, arg)
		if !strings.Contains(arg, "=") && arg != "--insecure" && arg != "-insecure" && arg != "--help" && arg != "-h" {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing value for %s", arg)
			}
			i++
			flags = append(flags, args[i])
		}
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	want := 1
	if o.action == "list" {
		want = 0
	}
	if len(names) != want {
		return nil, fmt.Errorf("unexpected domain arguments")
	}
	if want == 1 {
		var err error
		o.name, err = domains.NormalizeName(names[0], "")
		if err != nil {
			return nil, err
		}
	}
	if o.action == "add" && (!domains.ValidLabel(o.tunnel) || !validCLIEndpoint(o.tunnel)) {
		return nil, fmt.Errorf("valid --tunnel name required")
	}
	return o, nil
}
func runDomains(args []string) {
	if err := executeDomains(args, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(os.Stdout, domainUsage)
			return
		}
		_, _ = fmt.Fprintln(os.Stderr, err)
		_, _ = fmt.Fprint(os.Stderr, domainUsage)
		os.Exit(1)
	}
}
func executeDomains(args []string, out io.Writer) error {
	o, err := parseDomainOptions(args)
	if err != nil {
		return err
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if o.server == "" {
		o.server = cfg.ServerAddr
	}
	var token string
	if o.ownerFile != "" {
		data, err := os.ReadFile(o.ownerFile)
		if err != nil {
			return err
		}
		token = string(data)
	} else {
		token, err = client.LoadToken()
		if err != nil {
			return err
		}
	}
	transport := relaytransport.Transport(o.insecure || *insecure)
	defer transport.CloseIdleConnections()
	c := &client.ManagementClient{ServerURL: o.server, OwnerToken: token, HTTPClient: &http.Client{Transport: transport, Timeout: 190 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 190*time.Second)
	defer cancel()
	var data []byte
	switch o.action {
	case "add":
		data, err = c.DomainCall(ctx, "POST", "", "", struct {
			Name   string `json:"name"`
			Tunnel string `json:"tunnel"`
		}{o.name, o.tunnel})
	case "verify":
		data, err = c.DomainCall(ctx, "POST", o.name, "verify", nil)
	case "list":
		data, err = c.DomainCall(ctx, "GET", "", "", nil)
	case "delete":
		_, err = c.DomainCall(ctx, "DELETE", o.name, "", nil)
		if err == nil {
			_, err = fmt.Fprintln(out, "Domain deleted; tunnel name remains reserved")
		}
		return err
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}
