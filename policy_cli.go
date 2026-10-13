package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/cliopts"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
	"github.com/ehrlich-b/tunn/internal/trafficpolicy"
)

const policyUsage = `Usage:
  tunn policy login               Browser sign-in for account management (24 hours)
  tunn policy get <name>
  tunn policy set <name> --file policy.json
  tunn policy clear <name>
Options: --server HTTPS_ORIGIN --owner-token-file PATH --insecure
Policies apply to an existing account-owned HTTP endpoint. See docs/traffic-policy.md.
`

type policyOptions struct {
	action, endpoint, file, server, ownerFile string
	insecure                                  bool
}

func parsePolicyOptions(args []string) (*policyOptions, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("policy action required")
	}
	if args[0] == "--help" || args[0] == "-h" {
		return nil, flag.ErrHelp
	}
	o := &policyOptions{action: args[0]}
	if o.action != "get" && o.action != "set" && o.action != "clear" && o.action != "login" {
		return nil, fmt.Errorf("use policy login, get, set or clear")
	}
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.file, "file", "", "policy JSON file")
	fs.StringVar(&o.server, "server", "", "relay HTTPS origin")
	fs.StringVar(&o.ownerFile, "owner-token-file", "", "owner JWT file")
	fs.BoolVar(&o.insecure, "insecure", false, "skip relay TLS verification")
	targets, err := cliopts.ParseInterspersed(fs, args[1:])
	if err != nil {
		return nil, err
	}
	if o.action == "login" {
		if len(targets) != 0 || o.file != "" || o.ownerFile != "" {
			return nil, fmt.Errorf("policy login accepts --server and --insecure, without an endpoint or credential file")
		}
		return o, nil
	}
	if len(targets) != 1 || !cliopts.ValidEndpoint(targets[0]) {
		return nil, fmt.Errorf("provide one endpoint name")
	}
	o.endpoint = targets[0]
	if o.action == "set" && o.file == "" || o.action != "set" && o.file != "" {
		return nil, fmt.Errorf("--file is required only for policy set")
	}
	return o, nil
}

func runPolicy(args []string) {
	if err := executePolicy(args, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(os.Stdout, policyUsage)
			return
		}
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprint(os.Stderr, policyUsage)
		os.Exit(1)
	}
}

func executePolicy(args []string, out io.Writer) error {
	o, err := parsePolicyOptions(args)
	if err != nil {
		return err
	}
	var policy *trafficpolicy.Policy
	if o.action == "set" {
		f, err := os.Open(o.file)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, trafficpolicy.MaxJSONBytes+1))
		_ = f.Close()
		if readErr != nil {
			return readErr
		}
		policy, err = trafficpolicy.Decode(data)
		if err != nil {
			return err
		}
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if o.server == "" {
		o.server = cfg.ServerAddr
	}
	if o.action == "login" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		return client.LoginPolicyOwner(ctx, o.server, o.insecure || *insecure, out)
	}
	var owner string
	if o.ownerFile != "" {
		f, err := os.Open(o.ownerFile)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 16385))
		_ = f.Close()
		if readErr != nil {
			return readErr
		}
		if len(data) > 16384 {
			return fmt.Errorf("owner credential exceeds size limit")
		}
		owner = string(data)
	} else {
		owner, err = client.LoadPolicyOwnerToken(o.server)
		if err != nil {
			return err
		}
	}
	transport := relaytransport.Transport(o.insecure || *insecure)
	defer transport.CloseIdleConnections()
	c := &client.ManagementClient{ServerURL: o.server, OwnerToken: owner, HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return client.ExecutePolicy(ctx, o.action, o.endpoint, policy, c, out)
}
