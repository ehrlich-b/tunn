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
	"github.com/ehrlich-b/tunn/internal/ippolicy"
	"github.com/ehrlich-b/tunn/internal/relaytransport"
)

const ipPolicyUsage = `tunn ip-policy <get|set|clear> [endpoint | --account] [options]
  --allow CIDR,...        IPv4/IPv6 allow list (set only)
  --deny CIDR,...         IPv4/IPv6 deny list (set only; deny takes priority)
  --server HTTPS_ORIGIN  Relay origin
  --owner-token-file PATH  Owner JWT file (publisher device tokens cannot manage policies)
Set replaces both lists. Empty lists permit every IP. Clear restores inheritance
for an endpoint or removes the account default. Policies apply to new requests.
`

type ipPolicyOptions struct {
	action, endpoint, server, ownerFile string
	account                             bool
	allow, deny                         []string
}

func parseIPPolicy(args []string) (*ipPolicyOptions, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("IP policy action required")
	}
	if args[0] == "--help" || args[0] == "-h" {
		return nil, flag.ErrHelp
	}
	o := &ipPolicyOptions{action: args[0]}
	if o.action != "get" && o.action != "set" && o.action != "clear" {
		return nil, fmt.Errorf("use get, set or clear")
	}
	fs := flag.NewFlagSet("ip-policy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var allow, deny string
	fs.BoolVar(&o.account, "account", false, "account default")
	fs.StringVar(&o.server, "server", "", "relay origin")
	fs.StringVar(&o.ownerFile, "owner-token-file", "", "owner JWT file")
	fs.StringVar(&allow, "allow", "", "comma separated allowed CIDRs")
	fs.StringVar(&deny, "deny", "", "comma separated denied CIDRs")
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		o.endpoint = rest[0]
		rest = rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return nil, err
	}
	if fs.NArg() > 1 || fs.NArg() == 1 && o.endpoint != "" {
		return nil, fmt.Errorf("choose one endpoint")
	}
	if fs.NArg() == 1 {
		o.endpoint = fs.Arg(0)
	}
	if o.account && o.endpoint != "" || !o.account && !validCLIEndpoint(o.endpoint) {
		return nil, fmt.Errorf("choose an endpoint or --account")
	}
	rulesSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "allow" || f.Name == "deny" {
			rulesSet = true
		}
	})
	if o.action != "set" && rulesSet {
		return nil, fmt.Errorf("--allow and --deny require set")
	}
	var err error
	if allow != "" {
		o.allow, err = ippolicy.Normalize(strings.Split(allow, ","))
		if err != nil {
			return nil, err
		}
	}
	if deny != "" {
		o.deny, err = ippolicy.Normalize(strings.Split(deny, ","))
		if err != nil {
			return nil, err
		}
	}
	return o, nil
}

func executeIPPolicy(args []string, out io.Writer) error {
	o, err := parseIPPolicy(args)
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
	transport := relaytransport.Transport(*insecure)
	defer transport.CloseIdleConnections()
	c := &client.ManagementClient{ServerURL: o.server, OwnerToken: token, HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data, err := c.IPPolicy(ctx, o.action, o.endpoint, o.allow, o.deny)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}
func runIPPolicy(args []string) {
	if err := executeIPPolicy(args, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(os.Stdout, ipPolicyUsage)
			return
		}
		_, _ = fmt.Fprintln(os.Stderr, err)
		_, _ = fmt.Fprint(os.Stderr, ipPolicyUsage)
		os.Exit(1)
	}
}
