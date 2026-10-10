package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/client"
	"github.com/ehrlich-b/tunn/internal/config"
	pb "github.com/ehrlich-b/tunn/pkg/proto/meteringv1"
)

type meteringOptions struct {
	action, endpoint, grantID, server, ownerFile, month, consumer, since string
	expires                                                              time.Time
	rate, requests, bytes                                                int64
	insecure                                                             bool
}

const meteringUsage = `Usage:
  tunn usage [--tunnel NAME] [--since DURATION]
  tunn grant create <endpoint> [--for email] [--expires 1h]
       [--rate requests-per-minute] [--monthly-requests N] [--monthly-bytes N]
  tunn grant revoke <endpoint> <grant-id>
  tunn grant list [<endpoint>]
Owner API options: --server, --owner-token-file, --insecure
Usage defaults to the current UTC month across all of the owner's tunnels.
The positional usage endpoint and --month YYYY-MM remain supported.
Zero budgets mean unlimited. Create prints JSON containing the grant and its
one-time consumer token; only the token's SHA-256 digest reaches the relay.
`

func parseMeteringOptions(command string, args []string, now time.Time) (*meteringOptions, error) {
	o := &meteringOptions{action: command}
	if command == "grant" {
		if len(args) == 0 {
			return nil, fmt.Errorf("grant action required")
		}
		if args[0] == "--help" || args[0] == "-h" {
			return nil, flag.ErrHelp
		}
		o.action = args[0]
		args = args[1:]
		if o.action != "create" && o.action != "list" && o.action != "revoke" {
			return nil, fmt.Errorf("grant action must be create, list or revoke")
		}
	} else if command != "usage" {
		return nil, fmt.Errorf("unknown metering command")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.server, "server", "", "relay host:port or HTTPS origin")
	fs.StringVar(&o.ownerFile, "owner-token-file", "", "owner JWT file (default: tunn login credential)")
	fs.BoolVar(&o.insecure, "insecure", false, "skip TLS certificate verification")
	expiry := "24h"
	switch o.action {
	case "create":
		fs.StringVar(&o.consumer, "for", "", "consumer label, not an email authorization policy")
		fs.StringVar(&expiry, "expires", "24h", "duration or RFC3339 timestamp (maximum one year)")
		fs.Int64Var(&o.rate, "rate", 0, "requests per fixed UTC minute")
		fs.Int64Var(&o.requests, "monthly-requests", 0, "monthly admitted request budget")
		fs.Int64Var(&o.bytes, "monthly-bytes", 0, "monthly request + response body byte budget")
	case "usage":
		fs.StringVar(&o.endpoint, "tunnel", "", "filter by tunnel name")
		fs.StringVar(&o.since, "since", "", "usage since a positive duration ago (for example 24h)")
		fs.StringVar(&o.month, "month", "", "UTC admission month")
	}
	// Permit flags before or after endpoint names, with both --flag=value and
	// --flag value. Values starting with '-' still belong to their flag.
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positionals = append(positionals, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(strings.SplitN(a, "=", 2)[0], "-")
		f := fs.Lookup(name)
		if !strings.Contains(a, "=") && f != nil {
			isBool := false
			if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
				isBool = b.IsBoolFlag()
			}
			if !isBool {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("missing value for %s", a)
				}
				i++
				flags = append(flags, args[i])
			}
		}
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	var sinceSet, monthSet, tunnelSet bool
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "since":
			sinceSet = true
		case "month":
			monthSet = true
		case "tunnel":
			tunnelSet = true
		}
	})
	if tunnelSet && o.endpoint == "" {
		return nil, fmt.Errorf("invalid endpoint name")
	}
	want := 1
	if o.action == "revoke" {
		want = 2
	}
	optional := o.action == "usage" || o.action == "list"
	if len(positionals) != want && (!optional || len(positionals) != 0) {
		return nil, fmt.Errorf("endpoint%s required", map[bool]string{true: " and grant ID", false: ""}[want == 2])
	}
	if len(positionals) > 0 {
		if o.endpoint != "" {
			return nil, fmt.Errorf("use either --tunnel or a positional endpoint")
		}
		o.endpoint = positionals[0]
	}
	if (!optional || o.endpoint != "") && !validCLIEndpoint(o.endpoint) {
		return nil, fmt.Errorf("invalid endpoint name")
	}
	if want == 2 {
		o.grantID = positionals[1]
		if strings.ContainsAny(o.grantID, "/?#") || len(o.grantID) > 64 {
			return nil, fmt.Errorf("invalid grant ID")
		}
	}
	if o.action == "create" {
		if d, err := time.ParseDuration(expiry); err == nil {
			o.expires = now.Add(d)
		} else {
			var err error
			o.expires, err = time.Parse(time.RFC3339, expiry)
			if err != nil {
				return nil, fmt.Errorf("expires must be a duration or RFC3339 timestamp")
			}
		}
		if !o.expires.After(now) || o.expires.After(now.Add(365*24*time.Hour)) || o.rate < 0 || o.requests < 0 || o.bytes < 0 {
			return nil, fmt.Errorf("require expiry within one year and nonnegative budgets")
		}
	}
	if o.action == "usage" {
		if sinceSet {
			duration, err := time.ParseDuration(o.since)
			if err != nil || duration < time.Millisecond || now.Add(-duration).UnixMilli() <= 0 || monthSet {
				return nil, fmt.Errorf("since must be a positive duration and cannot be combined with month")
			}
		} else if o.month == "" {
			o.month = now.UTC().Format("2006-01")
		}
		if o.month != "" || monthSet {
			if m, err := time.Parse("2006-01", o.month); err != nil || m.Format("2006-01") != o.month {
				return nil, fmt.Errorf("month must be YYYY-MM")
			}
		}
	}
	return o, nil
}
func validCLIEndpoint(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func runMetering(command string, args []string) {
	if err := executeMetering(command, args, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(os.Stdout, meteringUsage)
			return
		}
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprint(os.Stderr, meteringUsage)
		os.Exit(1)
	}
}
func executeMetering(command string, args []string, out io.Writer) error {
	o, err := parseMeteringOptions(command, args, time.Now())
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
	var ownerToken string
	if o.ownerFile != "" {
		data, err := os.ReadFile(o.ownerFile)
		if err != nil {
			return err
		}
		ownerToken = string(data)
	} else {
		ownerToken, err = client.LoadToken()
		if err != nil {
			return err
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: o.insecure || *insecure}
	defer transport.CloseIdleConnections()
	c := &client.ManagementClient{ServerURL: o.server, OwnerToken: ownerToken, HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch o.action {
	case "usage":
		query := "month=" + url.QueryEscape(o.month)
		if o.since != "" {
			query = "since=" + url.QueryEscape(o.since)
		}
		data, err := c.Call(ctx, "GET", o.endpoint, "usage?"+query, nil)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	case "list":
		data, err := c.Call(ctx, "GET", o.endpoint, "grants", nil)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	case "revoke":
		_, err := c.Call(ctx, "DELETE", o.endpoint, "grants/"+o.grantID, nil)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, "Grant revoked")
		return err
	case "create":
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		token := "tunn_gr_" + base64.RawURLEncoding.EncodeToString(random)
		digest := sha256.Sum256([]byte(token))
		data, err := c.Call(ctx, "POST", o.endpoint, "grants", &pb.Grant{Consumer: o.consumer, TokenSha256: digest[:], ExpiresAt: o.expires.UnixMilli(), RequestsPerMinute: o.rate, MonthlyRequests: o.requests, MonthlyBytes: o.bytes})
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(struct {
			Grant json.RawMessage `json:"grant"`
			Token string          `json:"token"`
		}{data, token})
	}
	return fmt.Errorf("unsupported metering action")
}
