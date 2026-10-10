package cliopts

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

type Metering struct {
	Action, Endpoint, GrantID, Server, OwnerFile, Month, Consumer, Since string
	Expires                                                              time.Time
	Rate, Requests, Bytes                                                int64
	Insecure                                                             bool
}

const MeteringUsage = `Usage:
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

func ParseMetering(command string, args []string, now time.Time) (*Metering, error) {
	o := &Metering{Action: command}
	if command == "grant" {
		if len(args) == 0 {
			return nil, fmt.Errorf("grant action required")
		}
		if args[0] == "--help" || args[0] == "-h" {
			return nil, flag.ErrHelp
		}
		o.Action = args[0]
		args = args[1:]
		if o.Action != "create" && o.Action != "list" && o.Action != "revoke" {
			return nil, fmt.Errorf("grant action must be create, list or revoke")
		}
	} else if command != "usage" {
		return nil, fmt.Errorf("unknown metering command")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.Server, "server", "", "relay host:port or HTTPS origin")
	fs.StringVar(&o.OwnerFile, "owner-token-file", "", "owner JWT file (default: tunn login credential)")
	fs.BoolVar(&o.Insecure, "insecure", false, "skip TLS certificate verification")
	expiry := "24h"
	switch o.Action {
	case "create":
		fs.StringVar(&o.Consumer, "for", "", "consumer label, not an email authorization policy")
		fs.StringVar(&expiry, "expires", "24h", "duration or RFC3339 timestamp (maximum one year)")
		fs.Int64Var(&o.Rate, "rate", 0, "requests per fixed UTC minute")
		fs.Int64Var(&o.Requests, "monthly-requests", 0, "monthly admitted request budget")
		fs.Int64Var(&o.Bytes, "monthly-bytes", 0, "monthly request + response body byte budget")
	case "usage":
		fs.StringVar(&o.Endpoint, "tunnel", "", "filter by tunnel name")
		fs.StringVar(&o.Since, "since", "", "usage since a positive duration ago (for example 24h)")
		fs.StringVar(&o.Month, "month", "", "UTC admission month")
	}
	// Permit flags before or after Endpoint names, with both --flag=value and
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
	if tunnelSet && o.Endpoint == "" {
		return nil, fmt.Errorf("invalid endpoint name")
	}
	want := 1
	if o.Action == "revoke" {
		want = 2
	}
	optional := o.Action == "usage" || o.Action == "list"
	if len(positionals) != want && (!optional || len(positionals) != 0) {
		return nil, fmt.Errorf("endpoint%s required", map[bool]string{true: " and grant ID", false: ""}[want == 2])
	}
	if len(positionals) > 0 {
		if o.Endpoint != "" {
			return nil, fmt.Errorf("use either --tunnel or a positional endpoint")
		}
		o.Endpoint = positionals[0]
	}
	if (!optional || o.Endpoint != "") && !ValidEndpoint(o.Endpoint) {
		return nil, fmt.Errorf("invalid endpoint name")
	}
	if want == 2 {
		o.GrantID = positionals[1]
		if strings.ContainsAny(o.GrantID, "/?#") || len(o.GrantID) > 64 {
			return nil, fmt.Errorf("invalid grant ID")
		}
	}
	if o.Action == "create" {
		if d, err := time.ParseDuration(expiry); err == nil {
			o.Expires = now.Add(d)
		} else {
			var err error
			o.Expires, err = time.Parse(time.RFC3339, expiry)
			if err != nil {
				return nil, fmt.Errorf("expires must be a duration or RFC3339 timestamp")
			}
		}
		if !o.Expires.After(now) || o.Expires.After(now.Add(365*24*time.Hour)) || o.Rate < 0 || o.Requests < 0 || o.Bytes < 0 {
			return nil, fmt.Errorf("require expiry within one year and nonnegative budgets")
		}
	}
	if o.Action == "usage" {
		if sinceSet {
			duration, err := time.ParseDuration(o.Since)
			if err != nil || duration < time.Millisecond || now.Add(-duration).UnixMilli() <= 0 || monthSet {
				return nil, fmt.Errorf("since must be a positive duration and cannot be combined with month")
			}
		} else if o.Month == "" {
			o.Month = now.UTC().Format("2006-01")
		}
		if o.Month != "" || monthSet {
			if m, err := time.Parse("2006-01", o.Month); err != nil || m.Format("2006-01") != o.Month {
				return nil, fmt.Errorf("month must be YYYY-MM")
			}
		}
	}
	return o, nil
}
func ValidEndpoint(s string) bool {
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
