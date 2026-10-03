package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ehrlich-b/tunn/internal/client"
)

func runMCPCheck(args []string) {
	if err := executeMCPCheck(context.Background(), args, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tunn mcp check:", err)
		os.Exit(1)
	}
}

func executeMCPCheck(ctx context.Context, args []string, out, diagnostics io.Writer) error {
	fs := flag.NewFlagSet("mcp check", flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	caFile := fs.String("ca-cert", "", "additional trusted CA certificate for a local or self-hosted fixture")
	issuer := fs.String("issuer", "", "authorize discovery at this exact separate HTTPS issuer origin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: tunn mcp check [--issuer HTTPS-origin] [--ca-cert certificate.pem] HTTPS-URL/mcp; put options before the URL")
	}
	options := client.MCPCheckOptions{Endpoint: fs.Arg(0), ExpectedIssuer: *issuer}
	if *caFile != "" {
		data, err := os.ReadFile(*caFile)
		if err != nil {
			return fmt.Errorf("read CA certificate: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(data) {
			return fmt.Errorf("CA file contains no certificates")
		}
		options.RootCAs = pool
	}
	report, checkErr := client.CheckMCPDiscovery(ctx, options)
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}
	return checkErr
}
