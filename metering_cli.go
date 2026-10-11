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
)

type meteringOptions struct {
	action, endpoint, grantID, server, ownerFile, month, consumer, since string
	expires                                                              time.Time
	rate, requests, bytes                                                int64
	insecure                                                             bool
}

const meteringUsage = cliopts.MeteringUsage

func parseMeteringOptions(command string, args []string, now time.Time) (*meteringOptions, error) {
	o, err := cliopts.ParseMetering(command, args, now)
	if err != nil {
		return nil, err
	}
	return &meteringOptions{action: o.Action, endpoint: o.Endpoint, grantID: o.GrantID, server: o.Server, ownerFile: o.OwnerFile, month: o.Month, consumer: o.Consumer, since: o.Since, expires: o.Expires, rate: o.Rate, requests: o.Requests, bytes: o.Bytes, insecure: o.Insecure}, nil
}
func validCLIEndpoint(s string) bool { return cliopts.ValidEndpoint(s) }
func runMetering(command string, args []string) {
	if err := executeMetering(command, args, os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(os.Stdout, meteringUsage)
			return
		}
		_, _ = fmt.Fprintln(os.Stderr, err)
		_, _ = fmt.Fprint(os.Stderr, meteringUsage)
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
	transport := relaytransport.Transport(o.insecure || *insecure)
	defer transport.CloseIdleConnections()
	c := &client.ManagementClient{ServerURL: o.server, OwnerToken: ownerToken, HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	shared, err := cliopts.ParseMetering(command, args, time.Now())
	if err != nil {
		return err
	}
	return client.ExecuteMetering(ctx, shared, c, out)
}
