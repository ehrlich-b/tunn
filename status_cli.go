package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	statuspage "github.com/ehrlich-b/tunn/internal/status"
)

func runStatus(args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := executeStatus(ctx, args, os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func executeStatus(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: tunn status serve|incident|resolve [options]")
	}
	fs := flag.NewFlagSet("status "+args[0], flag.ContinueOnError)
	fs.SetOutput(errOut)
	dbPath := fs.String("db", "status.db", "dedicated status SQLite database (persistent local disk)")
	switch args[0] {
	case "serve":
		listen := fs.String("listen", "127.0.0.1:8091", "HTTP listen address; put behind a TLS reverse proxy")
		rawOrigin := fs.String("probe", "https://tunn.to", "relay HTTPS origin (TLS verified, no redirects)")
		allowHTTPLoopback := fs.Bool("allow-http-loopback", false, "allow HTTP to literal loopback IPs for local fixtures only")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		origin, err := statuspage.ProbeOrigin(*rawOrigin, *allowHTTPLoopback)
		if err != nil {
			return err
		}
		s, err := statuspage.Open(*dbPath)
		if err != nil {
			return err
		}
		defer s.Close()
		if err := s.BindOrigin(ctx, origin.String()); err != nil {
			return err
		}
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		defer listener.Close()
		child, cancel := context.WithCancel(ctx)
		defer cancel()
		collector := statuspage.Collector{Store: s, Origin: origin, Client: statuspage.ProbeClient(5 * time.Second)}
		done := make(chan struct{})
		go func() { defer close(done); collector.Run(child) }()
		server := &http.Server{Handler: statuspage.Handler(s), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
		stop := context.AfterFunc(child, func() { _ = server.Close() })
		defer stop()
		fmt.Fprintln(out, "Status collector listening on", listener.Addr())
		err = server.Serve(listener)
		cancel()
		<-done
		if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
			return nil
		}
		return err
	case "incident":
		title := fs.String("title", "", "public incident title (1–120 bytes)")
		note := fs.String("note", "", "public plain-text note (1–2000 bytes)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		s, err := statuspage.Open(*dbPath)
		if err != nil {
			return err
		}
		defer s.Close()
		id, err := s.AddIncident(ctx, time.Now().UTC(), *title, *note)
		if err == nil {
			fmt.Fprintln(out, id)
		}
		return err
	case "resolve":
		note := fs.String("note", "", "public resolution note (replaces current note)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("provide one incident ID after the options")
		}
		id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
		if err != nil || id <= 0 {
			return errors.New("invalid incident ID")
		}
		s, err := statuspage.Open(*dbPath)
		if err != nil {
			return err
		}
		defer s.Close()
		return s.ResolveIncident(ctx, time.Now().UTC(), id, *note)
	default:
		return errors.New("usage: tunn status serve|incident|resolve [options]")
	}
}
