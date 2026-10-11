package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/ehrlich-b/tunn/internal/cliopts"
	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/config"
	"github.com/ehrlich-b/tunn/internal/hostmode"
)

func runHostCommand(command string, args []string) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := hostCommand(ctx, command, args, os.Stdout, os.Stderr); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func hostCommand(ctx context.Context, command string, args []string, out, errout io.Writer) error {
	defaultPath, err := hostmode.DefaultPath()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(errout)
	var path *string
	var action string
	var dry *bool
	var platform *string
	var jsonOutput *bool
	var name, gateway, qrFile, domain *string
	switch command {
	case "service":
		if len(args) == 0 {
			return fmt.Errorf("usage: tunn service install|uninstall|restart|status|check|run [--config path] [--dry-run] [--os darwin|linux|windows]")
		}
		action, args = args[0], args[1:]
		if !cliopts.ValidServiceAction(action) {
			return fmt.Errorf("unknown service action %q", action)
		}
		o := new(cliopts.Service)
		cliopts.ServiceFlags(fs, o, defaultPath, runtime.GOOS)
		path, dry, platform = &o.Config, &o.DryRun, &o.OS
	case "hosts":
		jsonOutput = fs.Bool("json", false, "print the machine inventory as JSON")
	case "openclaw":
		name = fs.String("name", "home-openclaw", "stable endpoint name")
		gateway = fs.String("gateway", "", "local gateway URL (default port 18789, or the named http tunnel in host.yaml)")
		qrFile = fs.String("qr-file", "", "also write a QR PNG")
		domain = fs.String("domain", "", "public relay domain")
	}
	if command != "service" {
		path = fs.String("config", defaultPath, "host manifest path")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	configPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	c, loadErr := hostmode.Load(configPath)
	if command == "openclaw" {
		if loadErr != nil && !os.IsNotExist(loadErr) {
			return loadErr
		}
		if c != nil {
			if *domain == "" {
				*domain = c.Domain
			}
			if *gateway == "" {
				for _, t := range c.Tunnels {
					if t.Name == *name && t.Kind == "http" {
						*gateway = t.Target
					}
				}
			}
		}
		return hostmode.OpenClaw(ctx, hostmode.OpenClawOptions{Name: *name, Domain: *domain, Gateway: *gateway, ConfigPath: configPath, QRFile: *qrFile}, out)
	}
	if command == "service" && action != "run" {
		if (action == "install" || action == "restart" || action == "check") && loadErr != nil {
			return loadErr
		}
		if action == "check" {
			if _, err := hostmode.Credentials(c); err != nil {
				return err
			}
			_, err := fmt.Fprintf(out, "PASS local host config v%d: machine %s, %d endpoints, private credential; JWT expiry checked locally. Relay authentication and readiness remain unchecked.\n", c.Version, c.Machine, len(c.Tunnels))
			return err
		}
		if *platform != runtime.GOOS && !*dry {
			return fmt.Errorf("--os requires --dry-run when previewing another OS")
		}
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		owner, err := user.Current()
		if err != nil {
			return err
		}
		uid, _ := strconv.Atoi(owner.Uid)
		spec := hostmode.ServiceSpec{OS: *platform, Home: home, Binary: binary, Config: configPath, UID: uid, Username: owner.Username}
		if *dry {
			unit, err := spec.Unit()
			if err != nil {
				return err
			}
			_, err = io.WriteString(out, unit)
			return err
		}
		if action == "install" || action == "restart" {
			if _, err := hostmode.Credentials(c); err != nil {
				return err
			}
		}
		result, err := spec.Manage(action, hostmode.ExecCommand)
		_, _ = fmt.Fprint(out, result)
		return err
	}
	if loadErr != nil {
		// Listing is account-wide and does not require this machine to have a manifest.
		if command != "hosts" || !os.IsNotExist(loadErr) {
			return loadErr
		}
		c = &hostmode.Config{}
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	server := c.Server
	if server == "" {
		server = cfg.ServerAddr
	}
	token, err := hostmode.Credentials(c)
	if err != nil {
		return err
	}
	api := hostmode.API{Server: server, Token: token, Insecure: c.Insecure || *insecure}
	if command == "hosts" {
		machines, err := api.Hosts(ctx)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return json.NewEncoder(out).Encode(machines)
		}
		if len(machines) == 0 {
			_, err := fmt.Fprintln(out, "No registered machines.")
			return err
		}
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "MACHINE\tTUNNEL\tKIND\tSTATUS\tLAST SEEN\tURL")
		for _, m := range machines {
			for _, t := range m.Tunnels {
				status, seen := "offline", "never"
				if t.Online {
					status = "online"
				}
				if !t.LastSeen.IsZero() {
					seen = t.LastSeen.UTC().Format(time.RFC3339)
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", m.Name, t.Name, t.Kind, status, seen, t.URL)
			}
		}
		return w.Flush()
	}
	log, err := hostmode.OpenLog(filepath.Join(filepath.Dir(configPath), "host.log"), 1024*1024)
	if err != nil {
		return err
	}
	defer func() { _ = log.Close() }()
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: slog.LevelError})))
	defer slog.SetDefault(previous)
	common.LogError("host service starting", "machine", c.Machine)
	return (&hostmode.Runtime{Config: c, API: api, TunnelKey: cfg.WellKnownKey}).Run(ctx)
}
