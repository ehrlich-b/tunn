package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/terminal"
)

type cliCommandError struct {
	cause                         error
	state, title, detail, command string
}

func (e *cliCommandError) Error() string { return e.title }
func (e *cliCommandError) Unwrap() error { return e.cause }
func jsonRequested(args []string) bool {
	value := false
	for _, arg := range args {
		if arg == "--json" || arg == "--json=true" {
			value = true
		}
		if arg == "--json=false" {
			value = false
		}
	}
	return value
}
func printHosts(out, errout io.Writer, machines []common.Machine) error {
	o := terminal.New(out, errout, false)
	if len(machines) == 0 {
		o.Reading("No registered machines")
		o.Reading("tunn service --help")
		return nil
	}
	for index, m := range machines {
		if index > 0 {
			o.Reading("")
		}
		o.Reading(m.Name)
		if len(m.Tunnels) == 0 {
			o.Reading("No tunnels on this machine")
			continue
		}
		for _, t := range m.Tunnels {
			o.Reading("  " + t.Name + " · " + strings.ToUpper(t.Kind))
			o.URL("  " + t.URL)
			state := "[o] Status unknown"
			if t.Online {
				state = "[i] Edge connected"
			} else if !t.LastSeen.IsZero() {
				state = "[x] Offline"
			}
			o.Reading("  " + state)
			seen := "No check received"
			if !t.LastSeen.IsZero() {
				age := time.Since(t.LastSeen)
				if age < 0 {
					seen = "Check time unavailable"
				} else {
					seen = "Seen " + age.Round(time.Second).String() + " ago"
				}
			}
			o.Reading("  App not checked · " + seen)
			scope := "Unknown · check access"
			switch t.Access {
			case "public", "legacy-public":
				scope = "Anyone with the link"
			case "private":
				scope = "Only you and invited people"
				if t.EndpointToken {
					scope = "Sign in or use an endpoint token"
				}
			}
			o.Reading("  Access: " + scope)
			if t.Access == "" || t.Access == "unknown" {
				o.Hint("  tunn access " + shellURL(t.Name))
			}
		}
	}
	return nil
}
func serviceStatusResult(out io.Writer, result string, err error) error {
	text := strings.ToLower(result)
	if err != nil {
		if strings.Contains(text, "could not be found") || strings.Contains(text, "not installed") || strings.Contains(text, "not-found") {
			return &cliCommandError{cause: err, state: "stopped", title: "Service not installed", command: "tunn service install"}
		}
		if strings.Contains(text, "inactive") || strings.Contains(text, "stopped") {
			return &cliCommandError{cause: err, state: "stopped", title: "Service stopped", command: "tunn service restart"}
		}
		return &cliCommandError{cause: err, state: "error", title: "Service status unavailable", detail: "The service manager did not return a status.", command: "tunn service check"}
	}
	state := "[o] Service status unknown"
	if strings.Contains(text, "active (running)") || strings.Contains(text, "state = running") {
		state = "[i] Service running"
	}
	fmt.Fprintln(out, state)
	fmt.Fprintln(out, "Tunnel health not checked")
	fmt.Fprintln(out, "tunn hosts")
	return nil
}
func writeHostError(out, errout io.Writer, err error, args []string) {
	var e *cliCommandError
	if errors.As(err, &e) {
		terminal.New(out, errout, jsonRequested(args)).State(e.state, e.title, e.detail, e.command, 0)
		return
	}
	terminal.New(out, errout, jsonRequested(args)).State("error", "Command failed", err.Error(), "tunn --help", 0)
}
