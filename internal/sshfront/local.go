package sshfront

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/ehrlich-b/tunn/internal/cliopts"
	"github.com/ehrlich-b/tunn/internal/hostmode"
)

// ServicePlan emits a native OpenSSH service plan for the caller's machine.
// A remote SSH API cannot install files on its caller; the caller applies the
// returned script locally. The relay never executes an installation command.
func ServicePlan(args []string, in io.Reader, domain string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("service install|uninstall|restart|status|check|run --os linux|darwin|windows --config - < host.yaml")
	}
	action := args[0]
	if !cliopts.ValidServiceAction(action) {
		return fmt.Errorf("invalid service action")
	}
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := new(cliopts.Service)
	cliopts.ServiceFlags(fs, o, "-", "linux")
	platform, config, dry := &o.OS, &o.Config, &o.DryRun
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *config != "-" {
		return fmt.Errorf("pipe host.yaml to SSH stdin and use --config -")
	}
	data, err := io.ReadAll(io.LimitReader(in, 64*1024+1))
	if err != nil {
		return err
	}
	if len(data) > 64*1024 {
		return fmt.Errorf("host manifest exceeds 64 KiB")
	}
	c, err := hostmode.Parse(data)
	if err != nil {
		return err
	}
	if *platform != "linux" && *platform != "darwin" && *platform != "windows" {
		return fmt.Errorf("unsupported service OS")
	}
	if action == "check" {
		_, err := fmt.Fprintf(out, "PASS local host config v%d: machine %s, %d endpoints. Caller SSH key, host-key trust and relay readiness remain unchecked.\n", c.Version, c.Machine, len(c.Tunnels))
		return err
	}
	processes := make([][]string, len(c.Tunnels))
	for i, t := range c.Tunnels {
		args, err := serviceSSHArgs(t, domain)
		if err != nil {
			return err
		}
		processes[i], err = serviceProcess(t, *platform, args)
		if err != nil {
			return err
		}
	}
	if !*dry && action != "run" {
		if *platform == "windows" {
			fmt.Fprintln(out, "$ErrorActionPreference = 'Stop'")
		} else {
			fmt.Fprintln(out, "#!/bin/sh\nset -eu\numask 077")
		}
	}
	for i, t := range c.Tunnels {
		process := processes[i]
		label := "tunn-ssh-" + t.Name
		if action == "run" {
			if *platform == "windows" {
				var quoted []string
				for _, arg := range process {
					quoted = append(quoted, powershellQuote(arg))
				}
				fmt.Fprintln(out, "& "+strings.Join(quoted, " "))
			} else {
				fmt.Fprintln(out, shellCommand(process))
			}
			continue
		}
		unit := serviceUnit(*platform, label, process)
		if *dry {
			fmt.Fprintln(out, unit)
			continue
		}
		emitServicePlan(out, action, *platform, label, t.Name, unit)
	}
	return nil
}

func serviceSSHArgs(t hostmode.Tunnel, domain string) ([]string, error) {
	args := []string{"-T", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-p", "443"}
	if t.Kind == "mcp" && len(t.Command) > 0 {
		args = append(args, domain, "--", "mcp", "--stdio", "--name", t.Name)
		if len(t.Allow) > 0 {
			args = append(args, "--allow", strings.Join(t.Allow, ","))
		}
		if len(t.Tools) > 0 {
			args = append(args, "--tools", strings.Join(t.Tools, ","))
		}
		return args, nil
	}
	target := t.Target
	upstream := ""
	if strings.ContainsAny(target, "\x00\r\n") {
		return nil, fmt.Errorf("service targets must not contain control characters")
	}
	if t.Kind == "http" || t.Kind == "mcp" {
		u, err := hostmode.HTTPURL(target)
		if err != nil {
			return nil, err
		}
		if u.Scheme == "https" || u.Path != "" && u.Path != "/" || u.RawQuery != "" {
			upstream = u.String()
		}
		port := u.Port()
		if port == "" {
			port = "80"
			if u.Scheme == "https" {
				port = "443"
			}
		}
		target = net.JoinHostPort(u.Hostname(), port)
	}
	kind := t.Kind
	if kind == "http" {
		kind = "serve"
	}
	args = append(args, "-R", "0:"+target, domain, "--", kind, "--name", t.Name)
	if upstream != "" {
		args = append(args, "--target", upstream)
	}
	if t.Kind == "unix" && t.As == "http" {
		args = append(args, "--as", "http")
	}
	if len(t.Allow) > 0 {
		args = append(args, "--allow", strings.Join(t.Allow, ","))
	}
	return args, nil
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func shellCommand(args []string) string {
	var quoted []string
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}
func xmlValue(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
func serviceUnit(platform, label string, process []string) string {
	switch platform {
	case "linux":
		var quoted []string
		for _, arg := range process {
			arg = strings.ReplaceAll(arg, "%", "%%")
			arg = strings.ReplaceAll(arg, "$", "$$")
			arg = strings.ReplaceAll(arg, "\\", "\\\\")
			arg = strings.ReplaceAll(arg, "\"", "\\\"")
			arg = strings.ReplaceAll(arg, "\n", "\\n")
			arg = strings.ReplaceAll(arg, "\t", "\\t")
			quoted = append(quoted, "\""+arg+"\"")
		}
		return "[Unit]\nDescription=Tunn SSH endpoint\nAfter=network.target\n\n[Service]\nExecStart=" + strings.Join(quoted, " ") + "\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=default.target"
	case "darwin":
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.tunn.ssh.` + strings.TrimPrefix(label, "tunn-ssh-") + `</string><key>ProgramArguments</key><array>`)
		for _, arg := range process {
			b.WriteString("<string>" + xmlValue(arg) + "</string>")
		}
		b.WriteString("</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>5</integer></dict></plist>")
		return b.String()
	default:
		var quoted []string
		for _, arg := range process[1:] {
			quoted = append(quoted, windowsQuote(arg))
		}
		return `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>` + xmlValue(process[0]) + `</Command><Arguments>` + xmlValue(strings.Join(quoted, " ")) + `</Arguments></Exec></Actions></Task>`
	}
}
func windowsQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range s {
		if r == '\\' {
			slashes++
			continue
		}
		if r == '"' {
			b.WriteString(strings.Repeat("\\", slashes*2+1))
		} else {
			b.WriteString(strings.Repeat("\\", slashes))
		}
		slashes = 0
		b.WriteRune(r)
	}
	b.WriteString(strings.Repeat("\\", slashes*2))
	b.WriteByte('"')
	return b.String()
}
