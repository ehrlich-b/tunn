package sshfront

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/ehrlich-b/tunn/internal/hostmode"
)

// ServicePlan emits a native OpenSSH service plan for the caller's machine.
// A remote SSH API cannot install files on its caller; the caller applies the
// returned script locally. The relay never executes an installation command.
func ServicePlan(args []string, in io.Reader, domain string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("service install|uninstall|status|run --os linux|darwin|windows --config - < host.yaml")
	}
	action := args[0]
	if action != "install" && action != "uninstall" && action != "status" && action != "run" {
		return fmt.Errorf("invalid service action")
	}
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	platform := fs.String("os", "linux", "OS on the caller's machine")
	config := fs.String("config", "-", "pipe the local host manifest to stdin")
	dry := fs.Bool("dry-run", false, "print native definitions only")
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
	if !*dry && action != "run" {
		if *platform == "windows" {
			fmt.Fprintln(out, "$ErrorActionPreference = 'Stop'")
		} else {
			fmt.Fprintln(out, "#!/bin/sh\nset -eu")
		}
	}
	for _, t := range c.Tunnels {
		sshArgs, err := serviceSSHArgs(t, domain)
		if err != nil {
			return err
		}
		label := "tunn-ssh-" + t.Name
		if action == "run" {
			fmt.Fprintln(out, shellCommand(append([]string{"ssh"}, sshArgs...)))
			continue
		}
		unit := serviceUnit(*platform, label, sshArgs)
		if *dry {
			fmt.Fprintln(out, unit)
			continue
		}
		switch *platform {
		case "linux":
			path := `"$HOME/.config/systemd/user/` + label + `.service"`
			switch action {
			case "install":
				fmt.Fprintf(out, "mkdir -p \"$HOME/.config/systemd/user\"\ncat > %s <<'TUNN_SSH_UNIT'\n%s\nTUNN_SSH_UNIT\nchmod 600 %s\nsystemctl --user daemon-reload\nsystemctl --user enable --now %s.service\n", path, unit, path, label)
			case "uninstall":
				fmt.Fprintf(out, "systemctl --user disable --now %s.service\nrm -f %s\nsystemctl --user daemon-reload\n", label, path)
			case "status":
				fmt.Fprintf(out, "systemctl --user status --no-pager %s.service\n", label)
			}
		case "darwin":
			path := `"$HOME/Library/LaunchAgents/com.tunn.ssh.` + t.Name + `.plist"`
			switch action {
			case "install":
				fmt.Fprintf(out, "mkdir -p \"$HOME/Library/LaunchAgents\"\ncat > %s <<'TUNN_SSH_UNIT'\n%s\nTUNN_SSH_UNIT\nchmod 600 %s\nlaunchctl bootstrap \"gui/$(id -u)\" %s\n", path, unit, path, path)
			case "uninstall":
				fmt.Fprintf(out, "launchctl bootout \"gui/$(id -u)/com.tunn.ssh.%s\"\nrm -f %s\n", t.Name, path)
			case "status":
				fmt.Fprintf(out, "launchctl print \"gui/$(id -u)/com.tunn.ssh.%s\"\n", t.Name)
			}
		case "windows":
			switch action {
			case "install":
				fmt.Fprintf(out, "$taskXml = @'\n%s\n'@\nRegister-ScheduledTask -TaskName '%s' -Xml $taskXml -Force | Out-Null\nStart-ScheduledTask -TaskName '%s'\n", unit, label, label)
			case "uninstall":
				fmt.Fprintf(out, "Stop-ScheduledTask -TaskName '%s' -ErrorAction SilentlyContinue\nUnregister-ScheduledTask -TaskName '%s' -Confirm:$false\n", label, label)
			case "status":
				fmt.Fprintf(out, "Get-ScheduledTask -TaskName '%s'\nGet-ScheduledTaskInfo -TaskName '%s'\n", label, label)
			}
		}
	}
	return nil
}

func serviceSSHArgs(t hostmode.Tunnel, domain string) ([]string, error) {
	args := []string{"-T", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3", "-p", "443"}
	if t.Kind == "mcp" && len(t.Command) > 0 {
		return nil, fmt.Errorf("stdio MCP requires a local stdio pump; use mcp --stdio for %s", t.Name)
	}
	target := t.Target
	if strings.ContainsAny(target, "\x00\r\n") {
		return nil, fmt.Errorf("service targets must not contain control characters")
	}
	if t.Kind == "http" || t.Kind == "mcp" {
		u, err := hostmode.HTTPURL(target)
		if err != nil {
			return nil, err
		}
		if u.Scheme != "http" || u.RawQuery != "" || u.Path != "" && u.Path != "/" {
			return nil, fmt.Errorf("SSH services need an HTTP origin; targets and paths remain local")
		}
		port := u.Port()
		if port == "" {
			port = "80"
		}
		target = net.JoinHostPort(u.Hostname(), port)
	}
	kind := t.Kind
	if kind == "http" {
		kind = "serve"
	}
	args = append(args, "-R", "0:"+target, domain, "--", kind, "--name", t.Name)
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
func serviceUnit(platform, label string, args []string) string {
	switch platform {
	case "linux":
		var quoted []string
		for _, arg := range append([]string{"/usr/bin/ssh"}, args...) {
			arg = strings.ReplaceAll(arg, "%", "%%")
			arg = strings.ReplaceAll(arg, "$", "$$")
			arg = strings.ReplaceAll(arg, "\\", "\\\\")
			arg = strings.ReplaceAll(arg, "\"", "\\\"")
			quoted = append(quoted, "\""+arg+"\"")
		}
		return "[Unit]\nDescription=Tunn SSH endpoint\nAfter=network.target\n\n[Service]\nExecStart=" + strings.Join(quoted, " ") + "\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=default.target"
	case "darwin":
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.tunn.ssh.` + strings.TrimPrefix(label, "tunn-ssh-") + `</string><key>ProgramArguments</key><array>`)
		for _, arg := range append([]string{"/usr/bin/ssh"}, args...) {
			b.WriteString("<string>" + xmlValue(arg) + "</string>")
		}
		b.WriteString("</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>5</integer></dict></plist>")
		return b.String()
	default:
		var quoted []string
		for _, arg := range args {
			quoted = append(quoted, windowsQuote(arg))
		}
		return `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>C:\Windows\System32\OpenSSH\ssh.exe</Command><Arguments>` + xmlValue(strings.Join(quoted, " ")) + `</Arguments></Exec></Actions></Task>`
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
