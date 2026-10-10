package hostmode

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const ServiceLabel = "com.tunn.host"

type ServiceSpec struct {
	OS, Home, Binary, Config, Username string
	ConfigHome                         string // Explicit root; never inferred when supplied by a rehearsal.
	UID                                int
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func systemdPath(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

func systemdArg(s string) string { return strings.ReplaceAll(systemdPath(s), "$", "$$") }

// windowsArg implements CommandLineToArgvW quoting, including trailing slashes.
func windowsArg(s string) string {
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

// Unit returns an OS-native per-user definition. No shell evaluates config paths.
func (s ServiceSpec) Unit() (string, error) {
	for _, value := range []string{s.Binary, s.Config, s.Home, s.Username} {
		if strings.ContainsAny(value, "\x00\r\n") {
			return "", fmt.Errorf("service values must not contain control characters")
		}
	}
	switch s.OS {
	case "darwin":
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.tunn.host</string>
  <key>ProgramArguments</key><array>
    <string>%s</string><string>--verbosity=error</string>
    <string>service</string><string>run</string><string>--config</string><string>%s</string>
  </array>
  <key>WorkingDirectory</key><string>%s</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>/dev/null</string>
  <key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
`, xmlText(s.Binary), xmlText(s.Config), xmlText(s.Home)), nil
	case "linux":
		return fmt.Sprintf(`[Unit]
Description=Tunn private machine endpoints
After=network.target

[Service]
Type=simple
ExecStart=%s --verbosity=error service run --config %s
WorkingDirectory=%s
Restart=always
RestartSec=30
UMask=0077
StandardOutput=null
StandardError=null

[Install]
WantedBy=default.target
`, systemdArg(s.Binary), systemdArg(s.Config), systemdPath(s.Home)), nil
	case "windows":
		if s.Username == "" {
			return "", fmt.Errorf("Windows scheduled task requires the current username")
		}
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>%s</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Owner"><UserId>%s</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>
  <Actions Context="Owner"><Exec><Command>%s</Command><Arguments>--verbosity=error service run --config %s</Arguments><WorkingDirectory>%s</WorkingDirectory></Exec></Actions>
</Task>
`, xmlText(s.Username), xmlText(s.Username), xmlText(s.Binary), xmlText(windowsArg(s.Config)), xmlText(s.Home)), nil
	default:
		return "", fmt.Errorf("unsupported service OS %q; WSL uses Linux systemd --user (see docs/host-mode.md)", s.OS)
	}
}

func (s ServiceSpec) Path() string {
	switch s.OS {
	case "darwin":
		return filepath.Join(s.Home, "Library", "LaunchAgents", ServiceLabel+".plist")
	case "linux":
		root := s.ConfigHome
		if root == "" {
			root = os.Getenv("XDG_CONFIG_HOME")
		}
		if root == "" {
			root = filepath.Join(s.Home, ".config")
		}
		return filepath.Join(root, "systemd", "user", "tunn-host.service")
	default:
		return filepath.Join(filepath.Dir(s.Config), "tunn-host-task.xml")
	}
}

type CommandRunner func(name string, args ...string) ([]byte, error)

func ExecCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func (s ServiceSpec) Manage(action string, run CommandRunner) (string, error) {
	unit, err := s.Unit()
	if err != nil {
		return "", err
	}
	path := s.Path()
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("service definition path must be absolute")
	}
	command := func(name string, args ...string) (string, error) {
		out, err := run(name, args...)
		if err != nil {
			return string(out), fmt.Errorf("%s failed: %w: %s", name, err, out)
		}
		return string(out), nil
	}
	if action == "install" {
		// An existing definition belongs to this invocation only if every path
		// matches. Updates use a stable binary path and an explicit restart.
		existing, err := serviceDefinition(path)
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if err == nil && string(existing) != unit {
			return "", fmt.Errorf("existing service definition differs; use its original binary and config to uninstall it first: %s", path)
		}
		if os.IsNotExist(err) {
			switch s.OS {
			case "linux":
				fragment, err := command("systemctl", "--user", "show", "--property=FragmentPath", "--value", "tunn-host.service")
				if err != nil {
					return "", err
				}
				if strings.TrimSpace(fragment) != "" {
					return "", fmt.Errorf("an existing systemd service has no matching local definition; refusing to replace %s", strings.TrimSpace(fragment))
				}
			case "windows":
				if _, err := command("schtasks", "/Query", "/TN", "TunnHost"); err == nil {
					return "", fmt.Errorf("TunnHost already exists without this local definition; refusing to replace it")
				}
			}
		}
		if err == nil {
			// print/Query succeeds for a registered job even when it is offline.
			// A failed query is never reported as success: registration below is
			// checked, and a failed manager leaves the definition for recovery.
			if s.OS == "darwin" {
				if _, err := command("launchctl", "print", fmt.Sprintf("gui/%d/%s", s.UID, ServiceLabel)); err == nil {
					return "Already installed " + path + "; use status or restart to check recovery.\n", nil
				}
			}
			if s.OS == "windows" {
				if _, err := command("schtasks", "/Query", "/TN", "TunnHost"); err == nil {
					if _, err := command("schtasks", "/Run", "/TN", "TunnHost"); err != nil {
						return "", err
					}
					return "Already installed " + path + "; use status or restart to check recovery.\n", nil
				}
			}
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return "", err
		}
		if os.IsNotExist(err) {
			if err := createPrivateFile(path, []byte(unit)); err != nil {
				return "", err
			}
		}
		switch s.OS {
		case "darwin":
			// bootstrap is deliberately not preceded by bootout: a failed install
			// must not terminate an already running service.
			if _, err := command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", s.UID), path); err != nil {
				return "", err
			}
		case "linux":
			if _, err := command("systemctl", "--user", "daemon-reload"); err != nil {
				return "", err
			}
			if _, err := command("systemctl", "--user", "enable", "--now", "tunn-host.service"); err != nil {
				return "", err
			}
		case "windows":
			if _, err := command("schtasks", "/Create", "/TN", "TunnHost", "/XML", path); err != nil {
				return "", err
			}
			if _, err := command("schtasks", "/Run", "/TN", "TunnHost"); err != nil {
				return "", err
			}
		}
		return "Installed " + path + "\n", nil
	}
	if action == "uninstall" {
		existing, err := serviceDefinition(path)
		if os.IsNotExist(err) {
			return "Service definition already absent; config and publisher/endpoint credentials retained.\n", nil
		}
		if err != nil {
			return "", err
		}
		if string(existing) != unit {
			return "", fmt.Errorf("refusing to remove a different service definition: %s", path)
		}
		switch s.OS {
		case "darwin":
			if _, err := command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", s.UID, ServiceLabel)); err != nil {
				return "", err
			}
		case "linux":
			if _, err := command("systemctl", "--user", "disable", "--now", "tunn-host.service"); err != nil {
				return "", err
			}
		case "windows":
			// Never delete registration after an unchecked stop: a running task
			// can outlive registration. Native acceptance covers stopped tasks.
			if _, err := command("schtasks", "/End", "/TN", "TunnHost"); err != nil {
				return "", err
			}
			if _, err := command("schtasks", "/Delete", "/TN", "TunnHost", "/F"); err != nil {
				return "", err
			}
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if s.OS == "linux" {
			if _, err := command("systemctl", "--user", "daemon-reload"); err != nil {
				return "", err
			}
		}
		return "Uninstalled service; config, publisher/endpoint credentials, relay inventory and reserved names retained.\n", nil
	}
	if action == "restart" {
		existing, err := serviceDefinition(path)
		if err != nil {
			return "", err
		}
		if string(existing) != unit {
			return "", fmt.Errorf("refusing to restart a different service definition: %s", path)
		}
		switch s.OS {
		case "darwin":
			return command("launchctl", "kickstart", "-k", fmt.Sprintf("gui/%d/%s", s.UID, ServiceLabel))
		case "linux":
			return command("systemctl", "--user", "restart", "tunn-host.service")
		case "windows":
			if _, err := command("schtasks", "/End", "/TN", "TunnHost"); err != nil {
				return "", err
			}
			return command("schtasks", "/Run", "/TN", "TunnHost")
		}
	}
	if action == "status" {
		switch s.OS {
		case "darwin":
			return command("launchctl", "print", fmt.Sprintf("gui/%d/%s", s.UID, ServiceLabel))
		case "linux":
			return command("systemctl", "--user", "status", "--no-pager", "tunn-host.service")
		case "windows":
			return command("schtasks", "/Query", "/TN", "TunnHost", "/V", "/FO", "LIST")
		}
	}
	return "", fmt.Errorf("expected service install, uninstall, restart, status, check, or run")
}

func serviceDefinition(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("service definition must be a regular file, not a symlink: %s", path)
	}
	return os.ReadFile(path)
}

// Link publishes the complete file without overwriting a competing install.
func createPrivateFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tunn-unit-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Link(f.Name(), path)
}
