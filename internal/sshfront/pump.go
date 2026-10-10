package sshfront

import (
	"fmt"
	"strings"

	"github.com/ehrlich-b/tunn/internal/hostmode"
)

func serviceProcess(t hostmode.Tunnel, platform string, sshArgs []string) ([]string, error) {
	sshBinary := "/usr/bin/ssh"
	if platform == "windows" {
		sshBinary = `C:\Windows\System32\OpenSSH\ssh.exe`
	}
	if t.Kind != "mcp" || len(t.Command) == 0 {
		return append([]string{sshBinary}, sshArgs...), nil
	}
	for _, arg := range t.Command {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return nil, fmt.Errorf("stdio command arguments must not contain control characters")
		}
	}
	if platform == "windows" {
		return []string{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-NoProfile", "-NonInteractive", "-Command", windowsPump(t.Command, append([]string{sshBinary}, sshArgs...))}, nil
	}
	return []string{"/bin/sh", "-c", posixPump(t.Command, append([]string{sshBinary}, sshArgs...))}, nil
}

// POSIX FIFOs opened in both directions avoid a startup deadlock. Each process
// has a watcher that terminates its peer, so inherited FIFO descriptors cannot
// keep a dead child or disconnected SSH session alive indefinitely.
func posixPump(command, sshCommand []string) string {
	return `set -eu
tunn_pump_dir=$(mktemp -d)
trap 'rm -rf "$tunn_pump_dir"' 0
mkfifo "$tunn_pump_dir/to-child" "$tunn_pump_dir/from-child"
exec 3<>"$tunn_pump_dir/to-child" 4<>"$tunn_pump_dir/from-child"
` + shellCommand(command) + ` <&3 >&4 &
tunn_child_pid=$!
(
 ` + shellCommand(sshCommand) + ` <&4 >&3 &
 tunn_ssh_pid=$!
 trap 'kill "$tunn_ssh_pid" 2>/dev/null || true' 0 HUP INT TERM
 wait "$tunn_ssh_pid" || true
 kill "$tunn_child_pid" 2>/dev/null || true
) &
tunn_bridge_pid=$!
trap 'kill "$tunn_child_pid" "$tunn_bridge_pid" 2>/dev/null || true; rm -rf "$tunn_pump_dir"' 0 HUP INT TERM
wait "$tunn_child_pid" || true
exit 1`
}

func powershellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func windowsPump(command, sshCommand []string) string {
	process := func(variable string, args []string) string {
		var parameters []string
		for _, arg := range args[1:] {
			parameters = append(parameters, windowsQuote(arg))
		}
		return "$" + variable + ` = New-Object System.Diagnostics.Process
$` + variable + `.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
$` + variable + `.StartInfo.FileName = ` + powershellQuote(args[0]) + `
$` + variable + `.StartInfo.Arguments = ` + powershellQuote(strings.Join(parameters, " ")) + `
$` + variable + `.StartInfo.UseShellExecute = $false
$` + variable + `.StartInfo.RedirectStandardInput = $true
$` + variable + `.StartInfo.RedirectStandardOutput = $true
`
	}
	return `$ErrorActionPreference = 'Stop'
` + process("tunnChild", command) + process("tunnSSH", sshCommand) + `$tunnChildStarted = $false
$tunnSSHStarted = $false
try {
 $tunnChildStarted = $tunnChild.Start()
 $tunnSSHStarted = $tunnSSH.Start()
 $tunnOutbound = $tunnChild.StandardOutput.BaseStream.CopyToAsync($tunnSSH.StandardInput.BaseStream)
 $tunnInbound = $tunnSSH.StandardOutput.BaseStream.CopyToAsync($tunnChild.StandardInput.BaseStream)
 [void][System.Threading.Tasks.Task]::WaitAny([System.Threading.Tasks.Task[]]@($tunnOutbound, $tunnInbound))
} finally {
 if ($tunnChildStarted -and !$tunnChild.HasExited) { $tunnChild.Kill() }
 if ($tunnSSHStarted -and !$tunnSSH.HasExited) { $tunnSSH.Kill() }
 $tunnChild.Dispose()
 $tunnSSH.Dispose()
}
exit 1`
}
