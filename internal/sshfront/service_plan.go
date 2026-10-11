package sshfront

import (
	"fmt"
	"io"
)

// Generated plans keep the native installer's ownership and recovery rules:
// publish a complete definition, never replace another registration, and retain
// the definition when a manager command fails. Only the caller runs these plans.
func emitServicePlan(out io.Writer, action, platform, label, name, unit string) {
	if platform == "windows" {
		emitWindowsServicePlan(out, action, label, unit)
		return
	}
	file := label + ".service"
	directory := `${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user`
	job := label + ".service"
	if platform == "darwin" {
		file = "com.tunn.ssh." + name + ".plist"
		directory = `$HOME/Library/LaunchAgents`
		job = "com.tunn.ssh." + name
	}
	// A subshell makes already-absent removal skip just this endpoint.
	_, _ = fmt.Fprintf(out, "(\n tunn_service_dir=\"%s\"\n case \"$tunn_service_dir\" in /*) ;; *) echo 'service directory must be absolute' >&2; exit 1;; esac\n tunn_service_path=\"$tunn_service_dir/%s\"\n", directory, file)
	if action == "status" {
		if platform == "linux" {
			_, _ = fmt.Fprintf(out, " systemctl --user status --no-pager %s\n", job)
		} else {
			_, _ = fmt.Fprintf(out, " launchctl print \"gui/$(id -u)/%s\"\n", job)
		}
		_, _ = fmt.Fprintln(out, ")")
		return
	}
	if action == "install" {
		_, _ = fmt.Fprintln(out, ` mkdir -p "$tunn_service_dir"`)
	} else {
		_, _ = fmt.Fprintln(out, ` if [ ! -e "$tunn_service_path" ] && [ ! -L "$tunn_service_path" ]; then`)
		if action == "uninstall" {
			_, _ = fmt.Fprintln(out, "  exit 0")
		} else {
			_, _ = fmt.Fprintln(out, "  echo 'service definition is absent' >&2; exit 1")
		}
		_, _ = fmt.Fprintln(out, " fi")
	}
	_, _ = fmt.Fprintln(out, ` if [ -L "$tunn_service_path" ] || { [ -e "$tunn_service_path" ] && [ ! -f "$tunn_service_path" ]; }; then
  echo 'service definition must be a regular file, not a symlink' >&2; exit 1
 fi
 tunn_service_tmp=$(mktemp "$tunn_service_dir/.tunn-ssh-XXXXXX")
 trap 'rm -f "$tunn_service_tmp"' 0 HUP INT TERM
 cat > "$tunn_service_tmp" <<'TUNN_SSH_UNIT'`)
	_, _ = fmt.Fprintln(out, unit)
	_, _ = fmt.Fprintln(out, `TUNN_SSH_UNIT
 if [ -f "$tunn_service_path" ]; then
  cmp -s "$tunn_service_tmp" "$tunn_service_path" || { echo 'existing service definition differs; use its original manifest to uninstall first' >&2; exit 1; }
 else`)
	if action != "install" {
		_, _ = fmt.Fprintln(out, "  echo 'service definition disappeared' >&2; exit 1")
	} else if platform == "linux" {
		_, _ = fmt.Fprintf(out, "  tunn_service_fragment=$(systemctl --user show --property=FragmentPath --value %s)\n  [ -z \"$tunn_service_fragment\" ] || { echo 'another service registration exists' >&2; exit 1; }\n", job)
	} else {
		_, _ = fmt.Fprintf(out, "  if launchctl print \"gui/$(id -u)/%s\" >/dev/null 2>&1; then echo 'another service registration exists' >&2; exit 1; fi\n", job)
	}
	if action == "install" {
		_, _ = fmt.Fprintln(out, `  ln "$tunn_service_tmp" "$tunn_service_path"`)
	}
	_, _ = fmt.Fprintln(out, " fi")
	if platform == "linux" {
		switch action {
		case "install":
			_, _ = fmt.Fprintf(out, " systemctl --user daemon-reload\n systemctl --user enable --now %s\n", job)
		case "restart":
			_, _ = fmt.Fprintf(out, " systemctl --user restart %s\n", job)
		case "uninstall":
			_, _ = fmt.Fprintf(out, " systemctl --user disable --now %s\n rm -f \"$tunn_service_path\"\n systemctl --user daemon-reload\n", job)
		}
	} else {
		switch action {
		case "install":
			_, _ = fmt.Fprintf(out, " if ! launchctl print \"gui/$(id -u)/%s\" >/dev/null 2>&1; then launchctl bootstrap \"gui/$(id -u)\" \"$tunn_service_path\"; fi\n", job)
		case "restart":
			_, _ = fmt.Fprintf(out, " launchctl kickstart -k \"gui/$(id -u)/%s\"\n", job)
		case "uninstall":
			_, _ = fmt.Fprintf(out, " launchctl bootout \"gui/$(id -u)/%s\"\n rm -f \"$tunn_service_path\"\n", job)
		}
	}
	_, _ = fmt.Fprintln(out, ")")
}

func emitWindowsServicePlan(out io.Writer, action, label, unit string) {
	_, _ = fmt.Fprintf(out, "$tunnTaskName = '%s'\n$tunnTaskDir = Join-Path $env:LOCALAPPDATA 'tunn\\ssh-services'\n$tunnTaskPath = Join-Path $tunnTaskDir '%s.xml'\n", label, label)
	if action == "status" {
		_, _ = fmt.Fprintln(out, "Get-ScheduledTask -TaskName $tunnTaskName\nGet-ScheduledTaskInfo -TaskName $tunnTaskName")
		return
	}
	_, _ = fmt.Fprintf(out, "$tunnTaskXml = @'\n%s\n'@\n& {\n", unit)
	_, _ = fmt.Fprintln(out, ` $tunnDefinition = Get-Item -LiteralPath $tunnTaskPath -ErrorAction SilentlyContinue
 if ($tunnDefinition) {
  if ($tunnDefinition.PSIsContainer -or ($tunnDefinition.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'service definition must be a regular file' }
  if ([IO.File]::ReadAllText($tunnTaskPath) -cne $tunnTaskXml) { throw 'existing service definition differs; use its original manifest to uninstall first' }
 }`)
	if action != "install" {
		if action == "uninstall" {
			_, _ = fmt.Fprintln(out, " if (!$tunnDefinition) { return }")
		} else {
			_, _ = fmt.Fprintln(out, " if (!$tunnDefinition) { throw 'service definition is absent' }")
		}
	}
	_, _ = fmt.Fprintln(out, " $tunnTask = Get-ScheduledTask -TaskName $tunnTaskName -ErrorAction SilentlyContinue")
	switch action {
	case "install":
		_, _ = fmt.Fprintln(out, ` if (!$tunnDefinition) {
  if ($tunnTask) { throw 'another service registration exists' }
  [void][IO.Directory]::CreateDirectory($tunnTaskDir)
  $tunnTaskTmp = Join-Path $tunnTaskDir ([IO.Path]::GetRandomFileName())
  try {
   [IO.File]::WriteAllText($tunnTaskTmp, $tunnTaskXml)
   [IO.File]::Move($tunnTaskTmp, $tunnTaskPath)
  } finally { if (Test-Path -LiteralPath $tunnTaskTmp) { Remove-Item -LiteralPath $tunnTaskTmp } }
 }
 if (!$tunnTask) { Register-ScheduledTask -TaskName $tunnTaskName -Xml $tunnTaskXml | Out-Null }
 Start-ScheduledTask -TaskName $tunnTaskName`)
	case "restart":
		_, _ = fmt.Fprintln(out, ` if (!$tunnTask) { throw 'service registration is absent' }
 if ($tunnTask.State -eq 'Running') { Stop-ScheduledTask -TaskName $tunnTaskName }
 Start-ScheduledTask -TaskName $tunnTaskName`)
	case "uninstall":
		_, _ = fmt.Fprintln(out, ` if ($tunnTask) {
  if ($tunnTask.State -eq 'Running') { Stop-ScheduledTask -TaskName $tunnTaskName }
  Unregister-ScheduledTask -TaskName $tunnTaskName -Confirm:$false
 }
 Remove-Item -LiteralPath $tunnTaskPath`)
	}
	_, _ = fmt.Fprintln(out, "}")
}
