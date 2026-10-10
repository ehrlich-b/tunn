package sshfront

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ehrlich-b/tunn/internal/cliopts"
	"github.com/ehrlich-b/tunn/internal/hostmode"
)

func TestIntegrationSSHServiceRecoveryAndSharedFlags(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			root := t.TempDir()
			configRoot := filepath.Join(root, "explicit config")
			profile := filepath.Join(root, "host.yaml")
			credential := filepath.Join(root, "private-token")
			manifest := fmt.Sprintf("version: 1\nmachine: workstation\ntoken_file: %q\ncredentials_dir: %q\ntunnels:\n  - name: demo\n    kind: http\n    target: 8080\n    allow: [owner@example.com, '@example.com']\n", credential, root)
			for path, data := range map[string]string{profile: manifest, credential: "fixture-publisher-identity"} {
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			c, err := hostmode.Load(profile)
			if err != nil {
				t.Fatal(err)
			}
			sshArgs, err := serviceSSHArgs(c.Tunnels[0], "tunn.test")
			if err != nil {
				t.Fatal(err)
			}
			var publication []string
			for n, arg := range sshArgs {
				if arg == "--" {
					publication = sshArgs[n+2:]
					break
				}
			}
			remote, err := cliopts.ParseSSHPublication(publication, "serve")
			if err != nil {
				t.Fatal(err)
			}
			local, err := cliopts.ParseServe(append([]string{"8080"}, publication...), true)
			if err != nil {
				t.Fatal(err)
			}
			local.Target = ""
			if !reflect.DeepEqual(local, remote) || remote.Name != "demo" || len(remote.AllowedEmails) != 2 {
				t.Fatalf("service publication drift: local=%+v remote=%+v", local, remote)
			}
			definition := filepath.Join(configRoot, "systemd", "user", "tunn-ssh-demo.service")
			if platform == "darwin" {
				definition = filepath.Join(root, "Library", "LaunchAgents", "com.tunn.ssh.demo.plist")
			}
			manager := filepath.Join(root, "fake-manager")
			if err := os.WriteFile(manager, []byte(sshFixtureManager), 0700); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(root, "state")
			if err := os.Mkdir(state, 0700); err != nil {
				t.Fatal(err)
			}
			run := func(action, input, failure string) error {
				t.Helper()
				var script bytes.Buffer
				if err := ServicePlan([]string{action, "--os", platform, "--config", "-"}, strings.NewReader(input), "tunn.test", &script); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(script.String(), "fixture-publisher-identity") || strings.Contains(script.String(), credential) {
					t.Fatal("SSH plan copied native publisher credentials")
				}
				// Redirect only the rendered fixture paths and manager names; no
				// native user service manager or real home directory is touched.
				plan := strings.NewReplacer("$HOME", "$TUNN_FIXTURE_HOME", "XDG_CONFIG_HOME", "TUNN_FIXTURE_CONFIG_HOME", "systemctl", shellQuote(manager), "launchctl", shellQuote(manager)).Replace(script.String())
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "sh")
				cmd.Stdin = strings.NewReader(plan)
				cmd.Env = append(os.Environ(), "TUNN_FIXTURE_HOME="+root, "TUNN_FIXTURE_CONFIG_HOME="+configRoot, "TUNN_FIXTURE_STATE="+state, "TUNN_FIXTURE_DEFINITION="+definition, "TUNN_FIXTURE_FAIL="+failure)
				data, err := cmd.CombinedOutput()
				if err != nil {
					return fmt.Errorf("%s: %w: %s", action, err, data)
				}
				return nil
			}
			for _, action := range []string{"install", "install", "restart", "status"} {
				if err := run(action, manifest, ""); err != nil {
					t.Fatal(err)
				}
			}
			unit, err := os.ReadFile(definition)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(definition)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("definition is not private: %v %v", info, err)
			}
			calls, err := os.ReadFile(filepath.Join(state, "calls"))
			if err != nil {
				t.Fatal(err)
			}
			other := strings.Replace(manifest, "target: 8080", "target: 9090", 1)
			for _, action := range []string{"install", "restart", "uninstall"} {
				if err := run(action, other, ""); err == nil {
					t.Fatalf("%s replaced another definition", action)
				}
			}
			unchangedCalls, _ := os.ReadFile(filepath.Join(state, "calls"))
			unchangedUnit, _ := os.ReadFile(definition)
			if !bytes.Equal(unit, unchangedUnit) || !bytes.Equal(calls, unchangedCalls) {
				t.Fatal("conflicting manifest changed prior registration")
			}
			stop := "disable"
			if platform == "darwin" {
				stop = "bootout"
			}
			if err := run("uninstall", manifest, stop); err == nil {
				t.Fatal("failed stop was reported as successful")
			}
			if _, err := os.Stat(definition); err != nil {
				t.Fatal("failed stop discarded recoverable definition")
			}
			for _, action := range []string{"uninstall", "uninstall"} {
				if err := run(action, manifest, ""); err != nil {
					t.Fatal(err)
				}
			}
			start := "enable"
			if platform == "darwin" {
				start = "bootstrap"
			}
			if err := run("install", manifest, start); err == nil {
				t.Fatal("failed start was reported as successful")
			}
			if _, err := os.Stat(definition); err != nil {
				t.Fatal("failed start discarded recoverable definition")
			}
			if err := run("install", manifest, ""); err != nil {
				t.Fatal(err)
			}
			if err := run("uninstall", manifest, ""); err != nil {
				t.Fatal(err)
			}
			// A registration elsewhere and a symlink both remain untouched.
			if err := os.WriteFile(filepath.Join(state, "registered"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := run("install", manifest, ""); err == nil {
				t.Fatal("replaced registration without an owned definition")
			}
			if err := os.Symlink(profile, definition); err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{"install", "restart", "uninstall"} {
				if err := run(action, manifest, ""); err == nil {
					t.Fatalf("%s accepted a symlink", action)
				}
			}
			if got, err := hostmode.Credentials(c); err != nil || got != "fixture-publisher-identity" {
				t.Fatalf("SSH lifecycle changed native identity: %q %v", got, err)
			}
			if got, _ := os.ReadFile(profile); string(got) != manifest {
				t.Fatal("SSH lifecycle changed host profile")
			}
			// Native and SSH services use separate labels under the same roots.
			spec := hostmode.ServiceSpec{OS: platform, Home: root, ConfigHome: configRoot, Binary: "/fixture/tunn", Config: profile}
			if spec.Path() == definition {
				t.Fatal("SSH service replaced the native host service")
			}
		})
	}
}

const sshFixtureManager = `#!/bin/sh
set -eu
if [ "$1" = '--user' ]; then shift; fi
tunn_fixture_action=$1
printf '%s\n' "$tunn_fixture_action" >> "$TUNN_FIXTURE_STATE/calls"
[ "$tunn_fixture_action" != "$TUNN_FIXTURE_FAIL" ] || exit 1
case "$tunn_fixture_action" in
 show) if [ -e "$TUNN_FIXTURE_STATE/registered" ]; then printf '%s\n' "$TUNN_FIXTURE_DEFINITION"; fi;;
 print|status) test -e "$TUNN_FIXTURE_STATE/registered";;
 daemon-reload) :;;
 enable|bootstrap) touch "$TUNN_FIXTURE_STATE/registered" "$TUNN_FIXTURE_STATE/active";;
 restart|kickstart) test -e "$TUNN_FIXTURE_STATE/registered"; touch "$TUNN_FIXTURE_STATE/active";;
 disable|bootout) rm -f "$TUNN_FIXTURE_STATE/registered" "$TUNN_FIXTURE_STATE/active";;
 *) exit 1;;
esac
`
