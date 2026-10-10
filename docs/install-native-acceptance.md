# Native acceptance command plan — REQUIRED/UNRUN

These commands are a dry-run plan for Bryan. None are executed by the fixture
gate or by the agent. Use disposable, nonproduction hosts and a compatible
standalone test relay. If testing on a real host, Bryan owns every mutation and
the maintenance window. Confirm an independent console/admin connection before
disconnecting tunn. Do not delete or replace an existing user's task, service,
profile, account or tokens to make the test pass.

Stage the checkout/helper files and architecture-correct binaries independently.
Use Python 3.9+, systemd on Linux/WSL, and a current-user Windows ACL for secrets.
Windows binaries must be built/staged separately; the existing release matrix
does not provide them. Resolve license packaging before redistributing anything.

## Common POSIX inputs and assertions

Run in the staged personal checkout. Set these to the previously configured
installation; no agent needs the credential plaintext:

```sh
install_root="$HOME/.local/lib/tunn-install"
binary="$install_root/bin/tunn"
profile="$HOME/.config/tunn/host.yaml"
credential_root="$HOME/.local/state/tunn-host/credentials"
mkdir -p .scratch/native-acceptance
"$binary" service check --config "$profile"
"$binary" hosts --config "$profile" --json > .scratch/native-acceptance/hosts-before.json
shasum -a 256 "$credential_root"/endpoints/*.token > .scratch/native-acceptance/tokens-before.txt
```

Check that the configured machine, account and exact endpoint names are the
intended ones. A missing endpoint file before first connection is expected;
take the digest baseline after the first successful ready state in that case.

## macOS logged-in user

Preview and lint before activation; the configured user must have a GUI domain:

```sh
"$binary" service install --config "$profile" --dry-run --os darwin \
  > .scratch/native-acceptance/com.tunn.host.plist
plutil -lint .scratch/native-acceptance/com.tunn.host.plist
"$binary" service install --config "$profile"
"$binary" service install --config "$profile"
"$binary" service status --config "$profile"
curl --fail --retry 20 --retry-delay 3 --retry-connrefused --max-time 5 --noproxy '*' http://127.0.0.1:9087/readyz
"$binary" service restart --config "$profile"
curl --fail --retry 20 --retry-delay 3 --retry-connrefused --max-time 5 --noproxy '*' http://127.0.0.1:9087/readyz
"$binary" service uninstall --config "$profile"
"$binary" service uninstall --config "$profile"
"$binary" service install --config "$profile"
```

Allow the documented reconnect backoff before the second readiness probe. Also
verify logout/login behavior in the disposable user session: this is a login
agent, not a boot daemon. Required fault window: renewal of an expired test
account login in the same credential directory followed by restart. Do not
edit a token's signed claims or use another account as recovery.

## Linux user manager

```sh
"$binary" service install --config "$profile" --dry-run --os linux \
  > .scratch/native-acceptance/tunn-host.service
systemd-analyze --user verify .scratch/native-acceptance/tunn-host.service
"$binary" service install --config "$profile"
"$binary" service install --config "$profile"
"$binary" service status --config "$profile"
curl --fail --retry 20 --retry-delay 3 --retry-connrefused --max-time 5 --noproxy '*' http://127.0.0.1:9087/readyz
"$binary" service restart --config "$profile"
curl --fail --retry 20 --retry-delay 3 --retry-connrefused --max-time 5 --noproxy '*' http://127.0.0.1:9087/readyz
"$binary" service uninstall --config "$profile"
"$binary" service uninstall --config "$profile"
"$binary" service install --config "$profile"
```

Verify a repeat install leaves one process, and that a foreign system or user
fragment is refused. The first-install `systemctl --user show
--property=FragmentPath --value tunn-host.service` must return an empty fragment
for an absent unit; this native behavior remains an acceptance gate. Test login
session/logout semantics; lingering is an independent administrator decision.

## Native Windows interactive user

PowerShell, in the staged checkout, using the same prepared v1 profile:

```powershell
$InstallRoot = Join-Path $env:LOCALAPPDATA 'tunn-install'
$Binary = Join-Path $InstallRoot 'bin\tunn.exe'
$Profile = Join-Path $env:USERPROFILE '.config\tunn\host.yaml'
$Credentials = Join-Path $env:LOCALAPPDATA 'tunn-host\credentials'
$Acceptance = Join-Path (Get-Location) '.scratch\native-acceptance'
New-Item -ItemType Directory -Force $Acceptance | Out-Null
function Invoke-Tunn {
  & $Binary @args
  if ($LASTEXITCODE -ne 0) { throw "tunn failed with exit $LASTEXITCODE" }
}
icacls $Profile
icacls $Credentials
Invoke-Tunn service check --config $Profile
Invoke-Tunn service install --config $Profile --dry-run --os windows |
  Set-Content -Encoding utf8 (Join-Path $Acceptance 'tunn-host-task.xml')
[xml](Get-Content -Raw (Join-Path $Acceptance 'tunn-host-task.xml')) | Out-Null
Invoke-Tunn service install --config $Profile
Invoke-Tunn service install --config $Profile
Invoke-Tunn service status --config $Profile
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:9087/readyz
Invoke-Tunn service restart --config $Profile
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:9087/readyz
Invoke-Tunn service uninstall --config $Profile
Invoke-Tunn service uninstall --config $Profile
Invoke-Tunn service install --config $Profile
Get-ChildItem (Join-Path $Credentials 'endpoints\*.token') | Get-FileHash -Algorithm SHA256
```

`Invoke-Tunn` stops this plan on a nonzero native exit. Review current-user ACLs locally;
`service check` cannot validate Windows ACL privacy. Prove one Task Scheduler
process, logon/battery behavior, and stop/delete of both a running and an already
stopped task. A failed `/End` must not be ignored or followed by a green removal
claim. Retain the XML and use Task Scheduler through the independent admin route
to diagnose a stopped-task error. Test stopped-binary replacement and rollback
with `py -3 deploy/install/artifacts.py ...`; running-file lock errors must retain
the prior selection.

## WSL

Inside the distro, use the Linux command block and Linux binary. Store profiles
and credentials on the distro's Linux filesystem, outside `/mnt/c`. Verify
recovery after Windows sleep/resume and WSL shutdown/relaunch. Starting Windows
alone does not start WSL. A Windows autostart task or `/etc/wsl.conf` change is a
separate owner action; this path creates neither.

## Verify recovery and upgrades on each platform

After reinstall/restart and ready state, compare exact host names/ownership and
endpoint-token digests to the baseline. A newly generated machine or token does
not satisfy continuity. On POSIX:

```sh
"$binary" hosts --config "$profile" --json > .scratch/native-acceptance/hosts-after.json
shasum -a 256 "$credential_root"/endpoints/*.token > .scratch/native-acceptance/tokens-after.txt
diff -u .scratch/native-acceptance/tokens-before.txt .scratch/native-acceptance/tokens-after.txt
```

Inventory timestamps/status legitimately change; compare machine/name/account
ownership, not byte equality of JSON. Run the exact maintenance-window
install/rollback commands in [install-recovery.md](install-recovery.md) with two
independently approved artifacts, and recheck these assertions. For the legacy
AI-host kit use its default rotation canary; for persistent host-mode forge/rig
use the same canary command with `--token-lifecycle preserve` in both phases.
Retain Bryan's fault/restart timing beside private receipts. The canary's
hardcoded tunn.to authority requires a separately verified compatible hosted
relay; it is not the isolated self-host test or authorization to change that relay.

Real phone/OpenClaw application login, pairing and repeat use on both physical
hosts remain separate E2/day-14 gates. A socket probe or unit-preview success
does not mark them accepted.

## Remaining coordinator command

After staging offline dependencies, run all local promotion gates in one
socket-capable clone. On macOS, with the environment from the install guide:

```sh
taskpolicy -b nice -n 15 make -j1 build vet test-ai-hosts test-hostmode-compile
taskpolicy -b nice -n 15 make -j1 test-hostmode
bash -n scripts/verify-install-recovery.sh
bash scripts/verify-install-recovery.sh --fixtures
taskpolicy -b nice -n 15 make -j1 test-hostmode-loopback
taskpolicy -b nice -n 15 make -j1 test-race
git diff --check
```

No release, deployment or service-install Make target belongs in the clone gate.
