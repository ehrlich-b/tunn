# AI host dogfood kit

This kit prepares `forge` (Debian) and `rig` (the Linux side of WSL2) as tunn
publishers. It is a supervised canary, pending the gates and reliability limits
in [SECURITY.md](SECURITY.md). Nothing here installs a relay or changes tunn.to.
The coordinator may stage files and run read-only checks. Bryan runs login and
any production start, stop, restart, rotation, or deployment commands himself.

## Configuration and layout

Use the patched tunn CLI from this branch, Python 3.9+, and an already installed
`wt` supporting `wt mcp stdio`. On each host, run as the user who owns wingthing
and the dashboard. SSH must already listen on `127.0.0.1:22`; the kit does not
install or reconfigure sshd, wingthing, or the dashboard.

| Endpoint | Local target | Visitor authentication |
| --- | --- | --- |
| `forge-ssh` / `rig-ssh` | `127.0.0.1:22` | Endpoint token, then SSH key and pinned host key |
| `forge-wt` / `rig-wt` | `wt mcp stdio` | Endpoint token; exact reviewed tool list |
| `forge-dashboard` / `rig-dashboard` | HTTP on loopback, configured port | Verified email allow-list and browser login, or account JWT |

Both hosts require six simultaneous tunnels. Free accounts permit three;
the Pro limit is ten. Check Bryan's existing plan before starting both hosts;
this kit never changes billing. Pro automatically reserves at most four names,
so it does not guarantee ownership of all six names while offline.

```text
~/.config/tunn-ai-hosts/host.json               0600; paths and policy, no secrets
~/.local/lib/tunn-ai-hosts/                    kit.py, runner.py, canary.py, wsl-run.sh
~/.local/state/tunn-ai-hosts/<forge|rig>/       0700
    credentials/                             0700; TUNN_CONFIG_DIR
        token                                0600; publisher login JWT
        endpoints/                           0700
            <host>-ssh.token                 0600; generated at publisher start
            <host>-wt.token                  0600; generated at publisher start
    logs/                                    0700; each file 0600
        ssh.log[.1-.3], wt.log[.1-.3], dashboard.log[.1-.3]
    <service>.lock, <service>.json             0600; locks and local process status
```

Each log is approximately 1 MiB plus one bounded entry, with three backups:
about 12 MiB across the three publishers. Child output lines over 4 KiB are
discarded; common endpoint tokens, JWTs, and Authorization values are redacted.
Wingthing stderr can contain other sensitive data, so logs remain private.
No request inspector or trace logging is enabled. Tokens belong on the WSL
distro's Linux filesystem, under its home directory, never `/mnt/c` or a repo.

Copy `host.json.example` to the host configuration location with mode 0600.
Replace all placeholders, set `host` to `forge` or `rig`, give absolute Linux
paths to the two executables and wingthing's working directory, set the actual
dashboard port/path, and enter Bryan's verified tunn account email. Choose a
nonempty list of exact wingthing tool names after reviewing local `tools/list`.
The runner refuses placeholder emails/tools, wildcard domains, empty tool
policies, and unsafe configuration permissions. Dashboard health must be a
read-only GET returning 200 without a redirect, with a distinctive page marker
for the remote canary. No MCP `tools/call` is performed by the canary.

The generated commands are:

```sh
tunn tcp --name forge-ssh 127.0.0.1:22
tunn mcp --name forge-wt --tools REVIEWED_EXACT_TOOLS -- wt mcp stdio
tunn serve --id=forge-dashboard --allow=VERIFIED_EMAIL http://127.0.0.1:DASHBOARD_PORT
```

The actual runner also selects error-level logging and explicitly sets
`TUNN_ENV=prod`, `TUNN_PUBLIC_MODE=false`, and the tunn.to server/domain. This is
required: the CLI currently defaults to dev configuration when `TUNN_ENV` is
unset, which skips TLS verification. It clears inherited tunn variables and
sets an empty `TUNN_SECRET` to prevent accidental secret authentication through
the working directory's `.env`. Neither raw endpoint uses `--public` or an
additional email allow-list; the creator identity is implicit. The dashboard
always supplies a nonempty exact email allow-list.

## Stage files and verify locally

The coordinator prepares these commands with the actual checkout path. These
are user-space host installation commands for Bryan to run on production hosts:

```sh
kit_dir=/absolute/path/to/checkout/deploy/ai-hosts
install -d -m 700 "$HOME/.config/tunn-ai-hosts" "$HOME/.local/lib/tunn-ai-hosts"
install -d -m 700 "$HOME/.config/systemd/user"
install -m 644 "$kit_dir/kit.py" "$kit_dir/runner.py" "$kit_dir/canary.py" "$HOME/.local/lib/tunn-ai-hosts/"
install -m 755 "$kit_dir/wsl-run.sh" "$HOME/.local/lib/tunn-ai-hosts/"
install -m 644 "$kit_dir/systemd/tunn-ai-hosts@.service" "$HOME/.config/systemd/user/"
# First install only; do not overwrite a configured host.json on an update.
install -m 600 "$kit_dir/host.json.example" "$HOME/.config/tunn-ai-hosts/host.json"
```

After configuration, the coordinator can check the generated commands without
login, token access, network access, or starting any service:

```sh
python3 "$HOME/.local/lib/tunn-ai-hosts/runner.py" check --config "$HOME/.config/tunn-ai-hosts/host.json"
systemd-analyze --user verify "$HOME/.config/systemd/user/tunn-ai-hosts@.service"
```

The systemd verification command is for Linux/WSL with systemd installed.
Build tunn locally with `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local make build`, then install the
binary for the host's architecture as part of Bryan's host deployment. A Mac
build is not a Linux binary. Use `make build-linux` only for an amd64 host; its
artifact is `tunn-linux`. For another architecture use the existing `make build`
with appropriate `GOOS` and `GOARCH`. Dependencies must already be cached for
offline builds. No automatic package downloads, upgrades, or relay deployments
are part of this kit.

## What Bryan must do

1. Confirm the full test gates and relay compatibility from [DOGFOOD.md](DOGFOOD.md).
2. Review the actual email, tool list, dashboard port, Linux executables, SSH
   account/key, and each host's SSH host-key fingerprint at its trusted console.
3. Confirm capacity for six tunnels in his existing account.
4. On each host, complete browser authorization himself. No coordinator receives
   login codes, account tokens, or endpoint token plaintext in chat or logs:

```sh
ai_host=forge                         # use rig inside its WSL distro
credential_dir="$HOME/.local/state/tunn-ai-hosts/$ai_host/credentials"
install -d -m 700 "$credential_dir"
TUNN_ENV=prod TUNN_CONFIG_DIR="$credential_dir" "$HOME/.local/bin/tunn" login
```

Use the configured binary path if it differs. On headless Debian or WSL, open
the printed login URL on the Mac, verify its code, and authorize. The patched
CLI atomically saves a mode-0600 account JWT in this isolated directory.
It expires after **24 hours**; there is no automatic refresh.

Bryan then starts the publishers on each host:

```sh
systemctl --user daemon-reload
systemctl --user enable --now tunn-ai-hosts@ssh tunn-ai-hosts@wt tunn-ai-hosts@dashboard
```

User systemd restarts a failed supervisor after 15 seconds, with at most five
starts per five minutes. Inside the supervisor, publisher exits retry with
5–60 second backoff; relay disconnects use tunn's own 1–30 second reconnect
backoff. SIGTERM shuts down the process group; systemd kills any remaining
group members after 15 seconds. A second copy of a publisher is refused by a
per-service lock. If an expired login exhausts systemd's start limit, Bryan
must relogin, then run `systemctl --user reset-failed` for these units before
restarting them. An updated login JWT is loaded only by new tunn processes.

To run across logout on Debian, Bryan may enable lingering for his own user:
`sudo loginctl enable-linger "$USER"`. This is an optional host mutation for
Bryan, not a coordinator action. WSL can use the same user units if systemd
is already enabled. Without a user manager, Bryan can run the foreground
fallback in a dedicated WSL terminal:

```sh
"$HOME/.local/lib/tunn-ai-hosts/wsl-run.sh"
```

Ctrl-C stops all three publisher groups. WSL shutdown, Windows sleep, or closing
the terminal kills availability. If unattended Windows startup is desired,
Bryan must explicitly configure a Task Scheduler task in his own Windows login
to run `wsl.exe -d DISTRO --exec /home/USER/.local/lib/tunn-ai-hosts/wsl-run.sh`
(replace both placeholders). The kit creates no Windows task or systemd setting.

## What the coordinator can run after credentials exist

On the host, this local read-only health check checks private credential modes,
login expiry, supervisor/child liveness, the SSH banner, and the dashboard GET:

```sh
python3 "$HOME/.local/lib/tunn-ai-hosts/runner.py" health --config "$HOME/.config/tunn-ai-hosts/host.json"
```

It is a local diagnostic; process status can be stale or refer to reused PIDs,
and it does not prove relay registration or wingthing protocol health. Use the
remote canary for those checks. Health failure never automatically rotates
credentials, restarts hosts, or logs in.

Bryan securely copies the two generated endpoint files to the Mac's private
consumer directory, preserving mode 0600, using a channel he already trusts.
The files are `credentials/endpoints/<host>-ssh.token` and `<host>-wt.token`.
Do not run `tunn token` in a captured terminal: it prints the credential.
The kit does not transfer files or expose account credentials to the hosts'
remote consumers. The Mac's directory should be mode 0700:
`~/.local/state/tunn-ai-hosts/consumer/`.

For an ordinary SSH connection from the Mac:

```sh
TUNN_ENV=prod tunn connect --listen 127.0.0.1:2222 \
  --token-file "$HOME/.local/state/tunn-ai-hosts/consumer/forge-ssh.token" forge-ssh
# In a second terminal; use a known_hosts file provisioned from the trusted console.
ssh -p 2222 -o StrictHostKeyChecking=yes -o HostKeyAlias=forge-tunn \
  -o UserKnownHostsFile="$HOME/.ssh/tunn_known_hosts" -o ForwardAgent=no USER@127.0.0.1
```

Use `rig-ssh` and `HostKeyAlias=rig-tunn` for rig, choosing another local port
if forge's connector is still running. `tunn connect` supplies HTTP/2 CONNECT;
no public raw SSH port is allocated. Keep the local listener on loopback.

For the complete read-only canary, Bryan first authorizes a separate Mac login
in `~/.local/state/tunn-ai-hosts/mac-login/`, using the same explicit
`TUNN_ENV=prod TUNN_CONFIG_DIR=... tunn login` command. Its account JWT is needed
only to test the email-protected dashboard; the two endpoint tokens cannot
authenticate there. Pin SSH host keys in a separate mode-0600 known_hosts file
with aliases `forge-tunn` and `rig-tunn`, comparing fingerprints at each trusted
host console. Do not disable host-key checks or use blind `ssh-keyscan` output.

On the Mac, the coordinator runs (replace uppercase values and use absolute paths):

```sh
python3 /ABSOLUTE/kit/canary.py --phase before --host forge \
  --tunn-binary /ABSOLUTE/bin/tunn \
  --token-dir "$HOME/.local/state/tunn-ai-hosts/consumer" \
  --dashboard-token-file "$HOME/.local/state/tunn-ai-hosts/mac-login/token" \
  --ssh-user USER --identity-file "$HOME/.ssh/id_ed25519" \
  --known-hosts "$HOME/.ssh/tunn_known_hosts" --expected-hostname HOSTNAME \
  --expected-tools TOOL_ONE,TOOL_TWO --dashboard-path / \
  --dashboard-marker 'DISTINCTIVE PAGE TEXT' \
  --receipt "$HOME/.local/state/tunn-ai-hosts/consumer/forge-baseline.json"
```

The canary checks absent/wrong tokens, a fresh connector and a fixed SSH
`printf`/`hostname` command, private MCP discovery and exact `tools/list`, and
anonymous/authenticated HTTPS dashboard access. It never calls MCP tools,
follows redirects, skips certificate checks, logs credential values, or changes
the host. It ignores SSH config, uses a pinned host key and explicit key file,
and disables agent forwarding. Stop any existing listener on 2222 first.
Use `--listen-port` for a different port. The baseline receipt stores only
configuration and SHA-256 token digests, with mode 0600, never token plaintext.

Bryan then restarts all three publishers on the host:

```sh
systemctl --user restart tunn-ai-hosts@ssh tunn-ai-hosts@wt tunn-ai-hosts@dashboard
```

For the foreground WSL runner, Bryan stops it with Ctrl-C and starts it again.
Starting new SSH/MCP publishers **replaces their endpoint tokens**. Bryan must
copy the fresh files to the Mac before the coordinator reruns the exact canary
command with `--phase after` and the same receipt. The after phase rejects
unchanged token digests and repeats all checks with a new connector; it proves
fresh connections work, not preservation of an existing SSH connection.
The SSH reconnect probe quietly retries up to 90 seconds with backoff. MCP and
dashboard checks have 30-second request deadlines; run after host local health
passes. Repeat this whole procedure separately for rig with its own receipt.

## Rotation and stop commands for Bryan

Rotate a live endpoint locally without printing its token into logs:

```sh
TUNN_ENV=prod TUNN_CONFIG_DIR="$credential_dir" tunn token --rotate "$ai_host-ssh" >/dev/null
TUNN_ENV=prod TUNN_CONFIG_DIR="$credential_dir" tunn token --rotate "$ai_host-wt" >/dev/null
```

New requests normally see the new digest within one second. Copy updated files
to consumers and restart their connector processes, which load tokens once.
Rotation does not cancel existing streams or already forwarded MCP work.
For immediate disconnection Bryan stops the publishers:

```sh
systemctl --user disable --now tunn-ai-hosts@ssh tunn-ai-hosts@wt tunn-ai-hosts@dashboard
```

Keep credential files for later resumption or delete them manually according to
Bryan's policy. Stopping the publisher removes the active endpoint; a credential
file alone cannot keep it accessible. Account login JWT revocation is separate
from endpoint rotation and is not implemented by this kit.
