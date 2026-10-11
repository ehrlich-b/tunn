# Install the account-only forge SSH publisher

These are reviewed commands for **Bryan to run himself**, as `ehrlich` on
forge and as himself on each laptop. The coordinator prepares artifacts and
runs offline checks; agents never execute production mutations. No root or
sudo is needed. **Do not touch `forgetunnel`, `hometunnel`, or sshd**: do not
stop/restart/edit their services, forwarding, SSH keys, or configuration.
This also leaves the installed general-purpose `tunn` binary alone.

## 1. Prepare binaries on the Mac coordinator workstation

Build from this branch's committed checkout. Go caches and artifacts remain
local to this clone. The module-cache source is the workstation's existing
download cache; missing dependencies fail rather than contacting a registry.

```sh
cd /Users/ehrlich/repos/w9-tunn-forge-ssh-20261011
mkdir -p .scratch/go-build .scratch/go-mod .scratch/tmp
export GOCACHE="$PWD/.scratch/go-build"
export GOMODCACHE="$PWD/.scratch/go-mod"
export GOTMPDIR="$PWD/.scratch/tmp"
export GOTOOLCHAIN=local GOSUMDB=off
export GOPROXY=file:///Users/ehrlich/go/pkg/mod/cache/download
taskpolicy -b nice -n 15 go build -o .scratch/tunn-forge-ssh-mac .
# Choose the architecture shown by uname -m on forge: x86_64=amd64, aarch64=arm64.
forge_arch=amd64
taskpolicy -b nice -n 15 env GOOS=linux GOARCH="$forge_arch" CGO_ENABLED=0 \
  go build -o .scratch/tunn-forge-ssh-linux .
shasum -a 256 .scratch/tunn-forge-ssh-mac .scratch/tunn-forge-ssh-linux
```

Transfer the Linux binary and
`deploy/ai-hosts/systemd/tunn-forge-ssh.service` through the existing trusted
management route to **new staging files** on forge:
`$HOME/tunn-forge-ssh-stage/tunn-forge-ssh-linux` and
`$HOME/tunn-forge-ssh-stage/tunn-forge-ssh.service`. Compare the Linux SHA-256
with the workstation result (`sha256sum` on forge). Do not overwrite a live
binary during transfer. No production relay artifact is built or installed.

## 2. Check prerequisites on forge, as ehrlich

```sh
set -eu
test "$(id -un)" = ehrlich
uname -m
loginctl show-user ehrlich -p Linger
systemctl --user show-environment >/dev/null
systemctl --user is-active tunn-ai-hosts@ssh.service || true
ss -ltn '( sport = :22 )'
python3 - <<'PY'
import socket
with socket.create_connection(("127.0.0.1", 22), timeout=5) as connection:
    banner = connection.recv(256)
    assert banner.startswith(b"SSH-"), banner
    print(banner.decode("ascii", "replace").strip())
PY
sha256sum "$HOME/tunn-forge-ssh-stage/tunn-forge-ssh-linux"
```

Stop here if the user manager or loopback SSH listener is unavailable. Do not
enable systemd, alter sshd, change firewall rules, or install packages in this
procedure. `Linger=yes` is required for availability across logout/boot without
an active login; `Linger=no` means the unit relies on the user login session.
No privileged lingering change is included.

If `tunn-ai-hosts@ssh` is active, it also claims `forge-ssh`; do not start a
second publisher or stop the old one as part of this installation. Resolve
that naming conflict separately. Ensure Bryan's account has one available
tunnel slot (free: 3, Pro: 10). Existing names/reservations remain in force;
this guide does not reserve a name or change billing.

## 3. Install and log in on forge

For a first installation only (the `test ! -e` checks intentionally refuse an
overwrite of another installed copy):

```sh
set -eu
umask 077
install -d -m 700 "$HOME/.local/bin" "$HOME/.config/systemd/user"
install -d -m 700 "$HOME/.local/state/tunn-forge-ssh/credentials"
test ! -e "$HOME/.local/bin/tunn-forge-ssh"
test ! -e "$HOME/.config/systemd/user/tunn-forge-ssh.service"
install -m 755 "$HOME/tunn-forge-ssh-stage/tunn-forge-ssh-linux" \
  "$HOME/.local/bin/tunn-forge-ssh"
install -m 644 "$HOME/tunn-forge-ssh-stage/tunn-forge-ssh.service" \
  "$HOME/.config/systemd/user/tunn-forge-ssh.service"
systemd-analyze --user verify "$HOME/.config/systemd/user/tunn-forge-ssh.service"
cd "$HOME/.local/state/tunn-forge-ssh"
env -i HOME="$HOME" PATH=/usr/local/bin:/usr/bin:/bin \
  TUNN_ENV=prod TUNN_PUBLIC_MODE=false TUNN_SECRET= \
  TUNN_SERVER_ADDR=tunn.to:443 TUNN_DOMAIN=tunn.to \
  TUNN_CONFIG_DIR="$HOME/.local/state/tunn-forge-ssh/credentials" \
  "$HOME/.local/bin/tunn-forge-ssh" login
```

Open the printed URL in Bryan's browser, match the device code, and authorize
**Bryan's tunn account**. This identity determines the endpoint's only grant;
no email placeholder, `--allow`, endpoint token transfer, or SSH-front-door key
link is needed. Do not display the saved token. Then start only the new unit:

```sh
systemctl --user daemon-reload
systemctl --user enable --now tunn-forge-ssh.service
systemctl --user status --no-pager tunn-forge-ssh.service
journalctl --user -u tunn-forge-ssh.service -n 20 --no-pager
```

An active process alone does not prove relay registration. The laptop SSH
verification below proves the complete path. Never paste account tokens into
chat or captured logs. No commands target either droplet tunnel or sshd.

## 4. Pin forge's SSH host key

At the trusted forge console, read the **public** key and fingerprint:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
cat /etc/ssh/ssh_host_ed25519_key.pub
```

Copy the public key into the laptop's private
`~/.ssh/forge-tunn_known_hosts` as one line:

```text
forge-tunn ssh-ed25519 BASE64_PUBLIC_HOST_KEY_FROM_FORGE
```

Use the existing configured host-key type if forge does not have an Ed25519
host key. Never copy a host private key, blindly trust `ssh-keyscan`, or change
sshd. On the laptop, create the file without overwriting an existing pin:

```sh
install -d -m 700 "$HOME/.ssh"
(set -C; umask 077; cat > "$HOME/.ssh/forge-tunn_known_hosts")
# Paste the verified public-key line above, then press Ctrl-D.
ssh-keygen -lf "$HOME/.ssh/forge-tunn_known_hosts"
```

Compare the fingerprint to the trusted forge console result before connecting.
If the pin file already exists, inspect its fingerprint and retain it when it
matches; do not replace a differing key automatically.

## 5. Install the laptop helper and log in

Run on the Mac with the binary prepared in step 1. On another laptop, build
the same committed CLI for that OS/architecture and use it at this path.

```sh
set -eu
umask 077
install -d -m 700 "$HOME/.local/bin" "$HOME/.local/state/tunn-forge-ssh/credentials"
test ! -e "$HOME/.local/bin/tunn-forge-ssh"
install -m 755 /Users/ehrlich/repos/w9-tunn-forge-ssh-20261011/.scratch/tunn-forge-ssh-mac \
  "$HOME/.local/bin/tunn-forge-ssh"
env -i HOME="$HOME" PATH=/usr/local/bin:/usr/bin:/bin \
  TUNN_ENV=prod TUNN_PUBLIC_MODE=false TUNN_SECRET= \
  TUNN_SERVER_ADDR=tunn.to:443 TUNN_DOMAIN=tunn.to \
  TUNN_CONFIG_DIR="$HOME/.local/state/tunn-forge-ssh/credentials" \
  "$HOME/.local/bin/tunn-forge-ssh" login
```

Authorize the **same Bryan account** on this laptop. Each machine keeps its
own login JWT. Add this stanza near the start of `~/.ssh/config`, before an
existing `Host forge` or `Host *` stanza so these first-obtained values win:

```sshconfig
Host forge
    HostName forge-ssh.tunn.to
    User ehrlich
    Port 22
    ProxyCommand /usr/bin/env -i HOME=$HOME PATH=/usr/local/bin:/usr/bin:/bin TUNN_ENV=prod TUNN_PUBLIC_MODE=false TUNN_SECRET= TUNN_SERVER_ADDR=tunn.to:443 TUNN_DOMAIN=tunn.to TUNN_CONFIG_DIR=$HOME/.local/state/tunn-forge-ssh/credentials $HOME/.local/bin/tunn-forge-ssh connect --stdio --account forge-ssh
    HostKeyAlias forge-tunn
    UserKnownHostsFile ~/.ssh/forge-tunn_known_hosts
    StrictHostKeyChecking yes
    ForwardAgent no
    PubkeyAuthentication yes
    PreferredAuthentications publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    ServerAliveInterval 30
    ServerAliveCountMax 3
    ControlMaster no
    ControlPath none
```

The long `ProxyCommand` is one line. ssh runs it through your shell, which expands `$HOME`; OpenSSH does not accept `%d` in `ProxyCommand`.
The clean environment protects this path from a working-directory `.env` or
inherited development/public/endpoint-token settings. The unit and stanza
explicitly select TLS-verified production client settings. If the laptop
requires an outbound proxy, explicitly add its reviewed `HTTPS_PROXY` (or
`ALL_PROXY`) to the environment list; do not include a proxy password in SSH
config. If the existing SSH key is not a default key or in the local agent,
add `IdentityFile ~/.ssh/YOUR_EXISTING_FORGE_KEY`. No key installation or sshd
change is included. `Port 22` is SSH metadata; the helper contacts HTTPS/443.

Inspect the effective config before the first connection, then verify:

```sh
ssh -G forge | awk '/^(hostname|user|port|proxycommand|hostkeyalias|stricthostkeychecking|forwardagent|controlpath) /'
ssh -o BatchMode=yes -o ConnectTimeout=20 forge 'hostname; id -un'
ssh forge
```

Expect forge's hostname and `ehrlich`. Test from a network without the VPN to
verify the intended route. `ControlPath none` forces a fresh connection rather
than reusing an older droplet/VPN session. Both tunn admission and sshd's
existing key authentication must pass; no password prompt or trust-on-first-use
host-key prompt should be needed.

## Recovery and removal, Bryan only

Both logins expire after 24 hours without automatic refresh. On the laptop,
repeat its login command, then reconnect. On forge, repeat the forge login
command and run only:

```sh
systemctl --user restart tunn-forge-ssh.service
```

The restart disconnects SSH sessions using this publisher. The unit restarts a
failed publisher after 30 seconds and reads new credentials at process startup;
no start-limit reset is needed. A live publisher's internal reconnects retain
the token it loaded previously. Keep a trusted independent management route
for recovery. Stopping this publisher immediately revokes this transport:

```sh
systemctl --user disable --now tunn-forge-ssh.service
```

This leaves credentials, binaries, SSH config, and the host-key pin for explicit
retention/removal later. Do not delete an account token as a claim of server-side
revocation, and do not alter either droplet tunnel or sshd.

## Coordinator loopback acceptance

On an ordinary **development/test** host that permits loopback, before any
production installation, run the repo's full `go vet ./...` and `go test ./...`
with local clone caches. On macOS use `taskpolicy -b nice -n 15` as above. The
focused transport acceptance includes:

```sh
taskpolicy -b nice -n 15 go test -race -count=1 -timeout=60s \
  -run '^(TestForgeSSH.*|TestConnectStdio.*|TestLoopbackConnectStdioHTTP2|TestConnectClientOverHTTP2CONNECT|TestInboundConnectionStreamsTCP)$' \
  . ./internal/client ./internal/host
```

`TestLoopbackConnectStdioHTTP2`, `TestConnectClientOverHTTP2CONNECT`, and
`TestInboundConnectionStreamsTCP` need real loopback sockets; memory-only
`TestForgeSSH*` and `TestConnectStdio*` do not. Linux unit verification also
belongs on a Linux host with a user manager. Never weaken authentication or
claim the denied loopback tests passed inside this sandbox.

Also run `taskpolicy -b nice -n 15 make integration-test-ai` for the existing
local TLS relay/publisher/CLI TCP echo, concurrent streams, half-close, token
denials, and publisher reconnect gate. It targets disposable loopback services,
not tunn.to.

## Recorded local validation (2026-10-11)

`go vet ./...` passed. The focused Go race tests passed in the CLI, client, and
host packages, including verified TLS/HTTP/2 over the memory transport, private
account-only registration on the unchanged relay, account grant revocation,
stream EOF, cancellation, and denied credentials. All 21 existing ai-hosts
Python tests passed. Mac arm64 and Linux amd64 builds passed. The install shell
blocks passed `sh -n`, and the SSH stanza passed local `ssh -G` inspection.
Linux systemd verification remains a coordinator check.

`go test ./...` was attempted against the final Go code and failed on these
loopback-dependent tests with `bind: operation not permitted`:

```text
internal/client: TestLoopbackConnectStdioHTTP2
internal/host: TestLoopbackEdgeOpenSSHAndHTTPSSharePort, TestLoopbackHostMode
internal/mcpbridge:
  TestBridgeMCPFlow
  TestBridgeOfficialGoSDKClient
  TestBridgeModernHeadersAndSessionlessCalls
  TestBridgeCarriesFiniteSSENotifications
  TestBridgeRejectsChildRequestsWithoutDeadlock
  TestBridgeEnforcesLocalToolAllowList
  TestBridgeValidatesHTTPEnvelope
  TestBridgeReportsChildExit
  TestBridgeFailsRequestWhenChildExits
```

The client and host package tests aborted at their listener panics; later tests
in those packages were not all reached. The full ordinary-host suite and the
named loopback acceptance above are still required. No production login,
publisher, SSH connection, deployment, restart, or configuration change was
executed by the agent.
