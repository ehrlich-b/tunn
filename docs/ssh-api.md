# SSH API

Use OpenSSH to expose a local service without installing the tunn binary. The
relay must have the SSH front door enabled. SSH and HTTPS share raw TCP port
443; the HTTP, TCP, WebSocket, access-control and metering paths are the same
ones used by the normal client.

## First tunnel

An unlinked key can create a short-lived private tunnel with an explicit email
allow-list:

```sh
ssh -T -p 443 -o ExitOnForwardFailure=yes -R0:localhost:8080 tunn.to -- \
  --allow bob@x.com,alice@y.com --allow-domain example.com --expire 2h --name demo --qr
```

The session prints the HTTPS URL, allowed identities, actual expiry and live
request/status lines. Visitors log in with the existing tunn email/GitHub login.
Ctrl-C, an SSH signal, loss of the connection or expiry removes the tunnel.
Use `-T` when piping output; an interactive terminal also works. Keep a session
open when publishing; `-N` does not request a shell or command and therefore
does not publish a remote forward.

Short options can also go in the username:

```sh
ssh -T -p 443 -R0:localhost:8080 'allow+bob@x.com@tunn.to'
ssh -T -p 443 -R0:localhost:8080 qr@tunn.to -- --allow bob@x.com
ssh -T -p 443 -R0:localhost:8080 'qr+allow+bob@x.com@tunn.to'
ssh -T -p 443 tunn.to -- help
```

OpenSSH separates the destination at the last `@`. Comma-separated emails work
in the username value. Use the remote-command form for email addresses with
`+`, quoting or longer option lists. `qr`, `public`, `inspect`, `bearer`, `allow`,
`allow-domain`, `name` and `expire` are recognized username options. Ordinary
local usernames are accepted; the public key determines identity.

The remote command is parsed as arguments, including single/double quotes and
backslash escapes. It is never evaluated by a shell. Both `--flag=value` and
`--flag value` work. HTTP publication uses the CLI's shared flag definitions,
including `--name`/`--id`/`--subdomain`, `--allow`, `--allow-domain`, `--public`,
`--expire`, `--qr`, `--bearer`, `--inspect`, `--require-upstream-auth` and the
WebSocket limits. `--secret` and `--tunnel-key` are rejected over SSH because
SSH key possession supplies publisher authentication.

## Link a key to your account

With the normal CLI already logged in:

```sh
tunn keys add ~/.ssh/id_ed25519.pub
tunn keys list
tunn keys remove SHA256:YOUR_FINGERPRINT
```

Or use email linking from the SSH session:

```sh
ssh -T -p 443 -i ~/.ssh/id_ed25519 tunn.to -- login --email you@example.com
```

The session prints the destination email and account page. Open the one-time
magic link sent to your inbox within five minutes, then reconnect. The email
proof itself is never printed in SSH output: exposing it to an unknown key
would let that key claim someone else's account. SMTP must be configured on
the relay. A key already owned by another identity cannot be overwritten.

From an already linked key, add another public key or manage existing keys:

```sh
ssh -T -p 443 tunn.to -- keys add 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... laptop'
ssh -T -p 443 tunn.to -- keys list
ssh -T -p 443 tunn.to -- keys remove SHA256:YOUR_FINGERPRINT
```

`keys add` with no operand re-adds the authenticating key. The normal CLI takes
a local public-key filename; SSH takes its contents, because the relay cannot
read a file on your machine. Ownership follows verified email buckets when
accounts merge. Every new forward and owner command rechecks ownership.

Linked keys use their account's tunnel count, current plan, monthly quota and
reserved-name rules. Their tunnels require the owner's login by default;
`--allow` adds visitors. To publish a public endpoint explicitly:

```sh
ssh -T -p 443 -R0:localhost:8080 tunn.to -- --name demo --public --qr
```

`--public` cannot be combined with an allow-list or `--bearer`.

Unlinked keys have a 30-minute maximum expiry, 1 Mbps sustained tunnel rate,
10 MiB per key and source IP per admission window, one simultaneous tunnel per
key, and three per source IP. They must supply an allow-list and cannot use
`--public`. Reconnecting or changing keys does not reset the IP budget. Their
synthetic free accounts also pass through ordinary account quotas and ingress
metering. SSH admission is bounded globally, per key and per IP; attempts to
link an email reuse the existing key/IP and email throttles.

After authentication, start a command or a permitted raw connection within
15 seconds. Idle handshakes and PTY-only sessions close automatically. Owner
commands have a 30-second deadline, including reading a service manifest.

## Names, HTTP targets and Unix sockets

```sh
# Requested subdomain; no DNS lookup or port bind occurs on the relay.
ssh -T -p 443 -R demo:80:localhost:8080 tunn.to -- --allow alice@example.com

# Multiple forwards: each named bind address becomes a separate tunnel.
ssh -T -p 443 -R web:80:localhost:8080 -R api-demo:80:localhost:9000 tunn.to -- \
  --allow alice@example.com

# HTTPS on the local side, carried inside SSH.
ssh -T -p 443 -R0:localhost:8443 tunn.to -- \
  --target https://localhost:8443 --skip-local-tls-verify --allow alice@example.com

# OpenSSH forwards the local Unix socket; HTTP ingress uses the normal adapter.
ssh -T -p 443 -R0:/var/run/docker.sock tunn.to -- unix --as http --name docker
```

`--name` applies to a single forward. Use named `-R` addresses for multiple
forwards. `--target` supplies HTTP scheme/path information; the dialer always
opens the corresponding SSH channel. It never dials that URL on the relay's
network. Registration stores the protocol marker, without a local target
address. Platform cookies, owner JWTs, endpoint tokens and grant credentials
are removed before reaching the local service by the usual ingress filters.

## TCP, tokens, inspection and metering

```sh
# Publish a private TCP endpoint.
ssh -T -p 443 -R0:localhost:5432 tunn.to -- tcp --name database

# Open that endpoint locally using a linked, allowed key.
ssh -N -p 443 -L127.0.0.1:15432:database:80 tunn.to

# Obtain the equivalent connection command.
ssh -T -p 443 tunn.to -- connect database

# The owner can read or rotate an SSH-managed endpoint token.
ssh -T -p 443 tunn.to -- token database
ssh -T -p 443 tunn.to -- token --rotate database

# Capture a bounded delivery history, then inspect/replay from another session.
ssh -T -p 443 -R0:localhost:8080 tunn.to -- --name demo --inspect --bearer
ssh -T -p 443 tunn.to -- inspect demo
ssh -T -p 443 tunn.to -- replay demo 1

ssh -T -p 443 tunn.to -- usage demo --since 24h
ssh -T -p 443 tunn.to -- grant create demo --for alice@example.com --expires 1h \
  --rate 60 --monthly-requests 1000 --monthly-bytes 10485760
ssh -T -p 443 tunn.to -- grant list demo
ssh -T -p 443 tunn.to -- grant revoke demo GRANT_ID
ssh -T -p 443 tunn.to -- hosts --json
```

TCP `-L` targets are tunnel names at logical port 80, never arbitrary relay-side
hosts. The endpoint must be online on this SSH relay. The connection goes
through authenticated HTTP CONNECT ingress, including allow-lists, quotas,
metering and half-close handling. `-N` is appropriate for this consuming
connection. Public raw endpoints are prohibited.

Inspection and replay require the owner and `--inspect` at publication time.
The bounded history and SSH-managed tokens live only as long as the forward.
Replay uses the original upstream adapter. Grant and usage commands share the
CLI parser and management implementation. They use this relay and key identity;
`--server`, `--owner-token-file` and `--insecure` do not apply to SSH commands.
`hosts` requires the existing `TUNN_HOST_MODE` registry to be enabled.

## MCP and OpenClaw

```sh
# An already running local Streamable HTTP MCP server.
ssh -T -p 443 -R0:localhost:3000 tunn.to -- mcp --name tools --bearer

# Rewrite the public /mcp path to the local server's custom path.
ssh -T -p 443 -R0:localhost:3000 tunn.to -- mcp --name tools \
  --target http://localhost:3000/internal/mcp --bearer

# Stdio transport: stdin receives the child's JSON-RPC replies; stdout emits
# requests for the local child. URL and status output go to stderr.
ssh -T -p 443 tunn.to -- mcp --stdio --name tools --tools read_file,list_directory

# OpenClaw preview and a private gateway tunnel.
ssh -T -p 443 tunn.to -- openclaw --name home-openclaw
ssh -T -p 443 -R0:localhost:18789 tunn.to -- --name home-openclaw \
  --bearer --require-upstream-auth --qr
```

For stdio MCP, connect your local process's stdout to SSH stdin and SSH stdout
to the process's stdin with a local stdio pump. The process stays on your
machine. No remote command is executed on the relay. The bridge uses tunn's
existing MCP protocol/session handling and tool policy. `--tools` applies only
to stdio MCP, matching the CLI. OpenClaw's QR contains a URL; it does not enroll
a device or bypass the gateway's own authentication.

## Persistent services

Machine-local operations return a script to apply on the caller's machine.
Reuse the normal `host.yaml` manifest; send it on stdin rather than passing a
remote filename. The generated services run OpenSSH with keepalives and native
restart policies, using your local key or SSH agent.

```sh
# Review before running the returned script locally.
ssh -T -p 443 tunn.to -- service install --os linux --config - < host.yaml > install-ssh.sh
sh install-ssh.sh

ssh -T -p 443 tunn.to -- service status --os linux --config - < host.yaml > status-ssh.sh
sh status-ssh.sh
ssh -T -p 443 tunn.to -- service uninstall --os linux --config - < host.yaml > uninstall-ssh.sh
sh uninstall-ssh.sh

# Native definitions only; no installation actions in the returned output.
ssh -T -p 443 tunn.to -- service install --os darwin --dry-run --config - < host.yaml
```

`--os darwin` emits LaunchAgent scripts and `--os windows` emits PowerShell
Scheduled Task scripts. `service run` prints the foreground SSH commands.
Verify the relay's host key and link your client key before installing a
service, because unattended services use `BatchMode=yes`. These ephemeral SSH
forwards do not reserve persistent machines in the separate host-mode registry.
Service manifests also support stdio MCP commands: the returned native service
starts the local process and an OpenSSH stdio pump, and stops both if either exits.

## Relay configuration and Fly.io

Set `TUNN_SSH_HOST_KEY_FILE` to a persistent, operator-generated SSH private key
on the login node. An empty value disables SSH. Key ownership and one-time
link challenges live in the login SQLite database. Non-login nodes fail startup
if SSH is enabled rather than accepting keys against an inconsistent registry.
For an additional plain port-22 listener, set `TUNN_SSH_ADDR=:22`.

```sh
ssh-keygen -t ed25519 -N '' -f /data/ssh_host_ed25519_key
TUNN_SSH_HOST_KEY_FILE=/data/ssh_host_ed25519_key
TUNN_SSH_ADDR=:22
```

Install `qrencode` on the relay for QR output; the supplied runtime Docker image
includes it. TLS certificates and SMTP configuration retain their normal
settings. Distribute the SSH host-key fingerprint through your usual trusted
channel. Client examples deliberately retain OpenSSH host-key verification.

Fly must forward **raw TCP** on 443, with no `http` or `tls` handlers. The
existing `fly.toml.dist` already uses that arrangement. Route SSH-capable
services to the authoritative login process; other processes need a separate
TLS-only service/destination if they do not share that key registry.

```toml
[[services]]
  internal_port = 443
  protocol = "tcp"
  # processes = ["login"] # when using a named login process
  [[services.ports]]
    port = 443
    # No handlers: the host distinguishes SSH banners from TLS ClientHello.

[[services]]
  internal_port = 22
  protocol = "tcp"
  [[services.ports]]
    port = 22
```

The UDP/443 service still serves HTTP/3. SSH uses TCP. One SSH connection owns
one session; use a fresh SSH connection for each owner command, rather than
reusing a ControlMaster session that already owns a publishing command.

## Verification

```sh
GOPROXY=off GOSUMDB=off make vet test-ssh
GOPROXY=off GOSUMDB=off make test
```

The SSH tests run real `x/crypto/ssh` clients and TLS requests over bounded
in-memory connections. They cover forwarding, access denial, credential
filtering, ordinary metering/grants, anonymous limits, key linking, token
rotation, request inspection/replay, raw TCP half-close, stdio MCP and expiry.
Existing socket-based tests remain mandatory and may need an environment that
permits loopback binds.
