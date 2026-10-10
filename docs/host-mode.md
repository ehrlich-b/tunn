# Persistent machine endpoints

Start with the [versioned install/recovery path](install-recovery.md) and its
[native acceptance plan](install-native-acceptance.md). The commands below
describe the host capability; native activation remains an owner-run gate.

Host mode keeps named, private capabilities on a GPU box or agent server
reachable while the user's service is running. It requires a relay with the
experimental `TUNN_HOST_MODE=true` feature enabled. This branch does not enable
the feature on the hosted service.

## Configure a machine

Log in with `tunn login`, then create `~/.config/tunn/host.yaml` (or
`$XDG_CONFIG_HOME/tunn/host.yaml`). Use mode 0600. Names are globally unique
within a relay; prefix them with a machine or account name.

```yaml
version: 1
machine: home-gpu
server: tunnel.example.com:443
domain: tunnel.example.com
health: 127.0.0.1:9087
# Pin this directory across terminal and daemon environments (absolute path):
# credentials_dir: /home/bryan/.local/state/tunn-host/credentials
# Optional: absolute path to a login JWT or a self-hosted per-user token.
# token_file: /home/bryan/.tunn/token
tunnels:
  - name: bryan-gpu-api
    kind: http
    target: "8080"
    allow: [bryan@example.com, "@example.org"]
  - name: bryan-gpu-ssh
    kind: tcp
    target: 127.0.0.1:22
  - name: bryan-gpu-tools
    kind: mcp
    target: http://127.0.0.1:3000/internal/mcp
```

`server` defaults to `TUNN_SERVER_ADDR` or the ordinary CLI relay address.
`domain` is used by the OpenClaw preview; `tunn hosts` gets authoritative URLs
from the relay. TLS verification is on unless `insecure: true` is explicitly
configured for a local test relay. Service definitions contain paths, not
credentials. The default publisher credential is `~/.tunn/token`; for a
self-hosted relay, `token_file` can hold a per-user token from `users.yaml`.
The self-hosted master secret maps to one shared account, `client@local`.

HTTP requires an explicit nonempty email/domain allow-list. TCP, Unix, and MCP
use private endpoint tokens; an optional `allow` additionally permits the
named tunn identities. Every endpoint gets a token in `~/.tunn/endpoints` (or
`$TUNN_CONFIG_DIR/endpoints` when configured in the daemon environment).
`credentials_dir`, when set, takes precedence over that environment and pins
the token root for the daemon. YAML, publisher and endpoint files require 0600;
native Windows requires a private current-user ACL instead of POSIX mode bits.
Tokens persist through reconnects and service restarts. Existing `tunn token`
and `tunn token --rotate` commands work with these endpoints.

A Unix socket can carry raw bytes or HTTP:

```yaml
  - name: bryan-control
    kind: unix
    target: /home/bryan/run/control.sock
    as: http  # omit for raw tunn CONNECT
```

For stdio MCP, replace `target` with an argv array. No shell interprets it:

```yaml
  - name: bryan-files
    kind: mcp
    command: [/usr/local/bin/filesystem-mcp, /home/bryan/shared]
    tools: [read_file, list_directory]
```

Prefer absolute executable paths: service managers have a smaller PATH than
interactive shells. Stdio child stderr is discarded because it may contain
credentials. The existing MCP bridge's protocol and concurrency boundaries
still apply. A terminated child restarts with backoff. Unix sockets require a
platform that supports them.

Unknown fields, multiple YAML documents, ambiguous MCP sources, duplicate or
invalid names, empty HTTP allow-lists, and non-loopback health binds fail
validation. One manifest can contain 1–10 tunnels. The relay's existing active
tunnel quotas still apply (3 free / 10 Pro); a reservation does not increase
that quota.

## Run and manage the user service

```bash
tunn service install
tunn service status
tunn service check
tunn service restart
tunn hosts
tunn hosts --json
tunn service uninstall

# Foreground operation, useful for a container or supervisor:
tunn service run --config ./host.yaml

# Inspect definitions without touching a service manager:
tunn service install --config ./host.yaml --dry-run --os darwin
tunn service install --config ./host.yaml --dry-run --os linux
tunn service install --config ./host.yaml --dry-run --os windows
```

Install validates the manifest and local publisher credential before writing
the unit and invoking the per-user manager. No administrator privileges are
requested. The binary must remain at its installed absolute path. Repeated
installation reconciles the same definition; a conflicting definition is refused.
Manifest changes take effect on the next service start; `service restart` reloads
them. If a login credential expires, log in to the same relay/account and restart the
user service to load it. Keep `token_file` private.

- **macOS:** `~/Library/LaunchAgents/com.tunn.host.plist`, loaded into the
  current GUI user's launchd domain. It starts at login and restarts after an
  exit. It runs while that user is logged in; it is not a system boot daemon.
- **Linux:** `~/.config/systemd/user/tunn-host.service` (honors an absolute
  `XDG_CONFIG_HOME`), enabled with `systemctl --user`. The user's manager must
  be running. For operation after logout or at boot, an administrator can
  enable lingering for that user; tunn does not change that setting.
- **Windows:** a `TunnHost` scheduled task with the current user's interactive
  token and least privileges. It starts immediately and at that user's logon,
  permits battery operation, and has no execution time limit. It runs in the
  logged-in user's session, not before login. The generated XML is beside the
  manifest.
- **WSL:** use the Linux binary and systemd user service inside a distribution
  with systemd enabled. Starting Windows does not by itself start WSL. For
  Windows logon autostart, create a per-user Windows scheduled task that runs
  `wsl.exe --distribution <distro> --exec /absolute/path/to/tunn service run
  --config /absolute/path/to/host.yaml`; keep the Windows task configured to
  run only as that user. If choosing systemd instead, have the task start the
  distribution and its enabled user manager. Tunn does not modify
  `/etc/wsl.conf` or the Windows startup policy.

The daemon binds health before registering endpoints, preventing a second
instance using the same health port. `/healthz` reports process liveness;
`/health` and `/readyz` return 200 only while all configured relay streams are
registered, otherwise 503. The JSON contains endpoint names and online flags,
not targets or credentials. This checks relay connectivity, not the local
application's readiness. Health listens only on a literal loopback IP.

Daemon error logs are bounded to `host.log` and `host.log.1` beside the manifest,
at most 1 MiB each, mode 0600. Managers discard stdout/stderr to avoid a second
unbounded log stream. Reconnect uses exponential equal jitter: 0.5–1 second on
the first retry, doubling to 15–30 seconds at the cap. Stable connections reset
backoff. OS managers also restart the daemon on exit. Stopping or uninstalling
the service disconnects endpoints, retaining config, tokens, inventory, and
reserved names.

## Relay change and stable-name ownership

The preexisting server model has durable Pro reservations but no machine
inventory. The experimental feature adds the smallest separate control API:

- `POST /api/hosts`: a bearer-authenticated machine label and list of
  `{name, kind}` entries. It atomically claims account-owned names using the
  existing `reserved_subdomains` table. It never receives targets, socket
  paths, process commands, allow-lists, or endpoint tokens.
- `GET /api/hosts`: that bearer identity's machines and endpoints, stable URLs,
  live stream status, and persisted last-seen timestamps. This is read-only;
  an identity with no machines gets `[]`.
- gRPC registration carries `tunn-host-id` metadata. The relay binds it to
  the authenticated account and checks the reserved machine, name, kind,
  protocol, and private access before admitting the stream.

The feature is disabled by default. `TUNN_HOST_MODE=true` requires an
authenticated standalone login relay with SQLite, no configured peer nodes,
and no Fly cluster discovery. It fails startup for unsupported topologies.
Cluster-wide machine presence is intentionally outside this first version:
a future implementation must proxy the manifest/presence API to the login
node, authenticate node sessions, expire presence leases, and make ownership
checks mandatory during admission even when the login node is unavailable.
Do not enable this flag in a cluster by removing its topology guard.

Within the standalone relay, the inventory survives a relay restart; status
becomes offline until new streams connect. Last seen updates at registration,
health pings, and disconnect. A machine is online if any of its endpoints is
connected; each endpoint has its own status. Ordinary publishers cannot take
another account's reserved name. The existing login-node registration RPC also
checks durable ownership for other nodes' ordinary registrations.

The preview permits up to 20 machines and 10 durable names per account,
including existing Pro names. Removing an endpoint from YAML stops publishing
it on the next daemon start, but keeps its reservation and offline inventory.
There is no release/delete UI in this preview. Registration is idempotent;
collisions roll back the whole manifest. Names cannot silently move between
machines.

Verified email-account merges transfer both reservations and inventory to the
surviving account. The management path is scoped to the relay authority;
`/api/hosts` on a tunnel subdomain continues to reach the local application.

## OpenClaw scaffold

```bash
tunn openclaw --name bryan-openclaw
tunn openclaw --name bryan-openclaw --gateway http://127.0.0.1:18789 \
  --domain tunnel.example.com --qr-file ./openclaw-setup.png
```

The helper probes only a loopback TCP port (18789 by default, or the named
HTTP target in host.yaml). A reachable port is not proof of OpenClaw identity.
It prints three setup steps, the intended reserved URL, and a QR code using
the locally installed `qrencode` executable. The QR contains only the URL;
it is not a credential or device-enrollment token. Install `qrencode` using
your OS package manager if QR rendering is unavailable.

**Remote control and phone pairing require the sibling `tunn-websocket`
branch.** This helper does not configure OpenClaw authentication, enroll a
phone, verify a remote reservation, or claim compatibility before that branch
lands. Keep OpenClaw gateway authentication enabled, authenticate at tunn,
and approve the phone at the gateway when pairing support is available.

## Local verification

These commands use repository fixtures and loopback only; no hosted service:

```bash
make build
make test-ai-hosts
bash scripts/verify-install-recovery.sh --fixtures
make test-hostmode           # race-checked contracts, no listeners
make test-hostmode-compile   # compile all tests without running them
make test-hostmode-loopback  # POSIX: real TLS/gRPC + daemon/adapters/reconnect
make test-race               # full existing suite, requires loopback
```

The loopback test covers private HTTP, HTTP MCP path mapping, TCP half-close,
HTTP over a Unix socket, readiness, saved tokens, reconnect after relay
connections close, account listing, and shutdown. Contract tests cover strict
config parsing, OS service goldens and escaping, command generation, bounded
logs, backoff bounds/overflow, inventory persistence and isolation, atomic
reservation conflicts, feature gates, and ordinary cross-node ownership checks.
Tests fail when required listeners are denied; they do not skip or weaken
assertions in a restricted sandbox. OS service activation has not been
performed as part of these tests; Windows/Linux definitions need native smoke
testing on those operating systems.

References for service semantics and OpenClaw's transport:
[Apple launch agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html),
[systemd service definition](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html),
[Microsoft task schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema),
[OpenClaw remote access](https://docs.openclaw.ai/gateway/remote).
