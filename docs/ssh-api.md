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

With owner account credentials saved for the CLI (publisher-only device
credentials cannot manage SSH keys):

```sh
# The matching private key must be beside the .pub file or loaded in ssh-agent.
tunn keys add ~/.ssh/id_ed25519.pub
tunn keys list
tunn keys remove SHA256:YOUR_FINGERPRINT
```

Or use email linking from the SSH session:

```sh
ssh -T -p 443 -i ~/.ssh/id_ed25519 tunn.to -- login --email you@example.com
```

The session prints the destination email and account page. Open the one-time
magic link sent to your inbox within five minutes, compare the displayed key
fingerprint with the terminal, click **Link SSH key**, then reconnect. Opening
the email link only shows a confirmation page; enrollment requires its POST.
The email
proof itself is never printed in SSH output: exposing it to an unknown key
would let that key claim someone else's account. SMTP must be configured on
the relay. A key already owned by another identity cannot be overwritten.

From an already linked key, re-add the authenticating key or manage existing keys:

```sh
ssh -T -p 443 tunn.to -- keys add
ssh -T -p 443 tunn.to -- keys list
ssh -T -p 443 tunn.to -- keys remove SHA256:YOUR_FINGERPRINT
```

`keys add` over SSH only accepts the authenticating key, whose possession was
verified by SSH. To enroll another key, run `login --email` using that private
key, or use `tunn keys add` locally. The CLI signs a fresh five-minute challenge
with the matching private key or SSH agent; encrypted keys can be unlocked with
`ssh-add`. A public-key file alone cannot reserve ownership.

For HTTP clients, POST `{"public_key":"..."}` to `/api/ssh/keys` with owner
account authentication. HTTP 202 returns `challenge`, `email`, `fingerprint`
and `message`. Sign the exact message bytes using the submitted private key,
then POST `public_key`, `challenge` and `signature` (the JSON representation of
an SSH signature: `Format` plus base64 `Blob`) with the same account credentials.
Only the verified one-time signature records ownership. Challenges bind the
identity, key, protocol and revocation generation; expired or replayed proofs
are rejected. Removing a key atomically invalidates all its pending email and
signature challenges, including authority issued before a concurrent removal.
Fresh consent and proof can enroll it again. Upgrading invalidates legacy
pending email links that did not bind a revocation generation. Ownership follows verified email buckets when
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
metering. SSH admission is bounded globally, per key, canonical account and per IP; attempts to
link an email reuse the existing key/IP and email throttles.

After authentication, start a command or a permitted raw connection within
15 seconds. Idle handshakes and PTY-only sessions close automatically.
Linked transports and concurrent publication/direct channels each have separate
budgets: 10 per key, 20 per canonical account and 30 per source IP. Counters are
released when their transport or channel closes. After the last direct channel
ends, its consumer transport expires after 15 idle seconds (plus up to one
second for orderly transport teardown); active multiplexed channels keep it alive. Owner
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
# Reconstruct omitted bodies, query values and headers explicitly when needed.
ssh -T -p 443 tunn.to -- replay demo 1 --request - < replay.json

ssh -T -p 443 tunn.to -- usage demo --since 24h
ssh -T -p 443 tunn.to -- grant create demo --for alice@example.com --expires 1h \
  --rate 60 --monthly-requests 1000 --monthly-bytes 10485760
ssh -T -p 443 tunn.to -- grant list demo
ssh -T -p 443 tunn.to -- grant revoke demo GRANT_ID
ssh -T -p 443 tunn.to -- hosts --json
```

TCP `-L` targets are tunnel names at logical port 22 or legacy port 80, never arbitrary relay-side
hosts. The endpoint must be online on this SSH relay. The connection goes
through authenticated HTTP CONNECT ingress, including allow-lists, quotas,
metering and half-close handling. `-N` is appropriate for this consuming
connection. Public raw endpoints are prohibited.

### Native OpenSSH jump pilot

With a key linked to the invited email and already authorized by the origin
sshd, recipients need only OpenSSH:

```sh
# Publisher (tunn installed and logged in; keep this process running):
tunn tcp --account-only --name forge-ssh --allow alice@example.com 127.0.0.1:22
# Recipient, after one-time email/key linking and verifying both host keys:
ssh -J tunn@tunn.to:443 deploy@forge-ssh
sftp -J tunn@tunn.to:443 deploy@forge-ssh
```

The jump host resolves `forge-ssh:22` to the publisher's configured target. It
terminates only the outer SSH transport; the inner host key, login and encrypted
session belong to the origin. A relay grant does not authorize an OS user.
Registered keys still need a matching endpoint email grant (or ownership),
including for public TCP publications consumed through SSH.

The pilot requires publishers and the SSH entry point on the same login node;
cross-node routing is not implemented. Host-key persistence and raw TCP/443
routing are opt-in as described below. Raw SSH on 443 can be blocked by HTTPS-only
networks. See [USER-JOURNEY.md](../USER-JOURNEY.md) for trust checks, precise
enrollment commands, repeat use and revocation. Removing a key denies new channels
even on an existing jump transport and closes active streams within five seconds
(one-second polling, three-second authority query timeout). To revoke a person's
endpoint grant in this pilot, stop its publisher and restart with a revised
`--allow` list; the stop cuts existing sessions. There is no live people editor
in this increment.

Inspection and replay require the owner and `--inspect` at publication time.
The bounded history and SSH-managed tokens live only as long as the forward.
Body capture requires `--inspect --inspect-body`; metadata capture is the default.
Replay uses the original upstream adapter and the local viewer's reconstruction
checks. `--request -` reads one JSON object up to 128 KiB with optional `path`,
`headers` and base64-encoded `body`. All redacted headers and query values must be
reconstructed, and an omitted body must match its observed byte count. Platform
tokens are rejected before dispatch and masked from captured bodies and metadata.
Grant and usage commands share the
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
`service restart` returns a restart plan; `service check` validates the manifest
without reading caller credentials on the relay. Native and SSH service commands
share their flag definitions. Install plans retain an identical definition on
repeat runs, refuse a conflicting definition or unowned registration, and retain
the definition after a manager failure for retry. Removal checks ownership and
preserves the manifest and credentials. Linux respects `XDG_CONFIG_HOME`.
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

## Security fixes and review comparison (2026-10-11)

The reviewed SSH candidate was `aa5d8eaefd32448ba278ffcac02779d3a8f2c941`.
The SSH commit was rebased as `c2a252c179bed4838cf23cda429ff8c5fe6080f1`
onto the latest durable-credentials base available for this work,
`4b7364503e428837b6fdb98e8c2ce4605b05da90`. No billing implementation,
production configuration, deployment or remote Git history was changed.

| Finding | Fix | Regression against the reviewed candidate |
| --- | --- | --- |
| F1: reachable SSH-library denial of service | Select `golang.org/x/crypto v0.58.0`; update its required dependencies and Go 1.26 build/compiler configuration. | `TestReviewSSHDependencyPatched` fails with the selected v0.41.0 dependency and passes with v0.58.0. Ordinary agent/Unix-channel rejections also remain covered. |
| F2: stalled authority lookup exceeds revocation deadline | Pass context through account, email and operational-state SQL; close the stream independently at the three-second check deadline; reject expired authority. | `TestReviewRevocationHasFiveSecondDeadline` fails with a successfully committed revocation and held SQLite pool lease. Both context-aware and deliberately cancellation-ignoring storage variants pass after the fix. |
| F3: pending link restores removed key | Atomically advance revocation generation and remove pending email/signature challenges. Completion checks generation in its transaction. An existing SSH session can only update an existing linked key. | `TestReviewPendingLinkCannotUndoRevocation` fails before the fix and passes afterward. Additional tests cover concurrent completion/removal, legacy-schema migration, restart, stale signatures and old sessions. |
| F4: account holder squats a foreign public key | Record ownership only after a fresh, one-time key signature bound to the authenticated verified identity, or the authenticating SSH key plus deliberate email confirmation. A challenge alone reserves nothing. | `TestReviewCannotRegisterAnotherPersonsKey` fails before the fix and passes afterward. HTTP and real CLI tests cover private files, agent signing, public-key-only rejection, mismatched signer/key/identity, replay and fresh re-enrollment. |
| F5: direct forwarding skips budgets and retains idle transports | Separate bounded transport/channel counters for key, canonical account and IP; release on closure; expire consumers after their last channel ends. | `TestReviewDirectForwardIdentityBudgets` and `TestReviewDirectForwardIdleExpiryAndRelease` fail before the fix and pass afterward, including multiplexing and origins that remain open after an input half-close. Additional tests cover transport limits, aliases and counter release. |
| F6: private target existence oracle | Resolve linked identity before target lookup; use uniform admission denial for offline, unauthorized and budget-denied targets. Release completed admission charges before delivering a rejection. | `TestReviewAnonymousTargetOracle` fails on both port 22 and legacy 80 before the fix and passes afterward under `-race`. |

The reviewer reproductions from `review_host_test.go` and
`review_registry_test.go` were ported into the permanent package suites. F1's
review reproduction was dependency/source inspection, not a malicious packet
or exhaustion test; the permanent dependency guard requires at least v0.56.0,
the minimum for [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) and
[GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355), which also includes the
[GO-2026-5016](https://pkg.go.dev/vuln/GO-2026-5016) rejected-channel fix.

All comparisons use installed Go 1.27.2 on Linux/amd64, actual loopback/Unix
listeners and umask `022`. The first inherited-umask runs exposed group-writable
fixture-directory failures on both bases. Umask `077` instead invalidated a
fixture's intended 0644 file permission. Neither production security check was
relaxed; the final comparisons use `022` on both sides. Two intermediate full
runs hit the existing one-second MCP fixture shutdown deadline; unchanged MCP
suites then passed five repetitions on both base and fixed trees. An intermediate SSH inspection fixture also observed its asynchronous event
before completion; its failure log is retained. An initial
native enrollment disconnect and a teardown EOF race were repaired in the SSH
session lifecycle; the final native and race suites exercise that lifecycle.

Full execution logs and the built Linux binary are retained in this forge at
`/work/lanes/tunn-sshj/validation/`, outside the tracked repository. The
original-candidate full-suite comparison excludes only the newly copied
`TestReview*` regressions; those same regressions run separately with `-race`
and fail for every reported finding on `aa5d8ea`.

### Additional dependency-scan results

`govulncheck v1.9.0` source analysis of `./internal/sshfront ./internal/host`
reports 23 reachable advisories on the durable base and six on the fixed tree.
The remaining six are inherited findings in unchanged `google.golang.org/grpc
v1.76.0` and `github.com/quic-go/quic-go v0.56.0`: GO-2026-6443,
GO-2026-6348, GO-2026-6061, GO-2026-4762, GO-2026-5676 and GO-2025-4233.
Both scans exit with status 3. These dependency advisories need separate work;
this change does not claim a clean vulnerability scan or authorize public
enablement. The source scan reports no reachable `x/crypto` advisory after the
upgrade. The stripped-binary scan conservatively reports eight advisories,
including uncalled xDS/OpenPGP paths; source results distinguish those paths.

### Completed checks

| Check | Result | Evidence in the forge validation directory |
| --- | --- | --- |
| Durable base: `go test -p=2 ./... -count=1` | PASS, including loopback fixtures | `base-durable-full-022.log` |
| Original candidate: all original tests, `go test -p=2 ./... -skip '^TestReview' -count=1` | PASS, including native OpenSSH fixture | `base-aa-full-022.log` |
| Fixed tree: `go test -p=1 -parallel=1 ./... -count=1` | PASS, including every loopback and native fixture | `final-full-verified.log` |
| Original candidate: six finding regressions with `-race` | Expected FAIL for all six; no race warnings | `base-regression-proof.log` |
| Fixed tree: identical six finding regressions with `-race` | PASS; stalled committed revocation closes in 3.003 seconds or less | `final-regression-proof.log` |
| Durable base: full SSH/auth/relay packages with `-race`, plus CLI/store/client | PASS | `base-durable-race.log`, `base-durable-cli-store-race.log`, `base-durable-client-race.log` |
| Fixed tree: `go test -p=1 -race . ./internal/host ./internal/sshfront ./internal/common ./internal/client ./internal/storage ./internal/store ./internal/relaytransport -count=1` | PASS; no race warnings | `final-race.log` |
| Final forwarding-lifetime refinement: complete sshfront race suite and host jump/native tests | PASS, including an origin that remains open after input EOF | `final-sshfront-race.log`, `closed-channel-lifetime.log` |
| `go vet ./...` | PASS | `verified-vet.log` |

The final native OpenSSH run under `-race` completed in 2.42 seconds. Its first
and second sessions took 249 ms and 204 ms; byte-for-byte verification of a
random 64 KiB SFTP download took 418 ms. It rejected unknown/non-granted keys,
wrong resources/users, relay loopback targets, substituted origin/relay host
keys and a relay grant without an origin-authorized key. Stopping the publisher
closed the active origin session in 5.94 ms; live key removal on a reused jump
transport closed it in 979 ms. These are fixture observations, not production
latency promises. The held-database regression separately verifies the
five-second cutoff under stalled authority lookup.
