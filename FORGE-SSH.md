# `ssh forge` from anywhere through tunn

This design works with the existing relay code at `110485c` (the supplied v38
production baseline). **tunn.to needs no deployment, configuration change, new
environment variable, SSH listener, VPN, or droplet.** Only the publisher and
laptop CLI need this branch's additions. No production operation was performed
to validate this design; runtime acceptance belongs to the coordinator on a
host that permits loopback, followed by Bryan's installation.

## End-to-end path

```text
laptop: ssh forge
  -> ProxyCommand: tunn connect --stdio --account forge-ssh
  -> TLS-verified HTTP/2 CONNECT to forge-ssh.tunn.to:443
     Tunn-Protocol: tcp/1; Tunn-Authorization: Bearer <tunn account JWT>
  -> existing tunn relay: authenticate account, enforce email policy and quota
  -> forge's outbound TLS gRPC publisher connection to tunn.to:443
  -> forge: 127.0.0.1:22 -> existing sshd -> ehrlich
```

The ordinary CONNECT wire form uses the endpoint hostname as authority; the
relay already normalizes it to `/_tunn/connect`. The client also sets the
existing raw TCP protocol header. Both directions use the existing bounded
connection-stream frames, including upload EOF/half-close. There is no consumer
listening socket, public raw SSH port, or new relay protocol. HTTPS proxies and
SOCKS proxies supported by the CLI can carry the laptop connection; they must
permit long-lived HTTP/2 inside the proxy tunnel.

On forge, the dedicated systemd **user** unit
[`tunn-forge-ssh.service`](deploy/ai-hosts/systemd/tunn-forge-ssh.service)
runs the separately installed `~/.local/bin/tunn-forge-ssh` as `ehrlich`:

```sh
tunn-forge-ssh --verbosity=error tcp --account-only --name forge-ssh 127.0.0.1:22
```

Its publisher account is Bryan's tunn account, authenticated using tunn's
existing device/browser OAuth login. Without `--allow`, the publisher grants
access only to the verified creator identity, including identities in that
same account's email bucket. `--account-only` registers this existing private
email policy with **no endpoint-token digest**, creates no new endpoint token,
and rejects `--public`, publisher secrets, and public-mode publishing. A stale
endpoint token left by another installation cannot authenticate here.

The laptop logs in independently to the same tunn account and runs one
`tunn connect --stdio --account forge-ssh` per SSH connection. `--account`
selects the saved account login explicitly, ignores endpoint-token environment
variables and local endpoint token files, and rejects arbitrary explicit URLs.
It sends the JWT only to the named endpoint on the configured relay and never
follows redirects. `--stdio` copies only raw remote bytes to stdout, puts
failures on stderr through the CLI, exits nonzero on failure, and binds no
listener. Stdin EOF closes only the upload; download remains readable. Signal
cancellation and remote completion close both streams and join the uploader.

## Private grants and existing production support

The private TCP grant flow is **account identity plus publisher allow-list**.
There is no bearer capability to copy between hosts. For this task, omit
`--allow` entirely so Bryan is the only account admitted. For an intentional
future share, an owner may publish with `--account-only --allow alice@example.com`;
Alice must log in with that verified identity, then use `connect --account`.
Removing the email and restarting the publisher removes that grant. The
creator is always implicitly allowed, so an owner cannot revoke itself by
removing its email from the list.

This is different from `tunn grant create`: v38 explicitly rejects metered
consumer grant tokens for TCP in both creation and ingress. Extending those
tokens would need a relay deployment and is unnecessary for Bryan's account
access. MCP OAuth is likewise not part of this SSH path. The CLI changes use
only existing registration fields and existing account-JWT visitor checks in
`internal/host/auth.go`, `webproxy.go`, and `grpc_server.go`.

Do not enable `TUNN_SSH_ADDR`, `TUNN_SSH_HOST_KEY_FILE`, or `TUNN_HOST_MODE` on
production for this feature. The SSH front door is an alternate SSH publishing
and management API, not a requirement for carrying SSH bytes over the existing
HTTPS relay. Enabling it would expand the relay's exposed protocol surface and
require persistent relay SSH key management. This path avoids that change.
The environment values in the unit/config wrapper configure local clients;
they do not change tunn.to.

## Authentication, keys, and revocation

There are two independent admission layers. First, tunn validates the signed,
unexpired account JWT and the private email policy before opening a connection
to forge. Anonymous visitors, another account, expired/forged JWTs, login-link
tokens, stale endpoint tokens, and TCP consumer grants are denied. Second,
**sshd's existing SSH key authentication still applies**: a tunn login grants
transport access, not a shell. The SSH private key stays on the laptop or its
local agent; tunn never receives it. Agent forwarding is disabled. No SSH keys
are linked to the tunn SSH front door.

Pin forge's existing SSH host key obtained through a trusted management path,
under `HostKeyAlias forge-tunn` in a dedicated known_hosts file. Verify its
fingerprint at the forge console before use. `StrictHostKeyChecking yes` keeps
a name collision, re-registration by a different host, or a malicious relay
from impersonating forge. SSH encrypts application contents end to end; the
relay sees account, endpoint, connection timing, and byte accounting.

The publisher and laptop use isolated mode-0700 credential directories;
`tunn login` atomically writes a mode-0600 account JWT. Never copy that JWT
between machines or put it in SSH config, command arguments, logs, or the repo.
It is an account credential with broader access than this endpoint. No
refresh token or automatic renewal is implemented: device login JWTs expire
after **24 hours**. An expired consumer needs a new local `tunn login`; an
expired publisher needs login plus a publisher restart to replace an already
loaded JWT. Account logout/deleting a local file does not revoke a stolen JWT
at the relay. There is no per-device account-JWT revocation in this flow.

To immediately revoke this transport, Bryan stops only
`tunn-forge-ssh.service`; active streams close and new connections fail.
Removing an SSH authorized key remains an sshd operation outside this task;
it affects future SSH authentication, not already authenticated SSH sessions.
JWT expiry is checked at connection admission and does not promise to kill a
session already in progress. Reconnecting after expiry is denied. The existing
account operational-state/quota checks still apply; nothing here bypasses them.

## Failure and reconnect behavior

| Condition | Behavior / recovery |
| --- | --- |
| Relay/network outage | Publisher retries with equal-jitter exponential delay, initially 0.5–1 second, capped at 15–30 seconds. Broken SSH streams end; a new `ssh forge` connects after registration recovers. |
| Publisher process exits | User systemd restarts it after 30 seconds, including clean exits, unless explicitly stopped. No exhausted start limit prevents recovery after re-login. |
| Invalid/expired publisher login | Registration fails closed. A fresh process reloads the credential file; Bryan logs in again and restarts this unit. Reconnects in an already running process keep its old JWT. |
| Invalid/expired laptop login | CONNECT fails with 401; log in on that laptop and run `ssh forge` again. No automatic endpoint-token fallback or browser login inside ProxyCommand. |
| Other account | CONNECT fails with 403 before contacting sshd. |
| Publisher offline / name collision | CONNECT returns offline/error; registration can fail if `forge-ssh` is in use. Do not take over another publisher or change an existing tunnel. |
| sshd cannot be reached on loopback | TCP target admission fails (normally 502); check the existing listener through trusted access, without changing sshd. |
| Quota/rate/capacity limit | Existing tunn limits deny or cut off traffic, with nonzero connector failure when a cutoff trailer is present. One additional tunnel slot is needed. No billing change is included. |
| Laptop sleeps or network switches | Existing TCP/SSH stream cannot migrate or replay. Resume with a fresh `ssh forge`; use an existing remote terminal multiplexer for work that must survive. |
| Forge reboots / user logs out | The enabled user unit runs when the user manager runs. Persistence across logout/boot requires lingering already enabled; otherwise availability depends on the login session. |
| SSH host key differs | SSH refuses connection. Verify at the trusted console; never disable checking to recover. |

The connector deliberately makes a single attempt and exits; silently replaying
an established SSH byte stream could corrupt it. Configure SSH keepalives as in
the install guide so a dead session is detected. The unit uses a clean
environment, a separate binary/state directory, restrictive umask, no privilege
gain or capabilities, no core dumps, limited address families, and capped
journald output. It needs no root, system unit, namespace setup, firewall
change, or listener creation. It does not upgrade other tunn installations.

## Verification boundary

Offline tests cover ProxyCommand flag validation, explicit account credential
selection, absence of a registered capability, existing private TCP admission,
binary stream purity, server-first full duplex, EOF/half-close, redirects,
quota trailer errors, and cancellation without a loopback listener. The
coordinator should also run the loopback tests and real `ssh forge hostname`
check listed in [INSTALL-FORGE.md](INSTALL-FORGE.md). Passing memory fixtures
does not establish live relay readiness or SSH key authorization.

**Leave the existing droplet tunnels `forgetunnel` and `hometunnel`, and sshd,
untouched.** They retain their current binaries, configuration, units, keys,
listeners, and runtime state. This unit is additive, and production commands
in the install guide are for Bryan to execute himself.
