# Always-on publishers and SSH clients

On a relay supporting durable device credentials, run `tunn login` independently
on the publisher and each laptop. Existing logins remain valid until their
24-hour expiry; run login once with the updated CLI to obtain renewable device
credentials. Never copy the credential files between machines.

Publish forge's SSH port using the updated binary:

```sh
tunn tcp --account-only --name forge-ssh 127.0.0.1:22
```

Use account authentication from the laptop in `~/.ssh/config`:

```sshconfig
Host forge
    HostName forge-ssh
    User YOUR_FORGE_USER
    ProxyCommand tunn connect --stdio --account forge-ssh
```

A publisher refreshes before expiry and sends its new access token on the
existing tunnel; live SSH connections remain open during successful renewal.
The laptop obtains a current token before opening each CONNECT. If the relay
returns 401, it renews once and retries before reading any SSH bytes. A local
listener (`tunn connect --account --listen 127.0.0.1:2222 forge-ssh`) also obtains
a current token for each new connection. An already authorized laptop session
can drain normally after device revocation; a revoked publisher loses its lease
and connections within five minutes with synchronized relay clocks (up to one additional minute of permitted relay clock skew). A login-server outage lasting past the
publisher lease expiry closes the tunnel rather than allowing indefinite access.

Open `https://YOUR_RELAY/account/devices` in a logged-in browser to list devices
and revoke a lost laptop or compromised publisher. Device credentials permit
publishing and connecting; account administration requires a browser session or
an existing unexpired management credential. They cannot change billing or
manage other devices. Self-hosted `--secret` and endpoint-token connections keep
their existing authentication behavior.

The CLI stores `credentials.json` (authoritative) and `token` (compatibility
mirror) in `~/.tunn`, or the absolute directory in `TUNN_CONFIG_DIR`. Files are
atomically replaced with mode 0600; the directory is mode 0700. Refreshes use
an OS file lock so multiple publishers and SSH commands on one machine can
safely share the same login. Credentials are bound to their original HTTPS
relay; use separate config directories for different relays. On Windows the
user must also protect the directory with a private user ACL.

Temporary refresh errors explain how to check connectivity and retry. A revoked
or reused credential reports `run tunn login on this device`; reauthorize on
that machine. A lost refresh response can recover the same rotation for 60
seconds. A crash or outage past that recovery window requires a fresh login.
An always-on publisher needs outbound HTTPS access to its login relay in
addition to the tunnel control connection. Update the relay before its clients;
new clients retain legacy access-token behavior when an old relay returns no
refresh credential.

## Deployment runbook

1. Keep independent access to forge throughout the rollout. Preserve its
   current publisher binary, user service unit and credentials for recovery.
   The forge unit from branch `956477e` is outside this repository; verify its
   executable, restart policy, environment and credential directory before
   replacing it. Take a consistent backup of the login node's SQLite database,
   including committed WAL state, and preserve the signing key.
2. Upgrade every resource relay first, keeping clients on their existing
   logins. Check listener readiness and legacy publisher registration after
   each replacement. In a single-node deployment, the resource and login node
   upgrades are one replacement. In a mesh, finish resource upgrades before
   enabling durable issuance on the login node: an old resource relay cannot
   accept a durable publisher.
3. Upgrade the login node using the existing persistent database. Preserve
   `TUNN_JWT_SECRET` on every node, `TUNN_NODE_SECRET` in the mesh,
   `TUNN_LOGIN_NODE`, `TUNN_DB_PATH`, volume mounts, public authority and node
   discovery settings. No new server environment variables or external
   dependencies are required. Confirm the additive `durable_devices` and
   `durable_device_used` tables, exchange/refresh forwarding, browser listing
   and revocation, and existing legacy sessions before upgrading clients.
   Keep signing-key rotation separate; refresh recovery uses that key.
4. Install the fixed CLI on forge and run a fresh `tunn login` there using the
   exact relay origin and an absolute private `TUNN_CONFIG_DIR` shared with the
   service. An existing token file does not become renewable automatically.
   Restart the user service to load `credentials.json` and negotiate
   `device-reauth-v1`, retaining
   `tcp --account-only --name forge-ssh 127.0.0.1:22`. Keep independent access
   available: restarting the publisher drops its live SSH sessions.
5. Update each laptop and log in independently. Retain
   `ProxyCommand tunn connect --stdio --account forge-ssh`, matching
   `TUNN_SERVER_ADDR` and config-directory settings. Do not copy refresh
   credentials between machines. Both publisher and laptops need outbound
   HTTPS to their saved login relay as well as tunnel access.
6. Verify SSH end to end, repeated refresh timestamps, concurrent commands
   sharing the credential file, and browser revocation of a disposable device.
   Include a mixed-case owner in the regression gate, including a device or
   authorized code stored before this fix. Observe publisher renewal without
   restarting it. Lost committed responses recover for less than 60 seconds;
   longer outages or crashes may require browser login. A login-node outage
   beyond the publisher lease closes the tunnel. Keep relay clocks synchronized.

Restarting the owning relay drops forge's publisher control stream and all live
SSH sessions. The publisher process reconnects afterward when its loaded
credential is valid; users must reopen SSH connections. A legacy publisher holds
its original access JWT in memory and cannot renew it. Replacing its token file
or installing a binary does not update that running process, and an expired
legacy JWT prevents reconnecting after the relay restart. An upgraded publisher
loads current durable state before reconnecting, but relay replacement still
interrupts SSH. Restarting only a separate login node leaves streams on other
resource relays intact if renewal service returns before lease expiry. The live
forge topology and service have not been inspected by these local checks.

Owner compatibility uses `common.NormalizeEmail` when reading old sessions,
authorized device codes and durable owners, and when checking device ownership.
New sessions, access tokens, authorized codes and devices use the same canonical
email. Existing durable rows remain intact and revocable without a database
backfill; aliases remain governed by the account email bucket.

## Rollback to 110485c

Stop or revert durable clients and publishers **before** returning resource
relays to `110485c`. Once the old server is available, log in with an old CLI
to obtain a legacy credential, or use the updated login against the old server
so its legacy response replaces durable JSON state. Restart forge's publisher
with a legacy-compatible binary and credential. Restarts interrupt live SSH
connections, and rollback restores the legacy 24-hour renewal limitation.

Preserve the current SQLite database, both additive durable tables and the same
signing key. Do not drop the new tables or restore a stale backup: doing so loses
issuance/revocation history and later account writes. The baseline accepts
existing legacy sessions and ignores the additive tables, but rejects
`device_access` JWTs and has no refresh endpoint. Rolling back only the server
while leaving durable clients active causes an authentication outage.
