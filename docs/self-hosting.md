# Standalone self-host install, export and rollback

The supported versioned reference path is one authenticated login relay, its
SQLite database and owner-managed TLS. It uses the same tunn binary as the
publisher. It is not a global edge, cluster recovery recipe or availability
promise. DNS, public reachability, certificate renewal, backups, abuse response
and operator access remain the owner's responsibilities.

Use [install-recovery.md](install-recovery.md) to select a pinned local artifact.
The helper files must come from the same staged source checkout. No helper
downloads binaries, acquires certificates, installs a service or touches hosted
state. An approved full license text is absent despite the README's MIT
declaration; release/license packaging remains unresolved. This local rehearsal
does not authorize redistribution or supply a new license.

## Version-1 relay configuration

Use Python 3.9+, an existing certificate/key pair covering both the apex and
wildcard tunnel authority, and a dedicated local data directory. The reference
configuration supports a single shared self-hosted publisher identity
(`client@local`), using an owner-supplied static client secret. It does not enable
public mode, cluster peers, billing, OAuth or SMTP. Other existing server
environment settings remain available outside this narrow rehearsed path.
Stage regular TLS files: symlinked key/certificate files are refused. Certificate
renewal and the reviewed relay restart remain owner actions.

Create `relay.json` only if absent; do not replace an existing profile on upgrade.
The following is a template: replace every absolute path, domain and secret
locally. Placeholders intentionally fail validation. Keep config/key/database
files at 0600 and the relay directory at 0700. Do not put secrets in shell argv,
repository history or captured stdout.

```json
{
  "version": 1,
  "domain": "tunnel.example.com",
  "http2_addr": "0.0.0.0:8443",
  "http3_addr": "0.0.0.0:8443",
  "internal_grpc_addr": "127.0.0.1:15051",
  "cert_file": "/home/OWNER/relay/fullchain.pem",
  "key_file": "/home/OWNER/relay/privkey.pem",
  "db_path": "/home/OWNER/relay/tunn.sqlite",
  "client_secret": "CHANGE_ME_OWNER_SUPPLIED_SECRET_AT_LEAST_32_CHARACTERS",
  "jwt_secret": "CHANGE_ME_DIFFERENT_OWNER_SUPPLIED_SECRET_AT_LEAST_32_CHARACTERS",
  "host_mode": true
}
```

Listeners require literal IPs and nonzero ports; internal gRPC must listen on
loopback with a distinct TCP port. Choose reachable external ports and configure the
publisher's `server` with that authority. HTTP/2 uses TCP and HTTP/3 uses UDP.
Use public port 443 or an owner-provisioned frontend if ordinary browser URLs
are needed: generated tunnel URLs do not include a custom listen port.
`TUNN_HOST_MODE` requires an authenticated standalone login node. The topology
guard is retained; do not remove it to enable cluster host mode.

HTTP/3 is off by default in production and remains on by default in development.
Set `TUNN_HTTP3=off` to disable the UDP listener and its `Alt-Svc` advertisement,
or `TUNN_HTTP3=on` to enable both. Production uses HTTP/2 because reused browser
HTTP/3 connections have stalled while reading response bodies. Enable HTTP/3
again only after verifying complete bodies with browsers on the deployed UDP path.
The enabled listener uses 1200-byte UDP payloads, disables MTU discovery, GSO
and ECN, and enforces the payload ceiling after port rebinding as well. This
avoids a reproduced stall when a path stops delivering a previously validated
larger packet size; it does not establish the cause of every production stall.
To trial it, set only `TUNN_HTTP3=on`, restart, and confirm Chrome's Network tab
shows `h3` and complete homepage, stylesheet and download bodies on repeated
requests and after 35 and 125 seconds idle. Compare headers and full-body times.
Set `TUNN_HTTP3=off` and restart to stop the trial if bodies stall; production
continues to default to off. There is no additional transport knob.
Cached advertisements expire after one hour; clients can fall back to TCP.
The startup log records the effective setting once.

When enabled, on SIGTERM, HTTP/3 sends GOAWAY, allows up to three seconds for draining,
then sends CONNECTION_CLOSE before releasing its UDP socket. Give the service
manager enough termination time for that drain. Keep `TUNN_JWT_SECRET` stable
across restarts: HTTP/3 derives its stateless-reset key from that secret so
clients can promptly abandon connections lost in a crash. Configurations without
a JWT secret use the loaded TLS private key instead. Rotating the source secret
also changes reset tokens; connections established before this support was
installed cannot benefit retroactively. HTTP/3 rejects 0-RTT early data; TLS
session tickets retain automatic rotation and stale tickets use a full handshake.
HTTP/2 is available with either setting.

Owner-run checks and foreground operation, from the staged checkout:

```sh
relay_profile="$HOME/.local/state/tunn-relay/relay.json"
relay_install="$HOME/.local/lib/tunn-relay-install"
relay_binary="$relay_install/bin/tunn"
python3 deploy/install/selfhost.py check --config "$relay_profile"
python3 deploy/install/selfhost.py run --config "$relay_profile" --binary "$relay_binary"
```

`check` validates schema, TLS key/certificate compatibility, and an existing
database with read-only SQLite `quick_check`. It permits a missing database only
when its parent exists, for first startup. This does not test certificate expiry,
DNS, clients, listener availability or a real native service. The launcher clears
inherited tunn/Fly settings and explicitly supplies prod, standalone login,
private mode, the declared TLS/SQLite paths and secrets. It refuses a `.env` in
the manifest directory, rather than letting that file silently add deployment
settings. `run` replaces the launcher process with the server; it opens listeners
and initializes the database, so it is an owner action, never part of fixtures.

For a publisher, provision the same static client secret privately into its
configured `credentials_dir/token`, or an explicit `token_file`. Use the same
secret/account after recovery. That shared identity has no independent
per-device revocation; do not claim continuity after replacing it. A browser
application-authentication/phone recipe needs separately accepted login support.

## Linux user-service plan — REQUIRED/UNRUN

Retain an independent admin console before start/stop/restart. Use a disposable
test host for acceptance. This example definition contains paths only, no
secret values. Replace paths with the staged checkout, dedicated artifact root
and configured relay manifest; systemd quoting must be verified on the target.

```ini
[Unit]
Description=Tunn standalone reference relay
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 "/home/OWNER/tunn checkout/deploy/install/selfhost.py" run --config "/home/OWNER/relay config/relay.json" --binary "/home/OWNER/tunn install/bin/tunn"
Restart=on-failure
RestartSec=30
UMask=0077

[Install]
WantedBy=default.target
```

Save the reviewed definition as `.scratch/native-acceptance/tunn-relay.service`
in the staged checkout. These are commands for the operator to run, not fixture actions:

```sh
systemd-analyze --user verify .scratch/native-acceptance/tunn-relay.service
install -d -m 700 "$HOME/.config/systemd/user"
# First install only: exclusive copy refuses an existing user definition.
(set -C; cat .scratch/native-acceptance/tunn-relay.service > "$HOME/.config/systemd/user/tunn-relay.service")
systemctl --user daemon-reload
systemctl --user enable --now tunn-relay.service
```

A user manager must exist. Operation after logout/boot and any lingering setting
are separate administrator decisions. There is no system-wide sudo installer,
container rollout or live certificate-renewal scheduler in the rehearsal.

## Export and import

Stop the standalone relay through its independent admin route before taking a
configuration/certificate/database cut. SQLite online backup captures committed
WAL content, but does not make concurrently changing config/TLS files one atomic
snapshot. Export writes a new mode-0700 directory and never replaces an existing
bundle; each file is 0600. The bundle includes the TLS private key, client/JWT
secrets and complete SQLite data. Treat it as credentials; do not share it in
chat or commit it.

```sh
systemctl --user stop tunn-relay.service
snapshot="$HOME/.local/state/tunn-relay-before-upgrade"
python3 deploy/install/selfhost.py export --config "$relay_profile" --output "$snapshot"

# Import requires a NEW directory, retaining the old profile/database:
restored="$HOME/.local/state/tunn-relay-restored"
python3 deploy/install/selfhost.py import --bundle "$snapshot" --output "$restored"
python3 deploy/install/selfhost.py check --config "$restored/relay.json"
```

Import verifies asset hashes, copies into a disposable staging directory, checks
TLS and SQLite, then publishes a complete new root. It rewrites only the three
local asset paths; domain, secrets, policy and stored identity/name mappings are
retained. Unknown schemas, corrupt assets and existing destinations fail without
overwriting a profile. Hashes detect accidental corruption, not malicious
replacement of the whole unsigned bundle. Recovery to the same domain still
requires operator-controlled DNS/TLS and the original account/identity data.

## Upgrade and rollback

With the relay stopped and an export retained, select the staged replacement at
the same artifact root. Then explicitly start and validate authenticated clients:

```sh
python3 deploy/install/artifacts.py install --root "$relay_install" \
  --binary "$candidate" --sha256 "$candidate_sha"
python3 deploy/install/selfhost.py check --config "$relay_profile"
systemctl --user start tunn-relay.service
```

If interrupted, run `artifacts.py reconcile --root "$relay_install"` before
further changes. If the artifact must be rolled back, stop the relay and run
`artifacts.py rollback --root "$relay_install"`. **Artifact rollback does not
undo SQLite migrations.** No backward-compatible schema downgrade is promised.
If the newer server changed the schema incompatibly, import the pre-upgrade
snapshot into a new root and explicitly change the reviewed service definition
to that manifest before starting the old binary. Keep the old root as evidence;
never overwrite it with an import. Confirm names, accounts, budgets and
authenticated client behavior on the original authority after restore.

Removal stops/disables the reviewed owner service before removing its selected
artifact. Configuration, SQLite, TLS/credentials, artifact history and all name
reservations remain. Deleting secrets/data or releasing remote names is a
separate explicit owner operation. Native service removal and real client
acceptance remain **REQUIRED/UNRUN**.

## Bounded local rehearsal

```sh
bash scripts/verify-install-recovery.sh --fixtures
```

This uses generated fixture TLS, synthetic secrets, isolated SQLite with
committed WAL rows, two fixture artifact versions, and a fake relay manager.
It proves configuration export/import, retained identity/name rows, artifact
upgrade/rollback and failure retention without launching a relay. The separate
`make test-hostmode-loopback` gate exercises the actual TLS/gRPC relay and host
runtime on loopback; neither gate is real OS activation or hosted acceptance.
