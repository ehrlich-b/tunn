# Versioned local install and recovery

This is the source-checkout installation path for one user-owned publisher and
one standalone relay. It uses a staged, architecture-correct binary and Python
3.9+. It does not fetch releases, install dependencies, configure DNS/TLS, modify
billing, or enable host mode on a hosted relay. The legacy `curl | sh` installer
and `make install` are outside this recovery path: they do not retain the
versioned selection journal. Use the commands below for the rehearsed path.

The host manifest is schema version 1. An existing machine label, relay/account,
endpoint names, publisher credential and endpoint files form its recovery state.
Generating a new machine label or logging in to another account is not recovery.

| State | Entry and evidence | Recovery / retained state |
| --- | --- | --- |
| Absent | No selected binary or user service | Existing user profiles remain untouched |
| Configured | `service check` accepts v1 YAML and a private publisher token | Unknown versions/fields fail without rewriting files |
| Installed | Complete owned unit registered with the user manager | A repeat install reconciles a staged definition; conflicting definitions/jobs are refused |
| Connected | `/readyz` is 200 and `hosts --json` lists the original names online | Manager success alone does not establish connectivity |
| Offline / recovered | Readiness is 503; reconnect uses the original endpoint files | Repair the app/relay or renew login to the same account, then explicitly restart |
| Upgraded / rolled back | Checked binary selection and previous digest are recorded | `reconcile` restores the committed artifact after an interruption; database rollback is separate |
| Removed | User service unregistered, selected binary removed | Configuration, all credentials, retained binaries, databases, relay inventory and reserved names stay |

Before stopping, upgrading or rotating anything, retain an **independent admin
route**: a trusted console or an existing management connection that does not
depend on tunn. This applies to forge, rig and the standalone relay. Availability
ends at logout/sleep/WSL shutdown unless the operator has arranged an appropriate
user manager. There is no automatic machine enrollment or login refresh.

## Build and select an artifact

From the desired pinned source checkout, with dependencies staged offline:

```sh
mkdir -p .scratch/tmp .scratch/go-build .scratch/gomod .scratch/npm .scratch/bin
export TMPDIR="$PWD/.scratch/tmp" GOCACHE="$PWD/.scratch/go-build"
export GOTMPDIR="$TMPDIR"
export GOMODCACHE="$PWD/.scratch/gomod" npm_config_cache="$PWD/.scratch/npm"
export npm_config_offline=true GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
export GOFLAGS=-p=2 GOMAXPROCS=2 BINARY_DIR="$PWD/.scratch/bin"
# On macOS:
taskpolicy -b nice -n 15 make -j1 build
# On Linux/WSL, use: nice -n 15 make -j1 build

install_root="$HOME/.local/lib/tunn-install"
candidate="$PWD/.scratch/bin/tunn"
candidate_sha=$(shasum -a 256 "$candidate" | awk '{print $1}')
python3 deploy/install/artifacts.py install --root "$install_root" \
  --binary "$candidate" --sha256 "$candidate_sha"
binary="$install_root/bin/tunn"
python3 deploy/install/artifacts.py status --root "$install_root"
```

This checksum records a locally built artifact from the trusted pinned checkout;
it does not independently authenticate an arbitrary downloaded executable. For a
staged release, supply its independently approved SHA-256 instead. The candidate
is copied to a disposable file, checksummed and probed with `--help` before
selection. A checksum mismatch, wrong executable or wrong architecture leaves
the prior selection intact. The root must be dedicated, absolute and free of
symlink ancestors. A nonempty unmarked directory is not adopted.

`install.json` records the selected and previous SHA-256 digests. Artifacts are
retained under `releases/<digest>`; the user service always points at the same
regular `bin/tunn` file (`bin/tunn.exe` on Windows). File rename selects a complete
artifact, without requiring Windows symlink privileges. Selection is serialized
with a native file lock. Windows may refuse replacement of a running executable;
stop the user task before upgrading. No helper calls a service manager.

## Create a profile once

Keep an existing profile. For a new profile, this exclusive create refuses to
overwrite it, including a dangling symlink. Edit the relay, email, machine and
names to your own values before logging in or installing a service:

```sh
profile="$HOME/.config/tunn/host.yaml"
credential_root="$HOME/.local/state/tunn-host/credentials"
python3 - "$profile" "$credential_root" <<'PY'
import json, os, pathlib, sys
os.umask(0o077)
profile, credentials = map(pathlib.Path, sys.argv[1:])
profile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
credentials.mkdir(parents=True, exist_ok=True, mode=0o700)
with profile.open('x') as output:
    output.write('version: 1\nmachine: home-gpu\n'
                 'server: tunnel.example.com:443\ndomain: tunnel.example.com\n'
                 'health: 127.0.0.1:9087\ncredentials_dir: ' + json.dumps(str(credentials)) + '\n'
                 'tunnels:\n  - name: owner-gpu-api\n    kind: http\n'
                 '    target: "8080"\n    allow: [owner@example.com]\n'
                 '  - name: owner-gpu-ssh\n    kind: tcp\n    target: 127.0.0.1:22\n')
PY
```

The relay must already support the experimental authenticated standalone host
API (`TUNN_HOST_MODE=true`). Names must be available to the same account.
`credentials_dir` pins the publisher/endpoint directory across terminal and
daemon environments. It takes precedence over `TUNN_CONFIG_DIR`. `token_file`
may override the publisher token only; endpoint files still use the pinned root.
Keep the YAML and tokens at 0600, credential directories at 0700. On native
Windows, enforce a private current-user ACL: POSIX mode bits are not an ACL check.

Owner-run authorization and local checks:

```sh
TUNN_ENV=prod TUNN_SERVER_ADDR=tunnel.example.com:443 \
  TUNN_CONFIG_DIR="$credential_root" "$binary" login
"$binary" service check --config "$profile"
"$binary" service install --config "$profile" --dry-run --os darwin
"$binary" service install --config "$profile" --dry-run --os linux
"$binary" service install --config "$profile" --dry-run --os windows
```

Use `TUNN_SERVER_ADDR` for login; the current login subcommand does not parse a
`--server` argument. For the supported self-hosted shared-account recipe, the
owner instead provisions the configured client secret privately into
`<credentials_dir>/token`. Do not print it into captured output or put it in argv.
`service check` validates local schema, file permissions and JWT expiry. It does
not validate JWT signatures, prove account continuity or contact the relay.

Actual activation is a separate native acceptance step in
[install-native-acceptance.md](install-native-acceptance.md). Per-user launchd,
systemd and Task Scheduler definitions contain executable/configuration paths,
not token values. A second macOS install queries the registered job rather than
bootstrapping it twice. Linux refuses an existing foreign fragment; Windows
refuses an existing task without its local definition and never forces `/Create`.
An existing definition with different paths is not overwritten. For relocation,
explicitly uninstall with its original binary and profile first.

## Recover and upgrade

During relay unavailability, daemon liveness may remain 200 while readiness is
503. Allow its bounded reconnect backoff, and inspect the private bounded
`host.log` beside the manifest. Check the local application separately. Name
collisions, rejected schemas and 4xx registry errors require operator repair;
they are not a reason to create a different identity.

An expired account JWT cannot authenticate a fresh connection. The owner logs
in to the **same relay/account**, using the same directory, checks the profile,
then runs `service restart --config "$profile"`. Login is not automatically
refreshed. A static self-hosted token has no JWT expiry diagnostic. Host-mode
endpoint tokens survive restarts; corrupt, readable or symlinked tokens fail
without replacement. Explicit rotation is a separate operation.

For a maintenance-window upgrade, uninstall the user service first, select a
new checked binary at the same root, and reinstall using the same profile.
Uninstall retains credentials and names. If the new candidate or service fails,
restore the retained binary, reinstall, and verify readiness and inventory:

Before changing a manifest, retain its original private bytes under a separate
filename. Neither artifact selection nor rollback migrates YAML. Older v1
readers may reject the newly added `credentials_dir` field. Check a replacement
or rollback binary against the retained compatible profile with
`"$candidate" service install --config "$compatible_profile" --dry-run` before
stopping the current service. Keep the original machine, names, account and
credential layout; do not install a new template over the existing profile.
Compatibility of the actual two artifact versions remains a native acceptance
gate, beyond the fixture selector's checksum and executable checks.

```sh
"$binary" service uninstall --config "$profile"
python3 deploy/install/artifacts.py install --root "$install_root" \
  --binary "$candidate" --sha256 "$candidate_sha"
"$binary" service check --config "$profile"
"$binary" service install --config "$profile"

# If an interrupted selection is reported, restore the committed artifact first:
python3 deploy/install/artifacts.py reconcile --root "$install_root"
# Deliberate rollback of a completed upgrade:
python3 deploy/install/artifacts.py rollback --root "$install_root"
"$binary" service check --config "$profile"
"$binary" service install --config "$profile"
```

Rerunning the same artifact install does not rewrite the selected file or discard
the previous digest. A killed process can leave `pending.json` before/after file
selection or state publication. `reconcile` always restores the last committed
artifact, including after a second interruption; it does not guess that a new
service or schema is healthy. Ordinary selection errors attempt that rollback
immediately. If restoration itself fails, retain the journal and use the
independent admin route; do not delete it to make status green. The helper is a
process-interruption recovery mechanism, not a tested power-loss guarantee.

Removal is explicit and repeated safely:

```sh
"$binary" service uninstall --config "$profile"
python3 deploy/install/artifacts.py remove --root "$install_root"
```

This removes the owned user service and selected executable. It retains the
profile, publisher/endpoint credentials, artifact history, offline relay
inventory, reserved names and databases. `rollback` can reselect the last removed
artifact. There is no implicit purge or remote-name release. If the local unit
was manually deleted, an absent-definition result is not proof that an orphaned
native registration stopped; inspect it through the independent admin route.
Windows stop errors leave the XML and registration for native diagnosis.

## Local evidence and outstanding acceptance

```sh
bash -n scripts/verify-install-recovery.sh
bash scripts/verify-install-recovery.sh --fixtures
bash scripts/verify-install-recovery.sh --native-plan
```

The fixture gate builds offline under `.scratch`, exercises stateful fake
launchd/systemd/Task Scheduler executors with explicit roots, checks the real
CLI's previews and local diagnostics, and runs private TLS/SQLite distribution
export/import plus interrupted upgrades and rollback. It never activates a
native manager, installs a login item, logs in, reaches a hosted service or uses
an owner's token. Failures are nonzero and no required assertion is skipped.

See [self-hosting.md](self-hosting.md) for the bounded single-node distribution
and [the AI-host kit](../deploy/ai-hosts/README.md) for the existing SSH/MCP/
dashboard canary. `--token-lifecycle preserve` explicitly checks retained
host-mode capabilities; default `rotate` still requires refreshed capabilities
for the legacy ordinary-publisher kit. Neither digest continuity nor a fake
manager establishes actual machine/account identity: native inventory and
authenticated reconnection must be checked on the same account.

Native service lifecycle on macOS/Linux/Windows/WSL, actual phone/OpenClaw
authentication, the two physical-host recovery windows, and day-14 dogfood
remain **REQUIRED/UNRUN**. The release workflow publishes macOS/Linux artifacts;
Windows has a generated task definition but no packaged release artifact in this
checkout. README declares MIT but an approved full license text is absent.
License packaging and distribution rights remain unresolved; no license or
ownership was invented. Local rehearsals are not permission to publish a release.

Recorded local validation on 2026-10-10, Go 1.26.2, using the offline Mac
resource wrapper and clone-local caches (JSON output flags change reporting only):

| Command | Measured result |
| --- | --- |
| `make -j1 build vet test-ai-hosts test-hostmode-compile` | PASS; 21 kit tests, 11 test-bearing packages compiled, 4 packages have no tests |
| `make -j1 test-hostmode` | PASS; 69 top-level tests + 81 subtests, 1 existing Cyrillic-homograph test skipped, 8 package runs |
| `bash -n scripts/verify-install-recovery.sh` | PASS |
| `bash scripts/verify-install-recovery.sh --fixtures` | PASS; 21 kit + 16 recovery Python tests, Go service/config/credential fixtures, no fixture skips |
| `make -j1 test-hostmode-loopback` | FAIL (environment); loopback bind returns `operation not permitted`; REQUIRED/UNRUN on a socket-capable host |
| `make -j1 test-race` | FAIL (environment); 154 top-level tests + 189 subtests pass, 12 listener failures, 1 existing skip; 8 test-bearing packages pass and 3 abort/fail |
| `git diff --check` | PASS |

The race suite aborts client/host packages at listener failures; unexecuted tests
are not counted as passes or skips. No new skip, listener fallback or changed
expected result was introduced. The existing homograph skip is counted separately
from four packages with no tests. Remaining coordinator command, after staging
offline caches in a socket-capable clone with the documented environment:

```sh
# macOS; Linux uses nice -n 15 in place of taskpolicy -b nice -n 15
 taskpolicy -b nice -n 15 make -j1 test-hostmode-loopback test-race
```

This remains a promotion gate. Review the native OS plan with
`bash scripts/verify-install-recovery.sh --native-plan`; Bryan runs any real
service, login, recovery or deployment operation himself.
