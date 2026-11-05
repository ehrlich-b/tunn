# Hosted restore rehearsal and evidence boundary

**Live T-07: BLOCKED.** No authorized hosted backup, native operator receipt, agreed RPO/RTO, or hosted reconciliation evidence was supplied. The offline verifier below checks a standalone database copy against the current relay schema. The older synthetic reconciliation rehearsal remains separate; its example schema is not the hosted Tunn schema. Neither a fixture pass nor a database boot proves hosted reconciliation or RPO/RTO. Full registered Tunn qualification is still required on the integrated release candidate.

## Verify a hosted backup copy on the Mac

The verifier uses Python 3's standard library only. Run from this checkout's root
on a private Mac directory, outside any synced/shared folder. It opens the input
using SQLite URI `mode=ro&immutable=1` and `query_only`, runs `integrity_check`,
and compares every table definition and index with
`scripts/hosted-backup-schema.json`. That reference comes from an empty database
created by the standalone login relay. The fixture test independently boots the
relay from the current checkout and checks that the reference still matches.
Extra/missing tables, altered definitions/indexes, views and triggers fail closed;
optional SSH, host-mode, custom-domain or organization schemas need a reviewed
reference for that configuration. This tool does not migrate an old backup to
make it pass. The receipt contains table row counts and validated newest scalar
timestamps, normalized to UTC before choosing the newest instant, including
values with different UTC offsets or mixed integer/text storage. Invalid values
are ignored; a column with no valid timestamps reports null. It does not print
row contents, identities, tokens, source paths or SQLite error details. Times
embedded in JSON/BLOB payloads are not extracted.

An authorized operator supplies the login Machine ID, its existing non-root
readable backup path on the `/data` volume, and an independently recorded SHA-256
for that exact artifact. `fly.toml.dist` mounts `tunn_data` at `/data`; its live
database defaults to `/data/tunn.db`. Fetch a **completed standalone backup**, not
the live database. A raw copy of an active database can omit committed WAL data.
Use the service's SQLite online-backup procedure to produce a new standalone
artifact if no completed backup exists; do not copy the live main file alone or
separately fetch moving WAL files. Backup inventory, actual Machine ID/path and
authenticated digest must come from the operator; they cannot be inferred here.

Exact Mac commands (set the four supplied values before running; no remote
backup creation or service changes are performed):

```sh
set -eu
export TUNN_BACKUP_MACHINE='REPLACE_WITH_LOGIN_MACHINE_ID'
export TUNN_BACKUP_REMOTE='/data/REPLACE_WITH_COMPLETED_BACKUP.sqlite'
export TUNN_BACKUP_USER='REPLACE_WITH_NON_ROOT_BACKUP_READER'
export TUNN_BACKUP_SHA256='REPLACE_WITH_AUTHENTICATED_SHA256'
umask 077
backup_dir=$(mktemp -d "$HOME/tunn-backup-verify.XXXXXX")
fly ssh sftp get --app tunn --machine "$TUNN_BACKUP_MACHINE" \
  --user "$TUNN_BACKUP_USER" "$TUNN_BACKUP_REMOTE" "$backup_dir/backup.sqlite"
printf '%s  %s\n' "$TUNN_BACKUP_SHA256" "$backup_dir/backup.sqlite" | shasum -a 256 -c -
chmod 400 "$backup_dir/backup.sqlite"
nice -n 10 python3 -B scripts/verify-hosted-backup.py "$backup_dir/backup.sqlite" \
  > "$backup_dir/receipt.json"
cat "$backup_dir/receipt.json"
```

Stop if transfer or digest verification fails. The [Fly SFTP get command](https://fly.io/docs/flyctl/ssh-sftp-get/)
downloads the named file; it does not create a SQLite-consistent snapshot.
Keep the source and downloaded copy quiescent throughout verification. Nonempty
`-wal` or `-journal` siblings are rejected, without checkpointing or changing
them. A missing WAL cannot be detected if it was never supplied: authenticated
standalone-backup provenance is still required. Do not remove sidecars to pass.

For the optional loopback boot proof, Go matching `go.mod`, its already available
module dependencies, Git, and OpenSSL must be present. The tool builds an archive
of committed HEAD without installing a binary. Use a clean, reviewed checkout at the intended HEAD;
record `git rev-parse HEAD` with the receipt. It boots on a temporary SQLite backup
of the verified copy and discards that temporary target on exit. It never starts
the relay on the supplied input. It clears inherited service/provider settings,
uses an empty working directory, disables mock OIDC, discovery, HTTP/3 and ACME,
and binds both TLS and internal gRPC to `127.0.0.1`. The only HTTP request is local
`/readyz`; success adds `relay: {bind: "127.0.0.1", readyz_status: 200}`. Startup
logs are suppressed to protect customer contents. No production/provider calls
are part of this proof. Run this flag on fixtures first:

```sh
nice -n 10 python3 -B scripts/test_verify_hosted_backup.py
git rev-parse HEAD
nice -n 10 python3 -B scripts/verify-hosted-backup.py --start-relay \
  "$backup_dir/backup.sqlite" > "$backup_dir/boot-receipt.json"
cat "$backup_dir/boot-receipt.json"
```

Exit codes: `0` verified; `2` corrupt/truncated SQLite; `3` wrong schema;
`4` uncheckpointed WAL/journal; `5` missing/unreadable/nonregular input;
`6` relay build/boot/readiness failure. CLI usage errors also use argparse's `2`.
Only successful runs print a JSON receipt. Keep database copies private; the
receipt is a technical check, not authorization to promote or grant access.

## Synthetic reconciliation rehearsal

Run the disposable offline fixture from the repository root:

```sh
python3 -B scripts/rehearse-hosted-restore.py --no-network --synthetic
python3 -B scripts/test_rehearse_hosted_restore.py
```

The JSON output reports measured synthetic restore elapsed seconds separately from unresolved hosted RPO/RTO. The fixture uses synthetic key references, accounts, reservations, paid and suspended states, pending receipts, usage, revocations and refunds; no actual keys or customer contents are read. A copied WAL is checked for header, frame, salt, and checksum consistency before SQLite integrity and state checks. Reconciliation applies post-backup revocation and refund events before acceptance. Missing reconciliation, stale sequence, mismatched hashes, damaged WAL, and production-labelled fixtures are rejected. Hashes detect accidental changes relative to a manifest; they do not authenticate an attacker-controlled manifest.

## Synthetic manifest contract

An operator may inspect and run an **approved synthetic** manifest at a known local path:

```sh
python3 -B scripts/rehearse-hosted-restore.py --no-network --manifest /approved/path/manifest.json
```

Version 1 JSON requires `version: 1`, `kind: "synthetic"`, `source: "generated-fixture"`, `key_references: ["synthetic:key-not-secret"]`, integer `backup_sequence` and `reconciliation_through`, and `files` mapping exactly `snapshot.sqlite`, `snapshot.sqlite-wal`, and `reconciliation.json` to lowercase SHA-256 hex digests. Files are siblings of the manifest. Each input must be a regular, non-symlink file no larger than 64 MiB; digests must be lowercase SHA-256 hex. Labels and hashes cannot establish that ordinary files contain no customer data: the operator must approve and inspect the fixture source and choose a synthetic-only directory, including its parent path. Reconciliation JSON requires `kind: "synthetic"`, matching `backup_sequence` and `through_sequence`, and arrays `revocations` and `refunds` of objects with `account` and post-backup `seq`. The through sequence must exceed the backup sequence. The example is deliberately fixed to the generated fixture and checks its expected records; it is not a general hosted import tool. `--no-network` is mandatory and the script makes no network calls.

## Hosted operator gate

An authorized service operator must separately approve a real manifest and a native hosted restore procedure. This synthetic tool intentionally rejects production manifests and cannot perform that restore. Before any such exercise, record the backup timestamp and consistent database/WAL provenance and authenticated digests, schema and software version, configuration and key *references* (never secret values), target isolation, owner and approval, and a complete independently authenticated revocation and provider/refund reconciliation source through a stated cutoff. Record backup schedule, off-host location and protection, access control, retention and expiry, alert routing and owner, and agreed RPO/RTO. All are currently unresolved; do not infer them from this fixture.

Restore to an isolated disposable target without production routing or provider calls, using an operator-approved native procedure. Verify accounts, reservations, paid states, pending receipts, suspension, retained usage and revocations, and reconcile every post-backup revocation and provider refund before any access can be granted. Record elapsed time, backup age, exact artifact versions, checks and operator-signed receipt without secrets or customer contents. Stop on missing or unauthenticated inputs, inconsistent database/WAL, missing state, incomplete reconciliation, uncertain cutoff, or any attempted production connection. Preserve the source backup and existing production state; discard only the authorized isolated target under the operator's procedure. Do not overwrite production, promote the target, regrant access, or execute provider changes as part of this rehearsal. Rollback ends at discarding that isolated target; a production recovery requires separate authorization and a reviewed plan.

The tool pins the generated synthetic base to a SHA-256 identity independent of the manifest, and also checks WAL page size. This fixture-specific binding does not authenticate hosted snapshots; authenticated paired provenance remains required for hosted evidence. If the local SQLite library generates a different base, the fixture fails closed and requires review rather than changing the pinned identity blindly.
