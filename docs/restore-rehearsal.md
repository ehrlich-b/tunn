# Hosted restore rehearsal and evidence boundary

**Live T-07: BLOCKED.** No authorized hosted backup, native operator receipt, agreed RPO/RTO, or hosted reconciliation evidence was supplied. The local tool exercises a disposable synthetic SQLite/WAL example only; its schema is not the hosted Tunn schema and its pass is not a hosted restore receipt. Full registered Tunn qualification is still required on the integrated release candidate.

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
