# Round 5 reproduction

Run from `/work/lanes/tunn-r4fix/tunn`, on
`codex/tunn-r4fix-20261012`, based on
`8d0bf599b68b25af9ad6f5b030255a986fcf828c`.

```bash
source evidence/fix-r5/env.sh
```

The environment sets `GOMAXPROCS=4`, `GOFLAGS=-p=4`, `umask 022`,
`GOCACHE=$PWD/.scratch/go-cache`, and `GOTMPDIR=TMPDIR=$PWD/.scratch/tmp`.
The existing cache helper reads shared immutable artifacts and writes new
entries only inside this clone. Module downloads and Go telemetry are disabled.
The installed Python/Chromium inputs enable both existing browser sharing and
cache regression tests; browser profiles and temporary files stay in the clone.
The opt-in Pebble gate remains disabled. DNS/issuance use synthetic local fixtures.

The permanent regression was first run before changing application source:

```bash
go test -race -p 4 -count=1 -parallel=2 -timeout=120s \
  -run '^TestR5ConcreteCachedKeyRechecksAuthority$' -v ./internal/domains
```

`regression-before.log` / `.exit` record six failures (exit 1): reservation
reassignment, Pro downgrade, combined lease/state revocation, expired lease,
cleared readiness, and expired certificate. Every case returns a private key
after the independent writer's mutation commits; the next call denies access.

Final source repeats the same permanent regression three times under race,
using `-count=3`: `regression-after.log` / `.exit`.
It requires a successful exact certificate/key read before revocation, a
one-row committed mutation at the key-query boundary, and a nil pair with
the existing `FailedPrecondition` authority-change denial afterward.

Generate the base-source and unchanged original-review overlays locally:

```bash
python3 - <<'PY'
import json
import subprocess
from pathlib import Path
root = Path.cwd()
scratch = root / '.scratch/r5'
scratch.mkdir(parents=True, exist_ok=True)
base = scratch / 'registry-base.go'
base.write_bytes(subprocess.check_output([
    'git', 'show',
    '8d0bf599b68b25af9ad6f5b030255a986fcf828c:internal/domains/registry.go']))
(scratch / 'base-overlay.json').write_text(json.dumps({'Replace': {
    str(root / 'internal/domains/registry.go'): str(base)}}))
(scratch / 'review-overlay.json').write_text(json.dumps({'Replace': {
    str(root / 'internal/domains/r5_cached_authority_test.go'):
    str(root / 'evidence/fix-r5/review_r5_cached_authority_test.go.txt')}}))
PY
go test -race -p 4 -count=1 -parallel=2 -timeout=120s \
  -overlay .scratch/r5/base-overlay.json \
  -run '^TestR5ConcreteCachedKeyRechecksAuthority$' -v ./internal/domains
go test -race -p 4 -count=3 -parallel=2 -timeout=120s \
  -overlay .scratch/r5/review-overlay.json \
  -run '^TestR5ConcreteCachedKeyRechecksAuthority$' -v ./internal/domains
```

`regression-base-recheck.log` / `.exit` reproduce all six failures (exit 1)
against the requested base at the final working source.
`review-after.log` / `.exit` run the byte-identical reviewer probe with its
unchanged assertions, for all nine required interleavings under race.
`source-manifest.json` records source hashes and the probe's original path/hash.

Full acceptance gates run without any source or test overlay:

```bash
go vet -p 4 ./...                                          # vet.log
go test -p 4 -count=1 -parallel=2 -timeout=600s ./...         # full.log
go test -race -p 4 -count=1 -parallel=2 -timeout=600s ./...   # race-1.log
go test -race -p 4 -count=1 -parallel=2 -timeout=600s ./...   # race-2.log
```

Each command's complete combined output is retained in the named log, with
the actual exit status in a matching `.exit` file. `-count=1` executes both
full race runs independently, including SDK consumer integration and all
existing domain and sharing regressions. `summary.json` records gate exits
and package counts. `git diff --check` is also required before committing.

The existing domain verifier regression also runs unchanged:

```bash
python3 evidence/fix-r3-domains/verifier-regression.py
```

`verifier-regression.log` / `.exit` record its successful local synthetic-key,
mocked-JWKS checks, including retired-key denial and retained identity checks.

All edits, evidence and commits stay inside this clone; no push, GitHub write,
deployment, production DB, provider login, real ACME, email, payment,
resource-exhaustion input or sub-agent work occurs.
