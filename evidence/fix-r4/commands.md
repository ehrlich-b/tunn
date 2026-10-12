# Round 4 reproduction

All commands run in `/work/lanes/tunn-r4fix/tunn`, branch
`codex/tunn-r4fix-20261012`, based on
`1188c576529660211a5c4a0a39d2e964eafeb9ac`, using Go 1.27.2 linux/amd64.
The starting tree was clean; the round-three implementation and evidence were
retained. The complete lane BRIEF.md, independent REVIEW.md, original regression
and diagnostic control log were read before changes.

```bash
source evidence/fix-r4/env.sh
```

This sources the existing round-three domain environment: `GOMAXPROCS=4`,
`GOFLAGS=-p=4`, `umask 022`, `GOCACHE=$PWD/.scratch/go-cache`, and
`GOTMPDIR=TMPDIR=$PWD/.scratch/tmp`. The existing Go cache protocol helper reads
shared immutable artifacts and writes new entries only under this clone's
`.scratch/go-cache`. Module network access and Go telemetry are disabled.
No linker/debug stripping, test assertion changes, or test overlays are used
for the full acceptance gates. `.scratch/` is already gitignored.

The expanded regression was added and executed before any tracked base source
changed. Both subtests failed on the base with `409 Domain already claimed`:

```bash
go test -p 4 -count=1 -timeout=600s \
  -run '^TestR4PublicAPIExposesCompetingProof$' -v ./internal/host
```

Output: `regression-before.log`, exit 1 in `regression-before.exit`.
`review_r4_reclaim_test.go.txt` is a byte-for-byte copy of the independent
review regression. A test-only overlay replacing the new regression with that
copy also failed before the application change (`review-before.log`, exit 1).
The overlay is generated inside this clone:

```bash
python3 - <<'PY'
import json
from pathlib import Path
root = Path.cwd()
(root / '.scratch/review-overlay.json').write_text(json.dumps({'Replace': {
    str(root / 'internal/host/r4_reclaim_test.go'):
        str(root / 'evidence/fix-r4/review_r4_reclaim_test.go.txt')
}}))
PY
go test -p 4 -count=1 -timeout=600s -overlay .scratch/review-overlay.json \
  -run '^TestR4PublicAPIExposesCompetingProof$' -v ./internal/host
```

After the fix, the API regression, membership boundary test, and CLI error
propagation test run together:

```bash
go test -p 4 -count=1 -timeout=600s \
  -run '^(TestR4PublicAPIExposesCompetingProof|TestReviewMembershipRemovalAndNoRefreshExtension|TestDomainCLIReportsCompetingProof)$' \
  -v ./internal/host .
```

Output: `regression-after.log` and `.exit`. Final focused race command adds
`-race` and writes `regression-race-after.log` and `.exit`.
The independent review overlay also runs after the fix with `-race`, writing
`review-after.log` and `.exit`.

Full acceptance commands, each with a separate log and exit file:

```bash
go vet -p 4 ./...                                          # vet.log
go test -p 4 -count=1 -parallel=2 -timeout=600s ./...        # full.log
go test -race -p 4 -count=1 -parallel=2 -timeout=600s ./...  # race-1.log
go test -race -p 4 -count=1 -parallel=2 -timeout=600s ./...  # race-2.log
```

`-count=1` forces both race runs to execute tests. Both runs cover all packages,
including the SDK consumer integration; no package subset substitutes for a
full race gate. Default test conditions apply; optional Chromium/Pebble gates
are not enabled. Domain proof checks use small synthetic TXT records and a
local database; no CA issuer is configured for the new regression.

An explicit base-source overlay recheck can be reproduced at the final head:

```bash
python3 - <<'PY'
import json
import subprocess
from pathlib import Path
root = Path.cwd()
base = root / '.scratch/base-domains.go'
base.write_bytes(subprocess.check_output(
    ['git', 'show', '1188c57:internal/host/domains.go']))
(root / '.scratch/base-overlay.json').write_text(json.dumps({'Replace': {
    str(root / 'internal/host/domains.go'): str(base)
}}))
PY
go test -p 4 -count=1 -timeout=600s -overlay .scratch/base-overlay.json \
  -run '^TestR4PublicAPIExposesCompetingProof$' -v ./internal/host
```

Output: `regression-base-recheck.log` and `.exit`, expected exit 1 for both
wildcard conflict cases. The response handler is the only changed application
file, so this overlay runs the complete unchanged base application against the
expanded regression; membership and CLI fixture edits are test-only.

The built CLI's actual stderr is also checked against a synthetic loopback API:

```bash
go build -p 4 -o .scratch/tunn-cli .       # cli-build.log and .exit
python3 evidence/fix-r4/cli-proof.py      # cli-proof.log and .exit
```

The probe requires CLI exit 1 for the HTTP 409, the complete caller TXT name,
target and retry instructions in stderr, and the authenticated expected JSON
request. Its token, binary and temporary files remain inside this clone.
