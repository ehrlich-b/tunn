# Reproduction

All commands run from `/work/lanes/tunn-r4share/tunn` on
`codex/tunn-r4share-20261012`, starting from `1188c57`.

```sh
source evidence/fix-r4-share/env.sh
# Before repair: apply only the lower owner cap option needed by the host fixture.
# before.log / before.exit were recorded before either defect was repaired.
# Reproduce all final regressions against the old application behavior:
python3 evidence/fix-r4-share/make-before-overlay.py
go test -p 4 -overlay=evidence/fix-r4-share/before-overlay.json -v -count=1 -parallel=2 -timeout=600s ./internal/metering ./internal/host -run '^TestR4'
# Acceptance uses no overlays, with unchanged existing tests and both browser gates:
go test -p 4 -v -count=1 -parallel=2 -timeout=600s ./internal/metering ./internal/host -run '^TestR[34]|^TestWebSharing|^TestOrgGroup'
go vet -p 4 ./...
go test -p 4 -json -count=1 -parallel=2 -timeout=600s ./...
go test -race -p 4 -json -count=1 -parallel=2 -timeout=600s ./internal/metering ./internal/host
go test -race -p 4 -json -count=1 -parallel=2 -timeout=600s ./internal/metering ./internal/host
go mod tidy -diff
git diff --check
```

Go module downloads are disabled. The existing module cache, Python environment
and Chromium installation are read-only inputs. Go build cache, GOPATH,
GOTMPDIR, TMPDIR and browser profiles use this clone's gitignored `.scratch`.
GOMAXPROCS=4 and -p=4 apply to every Go invocation. No cache fallback helper
or shared mutable build cache is used.

`regressions-browser-path-initial.log.gz` / `.exit` retain an environment failure:
Playwright 1.55 expected Chromium revision 1187, while the initially selected
shared browser directory contained revision 1243. The final environment selects
the already installed matching revision in `/home/ehrlich/.cache/ms-playwright`.
No browser download or test change was needed. `module-tidy.log.gz` records the
expected indirect-to-direct dependency change for the existing errdetails module;
`module-tidy-final.log.gz` / `.exit` confirm tidy with no remaining changes.

The before overlay preserves the lower owner-limit option and restores reviewed
sharing.go, sharing_limits.go and remote.go byte-for-byte from the base commit,
and restores the original ErrCapacity sentinel in store.go. It exists only for
negative evidence; no full, vet, race or acceptance gate uses it. The original
three supplied characterization files were read in full and left unchanged;
new test files assert corrected behavior.

Evidence logs and JSONL outputs are stored with lossless gzip compression;
use `gzip -dc` to read them without creating another file.
