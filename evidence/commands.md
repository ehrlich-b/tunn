# R2 fix commands and source identities

Carrier: `8cb0b92505fdaaaf7497005aea7521e84f157ee1`.
Implementation and focused tests: `fb8ae9a695e434538bb914f38c2abc4639d02d6c`.
Final source, including the container shell correction: `139abea637e4521967766eacad0d7c1d9b48679c`.
The final evidence/documentation commit adds no application, dependency, test or Dockerfile changes.

All Go worker commands use `GOFLAGS=-p=4 GOTOOLCHAIN=local` and `nice -n 10`.
Full suites use `umask 022`, `TUNN_SHARE_BROWSER_PYTHON=/work/lanes/tunn-share/review/.venv/bin/python`, and `PLAYWRIGHT_BROWSERS_PATH=/home/ehrlich/.cache/ms-playwright`, matching carrier acceptance. Final suites explicitly use `-p=1`, matching the carrier's recorded baseline and reducing simultaneous package workloads. Host Go is 1.27.2/Linux amd64; container Go is 1.26.9 from the unchanged 1.26 Alpine builder.

| Command (after the environment/nice prefix above) | Evidence |
| --- | --- |
| `go get google.golang.org/grpc@v1.83.2 github.com/quic-go/quic-go@v0.59.1` | `dependency-upgrade.log` |
| `go mod tidy` and `git diff -- go.mod go.sum` | `mod-tidy.log`, `mod-tidy.diff` |
| `go mod tidy -diff` | `mod-tidy-source-final.diff`, `.stderr`, `.exit` |
| `go mod verify` | `mod-verify.log`, `.exit` |
| `go vet ./...` | `vet-source-final.log`, `.exit` |
| `go test -race -json ./internal/host -run '^TestHTTPFidelityUnknownUploadLimitBeforeEmptyResponse$' -count=50 -timeout=300s` | `upload-before-fix-race-50.jsonl`, `.stderr`; carrier upload implementation, upgraded modules, before the fix |
| `go test -race -json ./internal/host -run '^TestHTTPFidelityUploadLimitCleanupCancellation$' -count=1 -timeout=60s` | `upload-cleanup-carrier.jsonl`, `.stderr`; isolated clone of carrier SHA with only the new regression test copied in |
| `go test -race -json ./internal/host -run '^TestHTTPFidelity(UnknownUploadLimitBeforeEmptyResponse\|UploadLimitCleanupCancellation)$' -count=50 -timeout=300s` | `upload-fixed-race-50.jsonl`, `.stderr`; fixed implementation |
| `go test -race -json ./internal/host -run '^(TestReleaseNativeInternalListenerAuthorization\|TestOpsLoopbackShutdownWithLivePublisherAndRestart\|TestReviewTLSListenerConfigurationIsolation\|TestLoopbackNativeSSHJump\|TestLoopbackEdgeOpenSSHAndHTTPSSharePort)$' -count=1 -timeout=180s` | `transports-race-final.jsonl`, `.stderr`; fb8ae9a |
| `go test -p=1 -json ./... -count=1 -timeout=300s` | `full-serial.jsonl`, `.stderr`, `.exit`; 139abea |
| `go test -p=1 -race -json ./... -count=1 -timeout=300s` | `full-race-serial.jsonl`, `.stderr`, `.exit`; 139abea |
| `/work/lanes/tunn-sshj/review2/scratch/bin/govulncheck -json ./...` | `govulncheck.jsonl`, `.stderr`; upgraded modules, fixed application implementation |
| Carrier-only `go test -p=1 -json ./internal/mcpbridge -count=10 -timeout=120s` and `... -run '^TestBridgeEnforcesLocalToolAllowList$' -count=50 -timeout=120s` | `carrier-mcp-repeat.jsonl`, `carrier-mcp-exact-repeat.jsonl`, corresponding `.stderr`/`.exit`; source SHA in `carrier-mcp-source-sha.txt` |
| Carrier-only `go test -p=1 -race -json ./internal/mcpbridge -count=10 -timeout=120s` under default GORACE | `carrier-mcp-race-repeat.jsonl`, `.stderr`, `.exit`; all three final race failures reproduced |
| `go list -m all` | `selected-modules.txt` |
| `go build -o ../artifacts/tunn .`; `go version -m ../artifacts/tunn`; `sha256sum ../artifacts/tunn` | `build.log`, `.exit`, `artifact-modules.txt`, `artifact-sha256.txt` |
| `docker build --platform linux/amd64 -t tunn-release-r2fix-local:20261011 .` with `GOFLAGS=-p=4 nice -n 10` | `container-build-final.log`, `.exit`; 139abea; Dockerfile also nices its builder shell and sets GOFLAGS |
| `docker image inspect tunn-release-r2fix-local:20261011 --format '{{.Id}}'` | `container-image-id.txt` |
| `docker run --rm --entrypoint /app/tunn tunn-release-r2fix-local:20261011 --help` and `... domain --help` | `container-help.log`, `.exit`, `container-domain-help.log`, `.exit` |
| `docker run --rm --entrypoint /bin/cat tunn-release-r2fix-local:20261011 /app/tunn > ../artifacts/tunn-container`; host `go version -m` and `sha256sum` | `container-artifact-modules.txt`, `container-artifact-sha256.txt` |

`source-revalidation.txt` records exact source excerpts and line numbers: public ServeHTTP dispatch, native internal Serve, HTTP/3 startup, gRPC default-enabled receive-buffer compaction, QUIC decoded header/trailer budgets, and net/http background-read cancellation. `compaction-overrides.txt` is empty: the application does not disable compaction. The scanner exits successfully with no called-symbol findings; its sole module-only finding is unchanged x/crypto OpenPGP (GO-2026-5932), which this application does not import. No exhaustion attack was run.

The tidy diff was reviewed: grpc and QUIC plus required protobuf, genproto/rpc, metadata and QPACK upgrades; checksum changes also reflect grpc's test/telemetry dependencies. No existing x/* security pin was lowered. The final tidy diff is empty. `upload-test-addition.diff` shows that the reviewed test and its 413 assertions are unchanged; only an import and a new cleanup-cancellation regression were added. `upload-reviewed-test-integrity.txt` verifies and hashes the original regression function byte-for-byte.

Initial logs are retained. `upload-cleanup-fixed.jsonl` records an initial missing-import build failure, corrected before validation. `transports-race.jsonl` and `full.jsonl` record the new native fixture's initial anonymous-before-authenticated ordering, which triggered the intended IP blacklist; the fixture now authenticates first and cleans up its own loopback block. `full-final.jsonl` records the initial nicing change violating the existing literal Docker build contract; 139abea moves nicing to Docker's shell and preserves that contract without changing its test. `full-race.jsonl` and `full-race-final.jsonl` retain intermediate MCP cleanup-deadline failures under concurrent package/suite/build load. The first sequential non-race suite (`full-serial-initial.jsonl`) also hit `TestBridgeEnforcesLocalToolAllowList` cleanup timeout. On untouched carrier SHA `8cb0b92`, ten complete MCP package repeats reproduced a `TestBridgeCarriesFiniteSSENotifications` cleanup timeout, and fifty exact `TestBridgeEnforcesLocalToolAllowList` repetitions reproduced that same test's timeout. `mcp-source-unchanged.diff` is empty; this package imports only the standard library. The carrier validation already documents intermittent MCP Close deadlines; the final non-race full suite passes. The final complete race suite exits 1 solely for three MCP cleanup failures, all independently reproduced under default -race on the carrier; it has zero detector warnings and zero new failed tests/packages. Exploratory `GORACE=atexit_sleep_ms=0` repetitions (`mcp-race-no-exit-sleep.jsonl` and `carrier-mcp-race-no-exit-sleep.jsonl`, ten package repetitions each) did not remove the flake and were not used for final acceptance. `container-build.log` is the earlier passing build before the shell correction.

`carrier-full-suite.diff` preserves the supplied zero-failure comparison. `review2-original-head-race.log` preserves the review's original 502 failure. `summary.json` and `comparison.txt` describe the final outcomes; `SHA256SUMS` hashes the saved evidence files. Binary artifacts stay outside the clone in `../artifacts/`. No push or deployment was performed, and the carrier remains unchanged.

Staged source/documentation whitespace checks pass (`source-docs-diff-check.exit`). The all-artifact check reports only verbatim module/help output tabs and unified-diff context whitespace (`staged-evidence-diff-check.txt`); the raw evidence is preserved.
