# Durable credential security fixes

Validation ran on Linux amd64, Go 1.27.2, with native TCP, UDP and Unix sockets,
against an archived `11ae780` checkout. The independent review was read in full;
its `.scratch` directory contains dependency and build caches, while its actual
reproductions live in `adversarial/internal/host/review_security_test.go` and the
retained native lifecycle logs. All six review tests are now in the normal test
suite. The database migration test uses checked-in production-base fixtures and
no longer depends on environment variables or skips when fixtures are absent.

## Findings and regression proof

| Check | 11ae780 with identical added tests | Fixed candidate |
| --- | --- | --- |
| Mixed-case browser login, authorization, exchange, list, revoke, refresh | FAIL: stored owner `Owner@Example.COM`, absent from list, revoke 404, refresh 200 | PASS: canonical stored owner, listed, revoke 303, refresh 401 |
| Existing mixed-case owners, aliases, whitespace and full-width Unicode | FAIL: noncanonical access claims, absent from list, revoke 404, refresh 200 | PASS: canonical rotation/retry claims, listed, revoke 303, refresh 401 |
| Already-authorized code, both legacy and durable exchange | FAIL: noncanonical token claims and durable row | PASS: canonical claims and durable row |
| Device-code storage and both code lookups | FAIL: noncanonical owners | PASS: the same `common.NormalizeEmail` policy on writes and compatibility reads |
| Concurrent native HTTP/2 and HTTP/3 startup | FAIL: shared TLS template mutation and detector reports in `http2.ConfigureServer` versus `tls.Config.Clone` | PASS: independent configurations and successful negotiation of both protocols |
| Cross-account device isolation, shared-file native refresh, concurrent replay, account route scope, production-base database migration | PASS | PASS |

The owner fix uses the existing account normalization policy for session and
legacy access issuance, identity lookup, device-code writes/reads, durable
issuance/rotation and list/revoke ownership checks. Old sessions, authorized
codes and durable rows work through compatibility reads without a backfill or
rewriting account data. Mixed-case account aliases remain revocable through
their current account bucket. Cross-account access remains denied.

HTTP/2 and HTTP/3 each clone the immutable TLS template before protocol setup;
the HTTP/2 server and TLS listener use the same copy. The inherited startup race
is fixed, with no skipped known-issue test. The native readiness lifecycle test
and the new TLS isolation/negotiation regression each passed 100 repetitions
under `-race` (200 total runs).

The database fixture comes from production base `110485c`. Repeated durable
initialization preserves all 20 original table schemas and all 20 existing rows;
only the two durable tables are added. Base-signed legacy access, browser session
and outstanding legacy device exchange remain usable. The fixture README
describes its fixed test token timestamps and signing key.

## Commands and retained evidence

Run from the repository root with `GOTOOLCHAIN=local`:

```sh
go test -p=1 ./... -count=1
go test -race -p=1 ./internal/common ./internal/host ./internal/store ./internal/storage ./internal/client -count=1
go test -race -v ./internal/host ./internal/store -run '^Test(Review|DeviceCodeOwnerNormalization)' -count=1
go test -race ./internal/host -run '^Test(OpsLoopbackReadinessLifecycleAndDependency|ReviewTLSListenerConfigurationIsolation)$' -count=100 -timeout=90s
go test -race -p=1 -parallel=2 ./internal/host -run '^Test(Durable|ProdAuth|Review|Security|GitHub|MagicLink|GetAuthFromTunnelBearer|MalformedAuthorization)' -count=1 -timeout=180s
go vet ./...
git diff --check
```

The complete local logs are retained in
`/work/lanes/tunn-refresh/fix-evidence/`: `before-full.log`, `after-full.log`,
`before-race.log`, `after-race.log`, `before-ported-regressions.log`,
`after-regressions.log`, `after-tls-race-100.log`, `after-auth-race.log` and
`after-vet.log`. The original
unpatched finding trace is also retained as `before-regressions.log`. The initial
full-suite and package-race comparison ran before adding the review tests to the
archived baseline; the separate regression comparison adds the same tests and
fixtures to that baseline. No aggregate tests were excluded or skipped to make
the gates appear green.

## Remaining aggregate failures

The full suite was executed and is **failing**, on both `11ae780` and the fixed
candidate, due to these unchanged host-mode checks:

- `TestHostRuntimeConfiguredCredentialRootSurvivesRestart`: private-directory
  rejection in `endpointTokenIn`.
- `TestHostRuntimeTokensSurviveRestart`: the same private-directory rejection.
- `TestLoopbackHostMode`: host state fails to converge, also reproduced by the
  independent review against `110485c`, with a private-directory rejection in
  its retained trace.

The package race run passed common/auth helpers, store, storage and client on
both versions. The host package failed on both versions due to host-mode state
convergence and an upload timing check; the baseline additionally reported the
TLS startup race, which is absent after the fix. The full package race gate is
therefore **failing**, not green, despite removal of the TLS race.

The focused authentication race command above passed in 47.257 seconds,
including all durable and review regressions, production authentication,
native HTTPS OAuth lifecycle, GitHub login, magic links and security checks.
All ten newly ported or added regression tests passed under `-race`. Vet,
formatting and whitespace checks also passed.

The baseline aggregate also encountered timing failures in
`TestBridgeRejectsChildRequestsWithoutDeadlock` (child close deadline) and, under
`-race`, `TestHTTPFidelityUnknownUploadLimitBeforeEmptyResponse` (early response
path returned 502). The fixed package race run also encountered the upload
timing failure. The child-close test passes three isolated baseline reruns;
the upload check passes three isolated `-race` reruns on both versions. Neither
appears in the fixed ordinary full-suite run. Logs are
`before-mcp-rerun.log`, `before-upload-race-rerun.log` and
`after-upload-race-rerun.log`. These are recorded separately from the security
fixes.

No billing implementation was changed, and nothing was pushed or deployed.
Deployment and rollback instructions are in [the durable credential
runbook](durable-credentials.md#deployment-runbook).
