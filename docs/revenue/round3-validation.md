# Round-3 validation — 2026-10-11

Clone: `w9-tunn-revenue-20261011`, branch `codex/tunn-revenue-20261011`.
Baseline: `4416eff`; old serving implementation/schema: `110485c`.
All data, receipts, signatures, provider identifiers and evidence are synthetic.
No production connection, mutation, deployment, push or external message occurred.

## Identical regression proof

The final bodies of these five regressions compile and fail on a fresh
`git archive 4416eff`, then pass with the fixes. These are failed safety
assertions, not compilation failures:

| Reproduction | Before | After |
| --- | --- | --- |
| `TestR3RedeployAfterOldMergeAndRevocation` | FK-on old merge fails; FK-off re-upgrade restores revoked Pro; scoped bootstrap lacks protection | PASS, including pre-journal recovery |
| `TestR3EditedReferenceBypassesQuarantine` | 2 verified subscriptions, 0 quarantines | PASS: 1 verified subscription, 1 quarantine |
| `TestR3DelayedSignedOnTimePaymentAcceptance` | Signed completion delivered at +25h is unfulfillable | PASS: fresh signed late delivery followed by reviewed Pro |
| `TestR3DelayedOnTimeCompletionCanBeFulfilled` | Store loses completion time and blocks fulfillment | PASS: retained completion evidence, reviewed Pro |
| `TestR3QuarantineCustomerAndOperatorVisibility` | Active Pro hides duplicate; unbound status fails | PASS: account/return page, API notice and operator visibility |

[Before evidence](validation-logs/round3-before.txt),
[after evidence](validation-logs/round3-after.txt).
The store completion-time reproduction encodes the new metadata through JSON,
so the identical body compiles at the baseline where that field is discarded.
The rollback test executes the old release's merge/UpdatePlan write sequence
against a reusable database seeded by the unmodified archived `110485c`.
It covers old OpenLocal FK-on and actual old host FK-off modes. The pre-journal
variant simulates a 4416eff snapshot without compatibility triggers.

Additional regressions cover missing **and** unknown references, ownership scope,
queue discoverability before binding, CAS replay, failed audit rollback, real
late purchases, explicit legitimate additional purchases, cancellation/refund
closure, restart/replay, blocking another sale during review, approval refusing
to revive older verified evidence, old grant requests requiring global approval,
and a legacy regrant never restoring a separately held subscription. Startup
also reconciles journaled plan caches used by metering/domains, so an old Pro
cache write cannot bypass the new grant decision. A prebound
Free state cannot substitute for an additional-purchase decision using only a
later lifecycle receipt. CLI coverage exercises the read-only queue and audited
approval against a real synthetic local SQLite DB.

The earlier billing/store/storage/host/CLI regressions remain green. One older
adapter test now expects explicit ownership quarantine for an unbound completion
instead of generic reconciliation; its no-webhook-created-account assertion is
retained. The existing unverified-cache fixture now explicitly marks its writes as
new-code projection corruption instead of old-code grant requests, retaining
its original no-import, plan and reservation-preservation assertions. Separate
R3 coverage requires journaled rollback cache repair. No prior entitlement,
ordering, refund, suspension, migration or reservation safety assertion was removed.

## Final checks

The portable run passes all **17 packages with tests**, including the previous
billing regressions and the new ones. Full store/storage race suites and focused
billing/host/CLI race checks pass. See
[portable package summary](validation-logs/round3-portable.txt) and
[race results](validation-logs/round3-race.txt). `git diff --check` passes.
The portable run uses the existing memory transport flags for WebSocket and
proxy dogfood tests, while excluding 35 tests that require socket listeners.
Those exclusions are explicit below; this is not an unrestricted full-suite pass.

The unrestricted `go test ./... -count=1` was attempted twice. It fails on denied
loopback listeners in inspector and MCP bridge tests; listener panics stop some
later client/host tests. [Attempt evidence](validation-logs/round3-full-attempt.txt).
The portable run also reports the existing homograph known-gap skip and three
constructor/run tests skipped because `certs/cert.pem` is absent. Constructor
acceptance remains dependent on normal test certificates and loopback access.
The prior round-3 actual-constructor preservation evidence was supplied evidence;
this fix did not independently repeat its 50-row/21-table process harness.

Go version: **go1.26.2 darwin/arm64**.

Every Go invocation uses `taskpolicy -b nice -n 15` and clone-local caches:

```sh
mkdir -p .scratch/go-build .scratch/go-mod .scratch/go-tmp
export GOCACHE="$PWD/.scratch/go-build"
export GOMODCACHE="$PWD/.scratch/go-mod"
export GOTMPDIR="$PWD/.scratch/go-tmp"
export GOPROXY=off
```

The fixed regression proof command is:

```sh
taskpolicy -b nice -n 15 go test ./internal/store ./internal/host -run '^TestR3(RedeployAfterOldMergeAndRevocation|DelayedOnTimeCompletionCanBeFulfilled|EditedReferenceBypassesQuarantine|DelayedSignedOnTimePaymentAcceptance|QuarantineCustomerAndOperatorVisibility)$' -count=1 -v
```

The race commands are:

```sh
taskpolicy -b nice -n 15 go test -race ./internal/store ./internal/storage -count=1
taskpolicy -b nice -n 15 go test -race ./internal/host . -run 'Billing|Review|R3|Rereview|AccountOperations' -count=1
```

To reproduce the portable run on this clone, the memory-transport wrapper is:

```sh
mkdir -p .scratch/r3-fix
cat > .scratch/r3-fix/test-exec <<'SH'
#!/bin/sh
set -eu
case "$1" in
  */host.test) exec "$@" -websocket-memory ;;
  */client.test) exec "$@" -dogfood-proxy-memory ;;
  *) exec "$@" ;;
esac
SH
chmod 700 .scratch/r3-fix/test-exec
```

The portable command, using the caches above and the exact exclusion set:

```sh
taskpolicy -b nice -n 15 go test ./... -count=1 -json -exec "$PWD/.scratch/r3-fix/test-exec" -skip '^(TestInspectorCapturesAndReplaysToLocalTarget|TestInspectorStreamingCaptureAndReplayProtection|TestInspectorStartsOnLoopbackWithSessionSecret|TestHandleHttpRequest|TestHandleHttpRequestRewritesAdapterPath|TestInboundConnectionStreamsHTTP|TestHandleHttpRequestMultiValueHeaders|TestHandleHttpRequestConcurrent|TestHandleHttpRequestTimeout|TestProcessMessagesHttpRequest|TestInboundConnectionStreamsTCP|TestInboundConnectionStreamsUnixSocket|TestInboundConnectionServesHTTPOverUnixSocket|TestConnectClientOverHTTP2CONNECT|TestLoopbackEdgeOpenSSHAndHTTPSSharePort|TestLoopbackHostMode|TestBridgeMCPFlow|TestBridgeOfficialGoSDKClient|TestBridgeModernHeadersAndSessionlessCalls|TestBridgeCarriesFiniteSSENotifications|TestBridgeRejectsChildRequestsWithoutDeadlock|TestBridgeEnforcesLocalToolAllowList|TestBridgeValidatesHTTPEnvelope|TestBridgeReportsChildExit|TestBridgeFailsRequestWhenChildExits|TestOpsLoopbackReadinessLifecycleAndDependency|TestOpsLoopbackStartupFailureReleasesSiblingListeners|TestOpsLoopbackShutdownWithLivePublisherAndRestart|TestProdAuthLoopbackHTTPSOAuthLifecycle|TestSDKResponseConformance|TestSDKResponseControllerConformance|TestSDKCLIHTTPAndWebSocketContract|TestSDKActiveWebSocketClose|TestSDKExternalResponseConsumer|TestStreamingHTTPAcrossRealGRPCTunnel)$'
```

## REQUIRED-UNRUN

Run the unrestricted full suite in this clone where TCP/UDP/Unix loopback
listeners are permitted and the repository's normal synthetic test certificate
fixtures are available. This exact command has no test exclusions or memory
transport substitutions:

```sh
taskpolicy -b nice -n 15 env GOCACHE="$PWD/.scratch/go-build" GOMODCACHE="$PWD/.scratch/go-mod" GOTMPDIR="$PWD/.scratch/go-tmp" GOPROXY=off go test ./... -count=1
```

Real Stripe sandbox lifecycle, hosted clients, immutable image build, actual
production inventory and deploy/rollback rehearsal remain the separately owned
release gates in the [runbook](round3-fixes.md). No live-mode payment was used
or represented as acceptance evidence.
