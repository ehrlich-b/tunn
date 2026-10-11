# Durable credential validation

The unsandboxed security-fix validation supersedes the native REQUIRED-UNRUN
status below. See [durable security validation](docs/durable-security-validation.md)
for the `11ae780` comparison, failing-before/passing-after regressions, executed
full-suite and race gates, and remaining inherited failures. The remainder of
this file is the historical validation for `11ae780`.

Validated on Go 1.27.2 in `/work/lanes/tunn-refresh/tunn`, using only clone-local caches. The committed copy is `/work/lanes/tunn-refresh/committed-tunn` on `codex/tunn-durable-credentials-20261011`; the original checkout's `.git` is mounted read-only. Implementation files are copied byte-for-byte into the committed checkout.

Set up these environment variables from the tested source checkout (or seed the equivalent caches in another checkout):

```sh
export GOCACHE="$PWD/.scratch/go-build"
export GOMODCACHE="$PWD/.scratch/go-mod"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
```

## Passed

- Available full suite: **3,088 passing test cases**, including subtests; every package passed after excluding the blocked tests and two reproduced baseline failures listed below.
- Real SQLite durable exchange, pending/consumed codes, legacy 24-hour exchange, rotation, recovery-window expiry, restart, old-generation replay revocation, explicit device revocation, management isolation, scoped JWT expiry, identity binding and relay clock skew.
- Client relative-expiry scheduling, atomic 0600 state, lost-response recovery, actionable failures, server binding, redirect refusal, concurrent threads/processes, symlink-safe lock files, and cancellation.
- Publisher and client each survived a simulated **48 hours** with 720 rotations. The relay test delivered SSH bytes on the same logical connection throughout, without replacing the publisher. Revocation then stopped refresh, expired the lease and closed SSH. A blocked delivery could not prevent lease expiry.
- Actual TLS/HTTP2 CONNECT over in-memory sockets: 401, forced refresh, retry, then SSH upload/reply; no loopback bind required.
- Build, vet and whitespace checks passed. Windows amd64 and Darwin arm64 OS lock helpers compiled independently. A full Windows client compile could not complete offline because existing SQLite dependencies `go-strftime` and `go-isatty` were not cached; this is not a Windows runtime test.

```sh
go test -race ./internal/client ./internal/host . -run '^TestDurable' -count=1 -timeout=90s
go test -race ./internal/host -run '^TestProdAuth' -skip 'TestProdAuthLoopbackHTTPSOAuthLifecycle' -count=1 -timeout=90s
go test -race ./internal/host -run '^TestWebSocket' -skip 'TestWebSocketIntegration(SelfHostedApplicationJWTAndPlatformCredentials|MeteringAndAccountQuota)' -count=1 -timeout=90s -args -websocket-memory
go test -race ./internal/client -run '^TestDogfood' -count=1 -timeout=90s -args -dogfood-proxy-memory
go build -o .scratch/tunn .
go vet ./...
git diff --check
```

The full available suite command was:

```sh
go test -json -p=1 -parallel=2 ./... -count=1 -timeout=90s -skip 'TestBridgeCarriesFiniteSSENotifications|TestBridgeEnforcesLocalToolAllowList|TestBridgeFailsRequestWhenChildExits|TestBridgeMCPFlow|TestBridgeModernHeadersAndSessionlessCalls|TestBridgeOfficialGoSDKClient|TestBridgeRejectsChildRequestsWithoutDeadlock|TestBridgeReportsChildExit|TestBridgeValidatesHTTPEnvelope|TestConnectClientOverHTTP2CONNECT|TestDogfoodProxyLoginAndHTTP2Control|TestHandleHttpRequest|TestHostRuntimeConfiguredCredentialRootSurvivesRestart|TestHostRuntimeTokensSurviveRestart|TestInboundConnectionServesHTTPOverUnixSocket|TestInboundConnectionStreamsHTTP|TestInboundConnectionStreamsTCP|TestInboundConnectionStreamsUnixSocket|TestInspectorCapturesAndReplaysToLocalTarget|TestInspectorStartsOnLoopbackWithSessionSecret|TestInspectorStreamingCaptureAndReplayProtection|TestLoopbackEdgeOpenSSHAndHTTPSSharePort|TestLoopbackHostMode|TestOpsLoopbackReadinessLifecycleAndDependency|TestOpsLoopbackShutdownWithLivePublisherAndRestart|TestOpsLoopbackStartupFailureReleasesSiblingListeners|TestProcessMessagesHttpRequest|TestProdAuthLoopbackHTTPSOAuthLifecycle|TestSDKActiveWebSocketClose|TestSDKCLIHTTPAndWebSocketContract|TestSDKExternalResponseConsumer|TestSDKResponseConformance|TestSDKResponseControllerConformance|TestStreamingHTTPAcrossRealGRPCTunnel|TestWebSocketBearerDisabledAndUpstreamHTTPGuard|TestWebSocketBearerHTTPRotationAndRevocation|TestWebSocketBufferedUpgradeFrames|TestWebSocketConcurrentSockets|TestWebSocketEchoAcrossTLSRelay|TestWebSocketFailedUpgradesAndPublisherShutdown|TestWebSocketIdleAndKeepalive|TestWebSocketIntegrationMeteringAndAccountQuota|TestWebSocketIntegrationSelfHostedApplicationJWTAndPlatformCredentials|TestWebSocketLocalHTTPS|TestWebSocketMessageLimits|TestWebSocketPartialFrameIdle|TestWebSocketRequireUpstreamAuth|TestWebSocketServerControlsAndClose|TestWebSocketUpgradeAuthenticationAndHeaders'
```

## REQUIRED-UNRUN native socket checks

The sandbox denies TCP loopback listener creation (`socket: operation not permitted`) and Unix socket setup (`setsockopt: operation not permitted`). Native versions remain required, even when their in-memory counterparts pass. Exact aggregate command, with the environment above:

```sh
go test -p=1 -parallel=2 ./... -count=1 -timeout=90s
```

The unavailable native tests are:

- `TestBridgeCarriesFiniteSSENotifications`
- `TestBridgeEnforcesLocalToolAllowList`
- `TestBridgeFailsRequestWhenChildExits`
- `TestBridgeMCPFlow`
- `TestBridgeModernHeadersAndSessionlessCalls`
- `TestBridgeOfficialGoSDKClient`
- `TestBridgeRejectsChildRequestsWithoutDeadlock`
- `TestBridgeReportsChildExit`
- `TestBridgeValidatesHTTPEnvelope`
- `TestConnectClientOverHTTP2CONNECT`
- `TestDogfoodProxyLoginAndHTTP2Control`
- `TestHandleHttpRequest`
- `TestInboundConnectionServesHTTPOverUnixSocket`
- `TestInboundConnectionStreamsHTTP`
- `TestInboundConnectionStreamsTCP`
- `TestInboundConnectionStreamsUnixSocket`
- `TestInspectorCapturesAndReplaysToLocalTarget`
- `TestInspectorStartsOnLoopbackWithSessionSecret`
- `TestInspectorStreamingCaptureAndReplayProtection`
- `TestLoopbackEdgeOpenSSHAndHTTPSSharePort`
- `TestLoopbackHostMode`
- `TestOpsLoopbackReadinessLifecycleAndDependency`
- `TestOpsLoopbackShutdownWithLivePublisherAndRestart`
- `TestOpsLoopbackStartupFailureReleasesSiblingListeners`
- `TestProcessMessagesHttpRequest`
- `TestProdAuthLoopbackHTTPSOAuthLifecycle`
- `TestSDKActiveWebSocketClose`
- `TestSDKCLIHTTPAndWebSocketContract`
- `TestSDKExternalResponseConsumer`
- `TestSDKResponseConformance`
- `TestSDKResponseControllerConformance`
- `TestStreamingHTTPAcrossRealGRPCTunnel`
- `TestWebSocketBearerDisabledAndUpstreamHTTPGuard`
- `TestWebSocketBearerHTTPRotationAndRevocation`
- `TestWebSocketBufferedUpgradeFrames`
- `TestWebSocketConcurrentSockets`
- `TestWebSocketEchoAcrossTLSRelay`
- `TestWebSocketFailedUpgradesAndPublisherShutdown`
- `TestWebSocketIdleAndKeepalive`
- `TestWebSocketIntegrationMeteringAndAccountQuota`
- `TestWebSocketIntegrationSelfHostedApplicationJWTAndPlatformCredentials`
- `TestWebSocketLocalHTTPS`
- `TestWebSocketMessageLimits`
- `TestWebSocketPartialFrameIdle`
- `TestWebSocketRequireUpstreamAuth`
- `TestWebSocketServerControlsAndClose`
- `TestWebSocketUpgradeAuthenticationAndHeaders`

WebSocket tests share a native listener fixture; after repeated bind failures, its remaining native callers were excluded together and all WebSocket memory counterparts ran with the flag shown above. No tests were weakened or changed to skip automatically.

## Baseline failures and timing observations

`TestHostRuntimeConfiguredCredentialRootSurvivesRestart` and `TestHostRuntimeTokensSurviveRestart` fail the existing hostmode non-symlink/private-directory check under this environment. Both fail unchanged at production base **110485c**, reproduced from a clean `git archive` checkout. They were excluded from the available suite, not fixed as part of auth renewal.

```sh
go test ./internal/hostmode -run 'TestHostRuntime(ConfiguredCredentialRootSurvivesRestart|TokensSurviveRestart)$' -count=1
```

Two existing timing-sensitive checks (`TestBridgeLifecycleQueueDeadline` and `TestHTTPFidelityUnknownUploadLimitBeforeEmptyResponse`) failed during heavily concurrent build/test discovery. Both passed three isolated reruns and the final serialized full suite; neither was excluded.

No billing, checkout or pricing implementation changed. Nothing was pushed or deployed.
