# Revenue change validation — 2026-10-11

Carrier: `codex/tunn-revenue-20261011`, baseline `110485c`. All implementation
and commits are in `tunn/.scratch/carrier`; the parent checkout is unchanged.
No external writes or deployment were used for validation.

## Required gates: passed

Go version: **go1.27.2 linux/amd64**, `/usr/local/go/bin/go`.

```bash
umask 077
export GOCACHE=/tmp/tunn-revenue-go-cache
export GOMODCACHE=/tmp/tunn-revenue-mods-full
export GOTOOLCHAIN=local
/usr/local/go/bin/go vet ./...
/usr/local/go/bin/go test ./... -count=1
```

Both exited **0** after the final code changes. The test flag forces an
uncached run of every package. [Full test output](validation-logs/go-test.txt);
[vet output](validation-logs/go-vet.txt) is empty, as expected on success.
[Focused route/operator output](validation-logs/revenue-focused.txt) also passed.
`git diff --check` passed.

The default Go caches under `/work/cache` were read-only, and some required
module versions were absent. A writable copy plus missing module downloads was
used under `/tmp`; go.mod/go.sum were not changed. The shell's original umask
0002 made Go 1.27 `t.TempDir` fixtures group-writable, which correctly failed
private-credential tests. Umask 077 fixes the fixture environment without
weakening credential enforcement. The OpenSSH edge fixture now passes
`-F /dev/null` to isolate its explicit test configuration from the sandbox's
non-private system SSH configuration; product SSH handling is unchanged.

## Loopback-dependent tests

The full suite includes real local HTTPS, gRPC, SSH, WebSocket and inspector
listeners. It needs loopback networking and temporary port binding. In
particular, these named tests exercised the relevant paths:

- `internal/host`: `TestLoopbackHostMode`,
  `TestLoopbackEdgeOpenSSHAndHTTPSSharePort` (also needs OpenSSH),
  `TestMCPOAuthConnectorEndToEnd`, `TestProdAuthLoopbackHTTPSOAuthLifecycle`,
  `TestStreamingHTTPAcrossRealGRPCTunnel`, `TestWebSocketEchoAcrossTLSRelay`,
  `TestOpsLoopbackReadinessLifecycleAndDependency`.
- `internal/client`: `TestInspectorStartsOnLoopbackWithSessionSecret`,
  `TestDogfoodProxyLoginAndHTTP2Control`, `TestConnectClientOverHTTP2CONNECT`.
- `internal/mcpbridge`: `TestBridgeOfficialGoSDKClient`,
  `TestBridgeCarriesFiniteSSENotifications`.

Other transport/conformance cases in these packages also use local fixtures;
this is not an assertion that every other test is socket-free. No test overlay
or package exclusion was used. The newly added revenue route tests use an
in-process response recorder, and reviewed-billing tests use disposable SQLite.

## Revenue acceptance covered

Routes return actual pricing/docs/comparison rather than the homepage; route
inventory/principal matrix includes all new routes; unknown apex paths 404;
publisher paths remain owned by the publisher. Configured prices and tighter
caps render from the enforced constants. Monthly/yearly choices are independent;
missing, disabled and unsafe checkout config fails visibly. Authentication
preserves upgrade intent; storage errors return 503; suspended accounts cannot
buy and Pro accounts are sent back to their account.

URL parameters, a forged return session, and a signed lifecycle receipt do not
grant Pro. Account status reflects committed entitlement; operator reviewed
activation changes it; suspension remains separate. Store tests cover activation,
cancellation, reordered receipts, unauthorized scope, stale/future evidence,
missing digests/prices/receipts, unpaid/trialing status, version conflicts and
atomic batch failure. `TestReviewedBillingCLIOnNonFixtureDatabase` covers a
real local database without a fixture marker: read-only dry run, pending receipt
listing, explicit reviewed commit, stale repeat rejection, and prohibited
fixture/mixed apply modes. No Stripe network call is needed or made.

`tunn http --help` was executed with the new alias
([output](validation-logs/http-shortcut.txt)). The dependency-free Python echo
example answered initialize, tools/list and tools/call with `message=hello`.

## Read-only live evidence

[Capture manifest](evidence/live-manifest.json) records GET URLs, response dates,
status, body sizes and SHA-256, with captured public headers. `/`, `/pricing`,
`/docs` and `/upgrade` returned identical body hashes; `/account` redirected
to login. Full temporary bodies remain in `/tmp/tunn-revenue-evidence/live`.
Competitor/source URLs and fetch dates are recorded in REALITY.md, PRICING.md,
DISTRIBUTION.md and the comparison page. Quotes are limited and attributed;
full third-party articles are not copied into this repository.

## Coordinator gates still required

Container build with the existing Go 1.25 Dockerfile; native macOS/Linux install
and Homebrew test (brew/Ruby unavailable here); actual hosted Claude.ai/ChatGPT
OAuth and tool invocation; Stripe sandbox payment, portal and cancellation;
production inventory/backup and deployment; approved support queue ownership;
public CLI ref/artifact publication; license resolution; directory eligibility
and founder-post approval. These are explicit launch prerequisites, not tests
claimed to have passed. See [GO-LIVE.md](../../GO-LIVE.md).

The final self-contained bundle is verified by `git bundle verify`, clean clone
of the named branch, matching HEAD, and `git fsck --full`. Its verification log
and SHA-256 sidecar are beside `tunn/.scratch/tunn-revenue.bundle` so recording
the final artifact hash does not recursively change that artifact.
