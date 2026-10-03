# Recorded local workflow evidence

Date: 2026-10-03. Environment: Bryan's Mac, local isolated Tunn worktree. Synthetic
workspace only; no hosted model API, private source upload, live ingress change,
public push, or deployment.

## Commands that passed

```sh
GOCACHE=/tmp/tunn-go-cache make -f scripts/integration-tests/build-investigation/Makefile test build
GOCACHE=/tmp/tunn-go-cache bash scripts/integration-tests/build-investigation/run-local.sh
GOCACHE=/tmp/tunn-go-cache make -f scripts/integration-tests/build-investigation/Makefile test-relay
```

The focused fixture tests passed with race detection. They include remote
evidence collection, refusal when CI already runs generation, exact-corpus-only
reads (rejecting real paths and traversal), query bounds, read-only annotations,
and configured bearer authentication.

Independent review identified credential reattachment during Go HTTP redirects.
The harness now rejects redirects, and a regression exercises the actual CLI
against two synthetic loopback origins to verify that the redirected origin
receives no request. Python's HTTP client also leaves redirect following disabled.
The focused race test passed with the guard present. Removing only the guard in
a temporary Go source overlay made this same regression fail with two redirected
requests, confirming it catches the reviewed bug. The shared source was never
reverted.

Both official SDK clients performed seven remote calls: search the failure,
read the build log, search the generation command, and read package scripts, CI,
documentation, and ignore rules. Each returned the same diagnosis:

> The clean CI checkout never generates src/generated/schema.ts before TypeScript compilation.

The recommendation was to run `npm run generate:schema` after `npm ci` and before
`npm run build`. Six supporting citations were collected from the remote corpus:
`logs/build-4821.log:5`, `package.json:4`, `package.json:5`, `ci/build.yml:4`,
`docs/build.md:3`, and `.gitignore:2`.

## Real relay verification

The two-SDK race test used an actual TLS gRPC publisher and native sessionless
HTTP MCP server, a separate TLS HTTP routing node, and authenticated login-node
storage RPC. It created two temporary grants through the owner HTTP API. The
Go client used `Tunn-Authorization`; Python used standard `Authorization`.
The Python client verified the test relay certificate against an explicit PEM
CA; the SDK harness offers no insecure TLS flag.

Observed facts from the final passing run:

- Go SDK **v1.7.0** negotiated **2026-07-28** and consumed **8** HTTP admissions.
- Python SDK **1.27.2** negotiated **2025-11-25** and consumed **10** admissions.
- Both produced seven tool results, the same useful answer, and six identical citations.
- Owner-visible grant counts matched requests that actually reached the target.
- Raw grants and digests were absent from the owner metadata export.
- Neither platform authorization headers nor platform cookies reached the target.
- After revocation acknowledgement, the revoked credential returned HTTP **403**
  with `X-Tunn-Grant-Reason: grant_revoked`, even with a valid owner cookie.
  The target saw no corresponding request.
- The other grant completed another full investigation.
- Publisher disconnect/reconnect preserved used counts and revoked status.
  The revoked credential remained denied and the other grant still worked.
- Caller completion counters matched admitted requests plus the two explicit
  revoked-grant denials; the routing node did not double-count them.

The command's complete output is retained locally at
`/tmp/tunn-grant-two-sdk-workflow.log`. It ends with:

```text
--- PASS: TestGrantTwoSDKBuildWorkflowAcrossRealRelay (0.71s)
PASS
ok  github.com/ehrlich-b/tunn/internal/host  2.059s
```

## Timing evidence and limits

Single passing run with race instrumentation; these are observations, not a
latency SLA or statistical benchmark:

| Scope | Go SDK | Python SDK |
|---|---:|---:|
| Direct loopback service: connection to first tool | 2.225 ms | 86.355 ms |
| Direct loopback service: connection to useful answer | 4.077 ms | 97.454 ms |
| Two-node relay: connection to first tool | 17.633 ms | 64.016 ms |
| Two-node relay: connection to useful answer | 72.793 ms | 122.269 ms |

Starting at fixture creation, the Go answer arrived in 134.8 ms. The sequential
Go-and-Python run reached Python's answer in 526.2 ms, including Python process
startup. All relay/revocation/reconnect/counter assertions completed in 704.2 ms;
the race test process took 2.059 s. Installation and compilation are excluded.

This proves independently implemented SDK transport compatibility, useful
multi-call evidence transfer, and the tested grant behavior on a synthetic local
route. The investigator logic is deterministic. It does not demonstrate hosted
ChatGPT/Claude onboarding, autonomous model reasoning, OAuth interoperability,
production network reachability, or isolated mutable stdio sessions.

## Final combined verification

After all independent-review fixes (including encoded routes, authoritative
TCP/unknown protocol rejection, and multiple Cookie/Authorization fields), the
combined command passed:

```sh
GOCACHE=/tmp/tunn-go-cache make check test-build-workflow build TEST_ARGS='-timeout=120s -count=1'
```

`/tmp/tunn-private-tool-final-check.log` contains the full aggregate race suite,
the explicit Go/Python relay test, and the successful local binary build. That
run observed 76.341 ms Go and 126.104 ms Python connection-to-answer, with eight
and ten HTTP admissions respectively. Both returned seven tool results and six
matching citations; revocation, surviving access, and reconnect checks passed.

A separate read-only reviewer reran grant/storage/auth/CLI, two-SDK relay,
redirect, buffered/streaming cookie, and multi-value header checks under race
detection and reported no remaining blocking findings for this selected native
HTTP MCP milestone. Its logs are `/tmp/tunn-grants-independent-final.log`,
`/tmp/tunn-grants-independent-two-sdk.log`,
`/tmp/tunn-grants-independent-forwarding.log`, and
`/tmp/tunn-grants-independent-header-final.log`.
