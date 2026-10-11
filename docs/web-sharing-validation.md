# Web sharing validation

Date: 2026-10-11. Base: `11ae780` on `codex/tunn-share-20261011`.
All listeners were disposable loopback fixtures. No push, deploy, real invitation
send, real provider sign-in, billing change or production measurement occurred.

## Scripted timings

The clean Chromium gate's successful focused run measured:

| Measurement | Time |
| --- | ---: |
| Dashboard Share to recipient in, including fixture provider consent/callback | 685.66 ms |
| Dashboard Remove access to next browser request denied | 189.99 ms |
| Actual gRPC publisher start to granted recipient reaching the local origin | 31.27 ms |
| Revoke to idle HTTP/SSE stream cutoff | Approximately 1 second |
| Revoke to idle WebSocket cutoff on an actual gRPC publisher | 1,000.10 ms |

The browser has separate empty publisher/recipient/stranger contexts and uses
ordinary cookies acquired through the actual login endpoint/callback. The
external Google authorization/token service is mocked, with verified email and
PKCE/state binding checked. The recipient installs nothing. The gate also opens
the link twice, refuses the wrong person before/after copying the link, removes
access through a real CSRF-protected form, and checks identity in the audit page.
These are local scripted timings, not human or production-provider times.

The implementation's revocation bound is five seconds for browser HTTP/SSE and
WebSocket requests: a one-second polling interval plus a two-second deadline on
permission lookup. Permission expiry, authority failure and generation changes
also cancel admitted requests. Revoked/expired sessions cannot reopen. Separate
explicit machine grants and endpoint capabilities retain their existing
revocation mechanisms.

## Baseline comparison

Before editing, the required unsandboxed command was run on base `11ae780`:

```sh
go test -p=1 ./... -count=1
```

It failed in these existing tests:

- `TestLoopbackHostMode`: host state did not converge.
- `TestHTTPFidelityUnknownUploadLimitBeforeEmptyResponse/OK`: 502 instead of the
  expected oversized-upload status.
- `TestHostRuntimeConfiguredCredentialRootSurvivesRestart`: credential-directory
  permission rejection.
- `TestHostRuntimeTokensSurviveRestart`: the same permission rejection.
- `TestBridgeEnforcesLocalToolAllowList`: subprocess Close exceeded its deadline.

Subsequent full-suite runs retain the three host-mode failures; the upload/MCP
failures did not recur in the successful sharing-focused verification. Final
full-suite results are recorded below. The baseline failures were not patched
as part of this increment.

## Coverage and reproduction

```sh
TUNN_SHARE_BROWSER_PYTHON=/path/to/playwright/python \
  go test -p=1 ./... -count=1

go test -race -p=1 -count=1 ./internal/metering ./internal/host ./sdk . \
  -run '^(TestWebSharing|TestWebPublisher|TestGoogleLogin|TestSharingCLI|TestProdAuthRoute|TestProdAuthInternal|TestSDKWeb|TestSDKRefuses)'

make build
```

The regression tests cover owner-only HTTP, explicit-public HTTP, versioned
registration validation, older publisher behavior and downgrade refusal,
non-owner management refusal, consumer/node credentials refusing owner APIs,
email-bucket matching, expired/revoked identity denial, CSRF/origin protection,
permissions surviving database close/reopen, reconnect not replaying revoked
allow-lists, resource generations and different owners, idle SSE/WebSocket
cutoff, authority outage, anonymous streams losing public exposure, audit
identity/decision/terminal reason, visibility of machine access, CLI commands
and expiry, SDK default/explicit exposure and refusal of old relays, verified
Google email and browser binding, automatic enrollment resuming publication,
and accountless self-hosted publication requiring explicit public exposure.
New routes are also included in the existing
11-principal route matrix and descriptor-driven internal RPC authorization test.
The route fixture now uses the exact consent cookie, avoiding a timing-dependent
CSRF mismatch between independently minted same-person cookies.

Browser tests require Python/Playwright and installed Chromium; without
`TUNN_SHARE_BROWSER_PYTHON` the full suite labels that gate skipped. It was
explicitly enabled for final full-suite verification here. The race test covers
in-process permission/publisher/transport behavior; browser acceptance runs in
the separate ordinary suite.

## Final results

The final `go test -p=1 ./... -count=1` run, with the Chromium gate enabled,
exited 1 with exactly three baseline failures: `TestLoopbackHostMode`,
`TestHostRuntimeConfiguredCredentialRootSurvivesRestart`, and
`TestHostRuntimeTokensSurviveRestart`. All other tests passed, including the
new sharing and browser tests. The baseline upload and MCP cleanup failures
did not recur in this final run.

The race command above passed for all four selected packages, and `make build`
passed. The external SDK consumer fixture now explicitly supplies its existing
endpoint-token option to preserve intentional private access with the new SDK
default. No existing baseline failures were changed.

## Release dependencies

Deploy the new login-node/relay code before publishing with the new CLI or SDK.
The additive `web_resources` schema initializes automatically, and person
permissions reuse the existing grant ledger; there is no manual migration.
Legacy empty-list publications stay public until the owner explicitly upgrades
and chooses private/public exposure. Google requires operator client ID/secret
and the configured HTTPS callback. Real Google/GitHub outside-recipient
acceptance, production revocation latency and five outside recipients remain
unrun because this lane forbids deployment.
