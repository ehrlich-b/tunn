# Integrated release validation and deployment gates

Branch: `codex/tunn-release-integrated-20261011`, local checkout
`/work/lanes/tunn-release-merge/tunn`. Every current row below applies to tested
integrated source **`197f5bc6958074685b7f869e3916458a313787de`**. The final
handoff commit changes only this document, DEPLOY-READINESS.md and
integrated-release-evidence.json; its application, test, dependency and container
inputs match that source. The manifest records the input-tree fingerprint and
allowed documentation paths. Nothing was pushed or deployed.

## Source integration

| Input / merge | Status at integrated source | Provenance and resolution |
| --- | --- | --- |
| Carrier `8cb0b92505fdaaaf7497005aea7521e84f157ee1` | PASS: ancestor | Cloned from `/work/lanes/tunn-release/tunn`; original checkout untouched. |
| R2 fixes `dff48d378b5cd0416c7557c872565aeecd1aa03e` | PASS: real two-parent merge | Merge `b5517b85cf17bbf72fc1c77f65be15064065dbf0`; no conflicts. Transport upgrades, upload cleanup and container shell correction retained. |
| SSO fixes `1c24085d0883084bfab9e6bae830018b00a5c181` | PASS: real two-parent merge | Merge `197f5bc6958074685b7f869e3916458a313787de`; no conflicts. F1–F4, indexed admission, retained review attacks and MCP cleanup retained. |

Both branches descend from the exact carrier and changed compatible files. No
manual conflict resolution was needed. No gates/tests were removed or weakened.
The supplied source checkouts remain unchanged.

## Every inherited feature row at the integrated source

The carrier's earlier conflict resolutions remain intact. All listed package
sets passed the complete ordinary suite; the full-race feature status is PASS, with zero failures or race warnings.

| Feature | Current status | Retained integration intent and coverage |
| --- | --- | --- |
| Credentials | PASS: complete ordinary suite; full race PASS | `.`, client, host, store/storage. Canonical owners, renewable durable leases, token-purpose boundaries and separate listener TLS clones retained. Device publish/connect credentials still cannot manage domains. |
| Sharing | PASS: ordinary suite and real Chromium; full race PASS; independent verdict PENDING | `.`, client, host, metering, sdk. Private defaults, intended legacy-public behavior and durable grant/generation revocation retained. Fixture Google browser acceptance ran without its opt-in skip. |
| Domains | PASS: ordinary suite and local Pebble; full race PASS; independent verdict PENDING | `.`, host, domains, identity, config. Single TCP TLS clone with certificate callback and separate HTTP/3 clone retained. Exact-owner Google gate, handoff/replay and signed identity tests retained. |
| SSO | PASS: ordinary and focused race corpus; full race PASS | `.`, host, config, metering, identity. Combined org/identity loading and domain/JWKS/org route matrix retained. F1–F4 and all non-finding review probes pass. Zero-org disabling preserves personal/wildcard Google login. |
| SSH jump | PASS: ordinary and focused transport race; full race PASS | `.`, host, sshfront, store/storage. Native OpenSSH/SFTP and shared HTTPS/SSH ran. Original six fixes, secure x/crypto pin and endpoint-generation pinning retained. R2 findings resolved below. |
| Billing | PASS: ordinary suite; full race PASS; deployment DISABLED | `.`, host, store/storage, config, domains, metering. Original migration preservation plus exactly two additive durable tables retained. No provider configuration changed; keep billing disabled. |
| Distribution | PASS: ordinary suite; full race PASS | `.`, host. Both guide corpora, configured prices/quotas, standalone and legacy MCP paths, GET/HEAD/405 behavior and publisher-origin isolation retained. |

## Gates and reproducible evidence

New commands ran on the integrated source above, Linux amd64, host Go **1.27.2**,
`umask 0022`, `GOTOOLCHAIN=local`, `GOFLAGS=-p=4`, under `nice -n 10`.
Full suites use `-count=1 -parallel=2 -timeout=600s`. The cumulative 600-second
package deadline accommodates the expanded admission corpus; no cleanup deadline
or race instrumentation was relaxed. Browser environment:
`TUNN_SHARE_BROWSER_PYTHON=/work/lanes/tunn-share/review/.venv/bin/python` and
`PLAYWRIGHT_BROWSERS_PATH=/home/ehrlich/.cache/ms-playwright`.

New raw evidence lives outside the clone at
`/work/lanes/tunn-release-merge/evidence`. Each gate has `.log`, `.stderr`, `.exit`
and `.command.json` files recording command, source SHA, environment, time and
exit code. [integrated-release-evidence.json](integrated-release-evidence.json)
records outcome counts, failure/skip lists, image identity, review polling and
SHA-256 hashes. The older `release-evidence.json`, `full-suite.diff`, and
`evidence/` are historical carrier/R2 artifacts, not results of these new runs.
The prior validation document is preserved at
`../evidence/carrier-r2-validation.md`.

| Gate | Result at integrated source | Exact command / new evidence basename |
| --- | --- | --- |
| Go vet | PASS, exit 0 | `go vet ./...`; `vet` |
| Complete ordinary suite | PASS, exit 0; 3,929 pass / 5 inherited skips; 18 passing packages, 8 without tests; zero new failures | `go test -json -count=1 -parallel=2 -timeout=600s ./...`; `full-test` |
| Complete race suite | PASS, exit 0; 3,929 pass / 5 inherited skips; 18 passing packages, 8 without tests; zero failures and zero race-detector warnings | `go test -race -json -count=1 -parallel=2 -timeout=600s ./...`; `full-race` |
| Focused SSO security corpus | PASS, exit 0; 209 pass outcomes in four packages; zero warnings/failures | `make test-sso GO_TEST_FLAGS='-parallel=2 -json'`; `sso-security` |
| R2 413 regressions, 20 race repetitions | PASS, exit 0; both top-level tests pass 20/20; original OK/No Content 413 assertions pass 40/40; 80 total pass outcomes | `go test -race -json -count=20 -parallel=2 -timeout=300s -run '^TestHTTPFidelity(UnknownUploadLimitBeforeEmptyResponse\|UploadLimitCleanupCancellation)$' ./internal/host`; `r2-upload-20` |
| R2 public/internal transports and shared listener | PASS, exit 0; 5 top-level tests / 10 total pass outcomes; zero warnings/failures | `go test -race -json -count=1 -parallel=2 -timeout=180s -run '^(TestReleaseNativeInternalListenerAuthorization\|TestOpsLoopbackShutdownWithLivePublisherAndRestart\|TestReviewTLSListenerConfigurationIsolation\|TestLoopbackNativeSSHJump\|TestLoopbackEdgeOpenSSHAndHTTPSSharePort)$' ./internal/host`; `r2-transports` |
| Container build | PASS, exit 0 | `docker build --platform linux/amd64 -t tunn-release-integrated-local:20261011 .`; `container-build` |
| Container root/domain CLI smoke | PASS, both exit 0 | `docker run --rm --entrypoint /app/tunn tunn-release-integrated-local:20261011 --help` and `domain --help`; `container-help`, `container-domain-help` |
| Actual container dependencies | PASS: Go 1.26.9 binary; gRPC 1.83.2, quic-go 0.59.1, QPACK 0.6.0, x/crypto 0.58.0 | Extracted binary `../artifacts/tunn-container`; `container-artifact-modules.txt`, `container-artifact-sha256.txt`, `container-image-id.txt` |
| Chromium sharing journey | PASS in ordinary suite; full race PASS | `TestWebSharingBrowserJourney`; real Chromium, fixture Google |
| Local ACME HTTP-01 acceptance | PASS, exit 0; real Pebble issuance/cache test | `scripts/test-apps-pebble.sh`; `pebble`. Pinned disposable CA container cleaned up; estate DNS unchanged. |
| Unapplied forge app patch | PASS: dry-run against unchanged source and isolated lifecycle fixtures | Applied only to `../evidence/forgeapp-fixture/forgeapp`; reused carrier `verify_patch.py`; `forgeapp-fixtures`. Registration, private publication, idempotence, start/stop/remove, redaction, management override and private directory checks pass. Live CLI remains SHA-256 `54d2250e28585d33156dd139df9e2de8a1ac9cf9c86c7b5f18cc13240810e81c`. |

Counts include parent tests and subtests. The five inherited skips are three old
host integration stubs, the documented common Unicode case and opt-in Pebble.
Pebble passed separately. Chromium and native OpenSSH/SFTP ran rather than
skipped. Empty full-suite failure sets establish zero new failed tests against
the carrier's final passing comparison and the reproduced inherited MCP failure
set; the carrier baseline evidence was reused without repeating its run.

Docker emitted only its two existing fixed-platform style warnings. Inherited
verbatim evidence retains its original whitespace. No application changes
followed validation.

## Findings closed by the integrated fixes

| Finding | Status at integrated source | Evidence and retained mechanism |
| --- | --- | --- |
| SSH R2-F1: gRPC allocation DoS | RESOLVED | Selected and container-built gRPC v1.83.2; default compaction retained, no application override. Public ServeHTTP registration/restart and actual internal TLS authorization tests pass. Original exact-module source inspection/scan retained in `evidence/source-revalidation.txt` and `evidence/govulncheck.jsonl`; combined source revalidated by current suites. |
| SSH R2-F2: HTTP/3 expansion DoS | RESOLVED | Selected and container-built quic-go v0.59.1/QPACK v0.6.0; decoded header/trailer limits retained. Real UDP HTTP/3, isolated TLS and shared SSH/HTTPS pass. Exact merged R2 dependency inspection/scan evidence reused. |
| SSH R2-F3: intermittent 502 instead of 413 | RESOLVED | Response owner closes HTTP input after receiving upload-limit results; TCP cleanup remains caller-owned. Original and controlled cancellation regressions pass 20 race repetitions, preserving every original 413 assertion. Historical before-fix 10/50 failures and fixed 50/50 results remain in inherited evidence. |
| SSO F1: unauthenticated global login exhaustion | RESOLVED | Indexed peer/org admission: 8 peer / 128 org / 4,096 global limits, expiry/consumption/restart/migration and 32-org capacity tests pass. Personal/wildcard Google state is separate. |
| SSO F2: extra untrusted audience | RESOLVED | Every audience must match configured client; signed extra-audience tokens get 403 without auth cookies. Issuer/signature/nonce/authorized-party/expiry checks retained. |
| SSO F3: browser return-URL escape | RESOLVED | Shared parsed relative URLs reject backslashes, controls, malformed/encoded separators and external authority; callback revalidates persisted destinations. Review/normalization probes pass. |
| SSO F4: discovery blocks other orgs | RESOLVED | Network I/O outside cache lock; per-policy initialization, cancelable waits, bounded timeout and failure backoff. Healthy-cache isolation and cancellation tests pass. |
| Inherited MCP cleanup failures | RESOLVED: MCP package passes ordinary and race suites | Prompt unused-connection closure, racing-arrival closure, graceful active-request shutdown and timeout force-close retained. `TestBridgeCloseUnusedConnection` and existing MCP tests pass; cleanup deadlines unchanged. |

The original [SSH round-two report](/work/lanes/tunn-sshj/review2/REVIEW2.md)
is SHIP-AFTER-FIXES and the original
[SSO report](/work/lanes/tunn-sso/review/REVIEW.md) is BLOCK on older reviewed
heads. Neither is represented as fresh independent approval. Their enumerated
R2/F1–F4 conditions are addressed by the merged fixes and current regressions;
[SSO fix evidence](/work/lanes/tunn-ssofix/FIXES.md) maps the changes.

Organization SSO can ship **disabled**: unset/empty `TUNN_OIDC_ORGS_FILE` or a
private file containing `[]` on **every relay**, then restart every relay.
Starts/callbacks return 404 before discovery/state/session creation; personal
Google and wildcard app login still work. Real org tenant acceptance remains
required before later enablement; it does not block this disabled rollout.

## Exactly what still blocks deployment

The final review poll time, directory listings, report paths/verdicts and hashes
are recorded in integrated-release-evidence.json. Neither required directory
currently contains a completed `REVIEW.md`. Partial attack/race logs are evidence
of ongoing work, not a verdict.

| Remaining blocker | Current status | Coordinator completion condition |
| --- | --- | --- |
| Sharing and domains review verdicts | PENDING | Obtain `/work/lanes/tunn-share/review/REVIEW.md` and `/work/lanes/tunn-apps-domain/review/REVIEW.md`, record exact reviewed SHAs/verdicts and resolve every required finding on the final source. Missing reports do not mean SHIP. |
| Domain-management credential | REQUIRED-UNRUN | Provision a current owner management access JWT in a private file for registration/verification. Durable forge publish/connect credentials alone lack that scope; do not broaden device authority. |
| DNS and verified namespace | REQUIRED-UNRUN | DNS-only wildcard CNAME to `tunn.to`, exact returned TXT proof, verified public propagation/claim and raw TCP 80/443 plus UDP 443 routing. Reserve matching `grafana`/`dash` names under Bryan's account. |
| Live acceptance | REQUIRED-UNRUN | Actual production CA issuance/renewal; Bryan Google admission/other-account denial on both app URLs; repeat/cross-app/node SSO; host cookies/handoff and identity/JWKS; origin isolation, migration, renewal/reconnect and native SSH/SFTP. Keep org SSO/billing disabled. Fixtures cannot close this gate. |

**Not deploy-ready until those four blockers close.** Execute
[DEPLOY-READINESS.md](DEPLOY-READINESS.md) in order using the existing
[runbook](DEPLOY-RUNBOOK.md) and [forge app contract](FORGEAPP-TUNN.md).
Production/distribution publication and live acceptance remain coordinator work.
No push, deploy, DNS write, live credential read or org registration was performed.
