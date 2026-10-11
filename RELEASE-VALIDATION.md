# Carrier validation and review gates

The release uses real dependency-order merge commits on `codex/tunn-release-20261011`. Exact fetched source SHAs are in RELEASE-NOTES.md and `release-evidence.json`. All recorded sources are ancestors of the carrier. No source checkout, live forge CLI, production service, DNS or provider was changed; nothing was pushed or deployed.

## Merge checks and resolutions

After each merge, `GOTOOLCHAIN=local go build ./...`, `go vet ./...`, and complete focused packages ran with loopback available. Focused commands used `-p=2 -count=1 -timeout=240s`. All final checks passed. Evidence lives in `/work/lanes/tunn-release/evidence`, outside the carrier; SHA-256 hashes and outcome summaries are committed in `release-evidence.json`.

| Merge | Focused package set (module-relative) | Conflicts and retained intent |
| --- | --- | --- |
| Credentials | `.`, client, host, store | None; canonical old owners, renewable leases and isolated TLS listener clones retained. |
| Sharing | `.`, client, host, metering, sdk | None; private defaults, legacy-public compatibility and durable generation/grant revocation retained. |
| Domains | `.`, host, domains, identity, config | `internal/host/proxy.go`: retain a single isolated TLS clone per TCP listener and its custom certificate callback; HTTP/3 has its own clone. |
| SSO | `.`, host, config, metering, identity | config.go combines identity-key and org-file loading; prod_auth_routes_test.go keeps both domain/JWKS and org-route matrix rows. Auto-merged Google PKCE and Google-only app login retain both test corpora. |
| SSH jump | `.`, host, sshfront, store, storage | USER-JOURNEY.md retains app and native SSH journeys; go.mod/go.sum keep SSH security versions plus SSO's direct OAuth dependency, then tidy; webproxy.go retains identity-header stripping and SSH endpoint-generation pinning. |
| Billing | `.`, host, store, storage, config, domains, metering | prod_auth_routes_test.go retains both device-management and revenue rows. Additive billing tables required adapting the durable migration table-count assertion; all original baseline schemas/rows still compare unchanged, and exactly two durable tables are required beyond initialized store schema. |
| Distribution | `.`, host | Makefile retains both test targets. Both overlapping HTML files preserve sourced guides; the comparison also renders revenue's configuration-derived prices/quotas. The old revenue MCP tutorial is kept at `/docs/mcp-to-claude` through a separate embedded template. The standalone guide remains `/mcp-to-claude`. One shared comparison handler keeps GET/HEAD/405 and publisher-origin isolation. Stale anonymous-default guide text is updated to private-default exposure. |

There were 11 conflict occurrences in 10 distinct files. Both sides' relevant tests were inspected, and every conflicting feature's focused packages passed after resolution. The merge introduced no authentication scope expansion. Domain automation cannot manufacture management authority from publish/connect device credentials.

The domains lane's local ACME acceptance script pinned Go 1.25.6, below the SSH branch's merged Go 1.26 module requirement. It now honors `GOTOOLCHAIN` or uses automatic module-toolchain selection. The real local Pebble HTTP-01 acceptance passed after that integration fix.

## Baseline and full-suite diff

The comparison base is the exact production `110485c8a479572ef6cbaeda8b20d80ccc326ef2` in a separate detached worktree. Both final full runs used Go 1.27.2/Linux amd64, unrestricted loopback, `umask 022`, `GOTOOLCHAIN=local`, `go test -p=1 -json ./... -count=1 -timeout=300s` (baseline timeout 240s). The carrier additionally enabled the sharing browser gate with the existing review Python and installed Chromium cache. All original repository gates remain present.

See the exact terminal-test failure comparison in [full-suite.diff](full-suite.diff). Baseline final full suite passed; carrier final full suite passed, with zero new failed tests/packages. The report counts subtests as terminal tests. Inherited skips are the three old integration stubs and the documented common Unicode test; the ordinary full run also skips opt-in Pebble, which passed separately. Native OpenSSH/SFTP and shared SSH/HTTPS were executed rather than skipped, and browser sharing passed.

Initial runs are retained as evidence, not hidden: the ambient umask caused baseline credential-directory and host-mode fixture failures; using the source-documented 022 setting removed them on both revisions. An intermediate corrected baseline run had `TestBridgeMCPFlow` cleanup deadline failure; the final complete baseline run passed. The first carrier browser run pointed to a different browser version's cache and failed to find its executable; the final complete run uses `/home/ehrlich/.cache/ms-playwright` and passed. The billing merge's obsolete absolute table-count assertion failed once, then its original preservation assertions and new exact durable increment passed. No new product test failure remains in the final comparison.

## Race, browser, ACME and container checks

The race command covers the auth/host implementation (`internal/host`, identity/config), persistent stores (`store`, storage), edge/custom-domain code (`host`, domains), SSH (`sshfront`, host), billing/accounting (`host`, store, storage, metering), and client/common/relay transport:

```sh
umask 022
GOTOOLCHAIN=local go test -p=1 -race -json . ./internal/host ./internal/store ./internal/storage ./internal/domains ./internal/sshfront ./internal/metering ./internal/common ./internal/client ./internal/relaytransport ./internal/identity ./internal/config -count=1 -timeout=300s
```

Baseline race used the same existing packages (identity is new; config was additionally tested on the carrier). Its host test `TestOpsLoopbackReadinessLifecycleAndDependency` reported the inherited shared TLS config race between `http2.ConfigureServer` and `http3.ConfigureTLSConfig`. The credential branch's separate clones remove that mechanism. Final carrier outcomes are recorded in `release-evidence.json` and full-suite.diff.

The browser test enabled `TUNN_SHARE_BROWSER_PYTHON=/work/lanes/tunn-share/review/.venv/bin/python` and `PLAYWRIGHT_BROWSERS_PATH=/home/ehrlich/.cache/ms-playwright`. It exercises real Chromium with fixture Google endpoints, not live Google. `GOTOOLCHAIN=local scripts/test-apps-pebble.sh` used its pinned disposable Pebble image and real local HTTP-01 challenge/issuance and cleaned up its container. This proves local CA integration, not production DNS/issuance or renewal.

`docker build --platform linux/amd64 -t tunn-release-local:20261011 .` passed using the merged Go 1.26 Alpine builder; the image's root and domain help commands also passed. Docker emitted only the existing fixed-platform style warnings. This is a local image, not pushed. Whole-range `git diff --check 110485c..HEAD` reports whitespace in the source branches' retained raw HTTP-header evidence and unified-diff blank context lines (including the new forge patch); these are evidence/patch formatting, not code or test failures. The working-tree diff check is clean. An attempted unsupported `--version` smoke command correctly returned CLI usage; the supported `--help` smoke replaced it. Production secrets/topology/startup acceptance remain coordinator work.

The forge patch passed dry-run application to the unchanged CLI and isolated fixtures for registration, private publication, repeat-install idempotence, start/stop/remove ordering, redacted failures, management-token override and private-directory validation. Its test never read real credentials or called live systemd/tunn. The source CLI hash was rechecked unchanged.

## Outstanding review findings and deployment readiness

The latest SSH round-two report is [REVIEW2.md](/work/lanes/tunn-sshj/review2/REVIEW2.md), **SHIP-AFTER-FIXES**, reviewing the exact merged `2325a0f1b277a1ee8ecfc21cc73d17b09e1b17ff`. All original six SSH fixes remain present and their packages/native checks pass. The carrier still contains these exact round-two findings:

| Finding | Carrier state and remaining release condition |
| --- | --- |
| R2-F1, high, inherited gRPC allocation DoS | Still selects gRPC v1.76.0. Public ServeHTTP registration and native internal listener remain; review requires ≥v1.83.2 plus source/full/race revalidation. Keep internal port private, but that does not eliminate the public allocation path. |
| R2-F2, high, inherited HTTP/3 header/trailer expansion DoS | Still selects QUIC v0.56.0 and starts public HTTP/3; review requires ≥v0.59.1 with HTTP/3/shared-listener validation. |
| R2-F3, unresolved intermittent upload regression | The reviewed 502 versus required 413 assertion's implementation/test remain unchanged. Carrier full/race success does not explain or fix the intermittency or prove the same failure on that review's base. Retained as unresolved, rather than erased by passing repeats. |

The above is a re-check against the reviewed report and selected modules, not a new independent vulnerability scan. Inherited status does not confer deployment permission. Take any later operator fix only as a committed source merge and repeat the affected/full/race gates; no uncommitted source changes are imported.

Pending review directories are polled at the end and the timestamp, filenames/verdicts and latest committed SSH source are recorded in `release-evidence.json`. Sharing, domains, SSO and durable round-two reports were still absent at the last recorded poll; absence is not SHIP. If any subsequently reports BLOCK/SHIP-AFTER-FIXES, recheck its exact findings on this carrier before promotion.

**Not deploy-ready:** resolve SSH R2-F1/R2-F2/R2-F3 and pending verdicts; provision a current management credential for domain registration (durable forge credentials alone lack that scope); then complete real DNS, CA issuance/renewal, exact-owner Google/other-user, topology/native SSH and any enabled enterprise IdP acceptance. Billing remains disabled. The local carrier, release notes, runbook and unapplied forge patch are reviewable; production and distribution publication remain coordinator actions.
