# Round-three sharing fixes

Base: `70952e39ff18a58dcc01edd90c2c848b1baf2f97`; validated implementation head: `d31b510430a826269a15600b580e6fa08972f5de`; branch: `codex/tunn-r3fix-20261012`. The final documentation/evidence commit changes no application or test source.
Read `/work/lanes/tunn-r3fix/BRIEF.md` and `/work/lanes/tunn-share/review-r3/REVIEW.md` in full. Source edits, commits, additional fixtures, and evidence are confined to this clone. No push, GitHub writes, deployment, production database access, provider login, invitation/email delivery, or payment occurred. Go commands use `GOMAXPROCS=4` and `GOFLAGS=-p=4`. Capacity tests use small fixture limits and ordinary small inputs.

| Finding | Fix commit | Regression | Before → after |
| --- | --- | --- | --- |
| SHARE-R3-F1: account merge restores revoked access / legacy public downgrade | `8003324` | `TestR3AccountMergePreservesRevocationAndPrivateMode` in `internal/host/r3_merge_test.go`; upgrade repair additionally in `83406db` | Resource/grant owners differed, owner management returned 400, reconnect changed resource ID and restored Alice (200), legacy registration made the resource public → ownership moves atomically, obsolete UUID resolves to survivor, management succeeds, Bob retains live access, Alice remains denied (403), resource ID persists, actual legacy gRPC reconnect is rejected. |
| SHARE-R3-F2: non-authoritative Google email acquires owner authority | `6a45ef6` | `TestR3GoogleThirdPartyEmailCannotAcquireOwner`, authoritative-policy/device matrix, remote login-node binding, old-session rejection, durable subject/merge and transaction rollback tests | Third-party email without `hd` received an owner cookie and successfully shared with the attacker → callback returns 403 with no owner cookie; verified Gmail or matching verified Workspace identities are bound by issuer/subject before cookie issuance or device enrollment. |
| SHARE-R3-F3: HTTP caches bypass revocation | `3d91144`, `d31b510` | `TestR3BrowserCacheCannotBypassRevocation`, actual WebSocket upgrade headers, buffered/streaming GET/HEAD status matrix and admission/platform error/redirect checks in `internal/host/r3_cache_test.go` | Chromium retained `public, max-age=3600`, no Vary; force-cache reused private bytes after revocation → `no-store`, identity Vary, and force-cache returns 403 after revocation. |
| SHARE-R3-F4: repeated shares consume global grant capacity | `83406db` | `TestR3RepeatedSharingPreservesGlobalGrantCapacity` and owner/resource/global/audit/rate/upgrade/merge tests in `internal/metering/r3_security_test.go` | Three identical shares retained three grant rows and blocked an unrelated machine grant at fixture cap three → one current grant row survives renewal/re-sharing; unrelated grant succeeds; owner/resource limits and persistent mutation admission contain distinct-target churn. |

`e86b665` retains the independent review's unchanged person/resource-isolation and OAuth/cookie-scope safety checks.

The merge transaction includes web resources, provider bindings, sharing audit ownership, and merged mutation-rate windows. Startup repairs persisted obsolete resource owners without changing resource IDs or revocations. Existing private resources retain the legacy downgrade guard.

Google's fixed HTTPS userinfo endpoint supplies the provider identity; the accepted issuer is `https://accounts.google.com`. Historical third-party email verification is insufficient. Non-authoritative identities and changed bound emails must use the existing fresh email-link sign-in flow; no automatic third-party Google linking was added. Old Google session cookies without the new authority marker are rejected. The policy follows [Google's authoritative-email guidance](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token). Existing callback and domain SSO assertions were retained; their successful provider fixtures now explicitly supply verified Workspace identity and distinct stable subjects, and the callback fixture uses the real account authority.

The cache boundary applies after application headers, at response commitment, on all tunneled responses (including public tunnels, to accommodate later exposure changes), customer-domain responses, authentication/account/API/OAuth routes, and requests carrying cookies or authorization. It preserves application Vary entries, adds Cookie/Authorization/Tunn-Authorization, and removes Expires and conflicting CDN/surrogate policies. Buffered and streaming heads, 304s, redirects, and failures use this boundary. WebSocket 101 headers are written directly after hijacking and receive the same policy explicitly (`d31b510`). Browser evidence uses certificate-specific SPKI trust and normal Chromium caching, with no Playwright interception. Already saved/displayed bytes cannot be erased.

Sharing retains global capacity 10,000, with 256 current grant rows per owner (machine and person combined), 64 person/group decisions per resource, and 64 web resources per owner. Revoked current decisions stay durable; repeat sharing updates their ID/expiry/state in place. Historical duplicate rows migrate to audit while retaining the newest current decision, including revocation. Audit is capped at 128 rows per owner and 10,000 globally, with owner actor, target, action, time, grant ID, expiry and revocation metadata. Successful register/share/unshare mutations are capped at 60 per owner per minute at the authority, including across restart and merge. Capacity/rate denials are 429; rate denials include Retry-After. Sharing-reserved person/group consumer namespaces cannot be minted through machine-grant creation.

## Evidence and gates

- `evidence/fix-r3/review-before.log`: all six original review characterization cases PASS on unchanged base; four deliberately assert vulnerabilities.
- `evidence/fix-r3/regressions-before.log`: the four independent security acceptance cases FAIL on the unchanged base, for ownership mismatch, owner-cookie issuance, real browser cache reuse, and unrelated grant denial respectively.
- The first full-suite attempt inherited `umask 002`: three credential/host-mode tests rejected group-writable fixture directories. `full-suite-initial-umask002.log` and its exit file retain that result. Validation was rerun with `umask 022`, matching the review; credential security checks and test assertions were unchanged.
- The first complete race run detected a setup race in the copied browser fixture's assignment to `PublicAddr` after starting the server. `race-initial-fixture.log` retains that result. `d31b510` initializes the address before serving, without changing assertions. The focused race-instrumented Chromium and WebSocket checks then pass (`cache-boundaries-after.log`).
- `websocket-cache-before.log`: the added real WebSocket 101 header regression fails before the explicit hijacked-response policy; `cache-boundaries-after.log` records its pass after.
- `review-after.log`: original characterization assertions rerun under race against final application source via a test-only overlay. Exactly four vulnerable-behavior predicates now FAIL: split ownership is absent, third-party callback is 403, Chromium cache reuse is false, and the unrelated grant succeeds. The two independent safety cases PASS, with no race warnings. Browser fixture setup ordering was corrected and its script path localized; no characterization assertion was changed.
- `full-suite.log` / `full-suite.exit`: **PASS**, `go test -count=1 -parallel=2 -timeout=600s ./...`, 18 passing packages. The opt-in Chromium sharing and cache journeys ran.
- `race.log` / `race.exit`: **PASS**, `go test -race -count=1 -parallel=2 -timeout=600s` on `internal/common`, `internal/host`, `internal/metering`, `internal/store`, `internal/storage`, and `pkg/proto/internalv1`; five tested packages pass, generated protobuf package has no tests, zero race warnings.
- `vet.log` / `vet.exit`: **PASS**, `go vet ./...`.
- `regressions-after.log` / `regressions-after.exit`: **PASS** under race, 20 top-level security/safety cases, including the four independent finding regressions and the real Chromium cache case.
- `commands.md` records reproduction commands and fixture/environment adjustments; `summary.json` records exit statuses and counts. All final gates target the implementation head above. The original review's deliberate vulnerable-behavior characterization run has exit 1 because its four vulnerability predicates are now false; it is not a failing security acceptance gate.

Billing-disabled/org-SSO-disabled rollout constraints and separate live-domain/provider acceptance gates remain in force. This work performs no deployment and grants no deployment approval.

## Round-three domain fixes

Read `/work/lanes/tunn-r3fix/BRIEF-DOMAINS.md` and
`/work/lanes/tunn-apps-domain/review-r3/REVIEW.md` in full. Continued the prior
partial attempt's untracked review tests and before evidence. Base: `bbe8014`;
validated implementation: `3887576bd9ac24d7f13060d3ca3fad462135cf31`, on the same
`codex/tunn-r3fix-20261012` branch. The subsequent evidence commit changes no
application or Go test source. Sharing implementation files remain byte-for-byte
unchanged relative to the base; their full suite and race checks pass again.

| Finding | Fix and regression evidence |
| --- | --- |
| D1: unverified namespace squatting | DNS-unverified claims expire after 24 hours without resetting their lifetime on failure/restart. A conflicting Add supplies a fresh, bounded competing proof request. Repeating Add after publishing its unique CNAME/TXT reclaims overlapping unverified rows atomically, including an exact name occupying the primary key. A persisted `proven` flag grants exclusivity only after ownership proof and protects verified owners across lease failures. Legacy pending/failed-unverified rows receive a finite upgrade deadline; legacy ready/certified owners retain protection. `TestReviewUnverifiedWildcardCannotSquatNamespace`, `TestR3PendingClaimProofReclaim`, expiry/fresh-proof, legacy migration, request-capacity and verified-owner safety tests cover these boundaries. |
| D2: concrete verification bypasses issuance admission | Concrete and wildcard issuance call the same transactionally recorded owner/global budget and hostname backoff before invoking the issuer. Failed attempts and scheduled renewals count; admission survives restart. Verify rechecks DNS and reuses a concrete certificate outside the 30-day renewal window. Current entitlement/reservation predicates also protect concrete challenge publication, lease fallback and certificate commitment. Accounting, reuse/renewal, restart/backoff, exhausted owner/global budgets and cross-path budget consumption regressions fail before and pass after. |
| D3: in-flight reservation revocation | Challenge publication and certificate insertion include the current app reservation, Pro entitlement and ready parent lease in their SQL predicates. Challenge reads derive the exact single app label and require its current owner. All cached/failure/backoff key returns use a database read with the same current reservation predicate. Original successful-order and failed-renewal probes now pass; stronger release/reassignment/success/failure cases additionally require challenge denial, failed late publication and no new stored key. |
| D4: verifier/cache rotation guidance | The exact Python snippet sets `lifespan=60, cache_keys=False`. Normal overlap is distinguished from emergency revocation, including client/upstream cache delay, assertion lifetime, app skew/leeway and immediate client/cache replacement. Local PyJWT 2.10.1 fixtures exercise the exact snippet: removed key accepted at cache age 59 seconds, rejected at 61/181/301 seconds; new key accepted; original issuer/audience/provider/email/expiry/algorithm boundaries retained. |

`evidence/fix-r3-domains/` contains the original before attempt, a fresh original
review rerun before changes, expanded before/after security regressions, exact
verifier probes, gate logs with exit files, reproduction commands, source
overlays and `summary.json`. Before application source is supplied by a Go
overlay from `bbe8014`, entirely inside this clone, without another checkout or
altering the working implementation. The original review Go files match the
review archive's SHA-256 hashes; the exhausted-budget file is retained intact as
`review_r3_original.go.txt` and restored only for the original-review overlay.

Final acceptance gates, using `GOMAXPROCS=4`, `-p 4`, `umask 022`, with no source
or test overlay:

- `full.log` / `full.exit`: **PASS**, `go test -p 4 -count=1 -parallel=2 -timeout=600s ./...`; all 18 tested packages pass. Existing opt-in Chromium sharing/cache journeys were enabled.
- `race.log` / `race.exit`: **PASS**, `go test -race -p 4 -count=1 -parallel=2 -timeout=600s ./internal/domains ./internal/host ./internal/store ./internal/metering`; all four packages pass, zero race warnings.
- `vet.log` / `vet.exit`: **PASS**, `go vet -p 4 ./...`.
- `regressions-final.log` / `regressions-final.exit`: **PASS** under race, 15 top-level domain security/safety tests, including the unchanged original D1/D3/accounting checks.
- `verifier-regression-final.log` / `.exit`: **PASS**, local synthetic keys and mocked JWKS only.

The original spent-budget probe expects Verify to return nil even when the owner
budget is exhausted; its unchanged final rerun therefore stops at the fixed
`ResourceExhausted` response. `TestR3ConcreteSpentBudget` explicitly requires that
response on two calls and no issuer invocation for both owner/global limits.
Likewise, the unchanged original verifier probe requires the removed key to be
accepted at age 181 seconds; its final rerun fails because the key is rejected.
These two original characterization exits are retained as 1, not labeled passing
acceptance gates. Every other original domain probe passes after the fix. No
original assertion was relaxed. The existing cancellation/gate-release fixture
now advances its clock by one minute after a failed order, preserving all its
assertions while honoring the newly shared backoff.

**Write-scope caveat:** initial Go invocations inherited the shared
`/work/cache/go/{mod,build}` caches and system temporary directory, rather than
strictly confining all cache/temp writes to this clone. Later runs isolated
mutable paths. Copying caches with reflinks consumed the remaining lane disk and
caused full/race linker failures (`full-disk-initial.*`, `race-disk-initial.*`);
only those newly created clone cache copies were removed. Final successful gates
use a Go cache helper that reads existing shared immutable artifacts and writes
new entries under this clone's `.scratch/go-cache`; module network access is off,
and Go/browser temporary files are under `.scratch/tmp`. The installed Go cache
protocol, object size/hash checks, actual test execution and all security checks
are preserved. This limitation and the corrected environment are recorded in
`commands.md`, `env.sh`, and `cache-fallback.py`.

All application/test/documentation/evidence edits and commits are in this clone.
No push, GitHub write, deployment, production database access, provider login,
real-CA ACME call, email, payment, resource-exhaustion input or sub-agent work
occurred. Local tests use synthetic DNS and local issuers. Existing deployment
constraints and live-domain acceptance gates remain in force.

## Round 4

Base: `1188c576529660211a5c4a0a39d2e964eafeb9ac`; branch:
`codex/tunn-r4fix-20261012`. Continued the existing round-three implementation
and evidence from a clean starting tree. Read the complete
`/work/lanes/tunn-r4fix/BRIEF.md`, independent
`/work/lanes/tunn-r3fix/review-r4-apps-domain/REVIEW.md`, its public-API
regression, and `evidence/public-proof-control.log` before changes.

**R4-D1:** `domainHTTPError` now preserves the registry's safe `AlreadyExists`
status message in the authenticated management response. Pending conflicts
return HTTP 409 with the caller's own TXT record, unique target and retry
instructions. The registry still excludes proven owners and scopes pending
targets to the requesting account; its ownership/security implementation is
unchanged.

`TestR4PublicAPIExposesCompetingProof` exercises both the overlapping wildcard
`*.apps.example.com` and the exact-name wildcard `*.example.com`, with an
unverified incumbent `*.example.com`. Each case requires authenticated,
uncached HTTP 409 proof instructions, publishes exactly the delivered TXT
through a test resolver with no CNAME proof, and retries the public Add to
obtain HTTP 201 with the correct owner/target. It also requires distinct targets
for competing accounts, denies unauthenticated disclosure and use of another
account's published proof, and excludes a competitor after ownership is proven,
even when the competitor publishes its own matching TXT.

**Membership test stability:**
`TestReviewMembershipRemovalAndNoRefreshExtension` reads the signed issued
session expiry before the second login, then sets the verifier clock to that
whole-second expiry minus one second and plus one second. The existing old
snapshot acceptance, immediate fresh-membership removal, and expired-snapshot
denial assertions are retained. No production session clock or authorization
check changed.

Before/after evidence is retained in `evidence/fix-r4/`:

- `regression-before.log` / `.exit`: both public TXT recovery cases **FAIL** on
  unchanged base application source with `409 Domain already claimed` (exit 1).
- `regression-base-recheck.log` / `.exit`: an explicit overlay of the sole
  changed application file from `1188c57` reproduces both **FAIL** results at
  the final source (exit 1).
- `review-before.log` / `.exit`: the independent original API regression also
  **FAILS** before the fix (exit 1). Its byte-identical source copy is retained
  as `review_r4_reclaim_test.go.txt`; its hash is in `source-manifest.json`.
- `regression-after.log` / `.exit`: expanded API recovery/isolation, issued
  membership expiry, and CLI error propagation all **PASS** (exit 0).
- `regression-race-after.log` / `.exit`: the same three focused regressions
  **PASS** under race (exit 0), including both TXT conflict cases.
- `review-after.log` / `.exit`: the byte-identical independent review API
  regression **PASSES** under race after the fix (exit 0).
- `cli-build.log`, `cli-proof.log` and their exit files: built CLI **PASS**
  against a synthetic loopback owner API; actual stderr includes the complete
  TXT proof instructions, and the expected authenticated request is checked.

Full acceptance gates, with no source/test overlays and `-count=1` on each
test run:

| Gate | Result | Evidence |
| --- | --- | --- |
| `go vet -p 4 ./...` | **PASS**, exit 0 | `vet.log` / `.exit` |
| `go test -p 4 -count=1 -parallel=2 -timeout=600s ./...` | **PASS**, 18 tested packages | `full.log` / `.exit` |
| `go test -race -p 4 -count=1 -parallel=2 -timeout=600s ./...`, first run | **PASS**, 18 tested packages, zero race warnings | `race-1.log` / `.exit` |
| Same full race command, second uncached test run | **PASS**, 18 tested packages, zero race warnings | `race-2.log` / `.exit` |

Both full race runs include the SDK consumer integration. `summary.json`
records all exit statuses and full-suite package counts; `source-manifest.json`
records the validated application/test source hashes. The round-four commit
includes that validated source and its evidence.

`commands.md` records exact commands and overlay reproduction; `env.sh` reuses
the existing cache helper, which reads immutable shared artifacts and writes
new cache entries only inside this clone. All Go commands use `GOMAXPROCS=4`
and `-p 4`, with `GOCACHE`, `GOTMPDIR` and `TMPDIR` under the gitignored
`$PWD/.scratch`; module network access and telemetry are disabled. The new
domain tests use local databases and small synthetic DNS inputs, with no CA
issuer configured. Optional Chromium/Pebble gates are not enabled.

All edits and commits are confined to this clone. No push, GitHub write,
deployment, production database access, provider login, real ACME, email,
payment, resource-exhaustion input, or sub-agent work occurred.
