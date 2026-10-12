# Round-four sharing fixes

Base: clean `1188c57`; branch: `codex/tunn-r4share-20261012`.
Read `/work/lanes/tunn-r4share/BRIEF.md`, the complete round-four REVIEW.md and
all three supplied characterization files. No previous partial attempt existed.

## SHARE-R4-F1: retire obsolete resource sharing generations

When registration replaces a resource generation, `retireSharingGrants` moves
its person/group decisions to existing bounded `sharing_audit` with action
`resource-retired`, then deletes them from `meter_grants` in the same transaction
as replacement and publisher seed installation. A failed replacement rolls back
retirement, audit writes, registration and mutation accounting together.
Machine grants retain their independent lifecycle, including ones whose endpoint
string happens to match the old resource ID. Admission limits are unchanged.

Startup repairs merged resource ownership first, then retires sharing rows for
which no current resource matches both resource ID and owner. Existing historical
compaction uses the same retirement helper with action `legacy-history`, retaining
the newest live person/group decision, including revoked decisions. Retirement
processes one grant at a time and uses existing owner/global audit eviction bounds;
no tokens or other credentials enter audit storage. Audit eviction cannot alter a
live decision. Same-owner reconnects retain resource IDs and never replay seeds.

`WithOwnerGrantLimit` permits only a lower positive cap, validated against the
existing hard maximum of 256. It lets the actual authenticated registration
handler regression run with owner cap two and without filling production limits;
a regression rejects zero, negative and above-maximum values. The production
default remains 256.

## SHARE-R4-F2: preserve typed sharing admission failures across gRPC

`ErrSharingRate` and `ErrCapacity` remain errors with local sentinel identity and
implement `GRPCStatus`: `ResourceExhausted` plus an `ErrorInfo` detail in domain
`metering.tunn` distinguishes `SHARING_RATE` from `CAPACITY`. `Remote.Sharing`
translates only these typed reasons back to their original sentinels. Message-only,
foreign-domain, unknown-reason, wrong-code, unavailable and timeout errors retain
their existing meaning. Wrapped admission errors retain details and identity.
The existing HTTP handler consequently returns the same body/status on local
and remote relays: rate denial is 429 with `Retry-After: 60`; capacity denial is
429 with the same existing absence of Retry-After on both relays.

The errdetails dependency already existed; go.mod marks it direct, with no
version changes or go.sum changes.

## Regression evidence

New assertions fail on the reviewed behavior and pass on the fixed application.
`evidence/fix-r4-share/before.log.gz` / `.exit` show the original required failures;
`before-expanded.log.gz` / `.exit` reproduce all final defect assertions through a
source-only overlay of reviewed behavior. The rollback and hard-cap safety tests
also pass before repair. Existing tests and authorization checks are unchanged.

- Prior-release fixture with three orphan historical decisions and global cap
  three: startup audits all three and an unrelated owner machine grant succeeds.
- Authenticated gRPC registration handler: two fixture accounts release/reclaim
  the same unreserved name; the original owner shares with the same person in
  three distinct generations at owner cap two and can re-share after restart.
  Only that owner's three generations have publisher seeds; no more than three
  grant rows can exist even in the broken implementation.
- Store name-reuse regression confirms one current decision across restart.
- Person/group retirement preserves revoked audit metadata, obeys audit caps and
  retains a machine grant whose endpoint equals the obsolete resource ID.
- Failed seed installation rolls back retirement and retains live revocation;
  same-owner reconnect cannot replay the revoked seed.
- Upgrade retires a group with mismatched owner despite a matching resource ID,
  retains the current owner's revoked person decision, preserves machine grants,
  obeys audit bounds and is idempotent on restart.
- Authenticated node RPC checks rate and capacity HTTP parity, typed wire details
  and transaction rollback after admission denial; translation safety covers
  unrelated errors and wrapped sentinels.

`regressions.log.gz` / `.exit` pass all R3/R4, web-sharing and group regressions,
including both Chromium sharing/cache journeys. An initial browser-directory
mismatch and its corrected installed-browser selection are recorded separately
in `commands.md`; failed evidence remains labeled as failed.

## Required gates

Final gates use the complete working application and unchanged existing tests,
with no source/test overlay. Logs (lossless gzip) and exit files are in evidence/fix-r4-share;
summary.json records package/test counts, skips and R3/R4/browser outcomes.

| Gate | Result |
| --- | --- |
| go vet ./... | PASS, exit 0 |
| Full go test ./... | PASS, exit 0; 18 packages, 4017 passing outcomes, 5 existing skips |
| First race run: metering and host | PASS, exit 0; 2 packages, 3043 passing outcomes, 3 existing skips |
| Second race run: metering and host | PASS, exit 0; 2 packages, 3043 passing outcomes, 3 existing skips |
| R3/R4 sharing and group acceptance regressions | PASS, exit 0; both Chromium journeys enabled |
| go mod tidy -diff and git diff --check | PASS |

Both race runs report zero races and execute both browser gates. The five full
suite skips are the existing common Cyrillic normalization case, opt-in Pebble
case and three old host integration stubs; race runs include the same three host
skips. source-verification.json confirms reserved files match the base and hashes
the final implementation/test sources. commands.md provides exact reproduction.


## Scope and hard rules

All edits, generated evidence and commits are confined to this clone.
`internal/host/domains.go`, `internal/host/review_security_test.go` and FIX-R3.md
are unchanged from the base. Every Go invocation uses GOMAXPROCS=4, -p=4 and
GOCACHE/GOTMPDIR under the already gitignored `$PWD/.scratch`; TMPDIR and browser
profiles are also isolated there. Modules and installed browser/Python artifacts
are read-only inputs, with module downloads disabled. No resource-exhaustion
inputs, sub-agents, push, GitHub write, fly invocation, production DB, provider
login, email or payment occurred. Authentication/identity tests use synthetic
local fixtures. Existing rollout and external acceptance constraints remain.
