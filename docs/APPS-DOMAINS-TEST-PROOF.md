# App-domain validation against 7f5d619

Validation date: 2026-10-11. Linux/amd64, repository-pinned Go 1.25.6,
`umask 022`, literal loopback available. Baseline was a detached local worktree
at `7f5d619`; no baseline files were changed. No pushes, deployments, estate DNS
writes, Cloudflare credential access, or billing changes were performed.

| Check | Baseline 7f5d619 | Candidate |
| --- | --- | --- |
| Full `go test -count=1 -timeout=300s ./...` | PASS, 17 tested packages | PASS, 18 tested packages including identity |
| Complete auth/edge/domain race suite | FAIL: shared HTTP/2–HTTP/3 TLS configuration race in `TestOpsLoopbackReadinessLifecycleAndDependency` | PASS, all six packages; no races |
| Real Pebble HTTP-01 order and cached certificate reuse | Not present | PASS |
| Upload-limit check under race | PASS, five repetitions | PASS, ten repetitions after preserving request-body ownership during header stripping |
| DNS helper diff | Reference remains unchanged | Applies cleanly to a copy; `bash -n` PASS |
| Python verifier | Not present | Ten lines; Python syntax PASS |
| Google/production CA/browser acceptance | Not run | REQUIRED-UNRUN before deployment |

Reproduction from the candidate checkout:

```sh
umask 022
GOTOOLCHAIN=go1.25.6 go test -count=1 -timeout=300s ./...
GOTOOLCHAIN=go1.25.6 go test -race -count=1 -timeout=300s ./internal/host ./internal/domains ./internal/common ./internal/sshfront ./internal/cliopts ./internal/identity
scripts/test-apps-pebble.sh
```

`internal/host` contains the authentication and terminating edge implementation;
`internal/domains` contains DNS ownership, certificate authority/RPC and renewal;
SSH edge sniffing/options are covered by `internal/sshfront` and
`internal/cliopts`. The baseline race command uses the same packages except the
new identity package. The candidate gives each HTTP listener its own TLS config.

Security assertions include missing/incorrect TXT proof, generic CNAME not being
ownership proof, arbitrary SNI, unreserved names, nested hostnames, conflicting
claims, concurrent first connections, encrypted keys, restart reuse, durable
owner/global order limits, failed-order backoff, renewal, retained valid
certificates during CA failure, failed DNS proof, deletion during issuance, and
stale proof after takeover. Browser tests cover exact Bryan email versus other
emails, aliases and lookalikes, unverified Google UserInfo, alternate providers,
bearer/grant attempts, cross-host session reuse, signed audience/expiry/issuer,
spoofed identity headers, stripped cookies, nonce/host/token tampering, durable
one-use replay rejection, and central Google-session reuse. Rotation tests
verify old/new signatures, public-only JWKS, removed keys, expired assertions,
wrong audiences, and mismatched key material.

Pebble v2.10.1 image is pinned by digest in the script. It runs with a local test
DNS resolver and real HTTP-01 validation; validation skipping is not enabled.
The issued certificate names `dashboard.apps.ehrlich.dev`, with resolution to
loopback only in Pebble's test resolver. Nothing changes the estate's DNS.
An asynchronous finalize response lacking Location is covered both by this
acceptance run and by a fake-directory regression. The fallback uses only
`x/crypto/acme` order polling and certificate-fetch APIs.

Final raw evidence is in `/work/lanes/tunn-apps-domain/verified-full.log`,
`verified-race.log`, `final-pebble.log`, `header-upload-fixed.log`,
`baseline-matched-full.log`, and `baseline-matched-race.log`. Early exploratory
runs under a permissive umask exposed fixture permission failures; matched
runs above supersede those. Header-stripping request cloning was corrected
after the race check exposed an upload regression; the final evidence uses
the corrected implementation.

The unchanged `cf-dns.sh.reference` SHA-256 is
`5fdbb6d3ad870d656f888af9dc7d5c91365f7e27d9459b60846f30f600b19c03`.
Only a temporary copy was patched and syntax-checked; no helper was executed.
See [deployment prerequisites and the verifier](APPS-DOMAINS.md) and
[the seven-step first-app journey](../USER-JOURNEY.md).
