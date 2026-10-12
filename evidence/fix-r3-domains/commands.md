Base: bbe8014 (sharing fixes already committed); Go 1.27.2, Linux/amd64.
Run from the clone root; all Go invocations use GOMAXPROCS=4 and -p 4.

This lane's final environment reads already-installed module sources and build
artifacts from /work/cache/go, without writing to that shared cache. The Go
GOCACHEPROG helper implements the installed Go cache protocol, validates new
object hashes, and writes new entries only under .scratch/go-cache. Module
network access is disabled. Temporary files and browser profiles use
.scratch/tmp. Existing Python/Chromium executables are read from their installed
locations. No external provider, CA, payment, email, database, deployment, or
GitHub write is involved.

source evidence/fix-r3-domains/env.sh
export PLAYWRIGHT_BROWSERS_PATH=/home/ehrlich/.cache/ms-playwright
export TUNN_SHARE_BROWSER_PYTHON=/work/lanes/tunn-share/review/.venv/bin/python
python3 evidence/fix-r3-domains/make-overlays.py

Original review before (captured before application edits):
go test -race -p 4 -count=1 -timeout=180s -run '^(TestR3|TestReviewUnverifiedWildcard|TestReviewReservationLoss|TestReviewWildcardTXTChange|TestReviewConcreteVerify)' -v ./internal/domains

Expanded regressions before, using only a source overlay against the retained
sharing head; claims.go/issuance.go are replaced with empty package files:
go test -race -p 4 -overlay .scratch/domains-before-overlay.json -count=1 -timeout=180s -run '^TestR3(Pending|VerifiedClaim|LegacyClaim|Concrete|WildcardReservation)' -v ./internal/domains

Original review after (unaltered original exhausted-budget test restored by a
test-only overlay):
go test -race -p 4 -overlay .scratch/domains-review-overlay.json -count=1 -timeout=180s -run '^(TestR3ConcreteRepeatedVerify|TestR3ReservationLoss|TestReviewUnverifiedWildcard|TestReviewReservationLoss|TestReviewWildcardTXTChange|TestReviewConcreteVerify)' -v ./internal/domains

Positive acceptance regressions on final application source:
go test -race -p 4 -count=1 -timeout=180s -run '^TestR3|^TestReview' -v ./internal/domains

Final gates, with no overlay:
go test -p 4 -count=1 -parallel=2 -timeout=600s ./...
go test -race -p 4 -count=1 -parallel=2 -timeout=600s ./internal/domains ./internal/host ./internal/store ./internal/metering
go vet -p 4 ./...

Verifier: PyJWT 2.10.1 and cryptography. Local mocked JWKS only.
python3 evidence/fix-r3-domains/verifier-original.py
python3 evidence/fix-r3-domains/verifier-regression.py

The original exhausted-budget probe requires both Verify calls to return nil
before inspecting its zero-issuer-calls predicate. Once admission is fixed it
stops at the first ResourceExhausted response, so its original after run has exit
1. The original file is retained byte-for-byte as review_r3_original.go.txt;
TestR3ConcreteSpentBudget instead requires ResourceExhausted twice and zero
issuer calls for both owner and global exhausted budgets.
The original verifier probe deliberately requires a removed key to be accepted
at cache age 181 seconds. Its after run has exit 1 because the fixed snippet
rejects that key. The new verifier regression requires rejection at 61, 181,
and 301 seconds, acceptance at 59 seconds, acceptance of the new key, and all
original issuer/audience/provider/email/expiry/algorithm safety checks.

The gate-release fixture advances its clock by one minute after the ended
failed order, preserving all cancellation and gate-release assertions while
honoring the new retry delay. No test assertion or security check was weakened.

Initial Go invocations inherited /work/cache/go/{mod,build} and the default
system temporary directory. This did not obey strict clone-only cache/temp
writes. Later runs isolated all mutable paths; an attempt to copy both caches
with reflinks exhausted the lane's remaining disk during full/race linking.
full-disk-initial and race-disk-initial retain those failures. Only the newly
created clone cache copies were removed; no other lane was edited. The final
helper reads existing shared artifacts and writes only clone-local entries,
allowing full/race/vet to be rerun without relaxing any checks.
