Base source: 70952e39ff18a58dcc01edd90c2c848b1baf2f97.
Final implementation source: d31b510430a826269a15600b580e6fa08972f5de (plus documentation/evidence commit).
Go: go1.27.2 linux/amd64.

All Go commands set GOMAXPROCS=4 and GOFLAGS=-p=4; final gates set umask 022.
Temporary roots are .r3/tmp inside this clone. Browser:
PLAYWRIGHT_BROWSERS_PATH=/home/ehrlich/.cache/ms-playwright
TUNN_SHARE_BROWSER_PYTHON=/work/lanes/tunn-share/review/.venv/bin/python
Those existing Python/browser installations are only used to execute local fixtures.

Before: copied the independent review's host and metering tests into this clone,
changing only the browser script path to a clone-local copy of the exact review
Python script. Ran:

go test -race -v -count=1 -timeout=120s ./internal/host ./internal/metering -run '^TestReview(AccountMergeRevives|PersonMatching|GoogleThirdParty|OAuthStateRedirect|BrowserCacheCookie|RepeatedSharing)'

Then created security acceptance versions of the four finding reproducers and ran
on unchanged application source:

go test -v -count=1 -timeout=120s ./internal/host ./internal/metering -run '^TestR3(AccountMerge|GoogleThirdParty|BrowserCache|RepeatedSharing)'

All four security cases failed for their reported vulnerabilities. The acceptance
corpus was subsequently split into separate finding files and expanded with
policy/transaction/upgrade/status/boundary checks; all original security assertions
remain or are strengthened. The two non-finding review safety cases are unchanged.

Final gates:

go test -count=1 -parallel=2 -timeout=600s ./...
go test -race -count=1 -parallel=2 -timeout=600s ./internal/common ./internal/host ./internal/metering ./internal/store ./internal/storage ./pkg/proto/internalv1
go vet ./...
go test -race -v -count=1 -parallel=2 -timeout=120s ./internal/host ./internal/metering ./internal/store -run '^(TestR3(AccountMerge|Google|OldGoogle|BrowserCache|Private|RepeatedSharing|Sharing)|TestReview(PersonMatching|OAuthStateRedirect))'

After: reran the original review characterization corpus against the final source,
with its local Python path changed and PublicAddr initialization moved before server startup.
This corrects a fixture setup race without changing any characterization assertions. Its four vulnerable-behavior predicates
are expected to fail once fixed; the two safety cases must pass. The tests asserting
safe behavior are the positive acceptance gate. A Go test overlay replaces only the two test files for this characterization run;
the application source and committed tests are not changed. The overlay is omitted
from the security acceptance and gate runs.

Exact after-characterization invocation (overlay maps only test sources):

go test -race -overlay=.r3/review-overlay.json -v -count=1 -timeout=120s ./internal/host ./internal/metering -run '^TestReview(AccountMergeRevives|PersonMatching|GoogleThirdParty|OAuthStateRedirect|BrowserCacheCookie|RepeatedSharing)'
