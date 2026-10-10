# Local validation and required acceptance

2026-10-10, America/New_York. Task started at 16:36:11; the user's two-hour harness cap sets the deadline at 18:36:11 and final-gate start no later than 17:51:11. Final gates ran at about 16:50, well before those limits. The four-hour language in the source brief was superseded by the user.

Baseline: `refs/wave4/base = 53cdce9b4cc43c70b57f02dd32ea54b9978d4c8f`. This ref was absent initially and was created locally at the manually supplied clone HEAD. Work branch: `codex/wave4-tunn-thesis-experiments-20261010`. Manual thesis handoff: ventures `e2df01b`, full content SHA-256 in protocol.json. No setup-script checks, network tools, pushes, external messages, production operations or dependency installations were used.

## Exact gates and outcomes

Commands ran from the clone root with clone-local TMPDIR/GOTMPDIR, no Python bytecode, and offline clone-local npm cache settings. The Chrome job was additionally prefixed `taskpolicy -b nice -n 15`; one heavy job ran at a time.

| Exact gate | Outcome |
| --- | --- |
| `python3 -B -m unittest discover -s experiments/agent-access/tests -v` | PASS, 27 tests; frozen rules/copy pin, duplicate/incomplete/simulated exclusion, unknown denominators, missing real prerequisites, unsafe stop, retention exclusions, distinct intent/payment, hypothetical prices and escaped rendering |
| `python3 experiments/agent-access/build.py --out .scratch/agent-access-preview` | PASS; two static variants plus one offline result page, five local assets |
| `python3 experiments/agent-access/evaluate.py --input experiments/agent-access/fixtures/synthetic.json --out .scratch/agent-access-results.json` | PASS; 16 simulated rows, 0 actual; E1 and E2 both NO_ACTUAL_EVIDENCE |
| `node experiments/agent-access/tests/site-smoke.mjs` | REQUIRED-UNRUN, exit 2; static preflight ran, Chromium startup blocked; 0 completed browser page/viewport checks |
| `git diff --check` | PASS |

Additional gates: `node experiments/agent-access/tests/fixture-test.mjs` PASS (two original synthetic recipes, success/denied/revoked/offline, denied/revoked/offline requests do not increment the model's upstream operation count). `node --check experiments/agent-access/tests/site-smoke.mjs` PASS (syntax only).

Chrome's installed application first failed to bind its profile singleton socket (`Operation not permitted`). The existing cached headless shell then failed sandbox initialization (`Operation not permitted`), including its GPU process. The final runner records this as REQUIRED-UNRUN, without disabling the browser sandbox. Raw startup output is ignored at `.scratch/agent-access-browser-receipt.json`. These failures are an environment blocker, not a failed product security test or evidence of visual correctness.

## Measured counts

Two local landing/onboarding variants; four requested synthetic states in each; two fictional services/tokens; one timed-task worksheet; one evaluator; one result page. The committed fixture has ten E1 rows (one incomplete) and six E2 rows (one dropout); all sixteen are simulated. Reported actual participants, collected payments, sent invitations and published pages: **zero**. Invitation counts and actual cohort denominators in the synthetic report remain null. No price response is fabricated. Unknown support and later-use fields stay null.

The result page shows all submitted rows, exclusions and missing participants, with original recipe rosters. Actual activation, useful completion, written paid intent, collected payment and voluntary repeat use are separate. E3/E5/E6 are descriptive context only, not implemented PASS gates. Prices produce no existing entitlement changes.

## Backlog and handoff

1. DONE — thesis read; E1/E2 choices and frozen audience, tasks, baselines, thresholds, owner-time ceilings and real evidence requirements committed.
2. DONE — solo connector and shared-service variants, visibly unavailable functions, no forms or external assets.
3. DONE — synthetic success/denied/revoked/offline states and timed worksheet; fixture-model tests pass.
4. DONE — explicit local observations, fixed rosters and ineligible simulations; observation correctness tests pass.
5. DONE — offline denominators/dropouts/support/null result page; no false demand PASS.
6. ARTIFACTS DONE; BROWSER ACCEPTANCE BLOCKED — CLI gates, executable browser runner, exact-copy packet, experiment instructions, proposed destinations and source-to-claim checklist are prepared. Browser/visual/network-observation checks remain REQUIRED-UNRUN.

Other REQUIRED-UNRUN evidence: current primary substitute/task receipts; supported Claude.ai account/client OAuth acceptance; real browser-sharing acceptance; E4 independent security review and actual deny/revoke/stream/restart/quota tests; outsider responses and comparisons; voluntary repeat use; independent payments, team expansion and renewals; operating-cost/attention evidence. Publication and enrollment remain unapproved. This kit alone does not prove the thesis.

Concrete next action: run the exact `node experiments/agent-access/tests/site-smoke.mjs` command on a machine that can start existing Chromium with its sandbox intact, then inspect its six screenshots before Bryan decides on the exact copy and proposed destinations in APPROVAL-PACKET.md.
