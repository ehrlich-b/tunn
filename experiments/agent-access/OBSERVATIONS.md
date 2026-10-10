# Local observation format

`evaluate.py --input INPUT.json --out .scratch/OUTPUT.json` reads local JSON only. No URLs, receipts, credentials or customer records are fetched. Duplicate JSON keys and non-finite numbers are rejected. The collector's `actual` assertion and receipt strings are not independent verification; Bryan must inspect the local evidence.

Use `fixtures/synthetic.json` to learn the structure, never to report customer results. It has ten E1 and six E2 **simulated** rows, one explicitly incomplete E1 record and one E2 dropout. All identities, services and receipts are invented. Assertions of actual data inside unit tests exercise decision arithmetic only.

The top level requires `protocol_id: "tunn-access-e1-e2-v1"`, `cohorts` and `observations`. Input threshold/offer overrides are rejected. A cohort without a roster has a null denominator, not a zero or the target count. The target denominator is displayed separately from the declared roster and actual denominator.

Each E1/E2 cohort has:

- `kind`: `actual` or `simulated`; `participants`: original list of `{participant_id, task_id, recipe}` or null. IDs are unique within that experiment; a person may participate in both experiments. E1's response cohort is ten; E2's six must be three `mcp` and three `browser`.
- `invited`: full invitation count or null; `elapsed_day`: nonnegative integer since a separately approved start; `closed`: explicit boolean. Elapsed deadline or exhausted owner minutes closes the window even if `closed` is false.
- E1: `recruitment_minutes`, recorded within its 50-minute ceiling.
- E2: `owner_review_minutes`, `security_review_receipt`, `client_acceptance_receipt`, and `baseline_reproductions`: one entry each for `tunn`, `pomerium`, `cloudflare`, `pangolin`, with `status` (`supported` or `unsupported`) and a current local `receipt` reference covering both recipes. Tunn must be supported. No receipt means unknown, not unsupported.

Each observation requires `experiment`, `participant_id`, `task_id`, `recipe`, `kind`, `record_complete`, `source_receipt`, ISO date `observed_on`, and explicit boolean `dropped_out`. Duplicated identities/tasks exclude every copy and invalidate the cohort. An incomplete row never contributes to a success. Missing participants remain in the original denominator. A simulated row cannot finish an actual cohort, even as a dropout placeholder.

E1 also requires booleans `is_owner`, `outside_caller_task`, `last_occurrence` (ISO date in the preceding 31 days), integer `occurrences_last_month`, and nonempty `workaround`. Qualification requires actual ownership, an outside-caller task, a written receipt and no dropout. Recurrence requires at least two occurrences; the frozen per-recipe and total thresholds still apply.

E2 requires booleans `activated`, `completed_useful_task`, `required_assistance`, `unsafe_grant`; `order` (`tunn-first` or `baseline-first`); `baseline_name`, `baseline_reason`, `baseline_receipt`; timings `active_seconds`, `baseline_active_seconds`, `wall_seconds`, `passive_wait_seconds`; and `next_task_choice` (`tunn`, `baseline`, `neither`, null). The frozen order is two MCP tunn-first, one browser tunn-first; other attempts baseline-first. Completed useful attempts require nonnegative measured timings, a positive baseline time, a next-task choice and `useful_task_receipt`, `denied_receipt`, `revoked_receipt`. A completed-record dropout may have null timings and no useful result. Unsafe actual grants stop testing even if their row is incomplete or duplicated.

Descriptive fields remain distinct and optional:

- `support_minutes`: nonnegative number or null. The report exposes a known partial sum and a null total if any original participant's support is unknown.
- `price_response`: the recorded response or null. It is not a commitment or payment.
- `written_paid_intent`: true/false/null, with `written_paid_intent_receipt` when true.
- `payment_collected`: true/false/null, with `payment_collected_receipt` and positive `payment_usd` when true. This does not establish E6's independence, team seats or renewal gates.
- `repeat_use`: null if unobserved, an empty array if explicitly observed with no repeat, or events `{date, useful, voluntary, reminded, health_check, retry, receipt}`. Two distinct later dates count only useful voluntary tasks without reminders, health checks or retries. This descriptive count does not assert a completed 14-day E5 observation window.

Decisions: `NO_ACTUAL_EVIDENCE`, `INVALID`, `INCOMPLETE`, `PENDING`, `PASS`, `KILL`, `STOP_UNSAFE`. E1 missing responses at closure kill the recruitment hypothesis; E2 missing real prerequisites stays incomplete. No status is publication, real-host security or billing approval. A PASS is only the frozen small-cohort decision and cannot prove the market thesis.

Offer arithmetic is a pure hypothetical calculation: three maintainers × $6/month = $18/month, $216/year. It takes no existing entitlement data and produces `entitlement_changes: []`; no storage, payment or account API exists. Personal launch pricing remains $12/year for about 50 paying signups with early users grandfathered.
