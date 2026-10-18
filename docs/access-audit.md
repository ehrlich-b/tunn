# Access audit log

Open **Account → Access audit log** while signed in to review requests belonging to your account. Filter by endpoint, status class, and a UTC time window. The end time is exclusive. Older requests loads the next 50 records; CSV and JSON exports include all retained records matching the filters, across pages.

The view includes the recorded admission time, endpoint, response status, request and response body bytes, duration in milliseconds, and whether the request finished. In-progress requests have no final status or duration yet. The ledger does not record paths, client IP addresses, or user agents. Those fields appear as “Not recorded” on the page, empty cells in CSV, and null in JSON. The audit view adds no ingress collection. Caller identities, grant identifiers, and credentials are not included in this view or its exports.

Retention defaults to the existing capacity-based policy, with the same shared cap on stored request records. Choose 7, 30, or 90 days to remove older completed records automatically. Existing capacity eviction can remove records sooner. A changed setting immediately applies to the audit view; physical deletion runs in background batches. Increasing retention cannot restore deleted records. Active requests are kept until completion, and aggregate usage counters remain separate.

The login node runs an immediate sweep at startup and one sweep each minute. Each sweep examines at most 32 explicit account settings in primary-key order and deletes at most 100 completed records per account, using an indexed owner, completion-state, and timestamp lookup. Sweeps cycle through accounts, honor cancellation, and re-read the current setting within the delete transaction. Verified account merges keep the shorter explicit retention preference.

The schema update adds one settings table and two indexes over existing request metadata. Back up the database before upgrading. No existing table or stored request payload is rewritten by this migration. A rollback leaves the extra schema in place but stops enforcing the new retention settings; records already deleted remain deleted.
