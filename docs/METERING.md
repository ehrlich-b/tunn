# Account cutoffs, audit, usage, and consumer grants

Status: prototype contract v1, 2026-10-10. The in-process contract tests run
without sockets. The real relay/publisher/CLI test is local and needs loopback.

## Give each consumer a separate budget

Publish an HTTP endpoint with an owner allow-list so anonymous callers cannot
bypass consumer grants. The publisher must authenticate with a tunn account JWT;
the management CLI uses the owner's `tunn login` credential.

```bash
tunn serve --id=api --allow=owner@example.com 8080
tunn grant create api --for=agent@example.com --expires=1h \
  --rate=60 --monthly-requests=1000 --monthly-bytes=1000000
tunn grant list api
tunn usage --tunnel api --since 24h
tunn usage
tunn grant revoke api <grant-id>
```

Create prints JSON containing `grant` metadata and a one-time `token`. The CLI
generates the random credential locally and uploads only its SHA-256 digest.
Keep the printed token as a secret; the relay cannot recover it. The `--for`
value is an owner label, not proof that the bearer is that email address.
Each grant has its own stable caller ID, quota, expiry, and revocation state.
`grant list [<endpoint>]` shows retained grants, including expiry, limits, and
revocation, even when the endpoint is offline. It never returns tokens or their
digests; omit the endpoint to list all of the owner's grants.
The existing shared `tunn token` credential remains a separate access path.

Consumers send `Tunn-Authorization: Bearer <token>`, preserving their application's
`Authorization` header. `Authorization: Bearer <token>` also works. Tunn strips
the chosen credential and platform auth cookies before forwarding. An explicit
grant attempt takes precedence over browser cookies; an expired, revoked, or
wrong-endpoint grant cannot fall back to anonymous access on a public endpoint.
A public endpoint otherwise retains anonymous access. Use a private endpoint
when every consumer must have a grant.

All budgets are nonnegative integers; zero means unlimited. `--rate` is requests
per fixed UTC minute, not a sliding window, so bursts can straddle a minute
boundary. Expiry defaults to 24 hours, accepts a duration or RFC3339 timestamp,
and must be in the future and within one year. Monthly request and body-byte
budgets reset for new requests at the beginning of each UTC calendar month.
A stream stays in its admission month. An admitted request consumes one request
even if the publisher fails or the caller disconnects. Application retries are
new ingress requests and consume new units.

The login node enforces plan allowances across HTTP, streaming/SSE, MCP,
WebSocket frames and TCP CONNECT. Requests are unlimited (fair use) and are
still counted. Free accounts get 10 GB of transfer; Pro accounts get 500 GB
(decimal units). `TUNN_OWNER_MONTHLY_REQUESTS` optionally sets a monthly abuse
ceiling, counted separately for each account across all its endpoints and callers.
It defaults to zero (off); operators can set it on the login node and restart
without a code deploy. `TUNN_OWNER_MONTHLY_BYTES` optionally tightens transfer
caps; zero leaves the plan transfer allowance in place. The authority reads the
current account plan, so a connected publisher cannot retain an old paid limit.
Anonymous visitors, email aliases, endpoint tokens and grants all share the
account UUID's allowance. New grants and endpoints cannot multiply it.

Admission and byte reservations commit atomically on the login node before
forwarding. Exhaustion returns `429` with `owner_request_budget` or
`owner_byte_budget`. Missing accounts and unavailable account/ledger services
fail closed. Imported legacy bandwidth is included once; a restart cannot
reset counters or double-import the completion mirror. Verified account merges
transfer counters, grants and active events along with reserved names.

Each WebSocket upgrade or TCP CONNECT consumes one admission. WebSocket wire
frames (including masks/control frames) and TCP payloads now consume the same
account byte allowance as HTTP/MCP bodies. HTTP consumer grants still cannot
authorize WebSockets or raw TCP; use a session or endpoint token instead.
The owner `/account` view includes currently reserved active-stream bytes and
monthly admitted requests. `tunn usage` exports transport bytes under the
existing `body_bytes` schema label for compatibility; HTTP bodies, TCP payloads
and WebSocket wire frames are its exact counting units. TLS, HTTP and gRPC
transport framing remain excluded.

Expired/revoked/wrong-endpoint grants return `403`. Exhausted request or byte
budgets and request-rate limits return `429`. Responses include
`Tunn-Request-ID`, monthly `Tunn-Requests-Remaining` and `Tunn-Bytes-Remaining`
(`-1` means unlimited), and `Tunn-Limit-Reason` for limits. A `429` includes
`Retry-After` in seconds. Remaining counts are snapshots, not reservations for
the caller's next request. A known oversized request is rejected before the
publisher sees it; known response sizes are checked before response headers.
Unknown-length bodies are checked as they flow. If a response has already
started, HTTP cannot replace its status with `429` or `403`: tunn stops the
stream and reports the reason through the `Tunn-Limit-Reason` trailer and audit
record. Metered HTTP/1 streaming responses use chunked framing for trailers. Revocation and expiry are checked at admission and each byte check;
already forwarded application work may continue. Idle metered streams recheck
the authority every five seconds, with a five-second RPC deadline, and terminate
on byte exhaustion, grant revocation/expiry or ledger failure. A request allowance
blocks further admissions; work already admitted can finish within its remaining
byte allowance. WebSockets send a policy close (`1008`) or temporary-failure close
(`1013`) when an egress frame boundary permits it; a cutoff inside a frame closes
the transport instead of corrupting its payload. TCP CONNECT reports the limit
through the same trailer when its HTTP transport supports trailers.

## Contract and privacy

An endpoint is the registered tunnel name (for example `api` or `work-tools`),
not an application URL path. Counters are scoped by owner account UUID, endpoint, caller,
and UTC admission month. A caller is `email:<normalized verified email>`,
`token:<non-secret endpoint-token identifier>`, `grant:<grant-id>`, or
`anonymous`. Tokens rotated through the existing shared-token flow get a new
caller identity. Auth methods are `cookie`, `jwt`, `endpoint_token`, `grant`,
or `none`.

Each endpoint-ingress decision has a relay-generated request ID, endpoint,
owner when known, caller, auth method, admission outcome/reason, final HTTP
status, start time, duration, byte counts, completion flag, and whether it
was forwarded. The immutable `admission` object records the original limit
snapshot. Authentication, allow-list, grant, owner-quota, and forwarding failures
appear alongside successful calls. Unknown offline endpoints are recorded with
no owner; owner exports contain only decisions tied to that owner. Relay control
API calls and health/auth pages are outside the endpoint usage contract.

The ledger stores no URL paths, query strings, request/response bodies, arbitrary
headers, cookies, IPs, or plaintext credentials. Body inspection remains a
separate opt-in local feature. Caller emails are identity metadata, so exports
still need the owner's access controls. This contract describes the new SQLite
ledger; existing diagnostic log levels have their own logging behavior.

`usage` exports JSON with `schema_version: 1`, `byte_unit: "body_bytes"`,
monthly `usage` rows, retained `events`, and `audit_truncated` when event retention
cannot explain every aggregate request. Protobuf-derived JSON omits zero/false
fields; omitted counters mean zero. Units are:

| Field | Meaning |
| --- | --- |
| `requests` | All recorded decisions, including denials; never a proposed invoice count |
| `admitted_requests` | Allowed ingress admissions; the grant's monthly request units |
| `request_bytes` | Authorized body bytes read at ingress, including accepted prefixes of incomplete/failed requests |
| `response_bytes` | Body bytes accepted by the caller-facing HTTP writer; excludes relay error bodies |
| `total_bytes` | `request_bytes + response_bytes` |

`tunn usage [--tunnel NAME] [--since DURATION]` defaults to the current UTC month
across all tunnels owned by the authenticated user. `owner_usage` totals the
selected rows across callers and endpoints, including admitted requests and
bytes per owner. `--tunnel` filters both detail rows and that total. The old
positional endpoint and `--month YYYY-MM` remain supported; `--month` and
`--since` cannot be combined.

`--since` accepts a positive Go duration of at least 1 millisecond, such as `1h`
or `168h`. It selects events by admission start in `[since, until)`, returning
both boundaries as Unix milliseconds, and can cross UTC months. Since monthly
rollups cannot reconstruct part of a month, duration counts come from retained
events. `usage_truncated: true` flags potentially incomplete counts when events
in overlapping months were evicted or the window predates rollup retention.
Do not use an incomplete duration report to set a tier allowance. Monthly
reports retain complete rollup totals within the retained months even when
`audit_truncated` is true. Long-running requests remain in their admission
window/month; these are request-attributed body counts, not transfer-time
network telemetry.

Headers, TLS/gRPC framing, and connection overhead are excluded. A successful
write is not proof that the consumer received or processed the body. Egress
bytes are reserved durably before writing, then short/failed writes reconcile
the reservation to the actual writer count. A crash before reconciliation
keeps the reservation conservatively and marks the audit `relay_restart` on
startup. Those records require review before any commercial reconciliation.

## Durability, bounds, and relay routing

The login node owns the ledger in the existing `TUNN_DB_PATH` SQLite database.
Admission, minute-rate state, rollups, and byte reservations commit atomically;
counts and revocations survive restarts. Buffered HTTP, chunked HTTP/SSE, WebSockets and TCP CONNECT
use the same ledger. HTTP-backed MCP uses this ingress path too; grants do not
provide MCP OAuth onboarding, tool permissions, or stdio principal isolation.
Raw TCP grants are not supported in this preview.

Other relays use the authenticated internal Metering gRPC service over the
existing node-secret/TLS connection. Only the publisher's relay meters a routed
request. Admission IDs and cumulative byte charges make repeated internal RPCs
idempotent while their audit event is retained; caller-supplied IDs cannot
suppress charges. There is no automatic replay to the application. The login
node is a single authority, not a distributed billing system. If it is
unavailable, ingress fails closed with `503`; an audit that could not be
persisted is not invented. Existing account bandwidth quotas still apply and
are separate from grant budgets. Metered transfers update account bytes once,
including partial transfers, using the account ID.

The new tables have hard row caps: 10,000 audit events, 100,000 monthly rollups,
and 10,000 grants. Old completed events are evicted first, while current counters
and active events are preserved. Rollups retain the current and preceding 12
UTC months; grants expired more than 13 months ago are pruned during creation.
Cleanup happens on writes. At capacity, operations requiring new rows fail
closed rather than discarding a live budget. SQLite reuses freed pages; its file
size reflects a high-water mark. Back up the database and export periods before
retention removes details.

The owner API is `POST /api/endpoints/<name>/grants`,
`GET /api/endpoints/<name>/grants`, `GET /api/grants`,
`DELETE /api/endpoints/<name>/grants/<id>`, and
`GET /api/usage[?tunnel=<name>&since=<duration>]`.
`GET /api/endpoints/<name>/usage` supports `month=YYYY-MM` or `since=<duration>`.
It accepts owner JWT bearer auth,
not consumer grants or cookie-based writes. Creating a grant requires the live
publisher's owner identity; revocation and exports also work while offline.
Other owners receive no matching grant/usage records. `--server` selects a
self-hosted relay and `--owner-token-file` supplies an explicit owner JWT.
HTTPS is required outside loopback; `--insecure` is for local test certificates.
The CLI never follows redirects with the owner's credential.

## Verification and pricing evidence

```bash
make test-metering-contract    # SQLite, buffered/streamed fixtures, CLI, memory gRPC; race checked
make integration-test-metering # real TLS relay, publisher, CLI, independent grants and restart; loopback only
make check                    # full existing suite, including loopback-dependent tests
```

The focused suite covers accurate bytes on both paths, exact boundaries,
concurrent admissions, expiry/revocation during use, UTC rollover, durable rate
state and quotas, short writes, interrupted reservations, retention, credential
stripping, owner isolation, and authority failure. The E2E test starts only
local processes, uses literal loopback IPs, and creates disposable SQLite state
under `.scratch`. Socket-restricted sandboxes cannot run the E2E/full suite;
that is not a reason to skip or weaken those tests.

the operator's entry paid-tier target is **about $12/year** (about $1/month), with a
monthly request and bandwidth cap. The intended purchase should be a no-brainer,
strictly cheaper than a VPS and easier than a VPN. The plan allowances above are code defaults, not a new Starter entitlement or
a billing reconciliation implementation. Shared owner caps impose a tighter ceiling;
per-grant budgets divide that ceiling among consumers.

Export `tunn usage` per user/month and compare `owner_usage.request_bytes` and
`owner_usage.response_bytes` with actual Fly.io egress invoices. Request bodies
also leave the relay toward the publisher; response bodies leave toward the
caller. A first body-only estimate is
`(request_bytes * publisher_egress_rate + response_bytes * caller_egress_rate) / 1e9`,
where rates are dollars per decimal GB from the applicable Fly invoice/region.
Add framing, cluster hops, fixed hosting/storage, payment fees, and support
before choosing a cap that fits about $1 of monthly gross revenue. These meters
exclude network overhead and are not a substitute for provider billing data.
No current Fly rate or sustainable allowance is asserted by this prototype.

The counters are candidate packaging units, not billable usage or a payment
system. Before charging, reconcile real node routing,
authority failures, crashes, retries, and consumer receipts; define treatment
of failed admissions and conservative crash reservations, and provision paid
account plans. Team controls can be a separate higher
tier; the entry-tier target is the pricing input for this metering experiment.
See [the commercial thesis](COMMERCIAL-THESIS.md).

The funnel ledger is additive. To roll back the code, leave `funnel_events` and
`funnel_secret` in place; older binaries ignore them. If removal is required,
back up the database first, then drop those two tables while the service is
stopped. Removing the secret prevents correlating new events with old ones.

For local operators, `tunn admin funnel --db PATH --admin-config PATH
--token-file PATH` prints UTC daily counts; add `--json` to export the report.
It requires a global operator credential and opens the database read-only.
Each stage is recorded once per account using a database-specific HMAC hash;
the ledger contains the stage, hash, first occurrence time and signup source. Failed
ledger writes do not reject signup, admission, consent or billing requests.
Signup attribution keeps only an allow-listed first-touch token (`alt`, `saashub`, `docs`, `thread`, `direct`, or `other`) in a secure first-party cookie for 30 days and in `funnel_events`, never a full URL, referrer, IP address or email.
The report also groups daily signups by source; historical events without a
captured channel appear as `other`.

Public entry pages on the configured apex navigate to the configured public
HTTPS login authority before capturing attribution, so signup starts with the
same host-only, signed source cookie even when those hosts have unrelated names.
Both origins must serve the platform with valid HTTPS; a public address inside
the publisher tunnel namespace is unsupported and entry navigation fails closed.
Clients that skip entry navigation, and unsigned cookies from older versions
left only on the apex, cannot carry attribution across hosts; those old cookies
are ignored and the next entry establishes the first source for the new cookie.
Only the signed source bound into the single-use email login link reaches signup
when the link opens on another configured platform origin or browser.

Save that JSON and run `python3 scripts/launch-watch.py --funnel REPORT.json
LOGFILE` (or pipe saved logs on stdin). For a report alone, redirect stdin from
`/dev/null`. Conversion percentages compare lifetime stage totals, not cohorts.
Exit code 2 means a completed checkout in the last 24 hours has no matching
Pro-active event in that same window, or a billing webhook error appears in the
last 24 hours of supplied logs. An unmatched payment awaiting ownership review
also counts toward the alert, using a hashed provider identifier when ownership
is unknown. Pro history outside the window does not clear the alert.
When ownership is established, the checkout moves to the account's hash while
preserving its first occurrence time. Ownership review alone does not clear the
alert; a Pro-active event must also appear inside the window. Rejected webhook
metadata is logged without the payload and counts as a billing webhook error.
