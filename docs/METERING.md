# HTTP audit, usage, and consumer grants

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
tunn usage api --month=2026-10
tunn grant revoke api <grant-id>
```

Create prints JSON containing `grant` metadata and a one-time `token`. The CLI
generates the random credential locally and uploads only its SHA-256 digest.
Keep the printed token as a secret; the relay cannot recover it. The `--for`
value is an owner label, not proof that the bearer is that email address.
Each grant has its own stable caller ID, quota, expiry, and revocation state.
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
already forwarded application work may continue, and an idle stream ends when
its next byte check fails or it disconnects.

## Contract and privacy

An endpoint is the registered tunnel name (for example `api` or `work-tools`),
not an application URL path. Counters are scoped by owner, endpoint, caller,
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

Headers, TLS/gRPC framing, and connection overhead are excluded. A successful
write is not proof that the consumer received or processed the body. Egress
bytes are reserved durably before writing, then short/failed writes reconcile
the reservation to the actual writer count. A crash before reconciliation
keeps the reservation conservatively and marks the audit `relay_restart` on
startup. Those records require review before any commercial reconciliation.

## Durability, bounds, and relay routing

The login node owns the ledger in the existing `TUNN_DB_PATH` SQLite database.
Admission, minute-rate state, rollups, and byte reservations commit atomically;
counts and revocations survive restarts. Buffered HTTP and chunked HTTP/SSE
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
`DELETE /api/endpoints/<name>/grants/<id>`, and
`GET /api/endpoints/<name>/usage?month=YYYY-MM`. It accepts owner JWT bearer auth,
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

Usage-based tiers can package included admitted requests and body bytes, with
per-consumer hard budgets as spend controls and retention/grant management as
paid operational value. The counters are candidate packaging units, not
billable usage or a payment system. Before charging, reconcile real node routing,
authority failures, crashes, retries, and consumer receipts; define treatment
of failed admissions and conservative crash reservations. The existing team
pilot price remains a willingness-to-pay hypothesis, not a price implied by
these meters. See [the commercial thesis](COMMERCIAL-THESIS.md).
