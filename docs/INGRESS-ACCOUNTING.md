# HTTP ingress accounting

This is the first implementation slice of roadmap milestone 2. Registered,
account-owned HTTP endpoints (including HTTP MCP) now produce durable metadata
and monthly endpoint/caller counters. Buffered and streamed HTTP use the same
contract. TCP/Unix raw connections, unknown/offline endpoints, and publishers
without a resolved account ID remain outside this ledger.

## Owner workflow

Sign in and open `/account`. The monthly usage card links to request and caller
counter JSON exports. CLI callers can use a valid tunn account JWT on the apex
host, using `Authorization` or `Tunn-Authorization`. An endpoint token grants
access to its endpoint only and cannot read the owner's ledger.

```sh
curl --fail --header "Authorization: Bearer $TUNN_ACCOUNT_TOKEN" \
  'https://tunn.to/api/usage?month=2026-10&view=counters'
```

`GET /api/usage` accepts these filters:

| Parameter | Meaning |
| --- | --- |
| `month` | UTC request-start month, `YYYY-MM`; defaults to current month |
| `endpoint` | Optional endpoint ID, restricted to the authenticated account |
| `view` | `events` (default) or `counters` |
| `limit` | Page size, 1–500; default 100 |
| `after` | Cursor from the previous page; omit for the first page |

The response includes `month`, `events` or `counters`, `next_cursor`, and
`billable: false`. A zero cursor ends pagination. An empty page may omit the
array. Cursors belong to their view/filter combination. Events are ordered by
storage sequence; counters are mutable, so pages during live traffic do not
constitute a point-in-time snapshot. Exports use `Cache-Control: no-store`.
The same `/api/usage` path on an endpoint host still reaches the published app.
The endpoint ID selects a filter; it never grants access to another owner.

## Metadata and units

Each event contains a server-generated request ID, endpoint ID, authenticated
caller, auth method, ingress decision reason, completion outcome, final HTTP
status, UTC start time, duration in milliseconds, whether forwarding started,
and request/response payload byte counts. Duration excludes persistence latency.
It does not contain URLs, paths, queries, methods, IP addresses, headers, tokens,
or bodies. The local inspector remains a separate opt-in payload capture tool.

| Caller | Attribution |
| --- | --- |
| Verified cookie or account bearer | `email:<normalized verified email>` |
| Shared endpoint token | `endpoint-token`; this identifies the shared credential class, not its holder |
| Unauthenticated or open endpoint | `anonymous`; user-supplied identity headers are ignored |

Verified aliases are counted by their presented email, rather than collapsed into
one consumer. Shared token rotation does not create a new consumer identity.
Per-consumer grants and budgets remain roadmap milestone 3.

Reasons distinguish open access, allow-list access, endpoint-token access,
authentication required, access denied, and owner quota exceeded. Outcomes are
`completed`, `denied`, `proxy_error`, or `canceled`. An upstream `401` or `429`
with a complete response has outcome `completed`; it is an application response,
not an ingress denial. A login redirect is an ingress denial. A failure after
response headers preserves the emitted status and reports `proxy_error`.

Request bytes count payload successfully sent on the publisher transport.
Response bytes count payload accepted by the caller's HTTP response writer.
This measures transport/write acceptance, not proof that the remote app or user
consumed the data. Failed sends, rejected chunks, generated ingress error pages,
headers, and protocol overhead are excluded. Partial writes count only accepted
bytes. Denials before forwarding count one request and zero payload bytes. An
early target response stops the upload before finalizing its byte count.
Long streams are finalized when they close, so exports omit ongoing streams.

Monthly counters include all decisions, forwarded requests, ingress denials,
proxy failures/cancellations, and both byte directions per endpoint/caller/auth
method. Counts are diagnostic and explicitly marked non-billable.

## Ownership, retries, and quotas

Only the node hosting the endpoint authenticates the request and records its
event. Routing nodes do not record another event or trust inbound caller or
request-ID headers. Existing node-secret authentication protects the new
login-node storage RPCs; no trust or credential configuration changes are
required by this patch.

SQLite commits each HTTP event, its counters, and its owner's bandwidth charge
in one transaction. A unique server request ID prevents duplicate charging when
an internal storage RPC commits but its acknowledgement is lost. HTTP bandwidth
uses the event's UTC **start month**, including streams that finish after a month
boundary. New visitor requests have new IDs, even if their bodies are identical;
there is no application-level delivery deduplication. Existing account quota
checks now use the registered account ID, rather than the creator's email.
TCP retains its existing bandwidth accounting path.

Account merges atomically move history, combine overlapping caller counters and
monthly bandwidth, and preserve canonical aliases for active publishers holding
an old account ID. The caller's account never pays for another owner's endpoint.
Platform cookies and consumed tunn bearer credentials stay out of the publisher;
the reserved `Tunn-Authorization` header is also removed when a cookie won auth.
Upstream application authorization is preserved.

## Operational limits

Storage attempts have a two-second deadline detached from caller cancellation.
Failures enter a process-local queue capped at 1,024 metadata events, retried
every ten seconds. The proxy joins handler shutdown and attempts a final bounded
flush. Queue overflow or process termination before successful persistence can
lose **events, counters, and their owner bandwidth charges**. There is no durable
worker spool or end-to-end reconciliation yet. Existing stale-cache/fail-open
quota behavior during login-node outages is retained.

Durable SQLite history has no automatic retention policy in this slice; disk
usage grows with requests, including denied zero-payload calls. An operator must
set retention/capacity policy before treating this as a production audit service.
Existing historical account-bandwidth totals have no retroactive ingress events.
This is neither a payment integration nor a customer billing guarantee.

## Local verification

`make test-ingress` runs bounded race-enabled tests for synthetic attribution,
authentication, export isolation, privacy, owner quota rejection, partial writes,
cancellation, early upload termination, account merges, transactional rollback,
SQLite reopen persistence, internal node authentication, and duplicate/ambiguous
storage delivery. Real loopback fixtures include a TLS gRPC publisher, a second
HTTP routing node, and authenticated login-node RPC storage. They exercise both
buffered and streamed paths, with known request/response bytes.

`make check TEST_ARGS='-timeout=120s -count=1'` runs the repository's full format,
module tidy, and race checks. `make benchmark-ingress` measures WAL SQLite record
transactions and the marginal ledger cost in a synthetic in-memory HTTP fixture.
The fixture benchmark excludes TLS/network latency and is not a service SLO.
