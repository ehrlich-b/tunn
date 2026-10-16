# Local inspection and deliberate replay

Start an HTTP publisher with `tunn 8080 --inspect`. Open the printed literal
loopback URL in a local browser. Its fragment is a process-specific API secret;
keep that URL private. The viewer checks the exact Host and API secret, rejects
foreign Origins, disables caching and renders captured fields with `textContent`.
There is no disk history. Stopping tunn clears the local session. The
[owner-only web dashboard](#web-dashboard) observes HTTP traffic at the relay
with the same metadata redaction policy and never retains bodies.

The default retains metadata, not bodies. Credential/cookie/signature/custom
header values are replaced by `[redacted]`. Only Accept, Accept-Encoding,
Content-Type, Content-Length and Host retain values. Every query value is
redacted, including unknown application token fields. Application paths,
standard headers and field names can still contain sensitive data: this is not
an arbitrary application secret detector. Malformed or oversized metadata is
marked unavailable and cannot be replayed. Metadata keeps at most 64 headers
and 1 KiB per retained value; reconstructed values have the same 1 KiB limit.
Replay POSTs are limited to 128 KiB including the base64 body.

`--inspect --inspect-body` explicitly enables local request body capture, at
most 64 KiB per HTTP delivery. Arbitrary payloads are not automatically
secret-free; do this only with data you intend to retain in the local process.
The viewer API includes these opted-in bodies as base64. The separate
`/api/export` endpoint always omits bodies, even when local capture is enabled.
The process retains at most 50 completed deliveries, each with a 16 KiB budget
for path/header text; a 51st delivery evicts the oldest record and its replay action.
Active streams expose counts, with their terminal event added when they finish.

## Debug one webhook delivery

Use a disposable handler or an idempotent webhook. Replay can repeat application
side effects, and timestamped provider signatures can expire.

1. Run your local handler, then `tunn 8080 --inspect --inspect-body`. Send one
   test delivery through that publisher using your existing authorized relay.
2. Open the printed inspector URL and select the delivery. Check its status,
   terminal reason, duration, request/response bytes and connection ID. On a
   metered relay, that ID matches the ingress audit and `Tunn-Request-ID` response
   header. Fix the handler if it rejected the request.
3. Supply every redacted query value and header explicitly. The header editor
   requires the full original header object; the standard representation headers
   must remain unchanged. Without opted-in capture, supply the complete missing
   body as base64 with the observed byte count. Nothing fills in credentials from a hidden raw copy.
4. Press **Replay once to configured target**. The result appears and the replay
   event is selected, showing its original delivery ID, status and terminal
   reason. If the target is unavailable, the visible result says `target_error`.
   A validation or API error stays visible above the table. **Cancel replay** aborts the pending local
   request, but cannot undo a handler that already ran. Another replay click is
   a new deliberate action.

For an executable synthetic version of this journey, from the repository root:

```sh
make -j1 test-inspect-contract INSPECT_MODE=browser
```

That runs the offline contracts, generates redacted server snapshots, and uses
an installed Chrome/Chromium to inspect, select, double-click a deliberate
replay, see HTTP 202, and see an error. It checks rendered credential/body
sentinels and treats captured HTML as data. The browser uses a disposable
`.scratch` profile and mocked fetch responses; it is UI evidence, not evidence
of a hosted relay. Real target dispatch is independently exercised using an
HTTP transport over `net.Pipe`, and real loopback dispatch with:

```sh
make -j1 test-inspect-contract INSPECT_MODE=loopback
```

No dependencies are downloaded by the browser runner. Set `INSPECT_CHROME` to an
installed Chrome/Chromium binary if it is not in the usual location. Go modules
must already be available for offline checks. Listener or browser-launch denial
is a required unrun gate, never a passing skip.

## Outcomes and operational observations

| Protocol | Status and bytes | Completion and replay |
| --- | --- | --- |
| HTTP | Local response status; consumed request body bytes and read response body bytes | A response EOF gives `complete`; complete known-length uploads are recognized once every declared byte is consumed. Read/send/target failures and cancellation have distinct terminal reasons. Only a complete request at most 64 KiB with complete metadata is eligible. |
| SSE | HTTP status; request and response body byte counts | Classified from `text/event-stream`. The event appears at stream termination. No retained payload or replay. |
| WebSocket | Upgrade/rejection status; transport frame bytes in both directions, including frame headers/control traffic | `peer_closed`, `message_limit`, `protocol_error`, `idle_timeout`, `close_timeout`, `stream_error`, `relay_error` or `canceled`. No frame retention or replay. |
| CONNECT/TCP | 200 after successful local acceptance; raw transport bytes in each direction | Local EOF, target/read/send failure or cancellation. No payload retention or replay. |

Byte counts are publisher observations, not a second accounting ledger or a
billing guarantee. A failed relay send can leave observed bytes undelivered.
Inspector counters use fixed keys: active streams, completed events, publisher
admission denials, actual reconnect attempts, failed JSON exports, history
evictions and deliberate replay attempts. They contain no account/path labels.
`/api/metrics` requires the same local secret as history/export. Denials before
forwarding are absent from publisher history; inspect the existing ingress
usage ledger for those decisions.

The relay also offers `ProxyServer.OperationalMetrics()` to embedders for an
operator-only exporter: active ingress streams, denied admissions and audit or
usage export drops. It observes existing admission/finish/export calls. It does
not create a quota ledger, change allowance calculations, or expose a new public
metrics endpoint. Failed audit/usage export and failed inspector JSON writes are
counted separately in their respective processes; these counters reset at exit.

## Replay limits

Replay is an explicit POST with a freshly prepared, one-use action. The
inspector admits one replay at a time, independently of account accounting. Reusing that
action or preparing another while it is in progress cannot create a duplicate
dispatch. No reconnect path invokes replay. The inspector snapshots the original
configured target, local TLS policy, path mapping and dialer; request inputs
cannot replace that target. Redirect responses are returned without following
them. The original forwarded Host is preserved separately from the target's
network address. Replay results retain redacted metadata and, only if opted in,
bounded request bodies; reconstructed secrets are not persisted.

Incomplete/truncated requests, incomplete metadata, SSE, WebSocket and CONNECT
cannot be replayed. Reconstruction preserves the original path/query field
shape and all header names; it never sends a redaction marker as a credential.
Opted-in complete bodies cannot be changed by reconstruction. When the original
body was omitted, the user explicitly supplies its replacement; the inspector
cannot verify those bytes against content it did not retain.

Replay is bounded by the configured HTTP timeout (30 seconds by default) and a
1 MiB response read limit. A longer response reports `response_limit`; a broken
response reports `response_error`, rather than success after a partial read.
The raw `tunn tcp` CLI does not expose an inspector switch; TCP metadata is
available when an embedder attaches this inspector to its publisher. There is
no response body viewer, durable queue, provider retry, sender
verification, trailer/gRPC replay, or shared retention service. Loopback access
with a secret does not isolate the inspector from another process running as
the same local user.

Platform credentials (`tunn_mcp_`, `tunn_ep_`, `tunn_gr_`, and `tunn_sk_`) are also masked in visible metadata. Bodies containing those credentials are omitted even with body capture enabled, and replay reconstruction rejects them before contacting the application.

## Web dashboard

Sign in to your verified account, open **Account → Request inspector**, and
choose an HTTP endpoint. Metadata history works with existing publishers and needs no inspector flag.
Replay requires a publisher advertising `http-origin-replay-v1` and streamed HTTP
support. Upgrade and reconnect older publishers to enable replay; the dashboard
keeps their history readable and explains why their replay button is disabled. The dashboard shows the last 50 completed
HTTP deliveries for each live publisher connection. SSE deliveries appear after
they terminate and cannot replay. Open streams, WebSockets and TCP are excluded.

Only the endpoint's account owner can inspect or replay. Sharing an endpoint,
knowing its URL, or holding an endpoint/grant/device credential does not confer
inspection access. Browser sessions are bound to a verified account UUID;
legacy email-only sessions must sign in again. Every operation resolves current
account ownership and active status. Cloud history remains in relay memory,
clears on publisher disconnect/reconnect or relay restart, and is never written
to the usage ledger or a database. On a cluster, the dashboard routes to the
publisher's relay and that relay rechecks the owner.

The web inspector never captures request or response bodies, even when a local
publisher enables `--inspect-body`. It shares the local allow-list for retained
header values, query-value redaction and bounded metadata/reconstruction policy.
The displayed headers are incoming application headers after normal credential
sanitation; relay-generated forwarding and identity fields are omitted. Byte
counts describe consumed HTTP request bytes and delivered response bytes at the
relay. They are observations, not a replacement billing ledger. Authentication
or admission denials are available in usage audits, rather than request history.

Select a complete request and press **Prepare replay**. Restore every redacted
query value and the full original header object. For a nonempty body, supply the
complete original payload as UTF-8 text or base64, with its observed byte count.
The dashboard has no hidden payload or credential copy. Method, path/query
fields, standard representation headers and endpoint remain fixed. Requests
with incomplete metadata/uploads, forwarding failures or bodies above 64 KiB
cannot replay. A complete HTTP error response, such as 500, can replay after the
handler is fixed.

Check the confirmation checkbox, then press **Replay once to origin**. A replay
intent expires after 60 seconds, is bound to this browser session and publisher
connection, and dispatches at most once. Every dispatch follows the ordinary
relay routing, account/resource permission checks, ingress request/byte quotas,
bandwidth limits and platform credential stripping. Domain apps obtain a fresh
identity assertion through the same domain ownership/permission checks. The
publisher uses its configured origin; there is no target URL editor. The negotiated `http-replay` mode never
follows an origin redirect; ordinary publisher requests retain their existing
redirect behavior. A replay result appears as another request with the original ID.
Origin response content is discarded. Replay has a 30-second deadline and a
1 MiB delivered response limit, including if the handler changes to an SSE stream.

Cancel closes the reconstruction form or aborts a pending replay. It cannot undo
an origin side effect. A timeout/network error is ambiguous: inspect history and
the handler before preparing another action. There is no automatic replay retry.
Refreshing the history is manual. If the session-bound CSRF proof expires after
10 minutes, reload the page before preparing another action. Reconstruction
fields are cleared when the dialog closes and never saved to browser storage.

Validate the policy/API/ingress contracts with `make -j1 test-web-inspector`.
For a browser journey against a real disposable TLS relay, gRPC publisher and
HTTP origin, use an already installed Playwright module:

```sh
TUNN_INSPECT_PLAYWRIGHT_MODULE=/path/to/node_modules/playwright \
  make -j1 test-web-inspector-browser
```

The runner substitutes the external Google consent/token provider. It acquires
normal verified fixture-account browser cookies, exercises owner isolation,
empty views, redaction, explicit confirmation, double-click protection,
real origin replay and responsive layout. The browser offline-view check injects
one API 503 response; actual cross-node/offline routing is tested by the API
contracts. The runner writes screenshots at 1440×900
and 390×844 under `.scratch/web-inspector/`. Set `TUNN_INSPECT_EVIDENCE` to an
alternate local output directory. No dependency downloads or hosted account
changes occur. This is local acceptance evidence; hosted deployment, real user
login and production cluster behavior still require operator acceptance.

App device credentials and pairing invitation secrets are suppressed by the
shared inspection filter, including opt-in local body capture. They cannot be
supplied as reconstructed replay inputs. Relay hops preserve explicit credential
precedence even when a request nominates authentication fields in `Connection`.

## Is it my app or the tunnel?

The live request view and both inspectors show `app 2.6 s · tunnel 40 ms`,
plus app and tunnel TTFB (time to first response byte). App time starts after
the publisher has fully sent the request to your origin and includes waiting
for and reading the response. Time blocked sending response chunks to the relay
is excluded. Tunnel time is relay elapsed time minus that app time; it includes
transport, connection setup, request upload, queues and waiting for the visitor
to read. It is not a pure network latency measurement. TTFB uses the same split, through the origin's first response byte
and the relay's receipt of response headers. These clocks measure durations;
the machines do not need synchronized clocks. The split covers streamed
forwarding, after access and quota checks; it excludes browser-to-relay latency.

A side taking at least one second is marked `slow: app`, `slow: tunnel`, or
`slow: app and tunnel`. For a slow app, check the handler and its dependencies.
For a slow tunnel, compare a direct request with the same response size and
check the publisher's connection and the visitor's download speed. Large
responses can take time even when TTFB is fast.

Timing appears after the request finishes. Old publishers or relays, interrupted
requests, and local replays can show `Timing unavailable`; that does not mean
zero overhead. Upgrade both ends for the split. The publisher waits up to
three seconds after origin EOF for relay timing, then records it as unavailable.
This does not end the visitor response; check the web inspector after it completes.
SSE timing appears at EOF.
WebSocket and TCP timing is not split. tunn adds no `Server-Timing` header;
these measurements stay with the publisher and authenticated owner inspector.

Run `make test-request-timing` for a local TLS/gRPC relay, publisher and delayed
origin. It reports paired direct-versus-tunnel p50/p95 overhead for 1 KB,
300 KB, 3 MB, and eight parallel 300 KB requests. Each request has a ten-second
deadline and its full byte count is checked. Loopback numbers do not measure
internet latency. Scheduling noise can make paired overhead negative.
