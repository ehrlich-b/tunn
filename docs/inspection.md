# Local inspection and deliberate replay

Start an HTTP publisher with `tunn 8080 --inspect`. Open the printed literal
loopback URL in a local browser. Its fragment is a process-specific API secret;
keep that URL private. The viewer checks the exact Host and API secret, rejects
foreign Origins, disables caching and renders captured fields with `textContent`.
There is no cloud inspector or disk history. Stopping tunn clears the session.

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
