# Embedding the Go HTTP publisher

Import `github.com/ehrlich-b/tunn/sdk` as `tunn`. The package reuses
`internal/client.ServeClient`, including its registration, quota/authentication
checks at the relay, buffered HTTP fallback, streaming HTTP/SSE and WebSocket
transport. It supplies one application-owned lifetime. This is an additive Go
API at this repository revision; no registry release or stability/version
guarantee is implied.

```go
import tunn "github.com/ehrlich-b/tunn/sdk"

tunnel, err := tunn.Publish(ctx, tunn.Options{
    Origin: "http://127.0.0.1:8080",
    Name:   "my-app",
    Credentials: tunn.Credentials{
        AuthToken: loginJWTOrSelfHostedToken,
        TunnelKey: relayCreationKey,
    },
    AllowedEmails: []string{"alice@example.com"},
})
if err != nil {
    return err
}
defer tunnel.Close()

readyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
defer cancel()
publicURL, err := tunnel.WaitReady(readyCtx)
if err != nil {
    return err
}
fmt.Println(publicURL)
return tunnel.Wait()
```

`PublishHandler(ctx, handler, options)` accepts an existing `http.Handler` with
the same options and an empty `Origin`. It serves HTTP on private `net.Pipe`
connections, preserving normal `http.ResponseWriter`, streaming/flush and
WebSocket hijack behavior without opening a local TCP port. Application
handler state remains owned by the caller. `Publish` accepts an explicit
HTTP(S) origin without a user-info component, path, query or fragment. Request
paths and queries pass through the existing publisher adapter.

## Lifecycle and ownership

`Publish` returns after local validation and starts connecting asynchronously.
Keep its context alive for the tunnel's entire lifetime. A blank name is
generated once using cryptographic randomness; every reconnect registers that
same identity. The public URL must identify that name and remain unchanged
across reconnects. A registration rejection or invalid/duplicate registration
response terminates the publisher.

The event sequence is `Connecting → Ready`, followed by `Reconnecting →
Connecting → Ready` when a recoverable connection fails. `Reconnecting.Err`
describes the failed attempt and `RetryDelay` records the chosen backoff. A
terminal transport/registration/protocol error emits `Failed → Closed`.
Cancellation, caller deadline and explicit `Close` emit `Closed` directly.
`Closed` occurs once, last, and carries the final result.

`Events()` is a single-consumer channel with capacity **16**. The publisher
never waits for a reader. A full buffer evicts the oldest intermediate event;
retained events remain ordered, and the terminal `Closed` event is retained.
Use `Status()` for the latest state, `WaitReady(ctx)` for the retained first
registration result, and `Wait()` for the retained terminal result. These
methods support concurrent callers and do not consume events. `URL()` returns
the last confirmed URL; it may remain set while reconnecting or after closure.

The context passed to `WaitReady` limits that wait alone. Canceling the context
passed to `Publish` cancels initialization, registration, active requests,
WebSockets and backoff. `Wait` returns `context.Canceled` or
`context.DeadlineExceeded` for caller cancellation/deadline. An explicit
`Close()` cancels and joins the publisher and returns nil on intentional
shutdown. A previously completed failure remains observable through `Close`
and `Wait`. Repeated and concurrent `Close` calls are safe. `Done()` closes
after forwarding workers stop and the final event/channel closure is recorded.

Each tunnel owns its relay connection, forwarding transports/workers, timers
and optional handler transport. Closing one tunnel never cancels the caller's
context, shuts down an existing origin server, stops another tunnel, or changes
process logging/signals/flags. Caller handlers must honor request cancellation;
Go cannot forcibly stop application code or goroutines that ignore it. Handler
state, application goroutines and caller-supplied logging handlers remain the
caller's responsibility. The SDK does not run subprocesses or call `os.Exit`.

## Defaults and explicit options

| Option | Default / behavior |
| --- | --- |
| `ServerAddr` | `tunn.to:443`; explicit host and numeric port for self-hosting |
| `Name` | Random 12-character DNS label; fixed for this lifetime |
| `TLSConfig` / `OriginTLSConfig` | System trust with verification; optional independent custom CA configs |
| `ConnectTimeout` | 10 seconds per connection and registration attempt |
| `HTTPTimeout` | 30 seconds for a buffered request; 30 seconds for streaming response headers |
| `Reconnect` | Five consecutive retries; initial delay 1s, maximum 30s, equal jitter |
| `ReconnectPolicy.MaxAttempts` | Zero disables retries when an explicit policy is supplied |
| `WebSocket` | 5-minute idle expiry, 30-second keepalive, 8 MiB message limit |
| `Logger` | Discard; a supplied `slog.Logger` receives only static messages |

Retry delay starts between half the exponential cap and the cap itself.
Backoff and the retry budget reset after a connection lasts 30 seconds.
Connection timeouts do not expire an already ready tunnel. Streaming response
bodies live until completion or lifetime cancellation; buffered requests retain
the core's total HTTP timeout. A caller deadline bounds the overall lifetime.
TLS configurations, slices and policy values are copied at startup; do not
mutate TLS configurations concurrently with the startup call.

## Authentication and private data

Pass credentials as Go values. `AuthToken` accepts the existing tunn login JWT,
self-hosted master secret or configured per-user token. `TunnelKey` is the
relay's creation key. `EndpointToken` optionally accepts an existing
`tunn_ep_...` bearer token; the SDK sends only its SHA-256 digest. It creates no
second account/token cache, reads no implicit credentials, launches no login
flow and performs no control-plane writes. An application may read its existing
credential storage and supply the value explicitly.

`AllowedEmails`, including `@domain` entries, retain the relay's access-control
semantics. An empty allow-list without an endpoint token permits anonymous
visitors under the current HTTP publisher rules. Empty publisher credentials
work only when the relay itself permits them. Hosted account verification,
ownership, admission limits and quota enforcement still belong to the relay.
The SDK never treats a name or successful import as proof of authorization.

For bearer ingress use `Tunn-Authorization: Bearer <endpoint-token>` and reserve
`Authorization` for the application's credential. The relay strips platform
credentials using the same HTTP/WS path as the CLI. `RequireUpstreamAuth`
requires a remaining application `Authorization` header and a relay with the
existing `websocket-v1` capability.

Lifecycle events contain a public URL, state, retry delay and safe error only.
Private origins, allow-lists and credentials are excluded. `Credentials` has
redacted string/debug formatting. Asynchronous `*tunn.Error` exposes one of
`ConnectionFailed`, `RegistrationRejected` or `ProtocolViolation`; local
validation uses `InvalidOptions`. Check the category with `errors.As`. Remote
error text and wrapped transport errors are excluded because they may echo
credentials. SDK logs contain no remote error text or private target data.

## Examples and offline validation

Two complete examples live in `examples/sdk-handler` and `examples/sdk-origin`.
Both read `TUNN_AUTH_TOKEN`, `TUNN_TUNNEL_KEY`, `TUNN_ALLOWED_EMAIL`, optional
`TUNN_SERVER_ADDR` and optional `TUNN_NAME` from the application environment.
The origin example defaults to `http://127.0.0.1:8080` and accepts `TUNN_ORIGIN`.
Supply the allowed email explicitly. Use your application's secret storage
when embedding; credentials need not appear in process arguments.
Run `make run-sdk-handler` or `make run-sdk-origin` in an environment authorized
to connect to your relay, with those environment variables already set.

`make test-sdk-consumer` stages a separate tiny module under
`.scratch/sdk-consumer` with a local `replace => ../..`, tests the public API
from outside this module and compiles both examples. All Go resolution uses
`GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`; a missing cached dependency is
a setup requirement. No registry publication occurs.

`make test-sdk-unit` runs race-enabled memory TLS/gRPC fixtures for lifecycle
ordering, cancellation at connect/registration/ready/reconnect, initialization
timeout, caller deadlines, concurrent Close, retry identity, protocol failures,
bounded events, terminal retention, credential redaction and buffered/streamed
handler HTTP. `make test-sdk-contract` includes those checks, the external
consumer and a **required real loopback TLS/gRPC relay/auth/HTTP/WebSocket
contract**. The relay contract compares SDK handler/origin modes with the CLI
core using the established independent WebSocket wire fixture. A socket denial
leaves full acceptance REQUIRED/UNRUN; memory fixtures are local evidence only.
Existing build, vet, full test/race, lifecycle and WebSocket gates remain intact.

## HTTP response wire compatibility

The response wire contract has an additive `header_fields` list in both
`HttpResponse` (buffered) and `HttpResponseHead` (streaming). Each entry carries
one name and one value. A nonempty list replaces the entire legacy `headers`
map; receivers never consume both representations. An absent or empty list
uses the map. The map remains available for older peers and joins repeated
values with `, `. Exact multiplicity needs both upgraded endpoints. The legacy
host cookie-splitting heuristic cannot recover all valid cookie values.

The supported response matrix is:

| Handler behavior | Buffered path | Streaming path |
| --- | --- | --- |
| Repeated ordinary fields | Exact field list; joined legacy fallback | Same |
| Two cookies, including a comma in a value | Exact fields and platform-cookie filtering | Same; legacy fallback remains ambiguous |
| HEAD, 204 and 304 | No body read or forwarded bytes | Same; metadata completes without waiting for body frames |
| Empty or status-only response | Entire response collected before sending | Metadata followed by half-close |
| Known or unknown body length | Limited body read to EOF | Chunks read to EOF |
| Response trailers | Not serialized | Not serialized in terminal frame |
| Flush | Buffered until EOF | Metadata/chunks become visible before EOF |
| Body-reader error or early close | Error response before headers | Error close after accepted metadata |
| Informational 1xx before final status | Upstream client consumes 1xx | Same; only final metadata serialized |

`make test-http-fidelity` uses the existing memory TLS/gRPC SDK fixture, an
independent direct net/http handler-pipe reference, host reconstruction tests
and independent old protobuf descriptors. It requires no listening sockets.

## Unsupported features and later language boundary

This API exposes HTTP publishing only. Public raw TCP, Unix endpoints, raw TLS,
MCP child supervision, host-mode/service installation, inspector/replay APIs,
control-plane provisioning, account caches/login, token rotation, custom-domain
management and JS/Python/Rust wrappers are outside this SDK. Existing HTTP
transport limits also remain: trailers, gRPC
application forwarding and WebSocket compression have no new fidelity promise.

A later JS/Python/Rust binding needs only typed publisher options/credentials,
start/cancel/close, a bounded event stream, retained ready/terminal results and
the same transport conformance fixtures. An in-process handler needs a
language-owned HTTP adapter with explicit ownership. Relay auth/quota state and
tunnel protocol remain in the existing core; choose a release/FFI or local
process boundary only after this Go contract earns full acceptance. No wrappers,
new protocol or versioned release are implemented here.
