# tunn for Node

Start an HTTP tunnel inside a Node application. `publish` forwards to an
existing HTTP(S) origin; `publishHandler` owns an ephemeral loopback HTTP server
for a Node request listener (including an Express app). Both return immediately
and validate local options synchronously. Node 20 or later; ESM JavaScript and
TypeScript declarations are included. The package is a local release candidate
and is not published to npm.

From this repository:

```sh
cd sdk/js
npm ci
npm run check
npm pack
# In your Node app, use the actual path to the resulting archive:
npm install /path/to/tunn/sdk/js/tunn-sdk-0.1.0.tgz
```

## Quickstart: an existing Node MCP HTTP server

Run your MCP server on `http://127.0.0.1:3000/mcp`, then place this in your app
as `tunnel.mjs`. Supply an existing publisher token and the relay's creation key
through your application's secret configuration; the SDK performs no login and
reads no credential files.

```js
import { publish } from '@tunn/sdk';

const lifetime = new AbortController();
process.once('SIGINT', () => lifetime.abort());
process.once('SIGTERM', () => lifetime.abort());
const tunnel = publish({
  origin: 'http://127.0.0.1:3000',
  name: 'my-node-mcp',
  credentials: {
    authToken: process.env.TUNN_AUTH_TOKEN,
    tunnelKey: process.env.TUNN_TUNNEL_KEY,
    // Optional existing endpoint bearer token, useful for MCP clients:
    endpointToken: process.env.TUNN_ENDPOINT_TOKEN,
  },
  signal: lifetime.signal,
});
try {
  console.log(`${await tunnel.waitReady()}/mcp`);
  await tunnel.wait();
} catch (error) {
  if (error.code !== 'canceled') { console.error(error.code); process.exitCode = 1; }
} finally {
  await tunnel.close().catch(() => {});
}
```

Connect an MCP client to the printed URL. For an endpoint-token publication,
configure the client to send `Tunn-Authorization: Bearer <endpoint token>`.
Its independent application `Authorization` header is preserved. Clients that
cannot set that header need your application's own supported authentication
flow; this SDK does not expose the relay's stdio MCP bridge or MCP OAuth issuer.
The private default otherwise needs an authenticated owner browser session;
it is not an anonymous MCP endpoint.

For an in-process Express MCP app, use `publishHandler(app, options)` instead.
Keep the app's Host/Origin validation configured for the exact public hostname;
tunn preserves the public Host. The official [MCP Node server guide](https://ts.sdk.modelcontextprotocol.io/server)
provides Streamable HTTP app examples (v1 APIs; accessed October 12, 2026).
HTTP POST and SSE work through either publisher API. The SDK does not convert
stdio into HTTP. A reconnect interrupts active HTTP/SSE requests; the MCP client
must reconnect its transport/session according to the app's rules.

A complete stateless MCP server is also in
[`examples/mcp-server.mjs`](examples/mcp-server.mjs). From the checkout, `npm ci`
installs its pinned MCP v1 development dependency. Configure `TUNN_NAME`,
`TUNN_PUBLIC_ORIGIN` (for example `https://my-node-mcp.tunn.to`) and the existing
`TUNN_AUTH_TOKEN`, `TUNN_TUNNEL_KEY`, `TUNN_ENDPOINT_TOKEN` in your secret
configuration, then run `node examples/mcp-server.mjs`. It publishes the `hello`
tool and requires the exact Host/Origin; the endpoint bearer keeps access private.
When copying this example into an app, install `@modelcontextprotocol/sdk@1.32.1`
alongside the local tunn archive. The local test exercises initialize,
`tools/list`, `tools/call` and invalid Host/Origin rejection.

## Sharing and authentication

```js
// Owner-only by default; requires a relay with account/sharing authority.
const privateTunnel = publish({ origin: 'http://localhost:3000', credentials });
// Share with verified email accounts or a domain, using relay allow-list rules.
const sharedTunnel = publish({ origin: 'http://localhost:3000', credentials,
  allowedEmails: ['alice@example.com', '@example.org'] });
// Explicit anonymous exposure; preserve your application's authentication.
const publicTunnel = publish({ origin: 'http://localhost:3000', credentials,
  public: true });
```

These are alternative publications. Close each when finished. Publisher
credentials authenticate registration, never local HTTP requests. `public`
cannot be combined with `allowedEmails` or an endpoint token. Email/endpoint
publications use the same private legacy registration compatibility as Go;
empty/private and explicit public publications require `web-sharing-v1` from
the relay and fail closed without it. Durable sharing, owner identity,
revocation and quotas remain relay decisions. A self-hosted client secret
cannot create an owner-only publication without account/sharing authority;
use a configured account or explicit allow-list/endpoint token.

Set `requireUpstreamAuth: true` to reject HTTP requests without an application
`Authorization` header. This checks presence only; the app must validate it.
Relay and HTTPS origin certificate verification are always enabled. Custom
PEM CAs are separate: `relayCA` and `originCA`. HTTP origins are plaintext to
the local target. The SDK disables gRPC environment-proxy discovery.

## Lifecycle and limits

`await tunnel.waitReady(signal?)` retains the first successful URL or terminal
startup error. That signal cancels only the wait. The option `signal` cancels
the tunnel lifetime and returns `canceled` from `wait()`. `close()` is an
idempotent join and succeeds for intentional shutdown; a prior failure remains
observable. `done` resolves after resources close and never rejects. `url` is
the last confirmed URL; use `status.state` to check current connectivity.

`events` is a single-consumer async iterator retaining at most 16 events:
`connecting`, `ready`, `reconnecting`, `failed`, `closed`. The terminal event is
retained. Inspecting the returned tunnel does not expose options or credentials;
errors have static messages and one of `invalid_options`, `connection_failed`,
`registration_rejected`, `protocol_violation`, `canceled`.

Defaults: connection/registration timeout 10 seconds; origin response-header
timeout 30 seconds (whole response for buffered fallback); 100 concurrent
requests; buffered request/response limit 8 MiB, configurable up to 100 MiB.
Streaming bodies are not buffered in full. Upload queues are bounded to 512 KiB
per request; exceeding this bound fails that request. Streaming SSE bodies have
no SDK time limit after headers and end with cancellation, origin/relay close,
or the application's completion. Request bodies must end with relay EOF,
including a zero-length upload. Completed error responses (status 400 or higher)
can abandon an unfinished upload; successful responses validate upload EOF
before their clean terminal. Errors after response headers abort the stream.

`reconnect: { maxAttempts: 5, initialDelayMs: 1000, maxDelayMs: 30000 }` is the
default. Five consecutive retries use exponential equal jitter; the budget
resets after a successfully registered session stays ready for 30 seconds. Zero attempts disables retries. The
name is generated once if absent and retained; a changed URL on reconnect
fails closed. Registration rejection/protocol violations are terminal.
Caller origins remain running after close; handler servers and their sockets
are owned and closed by the SDK. Handler exceptions belong to the app's error
handling, as with `http.createServer`.

## Transport scope and checks

This implements the Go publisher lifecycle/auth/sharing contract with a native
Node gRPC adapter. It supports HTTP(S), streaming/SSE, repeated response fields,
bodyless HEAD/204/304 and negotiated declared response trailers. It does not
support WebSocket, TCP/Unix, informational responses, request trailers, gRPC
application forwarding, device-token renewal, endpoint-token rotation, proxy
configuration, CLI inspector or automatic OAuth/login. It advertises only
implemented capabilities; use Go/CLI for those other transports.

```sh
# From the repository root, after npm ci in sdk/js:
make test-js-sdk
make test-js-sdk-contract
```

The first gate checks local TLS lifecycle/protocol regressions and installs an
npm tarball into a separate consumer, checking its types/import/shutdown. The
second runs Node publishers against the actual Go TLS relay, durable synthetic
account/sharing authority and private/public/email/endpoint HTTP admission in
streaming and buffered modes. It fails if Node or loopback is unavailable.
These local fixtures do not prove hosted MCP client acceptance, npm publication,
or production credential behavior.
