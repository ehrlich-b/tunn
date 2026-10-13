# Embed tunn in Node

The local npm package [`@tunn/sdk`](../sdk/js/README.md) exposes `publish` and
`publishHandler` with TypeScript declarations. It implements the Go publisher
lifecycle, registration authentication and sharing flags with native Node gRPC.
It is not published to npm. Build and install its tarball as described in the
[package README](../sdk/js/README.md), which includes a Node MCP quickstart.

```js
import { publishHandler } from '@tunn/sdk';

const tunnel = publishHandler((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ path: req.url }));
}, {
  name: 'node-api',
  credentials: {
    authToken: process.env.TUNN_AUTH_TOKEN,
    tunnelKey: process.env.TUNN_TUNNEL_KEY,
  },
  allowedEmails: ['alice@example.com'],
});
try {
  console.log(await tunnel.waitReady());
  await tunnel.wait();
} finally {
  await tunnel.close().catch(() => {});
}
```

For an existing server use `publish({ origin: 'http://127.0.0.1:3000', ... })`.
Only HTTP(S) origins without path, query, fragment or embedded credentials are
accepted. The published request path/query is preserved. Caller servers are
never closed by the SDK. Handler mode owns an ephemeral IPv4 loopback listener
and destroys all its sockets on close or cancellation.

| Option | Meaning/default |
| --- | --- |
| `name` | 1–63 lowercase letters/digits/interior hyphens; generated once if absent |
| `serverAddr` | Relay `host:port`, default `tunn.to:443` |
| `credentials` | Caller `authToken`, `tunnelKey`, optional existing `endpointToken` |
| `public` | Explicit anonymous exposure, default false |
| `allowedEmails` | Relay email/domain allow-list, copied at startup |
| `signal` | AbortSignal for the whole publisher lifetime |
| `relayCA`, `originCA` | Separate PEM trust authorities; TLS verification stays enabled |
| `connectTimeoutMs` | Registration/connect deadline, 10000 |
| `httpTimeoutMs` | Streaming headers / buffered response deadline, 30000 |
| `reconnect` | Five retries, equal jitter from 1000 ms, capped at 30000 ms |
| `requireUpstreamAuth` | Require application Authorization presence, default false |
| `maxConnections` | Concurrent local HTTP workers, default/max 100 |
| `maxBufferedBytes` | Legacy body limit, default 8 MiB/max 100 MiB |

Empty/default publications remain owner-only and require the relay's account
and durable sharing authority. Explicit public exposure cannot also supply
email or endpoint-token access. Neither import nor readiness proves visitor
authorization. The relay enforces accounts, ownership, sharing revocation,
quotas and billing. Publisher credentials never reach the origin;
`Tunn-Authorization` is removed while application `Authorization` is preserved.
An endpoint token sends only its SHA-256 digest at registration. There is no
credential-file access, login flow, token renewal or rotation in this package.

`waitReady()` retains the first successful URL even after shutdown. Its optional
AbortSignal cancels only that wait. `wait()` joins and reports the retained
terminal result. `close()` requests shutdown and joins; intentional close
succeeds while prior errors remain failures. `done` always resolves after
cleanup. `events` is a single-consumer stream with 16 retained events and a
terminal `closed` event. `status` reflects current connectivity; `url` retains
the last confirmed address. Lifetime cancellation returns `canceled`.

This Node adapter supports HTTP(S), streaming/SSE, repeated response field
lines, bodyless responses and negotiated declared response trailers. It rejects
request trailers and does not advertise WebSocket, TCP/Unix or device renewal.
The Go SDK/CLI provides the other transports. `publishHandler` uses loopback
HTTP rather than Go's in-memory handler pipes; app handlers use ordinary Node
server semantics. Disconnected requests are interrupted and never replayed.
The MCP app/client must recover its own session after a reconnect.

Run `make test-js-sdk` for local TLS regressions and an isolated tarball/type
consumer, then `make test-js-sdk-contract` for real Node-to-Go TLS relay
acceptance with synthetic durable accounts and sharing. Loopback/Node failures
fail the explicit contract gate. Hosted MCP integrations and npm release need
separate acceptance; local fixtures do not establish live service behavior.
