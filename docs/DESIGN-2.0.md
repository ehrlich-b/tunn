# tunn 2.0: AI ingress for anything

Status: active prototype
Date: 2026-09-22

## The decision

tunn should not become another model-provider proxy. It should become the
shortest safe path from a remote agent to a capability that exists on a
laptop, private network, edge device, container, or local process.

> **tunn is AI ingress: give remote agents safe, temporary access to anything
> you can run or reach locally.**

The product remains a tunnel at its core. MCP is the first high-value adapter,
not the permanent shape of the data plane.

## Why this problem exists

AI clients are moving into browsers, hosted sandboxes, CI workers, and cloud
agent runtimes. The useful capability often remains somewhere those clients
cannot reach:

- a stdio-only MCP server on a developer laptop;
- an internal API or database behind NAT, a VPN, or a firewall;
- a Docker MCP Gateway whose public interface is still stdio;
- a Unix socket, device port, game server, or non-HTTP service;
- a short-lived development process that should not be deployed permanently.

The market is converging on two adjacent layers:

- OpenAI now offers Secure MCP Tunnel: an outbound-only, OpenAI-hosted path
  from private stdio or HTTP MCP servers into ChatGPT, Codex, the Responses
  API, and AgentKit. Its client includes profiles, health/readiness endpoints,
  metrics, and daemon deployment guidance. This validates the problem while
  making an OpenAI-only MCP tunnel an unattractive place to compete directly.
- Generic tunnel vendors are becoming policy gateways. ngrok now documents an
  MCP gateway made from an already-networked MCP endpoint, bearer
  authentication, rate limits, and traffic policy, and separately offers an
  egress-oriented AI model gateway.
- MCP aggregators govern servers that are already reachable. Cloudflare MCP
  portals explicitly cannot ingest stdio-only servers; Docker MCP Gateway runs
  and governs local/containerized servers and commonly exposes them to clients
  over stdio.

That leaves a narrower but more durable wedge: **turn any private or
process-local capability into a vendor-neutral, policy-scoped remote endpoint
without first deploying it.** OpenAI can provide the best private path into
OpenAI. tunn should provide one path into any hosted agent and carry the
non-MCP capabilities those agents increasingly need.

References:

- [ngrok MCP gateway](https://ngrok.com/docs/using-ngrok-with/using-mcp)
- [OpenAI Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
- [OpenAI tunnel client](https://github.com/openai/tunnel-client)
- [Cloudflare MCP portal limitations](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/#known-limitations)
- [Docker MCP Gateway](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway/)
- [MCP 2026-07-28 transport specification](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/streamable-http.mdx)
- [Official MCP Go SDK protocol support](https://github.com/modelcontextprotocol/go-sdk/blob/main/docs/protocol.md)

## Revised product wedge

Do not sell “an MCP tunnel for ChatGPT.” Sell **private capability access for
remote agents**:

- vendor-neutral: OpenAI, Anthropic, IDE agents, CI agents, and custom runtimes
  can use the same endpoint or grant;
- process-aware: tunn can spawn stdio servers instead of requiring users to
  convert them into network daemons first;
- protocol-complete: MCP is the safe discovery/control surface, while HTTP,
  TCP, and Unix sockets cover real work that does not fit MCP;
- grant-oriented: users share a capability, not a network. A grant has an
  identity, expiry, protocol, tool/action scope, limits, and immediate revoke;
- self-hostable: the relay and policy plane can live in the user's environment
  when a hosted control plane is unacceptable.

The concise pitch is:

> **tunn connects cloud agents to private capabilities. Tunnel anything; grant
> only what the agent needs.**

“AI gateway” is now widely understood as model-provider routing and should not
be the primary category label. “Agent ingress” or “capability gateway” more
accurately describes tunn.

## Product model

The durable abstraction is an endpoint:

```text
source                     adapter                  ingress
------                     -------                  -------
http://127.0.0.1:8080  ->  http passthrough     ->  https://id.tunn.to
process: npx server    ->  stdio <-> MCP HTTP   ->  https://id.tunn.to/mcp
/var/run/app.sock      ->  raw or HTTP          ->  assigned endpoint
tcp://db.internal:5432 ->  raw TCP              ->  HTTPS CONNECT endpoint
udp://device:19132     ->  datagrams            ->  assigned host:port
```

A source says where bytes or messages originate. An adapter understands an
application protocol when useful. Ingress supplies public addressing, TLS,
identity, authorization, quotas, and observability.

The eventual CLI should make those layers explicit while keeping easy things
easy:

```bash
# Existing HTTP behavior
tunn http 8080

# First new wedge: spawn a stdio MCP server and expose Streamable HTTP
tunn mcp --name filesystem -- npx -y @modelcontextprotocol/server-filesystem .

# Compose with Docker's local MCP gateway
tunn mcp --name work -- docker mcp gateway run --profile work

# Implemented connection preview
tunn tcp --name database db.internal:5432
tunn connect --listen 127.0.0.1:15432 database

# Later: more protocol-neutral transports
tunn udp 127.0.0.1:19132
tunn unix /var/run/docker.sock --as http
```

`tunn <target>` remains an HTTP shorthand for compatibility.

## First vertical slice: `tunn mcp`

The first implementation spawns one stdio MCP process, hosts a loopback-only
`/mcp` bridge, and sends that HTTP endpoint through the existing tunn control
and HTTP ingress path.

```text
remote MCP client
  | Streamable HTTP + tunn identity
  v
https://<id>.tunn.to/mcp
  | existing TLS/gRPC reverse tunnel
  v
loopback MCP bridge
  | newline-delimited JSON-RPC over stdin/stdout
  v
local MCP process
```

This is deliberately additive. It proves the user workflow and preserves the
existing production tunnel while the generic data plane is designed.

Current stdio compatibility boundary:

- MCP 2026-07-28 sessionless HTTP clients for discovery, tool listing and
  calls, translated to one legacy stdio child session;
- older HTTP initialization/session behavior through MCP 2025-11-25;
- JSON-RPC requests, responses, and notifications over Streamable HTTP POST;
- finite SSE responses when a server emits notifications before its result;
- no modern `subscriptions/listen`, multi round-trip requests, concurrent child
  calls, or server-to-client requests. The 2026-07-28 revision removed the
  standalone GET event stream and protocol-level sessions;
- 25-second request window inside the stdio adapter. Already-networked HTTP
  MCP servers use the chunked data path and may stream beyond that window.

The bridge must say when a feature is unsupported. It must never silently
grant a local MCP process more access or rewrite tool arguments.

## Security invariants

MCP turns network access into action, so tunn's defaults must be stricter than
its historical preview-URL defaults:

1. `tunn mcp` is private to the creator by default. Public access requires an
   explicit `--public` flag.
2. Machine clients authenticate with a random endpoint-scoped capability
   token. Only its SHA-256 digest reaches the relay, it is compared in constant
   time, stripped before forwarding, and becomes useless when the endpoint
   disconnects. OAuth and audience-bound signed tokens remain future options
   for managed multi-user access.
3. The stdio child inherits local credentials, but tunn never uploads, logs, or
   persists those credentials.
4. Local target addresses stay on the publishing machine. Registration sends
   only the adapter kind, not internal hostnames, ports, paths, or socket names.
5. Request bodies, tool arguments, tool results, and authorization headers are
   not logged by default. Metadata logging is opt-in and redacted.
6. Authentication happens at cloud ingress before traffic reaches the laptop.
7. Every endpoint has rate, concurrency, body-size, and request-time limits.
8. Future policy operates on MCP method and tool name headers where available,
   with raw-body inspection as an explicit higher-risk option.
9. Upstream OAuth tokens are never passed through as tunn credentials. The
   gateway keeps client identity, endpoint authorization, and upstream
   credentials separate.

Before multi-user or production use, add OAuth Protected Resource Metadata,
tool allow/deny policy, per-call audit metadata, and approval hooks for
destructive tools.

## Connection data plane now implemented

The legacy protocol serialized an entire HTTP request and response into one
protobuf message each. A backward-compatible connection path now multiplexes
32 KiB chunks on the existing gRPC stream:

```text
OPEN(protocol + metadata) -> DATA* -> HALF_CLOSE -> CLOSE
```

Capability negotiation keeps rolling upgrades safe: upgraded clients advertise
`http-stream-v1` and `connection-stream-v1`; older peers continue using the
buffered request/response messages. HTTP metadata travels in OPEN/ACCEPT while
bodies stream in either direction. Long-lived HTTP and SSE responses no longer
have a whole-response buffer or 30-second body deadline.

The first generic adapter is raw TCP:

```text
local application -> tunn connect -> authenticated HTTP/2 CONNECT
                  -> relay -> connection stream -> net.Dial(private target)
```

This preserves ordered bytes and half-close without exposing a new public port.
It also means policy and endpoint-token authentication still happen at the
HTTPS ingress. The target hostname and port never leave the publishing machine.

This is useful, but not yet the final transport. Multiplexing every logical
connection on one application-level gRPC stream can create head-of-line
blocking, and the current cluster hop remains an HTTP reverse proxy. The next
revision should separate control from independently flow-controlled data:

```text
control stream
  register endpoint -> authorize -> announce address -> health -> revoke

data streams
  one bidirectional stream per accepted connection
  OPEN(metadata) -> DATA* -> HALF_CLOSE -> CLOSE

datagrams
  FLOW_OPEN(metadata) -> DATAGRAM* -> FLOW_CLOSE
```

Properties:

- opaque byte streams at the kernel layer;
- adapters can attach typed metadata without becoming mandatory;
- backpressure comes from the transport rather than whole-body buffering;
- connection IDs are unguessable and scoped to one authenticated endpoint;
- limits apply at endpoint, connection, byte, and message levels;
- HTTP, TCP, Unix sockets, stdio, and process IO share lifecycle code;
- UDP keeps message boundaries and has explicit idle expiry;
- reconnect behavior distinguishes durable endpoints from ephemeral streams.

HTTP/2 or QUIC can carry these streams. The choice should follow benchmarks
and operational simplicity, not be exposed in the user model.

## Roadmap

### Immediate: turn the prototype into an alpha

1. Keep the real-process E2E deployment as a required CI check on Linux
   (implemented). It covers the TLS relay, private stdio MCP
   initialization/discovery/call, local tool filtering and rejection, live
   token rotation, private raw TCP publish/connect, concurrent connections,
   relay restart/reconnect, half-close, and clean shutdown.
2. Implement MCP authorization interoperability: OAuth 2.1, Protected Resource
   Metadata, authorization-server discovery, PKCE, audience-bound tokens,
   Client ID Metadata Documents, issuer validation, and refresh behavior.
   Endpoint tokens remain useful for scripts but are not the mainstream
   remote-client integration.
3. Finish the modern stdio adapter: per-principal child isolation, concurrent
   calls, `subscriptions/listen`, cancellation, and multi round-trip requests.
   Keep older sessions only for interoperability.
4. Add an operator surface: `tunn doctor`, endpoint readiness, structured
   metadata-only audit events, Prometheus metrics, live connection inspection,
   and a clear reason for every rejected request.
5. Fix HTTP proxy parity: preserve repeated headers such as `Set-Cookie`,
   support WebSocket upgrades, forward trailers, and prove HTTP/3 reachability
   through a live UDP deployment. The Fly configuration now exposes UDP 443,
   but production reachability has not yet been verified.
6. Dogfood three sources (a direct stdio server, Docker MCP Gateway, and a
   private TCP service) from at least three consumers (one OpenAI surface, one
   non-OpenAI client, and one ordinary TCP application).

### Productize: grants and capability bundles

The next product object after an endpoint should be a short-lived grant:

```bash
tunn grant create work-tools \
  --for agent@example.com \
  --tools read_file,list_directory \
  --expires 1h
tunn grant revoke <grant-id>
```

A small manifest can publish several related capabilities without turning tunn
into a service-mesh configuration language:

```yaml
endpoints:
  tools:
    adapter: mcp-stdio
    command: [docker, mcp, gateway, run, --profile, work]
    tools: [search_code, read_file]
  preview:
    adapter: http
    target: http://127.0.0.1:3000
  database:
    adapter: tcp
    target: 127.0.0.1:5432
```

The receiver gets one bootstrap instruction or standards-compatible OAuth
flow, not three permanent credentials. Policy remains attached to each
capability.

### Validate before widening

Recruit ten users who already run hosted agents against private resources. The
alpha is working only if a new user can reach a useful local tool in under two
minutes, without an inbound firewall rule, and can prove revocation. Track
setup completion, successful tool calls, reconnect recovery, added latency,
grant revocations, and weekly repeated use.

Defer UDP, public raw ports, a rich dashboard, model routing, a marketplace,
and a general policy language until repeated usage identifies a need. The
generic stream kernel should stay broad; the launch workflow should stay
narrow.

### Phase 0: prove remote stdio MCP — implemented

- ship `tunn mcp -- <command>`;
- make access private by default and accept bearer identity at ingress;
- cover initialize, tools/list, tools/call, notifications, process exit, and
  timeout behavior with an in-process fake MCP server;
- document the compatibility boundary honestly.

### Phase 1: make it a real remote MCP endpoint — in progress

- front already-networked Streamable HTTP servers with `tunn mcp <http-url>`
  (implemented);
- endpoint-token rotation without restarting the endpoint (implemented via
  atomic local replacement and digest-only relay updates);
- OAuth discovery/authorization for mainstream remote MCP clients;
- streaming responses and modern `subscriptions/listen`;
- multiple independent remote principals, each with an isolated child process;
- exact local stdio tool allow-lists (implemented); richer filters, call
  tracing, approval policy, and redaction;

### Phase 2: replace the buffered HTTP data path — connection preview implemented

- introduce the connection-oriented protocol (implemented on the existing gRPC
  stream; independent transport streams remain future work);
- migrate HTTP bodies and SSE to real streaming (implemented); add WebSockets;
- add authenticated raw TCP (implemented through `tunn tcp`/`tunn connect`)
  plus raw and HTTP-adapted Unix socket publishing (implemented);
- use MCP as one adapter on the generic stream kernel.

### Phase 3: tunnel anything

- UDP/datagram flows;
- persistent named endpoints and device agents;
- service discovery and endpoint manifests;
- team policy, audit export, and regional relays;
- A2A and OpenAI-compatible adapters where they solve an ingress problem.

## Non-goals

- Competing first with model-routing gateways such as LiteLLM or provider AI
  gateways. That is egress, a crowded market, and not tunn's advantage.
- Becoming an MCP catalog. Docker and other registries are better upstreams;
  tunn should make their selected runtime remotely reachable.
- Pretending arbitrary TCP is automatically safe. Raw transports get explicit
  opt-in, narrow bind targets, and protocol-appropriate authorization.
- Shipping a generic transport rewrite before the stdio-to-remote workflow has
  demonstrated real use.

## Success test

The first release succeeds when a user can run one command on a laptop, paste
one HTTPS endpoint into a remote MCP client, authenticate as themselves, list
the child server's tools, invoke one, stop tunn, and immediately remove all
remote reachability. No deployment, inbound firewall rule, or credential copy
from the child process is required.
