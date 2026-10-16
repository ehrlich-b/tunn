# Product roadmap: useful ingress before a paid gateway

Status: working plan with HTTP metering/grant prototype, 2026-10-10

## Product promise

One command makes a local or private capability reachable from a remote caller.
The owner can see who used it, put a limit on that use, and stop access at once.
HTTP, webhooks, and MCP should share those controls. The local developer workflow
must be good enough to use daily even if no team ever buys the managed version.

The product category is **private capability ingress**. A model-provider gateway
routes requests *out* to models; tunn brings callers *in* to services the owner
already runs. Keep `tunn 8080` simple.

## Three workflows to build against

| Workflow | First useful experience | What would make a team pay |
| --- | --- | --- |
| Local webhook development | Forward a provider webhook to localhost, inspect it, fix the handler, replay the same delivery locally | Shared history, verified senders, incident recovery, retention controls |
| Private context or tool service | Expose a policy-backed REST/MCP service to a hosted agent, with a clear caller and request trail | Short-lived caller grants, revocation, centrally managed policy and audit export |
| Metered local endpoint | Give a script, customer, or agent a URL with a request/byte budget and see usage by caller | Reliable enforcement, usage export, spend controls, and billing integration |

A policy-backed context service is a useful *shape* for the second workflow:
one authenticated service offers REST and MCP over the same authorization
logic, and records allowed and denied operations. Tunn should transport and
account for access to that service; its own resource permissions stay in that
service. Publishing an internal service requires a separate security review.

Other teams plausibly need the same ingress for staging APIs, internal search,
build/test harnesses, self-hosted models, device control, and customer-specific
MCP servers. Those are hypotheses to test with actual workflows. We should not
add a separate adapter for each one before the common HTTP/MCP path works well.

## What exists today

- HTTP forwarding, private email allow-lists, MCP stdio and HTTP publishing,
  endpoint tokens, raw TCP/Unix previews, streaming HTTP, WebSocket upgrades,
  and relay reconnects. Ordinary HTTP tunnels can opt into endpoint tokens with
  `--bearer`; WebSocket upgrades retain the HTTP email allow-list gate.
- Monthly **account-level bandwidth** accounting and per-tunnel bandwidth rate
  limits, plus a durable per-caller endpoint request/body-byte ledger and
  expiring, revocable HTTP grants with monthly budgets and minute-rate limits.
  See [the v1 usage contract](METERING.md); commercial reconciliation remains
  incomplete.
- An opt-in, process-local inspector now shows forwarded HTTP requests and
  replays complete small HTTP captures after explicit reconstruction of unavailable
  fields. Metadata is redacted by default; body capture requires `--inspect-body`.
  It has no durable history or ingress-side
  record of requests rejected before they reach the publisher.
- MCP authentication through tunn bearer tokens and OAuth discovery, dynamic
  registration, PKCE and consent; see [the connector contract](../MCP-CONNECTOR.md).
  Hosted-client acceptance and per-principal stdio process isolation remain open.

## The plan

### 1. Make one local session inspectable

**Implementation status:** the first local `--inspect` slice is in place for
HTTP serve sessions, with bounded memory, loopback access, capture/replay for
both forwarding paths, and tests. Dogfooding with a real webhook provider and
an ordinary API is still needed before calling the workflow finished.

Add an opt-in loopback inspector to `tunn serve`. Show each forwarded request's
method, path, status, duration, and byte counts. Capture a bounded number of
request bodies in local memory only when explicitly enabled, show truncation,
and let the owner replay a complete captured request directly to the local
target. Replay is a new delivery and is labeled as such. Never store bodies or
credentials at the relay for this developer feature.

**Done when:** a real webhook can be received, viewed, and replayed after the
handler changes, with the same path, headers, and body; a large or incomplete
body cannot be replayed; the inspector is unreachable from outside the local
machine; stopping tunn clears the capture. Verify the streaming and legacy
HTTP paths. This is a development tool, not durable webhook delivery.

### 2. Establish an audit and usage contract

**Implementation status:** the metadata-only SQLite ledger and owner JSON export
are implemented for buffered and streaming HTTP. It records ingress denials,
caller identities, admission/final outcomes, and request/body-byte units.
Bounded retention, short-write reconciliation, restart recovery, and shared
login-node RPC accounting have in-process tests. The local real-process E2E
is runnable; real cluster routing/failure reconciliation is still needed before
calling these counts billable. Details: [usage contract](METERING.md).

Define one privacy-safe event at the ingress for *every decision*: endpoint,
caller identity or anonymous, authentication method, allow/deny reason, status,
timing, request ID, and metered units. Include rejections that never reach the
publisher. A body capture is a separate object with an explicit lifetime and
permission; it is never the audit log. Add endpoint-scoped counters and export
before adding a polished dashboard. Measure both buffered and streaming paths,
including disconnects, without double charging on relay retries.

**Done when:** the owner can answer who called an endpoint, why a call was
denied, how many requests and bytes each caller consumed, and which counts
would be billable. Existing account bandwidth quotas still work.

### 3. Grant metered access to a local endpoint

**Implementation status:** `tunn grant create|list|revoke` and
`tunn usage [--tunnel NAME] [--since DURATION]` now provide
the HTTP CLI slice. Separate credentials have expiry, revocation, a fixed UTC
minute request limit, monthly admitted-request/body-byte budgets, and remaining
usage headers. Tests cover two independent consumers and quota boundaries.
Optional monthly owner caps apply across tunnels and callers, and usage exports
include owner request/byte totals for checking entry-tier economics.
MCP HTTP and OAuth tokens share the ingress accounting; tool/application
permissions remain separate work. Loopback E2E verifies the CLI/relay/publisher lifecycle
when run in an environment that permits sockets.

Issue a separate revocable credential per consumer, bound to one endpoint.
Add expiry, request rate, monthly request/byte budget, and a visible usage
counter. Enforce limits at ingress before forwarding. Keep the ordinary local
service responsible for its own application permissions. Start with HTTP;
apply the same grant identity and accounting to MCP after the HTTP contract is
proven. Ship a CLI flow before a team control panel.

**Done when:** two consumers can use one local endpoint with independent
limits, both can see predictable `429`/authorization outcomes, and revoking one
does not interrupt the other. An endpoint owner can export usage for a billing
period. Usage export is not a payment system or a claim of billing accuracy
until reconciliation tests cover failures and multi-node routing.

### 4. Make agent access safe for teams

Validate the implemented MCP OAuth discovery/onboarding with hosted clients;
complete per-principal stdio isolation, tool/action policy and approval flows. Then add
team ownership, audit export, and approval hooks where actual usage demands
them. Prove the context-service workflow with an authorized non-production
deployment and at least two independent agent clients. Keep credentials and
upstream tokens out of relay logs.

**Done when:** a hosted agent can connect without copying a long-lived shared
token, every call maps to a principal, and the owner can revoke that principal
without taking down the service.

### 5. Test willingness to pay

Dogfood all three workflows first. the operator's entry paid-tier target is about
**$12/year**, with monthly bandwidth and request caps: a no-brainer purchase
intended to be strictly cheaper than a VPS and easier than a VPN. Use per-user
usage exports to choose sustainable allowances against Fly.io egress and fixed
costs. Then put a paid team pilot in front of
teams already trying to connect hosted agents to private capabilities or
operate webhooks. The chargeable thing is managed grants, reliable policy,
shared audit/retention, and support. Personal inspection and simple tunnels
should remain easy to try. Treat price and packaging as experiments, measured
with real payment commitments rather than a spreadsheet forecast.

## Product boundaries and ordering

- **Audit versus capture:** audit is small, structured, durable, and safe to
  export. Payload capture can hold secrets and customer data; it is explicit,
  local in the first slice, bounded, and short-lived.
- **Replay versus delivery:** replay is an owner action for debugging. Retrying
  failed webhooks automatically requires a durable queue, idempotency model,
  provider signature handling, and clear delivery guarantees. Build that only
  if users need tunn to be their webhook infrastructure.
- **Metering versus billing:** existing account bandwidth tracking protects
  tunn's own costs. Per-consumer counts and enforceable budgets come before
  charging third parties. Never label estimates as billable usage.
- **Tunn versus application policy:** ingress decides whether a named caller may
  reach an endpoint and how much. The application decides which records, tools,
  or operations that caller may use.
- **HTTP parity:** WebSocket upgrades now have a local TLS-stack regression
  suite. Repeated headers, trailers, and live HTTP/3
  verification remain necessary for a credible general tunnel. Fix any parity
  bug that blocks these workflows before expanding protocol surface area.

## Market reality informing the order

Ngrok already offers webhook inspection/replay and an MCP gateway. Hookdeck
offers managed webhook queuing, rate control, retries, and replay. Cloudflare
AI Gateway offers model-call analytics, logs, rate limits, and paid log capacity.
Tunn's first reason to exist is the combination of a very small local workflow
with caller-specific access to arbitrary private capabilities. None of these
features alone is a moat; daily use and team control would have to earn one.

Primary sources:

- [ngrok webhook inspection and replay](https://ngrok.com/docs/integrations/webhooks/circleci-webhooks)
- [ngrok MCP gateway](https://ngrok.com/docs/using-ngrok-with/using-mcp)
- [Hookdeck Event Gateway](https://hookdeck.com/)
- [Cloudflare AI Gateway overview](https://developers.cloudflare.com/ai-gateway/)
- [Cloudflare AI Gateway pricing and log limits](https://developers.cloudflare.com/ai-gateway/reference/pricing/)

## Next concrete build step

Run `make integration-test-metering` on a loopback-capable machine, then dogfood
inspection plus the new grants with a small webhook receiver and an ordinary
API. Reconcile routed-node failures and crash reservations before a paid usage
pilot. The local inspector remains separate from the central audit ledger.
