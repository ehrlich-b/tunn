# Commercial thesis: private capabilities for cloud agents

Date: 2026-10-10

## Buyer and job

Start with teams running hosted agents against private services they cannot
deploy to the public internet: internal MCP tools, local development processes,
test environments, databases, and on-prem APIs. The first valuable workflow is
an engineer granting one remote agent temporary access to one named capability,
then seeing exactly which actions it took and revoking the grant immediately.

The CLI is the entry point. The paid product would manage grants, identities,
approvals, audit export, uptime, and policy across a team. A tunnel URL alone
has weak pricing power.

## Competitive reality

- [OpenAI Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
  already reaches private stdio and HTTP MCP servers from supported OpenAI
  products. It removes the need for tunn when a team only uses those surfaces.
- [ngrok's MCP gateway](https://ngrok.com/docs/using-ngrok-with/using-mcp)
  already combines private agent endpoints, cloud endpoints, authentication,
  rate limiting, and traffic policy. Its [pricing](https://ngrok.com/pricing)
  offers a free tier and usage-based upgrades. Generic tunnel parity is table
  stakes.
- [Cloudflare MCP portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/#known-limitations)
  provide governed remote MCP access, but currently require an HTTP server;
  stdio-only servers must first be hosted behind an HTTP endpoint.
- MCP [2026-07-28](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/blog/content/posts/2026-07-28-spec-ga/index.md)
  makes requests stateless and carries method and tool names in HTTP headers.
  That makes basic MCP routing and tool policy easier for existing gateways to
  add. The protocol itself is unlikely to create a durable moat.

The opening is a vendor-neutral bridge from process-local and private
capabilities to several agent vendors, with a security workflow that a team
can operate. This is a hypothesis, not evidence of demand.

## What to build before charging

The [product roadmap](PRODUCT-ROADMAP.md) puts a daily-use local webhook
inspector, privacy-safe audit contract, and per-caller endpoint metering ahead
of the team control plane. Webhook replay is a debugging feature in that first
slice; reliable webhook delivery would require its own queue and retry design.

1. Make the local HTTP and webhook workflow useful: inspection, bounded replay,
   HTTP parity, and a privacy-safe ingress audit contract. Add per-caller
   request and byte counters before calling usage billable.
2. Give each consumer an expiring, revocable endpoint grant with an enforceable
   budget. Verify usage reconciliation across disconnects and multiple nodes.
3. Add standards-compatible MCP authorization, including protected resource
   metadata, OAuth discovery, audience-bound tokens, PKCE, Client ID Metadata
   Documents, and issuer checks. Copying an endpoint token into every client
   is a prototype workflow.
4. Add per-principal child isolation, tool-level policy, and a two-minute
   setup path for at least two independent agent ecosystems. Shared stdio
   state cannot safely serve independent team members.

## Pricing experiment

Keep a free path for individual development. the operator's entry paid-tier target is
**about $12/year**, with monthly bandwidth and request caps: a no-brainer purchase
intended to be strictly cheaper than a VPS and easier than a VPN. Choose the
included units from measured per-user usage and Fly.io egress economics before
publishing an allowance. An annual price does not make the monthly cap annual.

Centrally managed team grants, policy, retention, audit, and support could be a
separate higher tier. The earlier $100–$500/team/month pilot idea is a secondary
willingness-to-pay hypothesis, not the entry price. Ask for payment commitments
before building a large admin console. Account bandwidth limits and shared
owner request/body-byte caps protect tunn's costs and abuse exposure.

## Usage-based tier experiment

The [HTTP metering/grant prototype](METERING.md) supplies per-consumer admitted
requests and body bytes, plus `owner_usage` totals across tunnels and callers.
Use `tunn usage` for durable monthly per-user totals and `--tunnel` / `--since`
for diagnosis. Duration reports explicitly flag missing retained events; use
monthly rollups when calculating entry-tier costs. Optional login-node settings
`TUNN_OWNER_MONTHLY_REQUESTS` and `TUNN_OWNER_MONTHLY_BYTES` atomically enforce
shared HTTP ceilings, in addition to individual grant budgets. This policy is
per owner email; merging account aliases and provisioning tier-specific caps
remain work for a paid launch.

At about $12/year the monthly gross budget is about $1/user. Compare both body
directions against applicable Fly.io invoice rates: request bodies are relay
egress toward publishers, and response bodies are relay egress toward callers.
Then account for framing, node hops, fixed hosting/storage, payment fees, and
support before choosing included GB and admitted requests. The request cap also
limits work from many small calls. Provider invoices must validate the estimate;
body counts alone do not prove a margin. No allowance, invoice, or Stripe change
is part of this prototype.

Keep denied decisions out of proposed request charges. Decide how failed
admissions, short writes, and conservative crash reservations reconcile before
calling counters billable. Test real multi-node routing and authority failures
before charging for these units. The about-$12/year entry tier is the operator's pricing
input, with a higher team tier still an experiment; usage meters support the
commercial bet but do not prove demand or a sustainable cap.

## Falsifiers

Use the webhook, ordinary HTTP, and private context/tool workflows ourselves
first. Then interview ten teams with a current private-agent-access or metered
endpoint problem. Put the prototype in front of them. A paid team product is
plausible only if repeated use and payment commitments emerge; the proposed
five successful setups, three weekly users, and three paid pilot commitments
are decision signals, not a prerequisite to building something we want to use
or a forecast.

The billion-dollar ambition would require a broadly adopted team platform.
For scale: 10,000 teams paying $1,000/month would be $120 million in annual
recurring revenue. The current repo demonstrates neither 10,000 buyers nor a
reason they would pay that much. If teams happily use ngrok, their existing
network stack, or a model vendor's built-in tunnel, stop treating tunnel
features as differentiation and either find a sharper security workflow or
retire the commercial thesis.
