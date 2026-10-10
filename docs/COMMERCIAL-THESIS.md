# Commercial thesis: private capabilities for cloud agents

Date: 2026-09-22

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

Keep individual development use free. Offer a paid team pilot for centrally
managed grants, policy, and audit at **$100–$500 per team per month**, quoted
as a willingness-to-pay experiment rather than a published price. Ask for a
payment commitment before building a large admin console. Charge for the
operational value of controlling agent access and accounting for each consumer.
Account bandwidth limits still protect tunn's own costs and abuse exposure.

## Usage-based tier experiment

The [HTTP metering/grant prototype](METERING.md) supplies per-consumer admitted
requests and body bytes as possible included units for usage-based tiers.
Personal development can stay easy to try; a managed team tier can sell durable
retention, central grants, support, and predictable consumer spend caps, with
additional request/byte allowances tested against actual customer needs.
No new prices, invoices, or Stripe writes are part of this prototype.

Keep denied decisions out of proposed request charges. Decide how failed
admissions, short writes, and conservative crash reservations reconcile before
calling counters billable. Test real multi-node routing and authority failures
before charging for these units. The existing $100–$500 team pilot is still a
payment-commitment experiment; usage meters support that commercial bet but do
not prove demand or a price point.

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
