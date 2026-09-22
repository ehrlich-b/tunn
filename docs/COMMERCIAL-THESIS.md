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

1. Standards-compatible MCP authorization, including protected resource
   metadata, OAuth discovery, audience-bound tokens, PKCE, Client ID Metadata
   Documents, and issuer checks. Copying an endpoint token into every client
   is a prototype workflow.
2. Per-principal child isolation, short-lived grants, tool-level policy,
   immediate revocation, and metadata-only audit records. Shared stdio state
   cannot safely serve independent team members.
3. Reliability and HTTP parity: reconnect correctness, observability,
   WebSockets, repeated headers such as `Set-Cookie`, trailers, and a live
   HTTP/3 reachability check. A broken ordinary tunnel destroys trust in the
   agent gateway too.
4. A two-minute setup path and a clear client-specific connection recipe for
   at least two independent agent ecosystems.

## Pricing experiment

Keep individual development use free. Offer a paid team pilot for centrally
managed grants, policy, and audit at **$100–$500 per team per month**, quoted
as a willingness-to-pay experiment rather than a published price. Ask for a
payment commitment before building a large admin console. Charge for the
operational value of controlling agent access; meter bandwidth only to protect
costs and abuse.

## Falsifiers

Interview ten teams with a current private-agent-access problem. Put the
prototype in front of them. Continue only if at least five reach a useful tool
in under two minutes, at least three use it again weekly for a month, and at
least three agree to a paid team pilot. These are decision gates, not forecasts.

The billion-dollar ambition would require a broadly adopted team platform.
For scale: 10,000 teams paying $1,000/month would be $120 million in annual
recurring revenue. The current repo demonstrates neither 10,000 buyers nor a
reason they would pay that much. If teams happily use ngrok, their existing
network stack, or a model vendor's built-in tunnel, stop treating tunnel
features as differentiation and either find a sharper security workflow or
retire the commercial thesis.
