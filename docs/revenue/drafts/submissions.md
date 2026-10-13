# DRAFT submissions — coordinator/Bryan actions only

Sources fetched 2026-10-11. Every entry below is unsubmitted. Publish approved
code/docs first, verify the actual connector flow, check maintainers' current
rules and use Bryan's existing identity/contact email only with approval.

## punkpeye/awesome-mcp-servers — Frameworks

Destination: https://github.com/punkpeye/awesome-mcp-servers (README Frameworks,
not a fabricated standalone tool server). Check contributor rules and license
eligibility first. Suggested PR title: `Add tunn MCP transport bridge`.

Exact proposed entry:

```markdown
- [ehrlich-b/tunn](https://github.com/ehrlich-b/tunn) 🏎️ 🏠 🍎 🐧 - Bridge a local stdio or HTTP MCP server to a private HTTPS endpoint, with OAuth consent, revocation and account-wide metering. Hosted relay at tunn.to; self-hosting supported.
```

Exact PR body:

> DRAFT: I'm the maintainer of tunn. This adds it as transport/developer
> infrastructure in Frameworks. It bridges user-supplied MCP tools rather than
> shipping a shared public tool catalog. Tutorial:
> https://tunn.to/docs/mcp-to-claude. Local protocol tests cover OAuth, consent,
> revocation and stdio bridging. Hosted client verification will be recorded
> before this PR is submitted. Free usage is finite; Pro is a subscription.
> Please omit the entry if transport infrastructure is outside this category.

Remove the DRAFT label only on Bryan approval, and replace the verification
sentence with the actual acceptance date/clients. Don't assert a license until
Bryan approves the missing full license text.

## MCP.so — developer tool / client infrastructure

Destination: https://mcp.so/ (Submit/feedback entry in the current UI).
Name: `tunn — local MCP to private HTTPS`.
Category: Developer Tool / Infrastructure; ask the reviewer if unavailable.
Repository: `https://github.com/ehrlich-b/tunn`.
Documentation: `https://tunn.to/docs/mcp-to-claude`.
Short description:

> tunn publishes a local stdio or Streamable HTTP MCP server at an HTTPS /mcp
> URL. Private by default with OAuth consent and client revocation. Includes
> account-wide request and transfer budgets. It is a bridge for your own tools,
> not a shared public tool server. macOS/Linux CLI, Free and Pro hosted plans,
> or self-host the relay.

Contact: coordinator fills an approved email; none is invented here. Do not
submit a user's private URL as the common server endpoint.

## mcpservers.org — free review

Destination: https://mcpservers.org/submit.
Name: `tunn MCP bridge`.
Category: Developer Tools/Infrastructure, if available; otherwise request a
guide/client placement before submission. Short Description:

> Publish local MCP tools as a private HTTPS endpoint with OAuth consent and
> revocation. stdio bridge or existing HTTP server; account-wide metering.

Repository, Website or Documentation:
`https://github.com/ehrlich-b/tunn`.
Official MCP Registry Name: **leave blank**, no registration exists.
Remote connections: yes, as a user-published endpoint.
Contact Email: coordinator's approved existing support address.
Submission plan: **Free**, not Premium. Reviewer note:

> This is transport infrastructure and a user-supplied tool bridge. There is
> no product-wide MCP endpoint; please categorize as a guide/client tool if
> that fits your directory better than a server listing.

## Smithery — guide/tool placement proposal, not server publish

Destination: current support/community route from
https://smithery.ai/docs/build/publish. Account/contact action requires approval.
Exact proposed message:

> I'm tunn's maintainer. Could this local-to-remote MCP tutorial fit your
> developer-tools or guides resources? https://tunn.to/docs/mcp-to-claude
> tunn supplies HTTPS ingress and OAuth consent for user-supplied stdio or
> HTTP MCP servers. We are not submitting a generic private tunnel URL as a
> public Smithery server. If you only accept deployed tool servers/MCPB,
> please skip this proposal.

No `smithery mcp publish` command is staged: its documented prerequisites are
not present. Do not create a permanent public server just to obtain a listing.

## awesome-tunneling — defer until eligibility evidence exists

Destination: https://github.com/anderspitman/awesome-tunneling.
Policy: 100 GitHub stars for new additions; commercial services need evidence
of happy customers and are reviewed case by case. Current tunn metadata showed
1 star on 2026-10-11, so **do not submit yet**. No testimonials fabricated.

Proposed entry, after Bryan supplies eligible evidence:

```markdown
* [tunn](https://tunn.to) - Go HTTPS tunnel for local apps, webhooks and MCP servers; email allow-lists, private MCP OAuth and account-wide metering. Hosted Free/Pro service and self-hosting support. [Code](https://github.com/ehrlich-b/tunn).
```

Proposed issue/PR text:

> I'm the maintainer of tunn and have read the current eligibility policy.
> Proposed entry above; docs: https://tunn.to/docs, pricing:
> https://tunn.to/pricing. I will attach legitimate qualifying evidence before
> submission. Free is 5 concurrent tunnels, 1m admissions and 10 GB per UTC
> month; Pro is a finite subscription allowance. No enterprise SLA is claimed.

## Official MCP Registry — no submission in this release

tunn is not itself a reusable tool catalog with a stable registry endpoint.
Do not fabricate an `io.github.ehrlich-b/tunn` registry entry or claim it is
registered. The echo demo is an acceptance fixture, not a new hosted service.
