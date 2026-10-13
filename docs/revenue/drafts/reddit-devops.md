# DRAFT — r/devops weekly self-promotion comment

Bryan approval required. Do not submit as a standalone post. Find the current
weekly self-promotion thread and confirm its invitation still applies. An
[observed example](https://www.reddit.com/r/devops/comments/1u68lsg/weekly_self_promotion_thread/)
was fetched 2026-10-11; that old thread is evidence of the format, not the
destination for a new launch. Deploy/release/payment/client gates precede use.

Comment draft:

Disclosure: I'm the developer of tunn (https://github.com/ehrlich-b/tunn).
It's an HTTPS tunnel for local MCP tools, webhook tests and app previews.

For a public webhook handler: `tunn login`, then `tunn http 8080 --inspect`.
Keep the sender's signature verification in your app. The inspector runs
locally and doesn't capture bodies by default.

For a stdio MCP server: `tunn mcp -- ./my-mcp-server` prints a private /mcp
connector URL. tunn handles OAuth consent and revocation; your tools stay local.
Tutorial with a harmless echo example: https://tunn.to/docs/mcp-to-claude

Free is 5 concurrent tunnels, 1m monthly admissions and 10 GB across your
account. Pro is $5/month or $48/year for larger finite limits and 10 reserved
names. Launch billing activation is reviewed by an operator; quota exhaustion
doesn't create overage charges. Details: https://tunn.to/pricing

This is a connector preview, not an enterprise gateway or an uptime SLA.
I'd welcome feedback on OAuth setup or repeat callback workflows.
