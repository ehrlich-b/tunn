# DRAFT — Show HN, Bryan approval required

Publish only after deployment, public CLI release, billing sandbox/live gates
and recorded Claude.ai acceptance. This draft does not attest those happened.
Review [Show HN guidelines](https://news.ycombinator.com/showhn.html), fetched
2026-10-11. Link code and a runnable example; disclose account signup.

Title: **Show HN: tunn — private HTTPS for local MCP tools and webhooks**

URL: `https://github.com/ehrlich-b/tunn`

First comment draft:

I built tunn to make local services reachable without deploying them. The MCP
path bridges a stdio server or forwards an HTTP server, then gives you an HTTPS
/mcp URL with OAuth consent and revocation. The tools still run on your machine.

```bash
tunn login
tunn mcp -- ./my-mcp-server
# Or a public webhook endpoint:
tunn http 8080 --inspect
```

There's a small read-only echo example in the repo, plus a local request
inspector for webhook debugging. The hosted service requires GitHub or email
login. Free includes 3 concurrent tunnels, 100k admissions and 1 GB per UTC
month across the account. Pro is $6/month or $60/year with 10 tunnels, 1m
admissions, 50 GB and up to 4 reserved names. Quotas stop traffic; no automatic
overage charges. During this beta an operator reviews activation after payment.

Claude tutorial: https://tunn.to/docs/mcp-to-claude
Usage units and pricing: https://tunn.to/pricing

The MCP integration is a preview, and your local server must remain online.
I'd like feedback from people repeatedly connecting local tools to cloud
clients or receiving webhook callbacks: where does your dev loop break?
