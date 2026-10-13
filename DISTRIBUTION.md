# Distribution plan and staged assets

**Nothing has been published, submitted, mailed or posted.** All founder posts
and submissions are DRAFTS for Bryan's approval. This checkout contains the
assets; public URLs require deployment/source publication and acceptance first.
External pages below were fetched 2026-10-11; recheck before taking action.

## Ship surfaces before attracting traffic

| Asset | Repo source | Destination / action |
| --- | --- | --- |
| Honest ngrok comparison | `internal/host/templates/ngrok-alternative.html` | `/ngrok-alternative`, with primary-source URLs and fetch date, unit caveats, ngrok strengths and cheaper substitutes |
| MCP-to-Claude tutorial | `docs/guides/mcp-to-claude.md`, embedded `templates/mcp-to-claude.html` | `/docs/mcp-to-claude`; stdio and HTTP paths, private OAuth, echo example, real-client acceptance caveat |
| README hero | `README.md` | Public GitHub README after approved push; intent-first examples, login, limits, prices labeled proposed until approved |
| Safe runnable tool | `examples/mcp/echo.py` | Use locally for connector acceptance and screenshots; no filesystem/network tools |
| Homebrew formula | `packaging/homebrew/tunn.rb` | Pinned reviewed product commit; install through a local tap after commit publication; native brew test required |
| Install one-liners | `docs/revenue/install-one-liners.md` | Existing installer and source-build routes; separate website/CLI release gates; no imaginary tap |
| Directory/awesome submissions | `docs/revenue/drafts/submissions.md` | Exact text/forms/eligibility; coordinator submits only after Bryan approves |
| Founder posts | `docs/revenue/drafts/show-hn.md`, `reddit-devops.md`, `x.md` | Copy after price, deployment, payment and hosted MCP acceptance; never post an unreleased promise |

## Intent and channel order

1. Publish the approved working tutorial and comparison alongside pricing. Link
   them from hero, README and CLI output. Use real headings/HTML content that
   crawlers can read; no dependence on a pricing JS toggle. Unknown URLs now 404.
2. First validate the echo flow with three developers Bryan already knows;
   invitations and contact are Bryan/coordinator actions, not agent outreach.
   Target repeated MCP reconnection/webhook use rather than generic homelabs.
3. Submit a truthful MCP bridge/developer-tool listing and framework list entry.
   tunn is a transport, not a generic SaaS tool server with a shared /mcp URL.
4. Founder demo with code, workflow and finite limits; one Show HN, a permitted
   Reddit weekly promotion **comment**, then X. Answer support where asked;
   don't paste a sales pitch into old user pain threads or mass-post copies.
5. After actual happy customers, consider awesome-tunneling. Its current
   [policy](https://github.com/anderspitman/awesome-tunneling) requires 100 GitHub
   stars or commercial-customer evidence/case-by-case review. Read-only
   [repository metadata](https://api.github.com/repos/ehrlich-b/tunn) returned
   **1 star** and no detected license today. A PR now is likely rejected; stage
   exact text, collect legitimate evidence, don't manufacture stars/testimonials.

[Show HN rules](https://news.ycombinator.com/showhn.html) favor something people
can try, not a landing page alone. Link a runnable tool/repo and disclose login.
For Reddit, [r/devops has an explicitly named weekly self-promotion thread](https://www.reddit.com/r/devops/comments/1u68lsg/weekly_self_promotion_thread/).
The rules page did not return readable rule text in this session; do not treat
that as permission for a standalone post. Coordinator locates the current
weekly thread, confirms it still invites promotion, then uses the staged comment.

## Feedback and revenue experiment

No revenue/conversion dashboard access was available. Run a two-week beta with
an approved activation queue owner before increasing traffic. Record aggregate
weekly funnel counts: tutorial/comparison visits, authenticated accounts, first
successful ingress, accounts nearing a quota, checkout redirects, pending
receipts, reviewed Pro activations, cancellations and support minutes. Billing
receipts plus actual paid subscription reads establish revenue; return-page hits
do not. Avoid adding payload/body collection to the production relay.

Hypothesis: reserved MCP/webhook names plus predictable included usage are worth
$5/month to repeat users. At 100 first-ingress activations, 10 paid accounts
would produce $50 MRR, not “1% of ngrok.” If payment friction is fixed and few
users pay, interview those users before adding more distribution or the $12/year
tier. Track free subsidy and ledger capacity as well as gross revenue.

## Honest restrictions on directories

[mcpservers.org's submission form](https://mcpservers.org/submit) supports free
review; do not purchase its $39 review fee. [MCP.so](https://mcp.so/) lists tools
and clients as well as servers; request developer-tool classification.
[Smithery publication](https://smithery.ai/docs/build/publish) expects an actual
reachable tool server or MCPB bundle. An arbitrary user's private tunn endpoint
does not qualify as a product-wide server; the staged request proposes a guide
or developer-tool placement and explicitly withholds a server submission.
No new public demo service, account or MCPB release was created in this task.
