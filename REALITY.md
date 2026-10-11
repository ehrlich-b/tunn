# Market reality — fetched 2026-10-11

This is a dated research snapshot, not a revenue forecast. All URLs below were
read on **2026-10-11 UTC**. Prices are USD before tax unless noted. A missing
published numeric limit means **unknown**, not unlimited. Hosted services and
self-hosted software have different operating costs. Re-fetch before publishing.

## ngrok: current offer and public scale

| Plan | Price | Included resources / restrictions |
| --- | --- | --- |
| Free | $0 | 3 online endpoints; one assigned dev domain; 1 GB outbound/month; 20,000 HTTP requests/month; browser HTML interstitial; 1 member; $5 one-time usage credit |
| Hobbyist | $10/month, or $8/month billed annually ($96/year) | 3 endpoints; $10 monthly credit; 5 GB and 100,000 HTTP requests included; no interstitial; up to 10 ngrok-branded domains; 1 member |
| Pay-as-you-go | $20/month base with $20 usage credit | 5 GB then $0.10/GB; 100,000 HTTP requests then $1/100,000; extra active endpoints $0.02/hour; own domain $0.01/active hour; 3 members then $5/member |
| Enterprise | Quote | Contracts, compliance and support arrangements; no verified universal list price |

Source: [ngrok pricing](https://ngrok.com/pricing), including the annual billing
toggle and full breakdown. Free HTTP rate limit is 4,000/minute; TCP connections
100/minute, 5,000/month. Paid HTTP is 20,000/minute. These are separate from
monthly quotas. [Usage metrics](https://ngrok.com/docs/pricing-limits/how-ngrok-charges/).

**Correct two common comparison mistakes:** free tunnels have no session timeout,
and free users already get a stable assigned domain. The interstitial applies to
HTML browser traffic; automated API clients are not universally blocked, and a
skip header/nonstandard User-Agent can bypass it.
[Free plan documentation](https://ngrok.com/docs/pricing-limits/free-plan-limits/).

ngrok's December 2022 company release reports $50 million Series A funding,
more than 5 million developers, over 30,000 paying customers, and revenue doubling
year over year. These are **historical company claims**, not 2026 counts.
[Company release](https://www.globenewswire.com/news-release/2022/12/13/2572855/0/en/ngrok-raises-50m-in-first-fundraise-to-meet-demand-for-frictionless-application-ingress.html).
No current audited revenue or ARR was found in the primary sources checked.
Do not use funding, customer counts, or private-company estimator sites as
revenue. “1% of ngrok revenue” cannot currently be quantified defensibly.

## Alternatives

| Tool | Published price | Limits / purchase implications | Primary source |
| --- | --- | --- | --- |
| Cloudflare Tunnel | Tunnel available without a tunnel subscription; Quick Tunnels free/accountless | Named public hostnames require account/DNS setup; Quick Tunnels use random names, max 200 in-flight requests, no SSE, development only. New optional email PIN protection requires interactive browsers. Access pricing is a separate product. | [Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/), [Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/), [2026 announcement](https://blog.cloudflare.com/protected-quick-tunnels/) |
| Tailscale Funnel | Included on all plans; Personal $0 for up to 6 users/non-commercial use; Standard $8/user/month; Premium $18/user/month | Tailnet DNS names only; ports 443/8443/10000; TLS only; non-configurable bandwidth limits, numeric throughput not published in page; beta | [Funnel](https://tailscale.com/kb/1223/funnel), [pricing](https://tailscale.com/pricing) |
| Pinggy | Free; Pro $3/seat/month or $2.50/seat/month annually ($30/year) | Free 60-minute timeout, random URL; advertised unlimited transfer. Pro gives 1 persistent tunnel, custom domain/subdomain and persistent port per seat. Homepage JS contains the USD prices; /pricing/ returned 404. | [Homepage pricing](https://pinggy.io/#prices), [help](https://pinggy.io/help/) |
| localhost.run | Free; stable custom domain $9/month billed annually ($108/year) | SSH without client installation; free names change and speed is limited (no numeric rate published); paid priority bandwidth | [home](https://localhost.run/), [free](https://localhost.run/docs/forever-free/), [custom domains](https://localhost.run/docs/custom-domains/) |
| zrok | Hosted Free $0; commercial quote | 5 GB/day, 25 environments, 50 share backends, 50 private access frontends; card removes interstitials; self-hosting also available | [pricing](https://zrok.io/pricing/) |
| LocalXpose | Starter $0; Pro $8/month billed annually ($96/year); enterprise quote | Free 2 HTTP/HTTPS tunnels; time limits and interstitial listed without numeric duration. Pro 10 tunnels, custom/wildcard domains, TCP/TLS/UDP, advertised unlimited bandwidth subject to acceptable use | [pricing](https://localxpose.io/pricing) |
| localtunnel | Open-source client and public service; no paid offer in README | npm installation; requested subdomain not guaranteed; no numeric hosted quota/SLA published in README; self-hosting possible | [project README](https://github.com/localtunnel/localtunnel) |
| bore | Open-source software; no subscription in README | TCP forwarding; public bore.pub or own server; not a managed HTTPS/domain/OAuth product; no numeric public-service quota/SLA published | [project README](https://github.com/ekzhang/bore) |
| frp | Open-source software; operator pays for server | Self-managed client/server reverse proxy; HTTP/HTTPS/TCP/UDP support; configuration, TLS, availability and hosting are operator work; no hosted plan in README | [project README](https://github.com/fatedier/frp) |
| Expose | Hobby free; Pro $79/user/year; Team $229/year up to 10 users, net of tax | Free random domains and EU servers; Pro custom/reserved domains and global servers. PHP needed; no numeric bandwidth/request quota shown | [homepage pricing/FAQ](https://expose.dev/) |

Cheap paid and generous free alternatives already exist. A $6 Pro is cheaper
than ngrok Hobbyist, **not the cheapest tunnel**. Do not compete by promising
unlimited transfer or implying every competitor requires registration.

## Public pain: quotes are reports, not verified product behavior

| Evidence | Quote | What it supports |
| --- | --- | --- |
| [SilverBullet, 2024-09-24](https://community.silverbullet.md/t/ngrok-http-requests-what-did-i-do-wrong/1038) | “blown through the limit of 20000 http requests in a couple of days” | Monthly request ceilings can interrupt ordinary development. Clearly show account usage and reset behavior. |
| [Atlassian Forge, April–May 2024](https://community.developer.atlassian.com/t/tunnel-service-returns-error/79434) | “my tunnel stopped working” | Users initially mistake quotas for application failures. Thread includes vendor acknowledgement and a planned replacement tunnel. |
| [r/webdev, September 2025](https://www.reddit.com/r/webdev/comments/1npacbj/did_ngrok_remove_traffic_policies_from_their_free/) | “I've not found any announcement for this.” | Perceived free-tier changes undermine trust. ngrok founder explicitly says traffic policy/url-rewrite was **not removed**; don't repeat the allegation as fact. |
| [r/selfhosted, December 2024](https://www.reddit.com/r/selfhosted/comments/1hij6k3/need_help_alternative_for_ngrok/) | “about 440 USD with pas-as-you-go plan” | High-frequency webhooks and bandwidth create price anxiety. Invoice/performance claims are unverified user reports. The author discovered alternatives through awesome-tunneling. |
| [r/mcp, December 2025](https://www.reddit.com/r/mcp/comments/1q1tt1w/i_made_a_project_to_expose_local_mcp_servers_to/) | “its redirection page is a real headache” | Connector onboarding and interstitial perception hurt the dev loop; author and commenters want local tools reachable by cloud clients. This is another vendor's launch, not an independent demand survey. |
| [r/n8n, September 2026](https://www.reddit.com/r/n8n/comments/1w8bfos/need_help_with_n8n_mcp_setup_tried_everything_pls/) | “all of which led to failure” | Path/transport/auth/IP restrictions make MCP setup hard. Comments claiming all non-browser requests get ngrok HTML conflict with ngrok docs. Teach diagnosis, not that false claim. |

These threads are qualitative evidence, not conversion estimates. Old quoted
rate limits must not replace the current ngrok table above. “Rate limit” in the
Forge thread includes monthly quota errors, not just requests per minute.

## Demand and discovery

Claude's cloud connects to internet-reachable remote MCP servers, even when its
UI runs on the desktop. Local stdio configuration is a separate mechanism.
Custom connectors are now documented across Free/Pro/Max/Team/Enterprise; Free
has one connector. [Claude connector guide](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).
OpenAI's current example explicitly recommends a localhost tunnel and an HTTPS
/mcp URL for a custom ChatGPT plugin.
[Official OpenAI quickstart](https://developers.openai.com/plugins/build/app-quickstart).
That is a direct acquisition surface for a tunn tutorial. New
[Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/tools-connectors-mcp)
also competes with public tunneling for API users; public access is not the only
way to reach local tools.

Webhook demand appears directly in the r/selfhosted case and vendor development
threads. Agent callbacks share the technical need for a reachable HTTPS URL;
their willingness to pay is a **hypothesis**, not established by this sample.
Priority users: developers who repeatedly reconnect a local MCP tool or keep a
webhook/callback endpoint online, then hit a quota or need a reserved name.

Discovery surfaces observed: Google/search and product comparison pages;
GitHub READMEs and [awesome-tunneling](https://github.com/anderspitman/awesome-tunneling);
MCP directories; r/mcp/r/ClaudeAI/r/selfhosted; application communities such as
Atlassian, n8n and SilverBullet; tool-vendor tutorials. Distribution should put a
working example at these intent points, with founder disclosure. For Reddit,
use an explicitly permitted weekly promotion thread, e.g.
[r/devops weekly self-promotion](https://www.reddit.com/r/devops/comments/1u68lsg/weekly_self_promotion_thread/),
and recheck the current thread/rules before the coordinator posts.

Suggested experiment, not a forecast: first 100 activated accounts → 10 verified
Pro subscriptions → $60 MRR at $6. Measure activation (first successful ingress),
pricing visits, checkout redirects, webhook-confirmed Pro, and quota denials.
Do not count a checkout return as revenue or log tool payloads for analytics.
