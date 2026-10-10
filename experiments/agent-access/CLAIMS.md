# Compact source-to-claim checklist

| Displayed claim / decision | Inspected evidence | Permitted wording / remaining evidence |
| --- | --- | --- |
| One local MCP tool into Claude.ai; one app shared by email | Completed thesis §3–4, ventures e2df01b, SHA-256 in protocol.json | Proposed recipes; zero real-client tests here |
| Recurring-pain and setup-speed thresholds | Thesis §6 E1/E2; frozen protocol.json, pinned digest in evaluate.py | Exact thresholds, no post-observation adjustments; actual trials unrun |
| Native `tunn mcp --name … --tools … -- ./…` syntax | main.go:147–235 (flags), 298–375 (private setup and bridge); internal/mcpbridge/bridge.go:282, 403–438 (tool rejection/filtering) at 53cdce9 | Source-inspected syntax only; service binary is fictional; no compatibility claim |
| `tunn 8080 --allow=reviewer@mosslight.invalid` syntax | main.go:855–916 (serve flags and allow list) at 53cdce9 | Source-inspected syntax only; no real email or service |
| Scoped tool authority has limits | internal/mcpbridge/bridge.go:403–414 checks exact tool name; thesis §3 distinguishes tool arguments and app permissions | No claim that authentication prevents prompt injection or constrains all arguments |
| HTTPS relay can read application traffic; sleeping origin unavailable | README.md How It Works; internal/host/proxy.go TLS listener setup; thesis §3 trust boundary | Trust caveat, no end-to-end confidentiality claim |
| Denied/revoked/offline demonstrations | site/walkthrough.js and fixture-test.mjs | Explicit synthetic states only; no E4/security, latency, restart or quota claim |
| “Can you complete this in 60 seconds?” | Experiment question; timed worksheet | Unmeasured question, never a verified promise |
| $12/year home launch for about 50 paying signups, grandfather early users | Task brief's drafting constraint; protocol.json offers | Proposed/unavailable; no entitlement changes or actual purchase |
| $6/maintainer/month; three maintainers $18/month | Thesis §4 proposal; evaluate.py offer_arithmetic | Hypothetical arithmetic; no external guest seat billing; no demand proof |
| Team caps and shared administration | Thesis §4, proposed 10 GB / 100,000 requests / 10 streams / 10 endpoints | Unavailable proposal, no SSO, audit-export, enterprise-control or SLA promise |
| Original denominators, missing values, intent/payment distinction | evaluate.py, render_results.py, tests/test_evaluate.py and test_results.py | Descriptive evidence; actual flag/receipt strings need human verification |
| Current competitor pricing, licensing, missing product features | No staged primary receipts for these claims | Omitted from pages; reproduction checklist names substitutes as test candidates only |
| SSH publisher / OAuth implementation / portability | Existing owners; thesis calls for acceptance evidence | No implementation changes or marketing promise in this kit |

The completed thesis is a local proposal, not primary competitor evidence. Its older source snapshots and training recollections are not promoted into current product claims. This task changes only `experiments/agent-access/` and ignored `.scratch/`; live auth, landing, payment and entitlement code remain outside its edit scope.
