# Local agent-access experiments

This is a draft evidence kit, not an available service or launch approval. It implements only synthetic demonstrations and offline observation analysis. It changes no landing page, authentication, SSH, OAuth, entitlement or billing implementation.

The completed thesis at `.scratch/inputs/ZERO-TRUST-THESIS.md` (ventures `e2df01b`, SHA-256 `83c4869a1dc043537703e4be120944943108c59c0a00bbb9732fc70a04eaeca0`) replaces the OpenClaw-first pitch with identity sharing. The cheapest first falsifiers are **E1, reachable recurring pain**, and **E2, advantage over the closest substitute**. Payment and team expansion remain later E6 questions. A team concept page is a comparison stimulus, not a completed team product or an E6 test.

Read [PROTOCOL.md](PROTOCOL.md) before collecting anything. `protocol.json` freezes the decisions before observations exist. Real participants, current substitute receipts, real connector acceptance, adequate security review and approval of exact outbound text/destinations remain required. No recruitment or publication is authorized here.

Use clone-local temporary storage. No dependency installation is needed. The Python tools use only the standard library; the pages use local HTML, CSS and JavaScript. Run commands from the repository root with `TMPDIR=$PWD/.scratch/tmp`, `GOTMPDIR=$PWD/.scratch/tmp`, `PYTHONDONTWRITEBYTECODE=1`, `npm_config_cache=$PWD/.scratch/npm` and `npm_config_offline=true`. On macOS prefix heavy commands with `taskpolicy -b nice -n 15`; keep one heavy process at a time.

The displayed personal price is a proposed **$12/year launch offer for about 50 paying signups, with early users grandfathered**. The proposed team comparison is $6 per maintaining human per month. Neither is an available purchase. Price arithmetic is descriptive and never updates existing entitlements.

The exact local gates are:

```sh
python3 -B -m unittest discover -s experiments/agent-access/tests -v
python3 experiments/agent-access/build.py --out .scratch/agent-access-preview
python3 experiments/agent-access/evaluate.py --input experiments/agent-access/fixtures/synthetic.json --out .scratch/agent-access-results.json
node experiments/agent-access/tests/site-smoke.mjs
git diff --check
```

Also run `node experiments/agent-access/tests/fixture-test.mjs` for pure synthetic state checks. Browser testing uses an existing Chromium/headless-shell executable through CDP pipes and a clone-local disposable profile, without npm packages or a web server. It tries cached headless-shell binaries before installed Chrome; `CHROMIUM_PATH` can identify an already available binary. It allows only preview-local file requests and fails anything else. Exit 2 means REQUIRED-UNRUN because the browser is absent or cannot start; exit 1 means an executed check failed. Do not install a browser, change its runtime or weaken sandbox/network guards to make it pass.

Open `.scratch/agent-access-preview/index.html`, `team.html` and `results.html` locally after building. The default report is clearly synthetic: 16 observation rows, zero actual participants. To render later approved, privately collected observations, use `build.py --input .scratch/private-observations.json --out .scratch/private-preview` and the same input with `evaluate.py`. Keep actual observations and generated private reports out of Git and publication.

Review [APPROVAL-PACKET.md](APPROVAL-PACKET.md), [DRAFT-COPY.md](DRAFT-COPY.md), [CLAIMS.md](CLAIMS.md), [WORKSHEET.md](WORKSHEET.md) and [OBSERVATIONS.md](OBSERVATIONS.md). [VALIDATION.md](VALIDATION.md) records the local gate outcomes and explicitly unrun acceptance. The source baseline remains the local `refs/wave4/base` pin; no network or push is used.
