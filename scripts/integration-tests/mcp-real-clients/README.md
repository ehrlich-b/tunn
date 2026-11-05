# Official MCP client checks

This harness starts a disposable TLS relay, signs a fixture account in through
mock OIDC and explicit device consent, then runs the real `tunn mcp` command with
the bundled harmless stdio echo server. It drives the official TypeScript SDK
1.29.0 and Python `mcp` 2.3.0 OAuth providers and Streamable HTTP clients. Their
OAuth implementations perform discovery, dynamic registration, S256 PKCE and
rotating refresh; their MCP sessions initialize, list tools and call echo before
and after refresh. Product dependencies and manifests are unchanged.

Use Node, Python 3.10+, Go, OpenSSL and an existing Playwright module/browser.
Fetch the test packages into a disposable directory outside the checkout:

```sh
export TUNN_MCP_CLIENTS_SCRATCH=/absolute/disposable/client-packages
export TUNN_MCP_CLIENTS_EVIDENCE=/absolute/disposable/client-results
nice -n 10 python3 scripts/integration-tests/mcp-real-clients/fetch.py
export TUNN_PLAYWRIGHT_MODULE=/absolute/existing/node_modules/playwright
export PLAYWRIGHT_BROWSERS_PATH=/work/cache/ms-playwright
nice -n 10 make test-mcp-clients
```

The module must match the existing cached browser. The test never downloads a
browser. `fetch.py` resolves test packages in scratch only; running the test does
not fetch packages. Defaults for scratch and evidence are sibling directories of
the checkout. Both paths must be outside the checkout. Keep the scratch private:
relay logs, SQLite and SDK process pipes contain disposable credentials.

Chromium renders and approves the actual consent form at 390 px. It verifies no
horizontal overflow, visible Allow, and the returned state and issuer. Callbacks
are intercepted before any outbound request; Claude and ChatGPT are never
contacted. SDK DNS is pinned to loopback. The publisher uses the existing dev
loopback hostname. Certificate trust, DNS, mock login and callback delivery are
the only transport/identity substitutions.

Expiry is deterministic: the driver updates only the fixture grant's expiry and
requires an HTTP 401 with the old access token. The TypeScript transport reacts
to that rejection and refreshes. Python's OAuth provider also has its cached
expiry advanced, then performs its normal refresh on the next MCP request.
Neither SDK's registration, PKCE, token exchange or refresh code is replaced.
Both must rotate access and refresh tokens, then successfully call echo again.

A separate scripted replay uses Claude's two callbacks and ChatGPT's documented
stable callback. Each registers, approves consent, exchanges its code, expires
access, refreshes, and verifies the renewed token reaches the publisher. Wrong
resource, wrong PKCE verifier and reused code must return 400 `invalid_grant`.
Deleting the fixture registration must return 401 `invalid_client` on both code
and refresh grants. The Go callback and deleted-client regression tests remain
in `internal/host/mcp_oauth_access_lifecycle_test.go` and `mcp_oauth_test.go`.

`clients.json` and five consent screenshots are written to the evidence directory
only after assertions execute. Hosted Claude web, Claude phone and ChatGPT stay
unverified: follow [the manual checklist](../../../docs/guides/mcp-hosted-check.md)
for those checks. Local SDK success does not establish hosted UI compatibility.
