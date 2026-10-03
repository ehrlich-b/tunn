# Hosted application acceptance for private MCP tools

The working synthetic Go/Python SDK workflow proves transport, useful cited
evidence transfer, attribution and independent revocation. It does not establish
that ChatGPT or Claude can connect through their own application UI. This
document defines the next bounded acceptance run and its approval boundary.

## Documented application contract

Use manually configured **pre-registered public OAuth clients**, authorization
code plus S256 PKCE, and token endpoint authentication `none`. Configure distinct
nonsecret client IDs and exact callback allowlists. No dynamic registration,
remote client metadata fetch, refresh tokens or paid model API is required for
the initial bounded run.

The discovery contract is:

- The unauthenticated `/mcp` request returns HTTP 401 and a Bearer
  `resource_metadata` challenge. The protected-resource JSON identifies the
  literal HTTPS MCP URL, including `/mcp`, one authorization server issuer and
  `mcp:access`. Claude ignores challenges on HTTP 200 and uses the first issuer.
- The HTTPS issuer's `/.well-known/oauth-authorization-server` advertises its
  exact issuer, authorization/token endpoints, code response,
  authorization-code grant, `none`, S256 and `mcp:access`.
- Authorization and token requests carry the exact resource. Tokens are bound
  to the endpoint. `mcp:access` grants route access; it does not enforce a
  per-tool read-only policy. The synthetic upstream itself exposes only reads.
- Issuer identification is enabled only with matching `iss` in both successful
  and error authorization responses. OpenAI then documents the stable callback
  `https://chatgpt.com/connector_platform_oauth_redirect`; otherwise it uses
  `https://chatgpt.com/connector/oauth/{callback_id}`. Always copy the actual
  callback shown by ChatGPT's connection management page.
- Hosted Claude's callback is exactly
  `https://claude.ai/api/mcp/auth_callback`. In its own-client configuration,
  enter the registered client ID and leave the secret blank. Claude sends token
  requests as `application/x-www-form-urlencoded` and limits discovery/token
  response waits to ten seconds.

Primary references: [OpenAI MCP authentication](https://developers.openai.com/plugins/build/auth),
[Claude authentication](https://claude.com/docs/connectors/building/authentication),
[MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

ChatGPT currently documents Plugins and developer-mode app connections, with
OAuth, no authentication or mixed authentication. Supplied OAuth client
credentials take precedence over CIMD/DCR. Developer mode supports arbitrary
tool names, so `build.search` and `build.read` do not need renaming. Its
predefined-client `none` protocol support is documented; the exact account UI's
acceptance of an empty client-secret field still needs observation.
[ChatGPT developer mode](https://developers.openai.com/api/docs/guides/developer-mode)

Claude custom connector setup varies: one screen uses Advanced settings, while
the newer dialog offers eager/deferred/no sign-in and published identity,
automatic registration or your own OAuth client. Select your own client for
this flow. Fixed bearer request headers are a limited beta; custom header names
require approval. Do not assume a `Tunn-Authorization` field exists or use an
access token as a client ID/secret. Authentication settings cannot be changed
in place after connector creation.
[Claude custom connector setup](https://claude.com/docs/connectors/custom/add-unlisted)

The common URL connection requires trusted HTTPS reachable from each provider's
cloud. OpenAI also offers its own private developer tunnel; Anthropic's private
tunnel is an Enterprise research preview by request. Neither establishes a
shared personal-account Tunn route.
[ChatGPT connection testing](https://developers.openai.com/plugins/deploy/connect-chatgpt),
[Claude MCP tunnels](https://claude.com/docs/connectors/mcp-tunnels/overview)

Refresh-token issuance is optional. The bounded token expires with its grant;
no `offline_access` scope or refresh support is advertised. Application behavior
after expiration needs observation rather than an assumed seamless renewal.
[RFC 6749 token response](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1)

## Read-only preflight

After building locally, inspect only an explicitly named HTTPS endpoint:

```sh
GOCACHE=/tmp/tunn-go-cache make build
./bin/tunn mcp check --issuer https://relay.example.test \
  --ca-cert /tmp/synthetic-fixture-ca.pem \
  https://build-demo.relay.example.test/mcp
```

The example hostnames are placeholders, not live routes. For a real trusted
public certificate omit `--ca-cert`. The checker sends at most three
unauthenticated GETs under a ten-second overall timeout, follows no redirects,
uses no saved credentials/cookies and limits each metadata body to 64 KiB.
Protected-resource metadata must be at its well-known path on the entered
endpoint origin. A separate issuer is never fetched unless `--issuer` names it
exactly. Output is JSON; exit zero means discovery passed. A failed discovery
also produces JSON plus a diagnostic and exits nonzero.

It does not register clients, exchange codes, log in, initialize MCP, invoke
tools or prove that the server actually has either configured client ID.

## Candidate isolated fixture and approval boundary

The proposed run uses a **new disposable OAuth-enabled relay**, a new private
endpoint and the existing in-memory builddemo. Publish only the synthetic
service; it never opens repository files or runs shell commands. Start the
fixture locally with:

```sh
make -f scripts/integration-tests/build-investigation/Makefile build
./bin/build-investigation serve
```

Use the printed loopback URL as the MCP upstream. Keep the endpoint private;
provide two application-specific static public client IDs and their observed
exact callbacks. Owner consent creates independent temporary grants with
bounded lifetime and request allowance. Install no new account credentials and
read no existing secret configuration into a report.

The smallest proposed approval package is:

| Item | Bounded action |
| --- | --- |
| Client contexts | One temporary custom connection in Bryan's personal ChatGPT account and one in his personal Claude account, using included allowance only. Confirm the actual selected accounts/workspaces before creation. |
| Endpoint | New private endpoint named `build-investigation` on a disposable, isolated relay. Its resource is exactly `https://build-investigation.<approved-relay-host>/mcp`. |
| Reachability | Operator-supplied, already approved, no-cost public HTTPS fixture host and exposure mechanism, for a single session capped at 60 minutes. The exact apex URL, endpoint URL and mechanism remain unresolved; no existing route has been proven suitable from the inspected repository. |
| Data and tools | Only the in-memory build-4821 corpus in `internal/builddemo`, exposed by `build.search` and `build.read`. No filesystem reads, shell execution, repository content or private uploads. |
| Authorization | Temporary public IDs `tunn-build-chatgpt` and `tunn-build-claude`, exact observed callback allowlists, owner consent, S256 PKCE, `mcp:access`, separate grants expiring within 30 minutes and capped at 100 HTTP admissions each. No client secret, paid API key or refresh token. |
| Acceptance | One cited useful investigation in each hosted app; owner accounting; revoke one grant and prove the other still works. Record setup latency separately from tool latency. |
| Cleanup | Revoke all fixture grants, delete both temporary connections and client configuration, and stop the disposable relay/exposure at session end. |

This is a prepared approval scope, not an executed registration or deployment.
The unresolved host, exposure mechanism and account contexts must be supplied
and the temporary external access explicitly authorized before a hosted run.
Existing instructions forbid public deployment and credential/access changes,
so this packet does not authorize those actions by itself. If a new disposable
relay deployment or DNS/TLS setup is needed, identify that concrete setup and
obtain its separate approval; it must not modify existing live ingress. No
approved exposure route was established during local work. Do not make a
private route public to unblock the demonstration.

## Observations and useful-answer exercise

Record setup-to-answer timing separately from first-tool/answer timing. Note
the account plan/workspace, actual UI labels, secret-field optionality, exact
callback, discovered tools and any permission prompts. Do not save raw access
tokens, authorization codes, cookie values or authorization request URLs in
screenshots/logs. No application UI has been proven usable merely because the
SDK fixture is green.

In a new conversation in each application, enable the same synthetic connector
and ask:

> Use only the Build Investigation connector. Investigate why build 4821 fails.
> Search the failure, read the relevant build log, then inspect the package
> scripts, CI steps, build instructions and ignore rules. Explain the cause,
> propose a minimal fix, and cite the evidence by path and line number.

Expected reasoning: TypeScript cannot resolve the generated schema; the package
has a schema-generation command, but CI installs dependencies then builds
without running it, and generated artifacts are ignored. Recommend generation
before compilation. Expected citations cover `logs/build-4821.log`,
`package.json`, `ci/build.yml`, `docs/build.md`, `.gitignore` and `src/app.ts`.
Read the actual returned line numbers; do not insert memorized ones.

Verify actual tool calls/arguments/results and the cited diagnosis in both
applications. Compare owner-side usage with HTTP admissions, including protocol
setup; allowance is not a tool-call counter. Confirm no platform credential
reaches the synthetic upstream. Revoke one application's grant: its next
protected request must fail even with a valid browser cookie, while the other's
grant can still perform a useful investigation. Record the denial reason and
owner accounting. Delete the temporary connections, revoke remaining fixture
grants and stop the approved relay/exposure at the end.
