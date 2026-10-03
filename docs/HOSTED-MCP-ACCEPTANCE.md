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

Failed checks put the relevant recovery action first in `next_steps`; application
setup instructions appear only after `ready:true`. For a grant-only relay, ask
the operator to enable the explicit OAuth client configuration. For a separate
issuer, review the returned origin and approve only that exact `--issuer` before
rerunning; no separate-origin discovery occurs until then. A passing check
still does not establish a registered client, owner login or hosted UI support.

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
bounded lifetime and request allowance. Preserve the default saved login and
existing account credentials; use only explicitly approved temporary fixture
credentials. Read no existing secret configuration into a report.

## Exact bounded approval package

Prepared scope: one session capped at **60 minutes**, one new private endpoint
named `build-investigation`, two temporary personal-account connections, one
cited investigation per provider, and independent revocation/accounting checks.
No route, registration, credential or connection has been created for this run.

### Host proposal and ownership evidence

The concrete candidate names are issuer `https://mcp-acceptance.tunn.to` and
resource `https://build-investigation.mcp-acceptance.tunn.to/mcp`, on a new
disposable relay. They are **proposals, not known live or available routes**.
Repository `CLAUDE.md` and `fly.toml.dist` describe `tunn.to` as the project's
production domain on Fly.io; they do not prove Bryan's current DNS authority,
permission to create these records, host availability or no-cost capacity.
No DNS, certificate or hosting account was inspected or modified for this packet.

There is a browser boundary to resolve before selecting those names. Existing
Tunn owner cookies use `Domain=.<configured-domain>`; a production `.tunn.to`
cookie would be sent to the proposed subdomain in a normal browser and could
also conflict with the fixture login. Prefer a **separately controlled
registrable fixture domain**, still to be supplied, with equivalent issuer and
endpoint names. The `tunn.to` candidate is usable only with an explicitly
approved isolated browser context containing no `.tunn.to` cookies. Do not
delete or copy production cookies to obtain that isolation.

Trusted TLS must cover both selected hosts. A `*.tunn.to` certificate does not
cover the nested endpoint name. Use independent fixture certificate/key
material; do not copy a production signing or TLS private key. The exact
approved domain/URL pair, DNS operator and TLS provisioning method remain inputs.

### Data, destinations and access changes

| Item | Exact requested scope |
| --- | --- |
| Runtime and exposure | Prefer the relay and synthetic upstream on Bryan's Mac, with a named, already approved no-cost HTTPS exposure mechanism. The public route serves this fixture only and closes by 60 minutes. The mechanism, routing target and permission to create DNS/TLS records are unresolved; no public deployment or paid capacity is assumed. |
| Endpoint | Keep `build-investigation` private; expose its literal `/mcp` URL plus OAuth/discovery endpoints on the isolated authority. Public discovery returns resource/issuer/scope metadata, not tool data. No `--public`, shared public bearer or existing-ingress change. |
| Data | Only six invented documents baked into `internal/builddemo/service.go`: `logs/build-4821.log`, `package.json`, `ci/build.yml`, `docs/build.md`, `.gitignore`, `src/app.ts`. Search/read results include synthetic contents, paths and line numbers. No repository files, source/history upload, real filesystem access, shell commands or environment-secret reads. |
| Providers | OpenAI's hosted ChatGPT and Anthropic's hosted Claude, one connection in each selected personal account/workspace. These providers receive the fixture's tool descriptions, synthetic tool outputs and their own temporary client grant. Included allowance only; no model API, API key, paid fallback, plan upgrade or billing change. |
| Public clients | `tunn-build-chatgpt` and `tunn-build-claude`, configured only on the fixture relay as distinct public OAuth clients, token endpoint authentication `none`, authorization code with S256 PKCE. No client secret, DCR or remote client-metadata fetch. |
| Callback destinations | ChatGPT's documented issuer-identification candidate is exactly `https://chatgpt.com/connector_platform_oauth_redirect`; otherwise its UI may supply `https://chatgpt.com/connector/oauth/{callback_id}`. Copy the actual approved UI's exact URI, never a guessed ID or wildcard. Claude's documented hosted callback is exactly `https://claude.ai/api/mcp/auth_callback`; confirm it in the selected setup. If the UI requires a different origin or confidential-client secret, stop rather than broaden access. |
| Owner identity | A dedicated fixture owner operated by Bryan, authenticated on the isolated authority by an explicitly selected existing Tunn login method. The principal, method and any identity-provider callback/permission remain unresolved. Do not reuse production sessions, keys or the default saved CLI login, or assume a new origin already has an authenticated owner. |
| Access changes to approve | Starting the disposable fixture's public HTTPS exposure and any explicitly identified new DNS/TLS setup; enabling its two static clients; creating two personal hosted connections; owner consent issuing two bounded grants. These actions need new explicit approval because current instructions forbid external deployment and credential/access changes. Production ingress, production OAuth apps and existing credentials remain outside that approval. |

The existing grant audience is logical owner+endpoint with literal `/mcp`; only
the authorization code binds the exact full resource URI. Use a separate
fixture database and signing authority, rather than sharing the production DB
or assuming cross-authority bearer isolation.

### Credentials and lifetime

| Material | Scope and bound |
| --- | --- |
| Each provider's opaque access grant | `mcp:access` on this fixture owner+endpoint; expires 30 minutes after its consent page is created; 100 HTTP admissions, including protocol setup; independently revocable. No refresh token or `offline_access`. The synthetic server itself enforces read-only tools. |
| Authorization code / consent ticket / CSRF cookie | Five-minute consent window, one-use code exchange bound to the exact client/callback/resource/S256 challenge; secure host-only Strict SameSite CSRF cookie. Values are never included in evidence or screenshots. |
| Fixture owner browser cookie | Existing Tunn lifetime is **seven days**, not 30 minutes, and it permits owner access on the fixture authority. Log out and dispose its approved isolated context at cleanup; destroy the independent fixture signing key/DB so retained cookies cannot authorize a revived fixture. The owner login method/provisioning must be supplied before this credential exists. |
| Fixture owner/publisher account JWT, if needed | Existing device-login JWT lifetime is **24 hours**. Use fixture-only material and explicit temporary credential handling; do not overwrite `~/.tunn/token` or reuse an existing production JWT. Provisioning and publisher authentication remain part of the owner-method input. Destroy fixture material at cleanup. |
| Publisher endpoint token, if generated | Endpoint-scoped capability with no intrinsic TTL. Keep it local; do not give it to hosted providers. Stop/unregister the endpoint and delete only its newly created fixture token file at cleanup. |
| Fixture signing/TLS keys and client file | Independent temporary materials for the selected isolated authority only; no production secret copies. Public client IDs are not secrets. Delete fixture configuration, keys and DB when the session closes. |

### Cleanup and required inputs

At completion or at the 60-minute cap: revoke both client grants, verify denial,
delete both temporary hosted connections, log out of the fixture owner session
while its relay is still reachable, stop/unregister the publisher, stop the
upstream/relay and public exposure, and dispose only the approved isolated
browser context. Remove only newly
created fixture token/config/key/DB files and DNS/TLS resources identified in
the approval. Preserve production logins, cookies, resources and credentials.
Keep only scrubbed observations and timings. Deleting connections is not a
claim that provider-retained conversation data has been erased.

Four input groups genuinely remain unknown:

1. **Authority and browser isolation:** the chosen exact URL pair, verified
   domain/DNS operator, and a disjoint registrable domain or approved clean
   browser context for the provisional `tunn.to` names.
2. **Exposure and TLS:** the actual already-approved no-cost mechanism,
   routing target, certificate coverage/provisioning and permission for only
   the named fixture DNS/TLS/public-exposure changes.
3. **Fixture owner and publisher:** principal, existing supported login method,
   any identity-provider destination/callback, independent-key provenance and
   temporary credential handling without changing the default saved login.
4. **Hosted accounts/UI:** the exact selected ChatGPT and Claude personal
   account/workspace contexts and included-allowance feature permissions; the
   ChatGPT callback shown by that UI and its acceptance of blank-secret public
   clients remain observations to collect during the approved setup.

The parent should obtain one confirmation covering the concrete resolved
inputs and the bounded actions above. A generic yes to this proposal is not
permission to choose unspecified infrastructure, spend money or expand
credentials. If a suitable host/login/UI path cannot be supplied within that
scope, retain local evidence and report that specific gate. Do not change live
ingress, weaken authentication or upload private source to make the run work.

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
