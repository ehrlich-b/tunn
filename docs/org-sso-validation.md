# Organization SSO validation

Date: 2026-10-11. Scope was checked against the complete live inbox immediately before local delivery: Okta, Microsoft Entra ID and Google Workspace OIDC login plus organization-scoped group sharing. SAML, linking, SCIM, posture and agent identities remain roadmap notes.

| Commit | Purpose |
| --- | --- |
| `7f5d619` | Untouched comparison baseline |
| `f028f1f` | Cited design, role ranking and one-page enterprise roadmap |
| `1660f85fd3cd75f8799ef43fd6cbb13de9506a5e` | OIDC implementation, sharing integration, fixtures and setup guide |

Execution used Go **1.27.2**, Linux/amd64; the module declares Go 1.25.0/toolchain 1.25.6. Runtime fixtures use disposable local SQLite databases, generated RSA keys and loopback HTTPS providers. No live tenant or hosted relay was contacted by the SSO fixtures.

The full race run tests implementation commit `1660f85`. This validation commit strengthens the Workspace fabricated-group assertion without changing production code; the focused race corpus and complete ordinary suite were rerun afterward.

## Commands and results

Run these from the repository with `umask 0022`:

```sh
make fmt tidy
GOFLAGS=-p=2 make vet build
GOFLAGS=-p=2 make test-sso GO_TEST_FLAGS=-v
GOFLAGS='-p=2 -count=1' make test
GOFLAGS=-p=2 make test-race GO_TEST_FLAGS='-parallel=2 -count=1'
```

| Gate | Final result |
| --- | --- |
| Format, dependency tidy, vet, binary build, diff whitespace check | PASS |
| Complete ordinary test suite, uncached | Earlier run PASS; latest repeat FAIL on the baseline MCP cleanup deadline |
| `test-sso`, uncached with race detection | PASS, all four packages; no skips |
| Complete race suite, uncached | FAIL: existing TLS startup race and MCP subprocess shutdown deadlines, described below |
| Example configuration JSON syntax | PASS |
| Live Okta/Entra/Workspace registration, browser and consent acceptance | REQUIRED-UNRUN |

The full suite and race gates are **not green** and must be resolved before deployment. The focused SSO result does not replace those gates.

## Security corpus

| Fixture | Evidence |
| --- | --- |
| Okta, Entra, Workspace provider shapes | All three complete discovery, authenticated code exchange, PKCE, RS256/JWKS verification and group-shared HTTP access. Okta requires `client_secret_basic`; Entra/Google use POST credentials. Personal sessions cannot inherit company permissions; group removal denies the next request. |
| Invalid-token corpus | **22/22 rejected**, each without an auth cookie, with subsequent callback replay rejected: issuer, audience, authorized party, multiple audiences without `azp`, missing/wrong nonce, expired/missing expiry, future/missing issue time, future `nbf`, unverified email, lookalike/subdomain email, missing subject, malformed group/role/entry, substituted access-token hash, HS256 confusion, invalid signature and stripped signature/`alg=none`. |
| Entra overage and roles | **7/7 cases pass**: `_claim_names.groups` and `hasgroups` both resolve paginated memberships and app roles; wrong Graph identity, denied Graph access, hostile pagination, wrong tenant and malformed overage are rejected. A hostile `_claim_sources` URL is ignored. |
| Workspace authority | **7/7 cases pass**: missing/wrong `hd`, Gmail with a company `hd`, unverified/missing verification and Directory failure are rejected. A fabricated token group cannot override Directory results. Delegation validates its signature, fixed token audience, impersonated admin and exact read-only scope; membership lookup uses signed `sub` and pagination. |
| Browser/callback state | Missing browser cookie and wrong-org callbacks fail; consumed callbacks fail on replay. Twenty simultaneous state consumers yield exactly one success. A new store instance retains consumed state; expired state fails. Real JWKS key rotation succeeds. |
| Account/session boundaries | Same-email company login creates a distinct stable subject account and cannot take over the personal resource owner. Org cookies fail as API bearer credentials. Expired sessions and remapped policies fail. Live group revocation and session expiry cancel permission watches within four seconds in fixtures. |
| Sharing and device flows | Company-group dashboard, owner checks, CSRF/origin refusal, unknown/ambiguous group rejection and cross-org group isolation pass. Publisher enrollment preserves the company subject; the resulting device token cannot open a group-only resource. Supplied identity/group headers confer no authority. |
| Publication | **7/7 cases pass**: managed private publication seeds an owner-scoped group grant; unknown/uppercase groups, missing authority/owner, TCP and raw MCP publication fail. |
| Persistence and transport | Group revocation survives database reopen and remains org/resource-generation scoped. HTTPS-only transport, bounded response bodies and refusal to follow credential redirects pass. CLI share/unshare retains authenticated owner and canonical group identifiers. |
| Configuration | Private-file permissions, bounded/strict JSON, existing Google credential reuse, issuer/domain/group constraints and policy-change invalidation pass. |

Original SAML XSW/signature/comment-injection/assertion-replay corpus: **DEFERRED by the explicit scope cut**, not executed or represented as passing.

## Baseline failures

The final race run detects concurrent mutation of the shared TLS configuration: `golang.org/x/net/http2.ConfigureServer` writes while `crypto/tls.Config.Clone` in `http3.ConfigureTLSConfig` reads. It manifests in `TestOpsLoopbackShutdownWithLivePublisherAndRestart`. A detached, untouched `7f5d619` worktree reproduces the same read/write race in `TestOpsLoopbackStartupFailureReleasesSiblingListeners/http2`. Those startup paths were not changed by this implementation.

The final race run also reports `bridge_test.go:425: Close: context deadline exceeded` in six MCP bridge cases: MCP flow, finite SSE notifications, child-request refusal, tool allowlist, child-exit reporting and request failure on child exit. The untouched baseline reproduces that cleanup timeout in MCP flow and finite SSE notifications. The latest ordinary-suite repeat fails at the same cleanup line in `TestBridgeMCPFlow`; an earlier uncached complete run passed. MCP bridge files were not changed.

The workspace starts with umask 0002, which makes existing host-mode fixture directories group-writable and fails their private-credential checks. Testing with 0077 instead changes the existing symlink-test victim from its expected 0644 to 0600. Both fixture mismatches were observed on the baseline. The final runs use 0022; production private-file requirements stay 0600/0400.

## Review and deployment gates

Independently review exact issuer/audience/tenant binding, immutable subject isolation, browser state/PKCE/nonce replay protection, group namespaces, Graph subject and pagination constraints, Workspace delegation scope/key handling, signing-key/cookie trust across relays, and credential stripping at origins. Review the bounded 15-minute membership snapshot and separately revocable publisher credentials; this MVP does not claim immediate IdP offboarding or enterprise MFA assurance.

Resolve the baseline TLS race and MCP shutdown failures, then obtain a green full race gate. In disposable real tenants, register exact callbacks, configure Okta ID-token groups and Basic client authentication, consent Entra Graph permissions and force overage/role scenarios, and authorize the documented Google Directory delegation scope. Exercise membership changes, denied lookup, policy restart, browser/device enrollment and open-stream revocation. Protect each origin against direct access. Integrate the adjacent app-domain lane's reviewed signed-identity/JWKS commit separately if the app needs trusted identity headers. See [setup and limits](org-sso.md) for exact settings.

All commits are local. No push, deployment, live IdP registration, DNS mutation or billing edit was performed.

## Raw evidence

Logs are retained in `/work/lanes/tunn-sso/` outside the repository. SHA-256 checksums identify the final evidence:

| Log | SHA-256 |
| --- | --- |
| `final-build.log` | `4a846d3307ba32f8dd8ce81286343ed880d91b8547a698540d067366932d615e` |
| `final-sso.log` | `75ef1b302e935d3b5c2af6f7f38d0f9e6ef5d4791ee4fd05c385ce68058357b2` |
| `final-full-test.log` | `a49fd2b3a67381998b27af9d35b298f5b423986759b326c2041c9b169f2f7c16` |
| `final-full-race.log` | `79d45e9eeb937ce404cba91d2a688c1ee9c105ccedc612ee8e20906e639ad9e3` |
| `baseline-race.log` | `f6e23db2b9d83c8ad67c2ec7abb502d1a3042b962856ef70553ef5d8b888b7e5` |
