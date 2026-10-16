# Organization SSO and group sharing

The current scope is **Okta, Microsoft Entra ID and Google Workspace OIDC sign-in and group sharing**. SAML, identity linking, SCIM, posture, AI identities and outbound OIDC-provider endpoints are deferred. The previous design is preserved in [docs/durable-device-design.md](docs/durable-device-design.md). Read the short [enterprise roadmap](ENTERPRISE-ZT.md) first.

## Value, effort and build order

| Rank | Role | Value / effort | Decision |
| --- | --- | --- | --- |
| 1 | Identity-aware proxy using customer OIDC and group policy | High / medium | Build now, using existing resource share/revoke. Upstream company sign-in, not a new consumer identity provider. |
| 2 | Signed app identity at the proxy | High / medium | Use the existing app-domain JWT/JWKS implementation; no duplicate signer. |
| 3 | SAML service provider for org login | Customer-dependent / high | Deferred; add for a customer unable to use OIDC. |
| 4 | Brokered OIDC issuer for apps needing their own login | Selective / high | Deferred plumbing. A proxy cannot automatically create app accounts or native application roles. |
| 5 | SAML IdP for legacy applications | Narrow / very high | Deferred stretch behind independent security review. |

## Market and pricing evidence

Small-company IT/security teams pay the SSO tax through enterprise upgrades/minimum seats; developers also pay in support time. [sso.tax](https://sso.tax/) lists GitHub $4 → $21/user/month (+425%, entry dated 2020-04-14), Figma $12 → $45 (+275%, 2019-10-19), and Docker $9 → $24 (+167%, 2023-10-16). These are dated dataset observations, **not verified 2026 quotes**. Compare actual contracts before promising savings.

The wedge is a service the publisher can put behind tunn. A proxy cannot force an unrelated SaaS vendor to enable SAML, remove its enterprise charge, provision app accounts, or disable an alternate public origin. “ANY app” depends on control of ingress/login. Test faster first share and repeated access with existing tools, consistent with the adjacent VISION/DECK, rather than building an identity network.

| Alternative | Public pricing checked on research date | Comparison |
| --- | --- | --- |
| [Cloudflare Access](https://www.cloudflare.com/plans/zero-trust-services/) | Current page advertises free proof of concept and sales packaging; the [vendor SMB guide](https://cf-assets.www.cloudflare.com/slt3lc6tev37/7oEleWnoR1ggS7GfMUb3oO/bc05cd36279b0e4bc5fcc942f2a3264e/Cloudflare-security-guide-for-small-and-medium-enterprises.pdf) describes up to 50 free users. The familiar $7/user/month was not confirmed on the current rendered page. | Strong free IdP gate; win on setup/sharing. |
| [Pomerium](https://www.pomerium.com/pricing) | Core open source; Zero Personal free; Zero Business $9/user/month monthly or $7 annually; Enterprise custom. | Closest proxy benchmark; enterprise directory sync/delegated policy already exists. |
| [Teleport](https://goteleport.com/pricing/) | Get Pricing/usage-based active-user and resource offer; no universal numeric list figure established. [Feature matrix](https://goteleport.com/docs/feature-matrix/) distinguishes paid governance. | Broader infrastructure identity and privileged-session product. |
| [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) / [Authelia](https://www.authelia.com/) | Open-source software, no license charge; hosting/operations remain. | Existing ingress gates; self-operation and UX distinguish tunn. |
| [authentik](https://goauthentik.io/pricing/) | Open source free; Enterprise $5/internal user/month and $0.02/external user/month annually; Enterprise Plus starts $20k/year. | Broader identity platform/proxy. |
| [WorkOS](https://workos.com/pricing) | SSO $125/connection/month for 1–15 connections, volume discounts; directory sync separate. | Vendor SDK/service, not standalone tunn ingress. |
| [Okta Access Gateway](https://www.okta.com/pricing/) | Included/add-on by workforce edition; Enterprise inquiry pricing. Starter suite $6/user/month is **not** a gateway quote. | Compare gateway entitlement and deployment needs. |

## Trust boundary and flow

Admin supplies a private config file: stable org slug, provider, exact issuer, client ID/secret, exact allowed domains and bounded mappings from shareable group slugs to remote group IDs/names or Entra app roles. Users cannot supply issuers/discovery URLs. Restart every relay for policy changes; old org browser sessions become invalid.

Authorization code + PKCE S256 → one-use persisted state bound to browser/org/callback → ID-token verification with [coreos/go-oidc v3.21.0](https://github.com/coreos/go-oidc/releases/tag/v3.21.0) → issuer, audience/authorized party, expiry, issue time, nonce and tenant/domain checks → group resolution → bounded signed 15-minute org session. No provider access/refresh tokens are saved or forwarded. Verified HTTPS, network deadlines and response bounds protect discovery/JWKS/API calls; the maintained library verifies signatures and rotation.

The baseline email-bucket account model merges verified emails across providers. **Org login must never pass a provider email to it.** Account compatibility uses an opaque deterministic principal derived from `(org, issuer, sub)`; same emails and consumer Google sessions confer no org authority. This is subject isolation, not identity linking. Group grants use `group:<org>:<group>` with existing immutable resource IDs, owner checks, expiry/revocation ledger and streaming permission checks. Only a validated org browser session carries groups; email, endpoint and device credentials do not.

Okta: configure an ID-token `groups` claim with the `groups` scope as described by [Okta](https://developer.okta.com/docs/guides/customize-tokens-groups-claim/). Entra: pin a tenant-specific v2 issuer and signed `tid`; use group object IDs and `roles` as separate mappings. Email/`preferred_username` are display/domain filters, never account identifiers or mailbox proof. Detect `_claim_names.groups`/`hasgroups` overage, ignore `_claim_sources` URLs, verify fixed Graph `/me` against signed `oid`, and fetch all bounded membership pages. [Entra overage/roles](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles); [Graph permissions](https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-1.0).

Workspace: reuse Google's existing sign-in entry and authorization/PKCE helpers. Require signed `hd` in allowed domains **and** `email_verified`; Gmail cannot satisfy company login. [Google guidance](https://developers.google.com/identity/openid-connect/reference) requires `hd`, not an email suffix, for Workspace membership. Resolve immutable group IDs with [Admin SDK groups.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/list), a domain-wide delegated service account restricted to `admin.directory.group.readonly`, and an impersonated administrator allowed to read groups. Enable Directory API and grant admin consent; ordinary user OAuth is insufficient. Direct membership only; nested expansion is not promised.

Membership is a login-time snapshot renewed by sign-in after at most 15 minutes (or earlier upstream token expiry). Missing/malformed claims never grant access; overage/API errors fail closed. Removing a tunn grant denies the next request and cancels managed web streams within the existing five-second polling bound. Expiry/config removal must also cancel org streams. Immediate IdP offboarding via SCIM is deferred. Device credentials remain independently revocable and cannot prove group membership. Group grants cover managed browser/HTTP resources, not origin OS roles, SSH keys or all machine clients.

## Deferred SAML notes

Use a maintained SP library, never hand-written XML-DSig. `crewjam/saml` provides SP/IdP/metadata plumbing, with signature bypasses in [2020](https://github.com/crewjam/saml/security/advisories/GHSA-rrfw-hg9m-j47h) and [multiple assertions in 2022](https://github.com/crewjam/saml/security/advisories/GHSA-j2jp-wvqg-wc2g), plus XML processing, decompression and XSS advisories in its [history](https://github.com/crewjam/saml/security/advisories). `goxmldsig` is a canonicalization/signature component, not an SP; its [advisories](https://github.com/russellhaering/goxmldsig/security/advisories) include 2020 signature validation bypass, March 2026 loop-variable signature bypass and August 2026 canonicalization memory amplification. Recent fixes make fresh exact-version/transitive vulnerability review essential. Neither is approved here. Alternatives: [gosaml2](https://github.com/russellhaering/gosaml2) or an external broker such as authentik; compare maintenance and parser boundaries when SAML is authorized.

Future attack corpus: XSW variants, duplicate IDs/ambiguous assertions, signature stripping and comment-injected NameID; validate the exact signed node and canonicalization result. Persist assertion-ID replay protection; bound skew and enforce audience/recipient/destination/outstanding `InResponseTo`; bind opaque RelayState to a stored safe redirect; pin metadata and overlap keys during rotation. Begin SP-initiated only, reject unsolicited IdP initiation, and explicitly scope encrypted assertions and SLO/session revocation. The original SAML corpus is **deferred by the scope cut**, not passed.

[docs/org-sso.md](docs/org-sso.md) records setup and review/deploy prerequisites: tenant binding, group API permissions, cookie trust, origin bypass and offboarding bounds. Run the full suite and race checks before enabling org SSO.
