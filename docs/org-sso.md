# Company sign-in and group sharing

This branch implements the 13:10/13:11 scope in [IDEAS-INBOX](../../IDEAS-INBOX.md): customer Okta, Microsoft Entra ID and Google Workspace sign-in with per-app group sharing. It is an OIDC client of those providers. [DESIGN](../DESIGN.md) ranks the remaining protocol roles; [ENTERPRISE-ZT](../ENTERPRISE-ZT.md) is the short enterprise roadmap. No SAML, identity linking, SCIM or new OIDC issuer is enabled.

## Disable organization SSO for a custom-domain release

Leave `TUNN_OIDC_ORGS_FILE` unset or empty on **every** relay and restart all
nodes. Alternatively, point it at a private 0600/0400 JSON file containing
`[]`. There is no default organization. With zero configured organizations,
GET `/auth/org/<id>`, its callback, and `/auth/google?org=<id>` return 404 before
forwarding, discovery, login-state allocation or session creation. These URL
patterns remain registered; no functional organization SSO entry is exposed.
The login node does not initialize the organization-login store, and the login
page renders no organization buttons. Existing organization sessions fail the
configured-policy check after removal.

Keep the existing personal Google/GitHub credentials and domain configuration.
Personal `/auth/google` (without `org`) and GitHub login use signed browser state,
not the organization pending-state table. Custom-domain login and the
`*.apps.ehrlich.dev` Google gate use personal Google sessions and their separate
handoff/replay storage. Organization-state exhaustion cannot consume their
login slots, even when organizations are enabled. Custom domains can therefore
ship with organization SSO disabled while real-tenant organization acceptance
remains pending, subject to the custom-domain release's own acceptance gates.

## Administrator setup

1. Register a confidential web OIDC application with authorization-code login. Register the **exact** callback `https://<TUNN_PUBLIC_ADDR>/auth/org/<org-id>/callback`. The path contains a stable, lower-case organization slug; a changed public address needs updated callback registration and a relay restart.
2. Copy the relevant entries from [org-sso.example.json](org-sso.example.json) into a private JSON file; replace every placeholder and remove unused entries. Set `TUNN_OIDC_ORGS_FILE` to its absolute path. The file must be regular, at most 1 MiB, and mode 0600 or 0400. Never commit populated credentials. Set the existing production JWT secret and login-node configuration. Up to 32 orgs and 16 shareable group mappings per org are supported. Domains are exact lower-case company domains, not wildcards; Gmail/Googlemail are refused.
3. Configure provider-specific claims and permissions below, then restart all relay nodes with the same org configuration and signing secret. Login state/replay protection lives in the login node's SQLite database; non-login nodes forward `/auth/org/` and Workspace starts to that authority. Providers initialize lazily so an unavailable IdP does not prevent other apps from being served. Configuration is immutable until restart.

**Okta:** use the precise org/custom authorization-server issuer, e.g. `https://acme.okta.com` or `https://acme.okta.com/oauth2/default`. Register the web app with `client_secret_basic` authentication (Okta's default); tunn sends client credentials in the Authorization header. Entra and Google use `client_secret_post`. The method is selected explicitly without retrying a one-use code. [Okta client authentication](https://developer.okta.com/docs/api/openapi/okta-oauth/guides/client-auth).

Configure `email`, boolean `email_verified` and the mapped `groups` claim in the **ID token**, including groups for the requested `groups` scope. Use exact case-sensitive group names/IDs. Missing group claims yield no group permissions; an unverified/missing verification flag refuses login. Do not assume a thin ID token contains groups: configure their inclusion explicitly. [Okta groups setup](https://developer.okta.com/docs/guides/customize-tokens-groups-claim/).

**Entra ID:** use `https://login.microsoftonline.com/<tenant-UUID>/v2.0`; `common`, `organizations` and domain-name tenant paths are rejected. Set the app's group claims to group **object IDs**, or map application `roles` separately using `"claim":"roles"`. The signed `tid` must match the configured tenant, with a nonempty `oid`. Email/`preferred_username` is a domain filter/display label only; Microsoft does not guarantee it is a verified, immutable mailbox. [ID-token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference).

Entra JWT groups can overflow beyond 200. `_claim_names.groups`/`hasgroups` triggers fixed **commercial-cloud Microsoft Graph** calls, never a URL from `_claim_sources`: `/v1.0/me?$select=id` must match signed `oid`, then `/v1.0/me/transitiveMemberOf/microsoft.graph.group?$select=id&$top=100`. Request delegated `https://graph.microsoft.com/User.Read` and consent it on the registered application. The documented least privilege for the signed-in user's transitive membership is `User.Read`; hidden membership may require `Member.Read.Hidden` and administrative consent. Do not map hidden groups without testing their visibility/permissions. Only group IDs are consumed. Safe pagination is confined to the same exact Graph host and membership path; lookup errors, unexpected pagination and incomplete/bounded-out responses refuse login. Sovereign-cloud Graph endpoints are not implemented. [Graph API permissions](https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-1.0), [overage and roles](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles).

**Google Workspace:** issuer must be `https://accounts.google.com`. The existing Google sign-in entry supports `/auth/google?org=<org-id>` and uses the same PKCE verifier helper as consumer login. The canonical Workspace callback is the org path above. Omitted Google client credentials reuse `TUNN_GOOGLE_CLIENT_ID`/`TUNN_GOOGLE_CLIENT_SECRET` **only if both are omitted**; register the org callback on that existing client too. Consumer Google login remains separate and cannot satisfy a company group, even when its verified email matches.

Google sign-in requests `openid profile email` and supplies `hd` as a UI hint, but authorization checks the **verified ID-token** `hd` against configured domains and requires boolean `email_verified=true` and an allowed email domain. A Gmail identity with a supplied/claimed hosted-domain hint is refused. [Google hosted-domain guidance](https://developers.google.com/identity/openid-connect/reference).

Google ID tokens do not provide Workspace group membership. For group mappings, enable Admin SDK Directory API, create a service account with domain-wide delegation, and authorize **only** `https://www.googleapis.com/auth/admin.directory.group.readonly` in the Workspace admin console. Store its JSON signing credentials in a private 0600/0400 file and set `google_credentials_file`; set `google_directory_admin` to an impersonated company administrator with permission to read groups. The delegated JWT is restricted to that scope, admin and Google's token endpoint. `groups.list` uses the signed, stable user `sub` as Directory `userKey` (unique user ID), and follows bounded `nextPageToken` pages. Map immutable group IDs, not mutable group email addresses. This returns direct membership; nested groups require a future Cloud Identity/transitive integration. If no group mappings exist, omit both delegation fields to use Workspace sign-in alone. [Directory groups.list and scope](https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/list), [Directory authorization](https://developers.google.com/workspace/admin/directory/v1/guides/authorizing).

## Login availability and token validation

Pending organization logins are bounded to 8 per network peer per organization,
128 per organization, and 4,096 globally across the maximum 32 organizations.
Admission happens before discovery and persisted state is committed atomically.
Abandoned flows expire in ten minutes; consumed flows free capacity immediately.
HTTP 429 indicates admission refusal. Peer identity uses the TCP remote address,
with IPv6 privacy addresses grouped by /64; supplied forwarding headers and
cookies do not widen admission. Reverse proxies and forwarding relay nodes
conservatively share their peer's limit. The one-time schema upgrade invalidates
pending pre-upgrade sign-ins; users restart those flows. Completed sessions are
unaffected. Limits and callback replay protection survive subsequent restarts.

Provider initialization is coalesced per organization policy. Cached unrelated
providers remain available during a stalled discovery; waiting callers respect
their own cancellation. Discovery is bounded to ten seconds with five seconds
of failure backoff. ID tokens may contain only the configured client audience;
additional application audiences are rejected even with a matching `azp`.

For an emergency signing-key compromise, remove the compromised key at the IdP
and restart **every relay** to clear discovery/JWKS caches. A usable cached key
has no periodic removal check; normal rotation refreshes on an unknown key.
Provider key removal alone does not promise immediate invalidation. Revoke
relevant tunn grants/devices separately and account for existing browser
sessions' maximum fifteen-minute lifetime.

## The share-button journey

An owner publishes a managed private web resource, opens **Account → Share access**, chooses the company group and optionally its expiry, and copies the app link. The recipient opens the link, selects their company sign-in, and reaches the app if that IdP confirms membership. Remove the group from the same page to revoke its resource permission.

The equivalent existing CLI/API operations are:

```sh
tunn share preview group:acme-entra:engineering --expires 8h
tunn access preview
tunn unshare preview group:acme-entra:engineering
```

`tunn ... --allow group:acme-entra:engineering` can initialize the permission on a **managed web** publication. Unknown groups, TCP and raw MCP group publication are refused. Reconnecting retains the resource's current permissions; it does not resurrect a revoked initial group. Using the browser avoids handling an owner API credential.

Authenticated owner requests to `POST /api/sharing/<resource>` can use `{"group":"acme-entra:engineering","expires_at":<Unix milliseconds>}`; DELETE accepts the same group without expiry. The existing `{"email":"group:acme-entra:engineering"}` wire format also supports the CLI. Supplying both email and group is refused. Owner checks, browser CSRF/origin checks, configured-group validation and the existing immutable resource generation remain mandatory. A copied resource URL is not itself an access grant.

Removing a group mapping disables its old sessions. Owners can still revoke an existing grant for that canonical group after it is removed from configuration; creating a new grant requires a current mapping.

## Identity and lifecycle limits

Company accounts use an opaque stable principal derived from `(org, issuer, sub)` for compatibility with existing account storage. They are separate from personal Google/GitHub/magic-link accounts with the same display email. No email merging or identity-linking flow is performed. Corporate sign-in can enroll the CLI through the existing explicit device-confirmation step; publisher/device credentials identify that isolated account and **carry no group membership**. A company member opens group-shared apps with their browser org session. To invite someone via existing personal-email sharing, they must use their personal account; an org email is not a new email-bucket alias.

Org sessions last at most **15 minutes**, shortened to ID-token expiry; only the up to 16 matched local group aliases are stored in a signed HttpOnly/Secure cookie. Provider bearer/refresh tokens and delegation tokens are never saved or forwarded to origins. Group status is a login-time snapshot: IdP removals take effect at the next login/session expiry, up to 15 minutes. Removing a tunn group grant denies the next request and cancels managed open streams within the existing five-second authority polling bound. Session expiry or changed/removed org config also cancels streams. Every relay must receive the policy change; temporarily inconsistent configurations fail matching-session checks.

SCIM-driven immediate offboarding and org session administration are deferred. Previously enrolled publisher devices remain separately revocable and can renew until revoked, including when the user leaves the IdP. The resource owner and explicitly issued machine grants retain their existing independent authority; adding a group does not silently revoke them. Organization/group permissions apply to tunn's web ingress, not app-internal roles, sshd users/keys or direct-origin traffic. Protect the origin against bypass. No enterprise-MFA assurance is asserted merely because OIDC succeeded.

The adjacent app-domain lane owns signed app identity/JWKS headers. Integrate its reviewed commit separately: use the stable subject for authorization, keep display email separate, and do not label Entra's email as mailbox-verified. This branch does not create another JWT header signer.

## Security review and acceptance

Review exact-issuer/client/tenant binding, subject/account isolation, callback/browser/PKCE/nonce replay guarantees, org-scoped group mapping, Graph subject/pagination trust, Directory delegation scope and key-file permissions. Review shared cookie/signing-key trust across relays and origin credential stripping. Test real IdP registration, group/role changes, overage, admin consent and offboarding/revocation limits in a disposable tenant before deployment. Live tenant acceptance and real browser/IdP consent are **REQUIRED-UNRUN** here; all fixtures stay local and use generated keys.

Run `make test-sso` for the security corpus, and the entire suite plus race with the repository's make targets. Use `umask 0022` for the existing tests: the workspace's 0002 makes host-mode fixture directories group-writable; 0077 changes a symlink-test victim's expected 0644 permissions. Both mismatches occur on untouched baseline `7f5d619`. Avoid changing production credential permissions or weakening checks to accommodate test fixtures.

Final test results and commit IDs are recorded in [org-sso-validation.md](org-sso-validation.md). Original SAML attacks are deferred by the explicit scope cut, rather than reported as passing. No push, deployment, IdP registration, DNS change or billing change is performed.
