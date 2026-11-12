# Browser entry and cookie scope

First touch is established on GET or HEAD navigation to `/`, `/about`, `/privacy`,
`/terms`, `/pricing`, `/ngrok-alternative`, `/client-previews`, `/mcp-to-claude`,
`/share-dev-server-oauth`, `/docs` and `/docs/*`, `/agents` and `/agents/*`,
`/status`, `/report`, `/login`, `/auth/login`, and `/upgrade`. Enabled Google and
GitHub login starts also qualify. Organization login routes do not qualify.
This policy is independent of query parameters: `src` never turns an asset,
health/readiness probe, JSON status request, download/installer, API, webhook,
verification callback, disabled auth route, or account action into an entry.
`TestFunnelSourceRouteInventory` checks the policy against registered platform
routes, apex pages and the agent catalogue; browser fixtures cover first touch
through verified, authenticated account access.

Signed-out platform entries navigate to the configured HTTPS PublicAddr before
establishing a signed, expiring, exact-authority-bound host-only source cookie.
The first valid source remains unchanged by subsequent navigation. Authenticated
account and checkout actions keep their valid origin and session-bound CSRF.
Only the source token is carried in a signed, single-use magic link; no unsigned
handoff or arbitrary redirect is used.

Platform session issuance and clearing use the exact request authority. The apex
retains its existing domain cookie. An explicitly configured unrelated PublicAddr
uses a Secure, HttpOnly, SameSite=Lax host-only session cookie. Unrelated origins
require separate sign-ins; their sessions are not transparently shared. A
PublicAddr in the publisher namespace is unsupported and fails closed. Publisher
origins never receive platform forms, attribution cookies or session issuance.
The same scope policy applies to provider callbacks, mailbox reissues, logout
and clearing credentials rejected by live account authority.
