# Namespace app-name capacity

Custom namespace app names live in `namespace_app_names`, keyed by parent claim,
proof target and app label; account ownership follows the parent. Pro permits
50 names per namespace, independently of the four shared `*.tunn.to` reservation
slots. New names use random internal publisher IDs and publish with
`tunn serve --namespace apps.example.com --name grafana <target>`. Add/list show
`app_names` and `app_name_limit`; the 51st add reports the namespace and 50-name
limit. The four-domain, ten-concurrent-tunnel, 10-owner-orders/hour and
100-global-orders/hour gates remain unchanged.

The forward-only migration preserves existing shared reservations, publisher
IDs and encrypted certificate data. It backfills historical owner-reserved
labels once and keeps their reservation revocation checks. Claim deletion,
expiry or replacement removes its names and stored app keys/challenges through
SQLite triggers, independently of foreign-key settings. A different account
cannot add names or publish scoped IDs belonging to this namespace. Every route,
challenge and certificate/key response checks current claim/binding authority.
Scoped publication never auto-reserves a global name. New namespace bindings
can reuse an already-owned global reservation; that independent reservation stays
reserved. The previous schema cannot identify app-only global reservations, so
none are automatically released. Rollback must disable app domains; old images
cannot route new scoped IDs. Names can currently be removed together by deleting
the namespace, rather than through a separate per-app deletion API.

# Wildcard app authorization by tunn account

A verified wildcard namespace and each app's namespace name belong to a durable
tunn account UUID. Routing rechecks that the connected publisher has that UUID.
The owner signs in through GitHub (verified primary email), an email magic link,
or Google when configured. All three callbacks resolve the verified identity
through the existing account authority before signing a session with account ID,
verified email and provider. A provider is authentication metadata, not access
policy. Google retains its existing authoritative-mailbox/subject safeguards.

App ingress requires this account session even for public publication. The
owning account is allowed independently of its primary email. Other accounts
require a live, explicit person share or the legacy publisher email allow-list;
resource generation, grant expiry and removal retain existing semantics. Public
mode and bearer/capability credentials do not bypass this wildcard boundary.
This preserves the namespace's private access gate while enabling normal sharing.

The app gate resolves the signed UUID and checks that its verified email remains
in that account's bucket. It never resolves ownership from provider-email text.
Existing linking rules remain: fresh mailbox proof joins the account containing
that exact case-folded email; GitHub can join verified mailbox buckets through
its verified email set, with the existing merge and suspension rules. Google
also binds issuer/subject and only links authoritative Gmail/Workspace mailboxes.
External login callbacks reject non-ASCII email lookalikes before normalization;
plus-addresses and dot variants are not invented aliases. Explicit verified
account merges resolve to their surviving UUID. A stale cookie whose mailbox
moved without that merge cannot rebind itself to another account. Legacy
email-only or Google-only app cookies require one new sign-in for this binding.

An attacker with a different GitHub account or different mailbox gets their own
UUID and receives 403 after login unless explicitly shared. A username, claimed
email, request header, unverified provider mailbox, or matching owner email in a
session for a different UUID confers no ownership. Actual verified control of an
already linked mailbox is account authentication under tunn's existing rules.

The platform signs a 60-second hostname/path/nonce handoff. Its callback requires
the secure host nonce, live namespace, live account/email binding and durable
one-use nonce consumption. A secure, HTTP-only, host-only one-hour app cookie is
bound to the exact hostname; the seven-day platform cookie never reaches apps.
Identity headers are stripped, then EdDSA assertions carry canonical account ID
in both `sub` and `account_id`, verified email and provider, exact hostname `aud`,
issuer, `kid`, and a two-minute expiry; existing public JWKS/key rotation remain.

New requests recheck namespace, reservation, publisher/account state and live
sharing. Idle SSE/WebSocket requests poll those authorities and session expiry
every second with a two-second check deadline and close on revocation/outage
(designed bound five seconds). Account suspension, email removal, sharing removal
and namespace/reservation loss revoke access. Ordinary logout clears its platform
cookie; it does not globally revoke existing app cookies. Their one-hour expiry,
authority changes, or visitor signing-key rotation provide the existing session
revocation mechanisms. Apps validate assertions at ingress; assertions already
issued remain cryptographically valid for at most two minutes.

Deployment is a coordinator action. No Google OAuth setup is required for app
access. Preserve visitor/node signing configuration, Ed25519 identity keys,
encrypted domain storage, ACME, DNS ownership proof and direct port 80/443 ingress.

The prior organization SSO design is preserved in [ORG-SSO-DESIGN.md](ORG-SSO-DESIGN.md).
