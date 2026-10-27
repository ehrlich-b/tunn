# Operator and app contract

`*.apps.example.com` is a publisher-owned namespace. A single-label name maps to
that publisher's namespace-bound tunnel; nested names and the bare
`apps.example.com` are excluded. Existing concrete domain bindings keep their
original contract. Verified exact/wildcard claims exclude overlapping claims.
Unverified claims expire after 24 hours and do not establish exclusive ownership.
When a pending claim conflicts, `tunn domain add` returns a unique competing DNS
proof target: publish the specified CNAME (exact name) or TXT (wildcard parent),
then repeat the same add within 24 hours. Successful fresh proof atomically
replaces only overlapping unverified claims, including an exact-name claim.
Proof requests share the four-domain limit per account. Expiry does not release
independently reserved tunnel names. Verified owners retain namespace protection
when their DNS lease fails; routing still fails closed until proof is restored.
Every local
or remotely routed request rechecks the tunnel account against the domain owner.
Wildcard app ingress requires a verified personal tunn account browser session.
The namespace/app-name owner UUID is authorized after personal sign-in using
Google or an email link where offered by the relay. Other accounts require
explicit live person sharing or the legacy email allow-list. Public mode and bearer grants do not
bypass this boundary. See [the account design](../DESIGN.md).

## App-name capacity and migration

`tunn domain add '*.apps.example.com' --tunnel grafana` registers a name within
that claim; it creates no shared reservation. Publish it with
`tunn serve --namespace apps.example.com --name grafana http://127.0.0.1:3000`.
The owner API and `tunn domain list` return `app_names` (label, publisher ID,
legacy flag) and `app_name_limit` (50 for Pro). The 51st new name returns HTTP
429 / ResourceExhausted with the namespace and plan limit. Repeating an existing
name remains idempotent at capacity. Equal labels in different namespaces use
separate internal publisher IDs unless they reuse the same owner's pre-existing
global reservation. The `ns-` plus 48 lowercase hexadecimal-digit syntax is reserved to internal
publishers; all shared-reservation writers and SQL inserts/renames reject new
names in that syntax. Existing historical global rows are preserved. Deleted
namespace IDs fail publisher reconnect rather than becoming shared reservations.
The read-only `POST /api/domains/publisher` lookup resolves one verified app under
its owning account. It accepts a live durable publisher device or an existing
owner JWT; durable tokens still cannot list, add, verify or delete domain claims.
Terminating edges forward durable lookup to the login node for device revocation
and account checks. This endpoint does not create any name or claim.

At authority startup, one transaction creates the namespace-name table and
claim cleanup triggers, backfills historical wildcard bindings, and records
`domain_settings['namespace-app-names-v1'] = '1'`. The previous wildcard contract
exposed every owner-reserved label; the migration retains those names and their
publisher IDs, encrypted certificates, issuance ledger and global reservations.
Historical bindings keep live global-reservation checks. Newly added names have
an independent 50-name namespace budget; no reservation is automatically released
because old rows did not record their intended use. No manual data rewrite is
required. Account merges move ownership through the parent claim.

Deleting/expiring/replacing a claim removes its names, stored app certificates,
encrypted app keys and challenges, while preserving shared reservations and
issuance attempt history. Names are removed together with the namespace; there
is no individual app-name deletion command in this increment. Back up the live
database on volume before enabling this head. Rollback preserves the forward
schema and data and sets custom domains off; the previous image cannot route
new namespace-only IDs. Re-enable only after restoring the reviewed image.

## Before deployment

Deploy is intentionally not performed by this work. Configure every terminating
relay with `TUNN_CUSTOM_DOMAINS=true`, `TUNN_HTTP01_ADDR=:80`, the same existing
visitor `TUNN_JWT_SECRET` and node secret, and `TUNN_IDENTITY_KEYS_FILE` pointing
to a private, operator-owned Ed25519 JWK ring. Existing platform TLS certificates
are still required for the control/login origin. Set up the login node's
persistent SQLite volume, `TUNN_DOMAIN_KEY_SECRET` (base64 AES-256 encryption
key), `TUNN_ACME_EMAIL`, and `TUNN_ACME_DIRECTORY` (staging before production).
The default directory is `https://acme-v02.api.letsencrypt.org/directory`. Back up the encrypted
database together with its encryption secret through existing operator tooling.

Use the login authority's configured personal sign-in methods.
Google OAuth is optional; no Google prompts, client secrets, callback setup or
owner-primary-email change are required for wildcard access. Existing browser
sessions lacking a signed account ID require one new sign-in after deployment.
Keep applications on loopback, publisher credentials durable, and
publisher/app systemd services active. The wildcard CNAME must be DNS-only and
point to `tunn.to`; TXT proof must remain available. Public TCP/80 on every edge
must reach the HTTP-01 listener directly, and TCP/443 must reach tunn TLS.
Existing node-secret/TLS RPC protection distributes challenges and certificates.

REQUIRED-UNRUN: real production CA issuance/renewal after DNS changes, real personal
sign-in as the owner and another account, and a browser SSO acceptance check across
apps/relay nodes. Local test CA success does not constitute production issuance.

## Certificate authority, storage, and renewal

The established [`golang.org/x/crypto/acme`](https://pkg.go.dev/golang.org/x/crypto/acme)
client performs HTTP-01; no ACME protocol or DNS automation is reimplemented.
Only verified namespaces and app names registered by their owner may order certificates.
A generic edge CNAME is not ownership proof: the unique TXT or unique ownership
CNAME must verify. Proof leases last two hours and refresh hourly. Losing DNS
proof, account entitlement, app-name binding authority, or the claim denies new
routing/certificate requests. Deleting the parent deletes its stored app keys.

The login node serializes orders and stores each hostname's certificate and
AES-GCM encrypted private key in SQLite. Any terminating relay requests them
through authenticated internal RPC. Concurrent first requests reuse one order;
no per-node orders or private-key persistence are introduced. On-demand RPC/TLS
selection allows up to three minutes for initial issuance. Cache hits do not
contact ACME. Concrete-domain verify refreshes ownership proof and reuses its
valid certificate until the same 30-day renewal window; concrete and app orders
share the persisted issuance ledger, including verification failures that reached
the issuer and scheduled renewals. Processing responses without a Location header resume polling
the original order through the ACME library; no JWS/HTTP protocol is hand-coded. The login node renews existing app certificates within 30 days of
expiry during its hourly refresh. Persisted limits count failed attempts:
10 orders per owner/hour, 100 globally/hour, and a one-minute retry delay per
hostname. Pro permits 50 registered app names per namespace, independently of
the ten Pro reserved `*.tunn.to` names per account; other plans cannot claim custom
domains. The four-domain and ten-concurrent-Pro-tunnel limits still apply. A valid old certificate remains usable after renewal failure while DNS
proof holds. Authority outage fails closed. Run one active login-node authority;
multiple independent databases would defeat deduplication/rate limits. Replicated
HA authority and edge-side caching are future operational work.

## Identity assertions and key rotation

The edge strips every client-supplied `X-Tunn-Identity` and `X-Tunn-User-Email`,
then injects its own on authenticated wildcard app requests, including HTTP
streaming and WebSocket handshakes. Public platform requests retain neither
spoofable header. The assertion uses EdDSA with `kid`, `iss=https://tunn.to:443`
(or configured login authority), `aud=<hostname>` without port, canonical tunn account UUID
in both `sub` and `account_id`, `email`, `email_verified=true`,
`provider` and `idp` (`github`, `magic_link`, or `google`), `iat`, `nbf`, and a
two-minute `exp`. The subject is the authenticated caller account, which may
differ from the publisher account for explicitly shared access.
JWKS is public at `https://tunn.to/.well-known/tunn-jwks.json`; no private key
appears there. Apps may trust the plain email header only when all ingress comes
through a trusted tunn publisher; otherwise verify the JWT and the expected
issuer/audience. This is application SSO, not an OIDC provider/discovery endpoint.

Key file format (placeholders, never real secrets):

```json
{"active":"2026-10","keys":[{"kid":"2026-10","kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","x":"BASE64URL_PUBLIC_KEY","d":"BASE64URL_32_BYTE_SEED"}]}
```

Provision a secure random Ed25519 seed using operator tooling, file mode 0600.
The corresponding public key must match. Each request reads the ring so an
atomic file replacement rotates keys without restarting. Rotation across nodes:
first distribute old and new public keys to every ring/JWKS, leaving old active;
allow every app verifier to refresh its JWKS (60 seconds for the snippet below,
plus any upstream HTTP cache delay); then switch the active private key on every
signing relay. Remove the retired private seed from signing rings once all nodes
have switched, retaining its public key without `d`. For normal rotation, retain
the old public key for at least the two-minute assertion lifetime plus the maximum
clock skew/leeway accepted by your apps after the last old signature. Three
minutes provides a 60-second timing margin when apps use the snippet's zero
leeway. Key IDs must be unique. Update all relays before issuing with a new `kid`.
Private keys are never shared with apps.

Emergency revocation has a separate delay: remove the compromised key from all
rings/JWKS immediately and stop signing with it. The snippet explicitly caches
JWKS for 60 seconds and disables the optional per-key cache. A fresh token signed
with a removed key can still pass until that JWKS cache expires; assertion expiry
does not constrain a compromised seed's ability to mint fresh tokens. Rejection
begins after each app can fetch the updated JWKS and its 60-second client cache
expires. The endpoint's `Cache-Control: max-age=60` does not configure PyJWT's
internal cache; an upstream HTTP cache can add its own delay. For immediate
revocation, purge upstream caches and recreate app verifier clients, or disable
affected ingress until every verifier rejects the key. Other app implementations
must document and test their actual cache and leeway settings.

The cache parameters follow the [PyJWT 2.10.1 client implementation](https://github.com/jpadilla/pyjwt/blob/2.10.1/jwt/jwks_client.py).
When testing key removal, verify the verifier rejects removed keys after its
60-second JWKS cache expires and continues to accept the replacement key.

Python verifier (`pip install 'PyJWT[crypto]'`; call at app ingress):

```python
import jwt
ISSUER = "https://tunn.to:443"  # Match TUNN_PUBLIC_ADDR/login authority exactly.
HOST = "dashboard.apps.example.com"
keys = jwt.PyJWKClient("https://tunn.to/.well-known/tunn-jwks.json", lifespan=60, cache_keys=False)
def verify(headers):
    token = headers["X-Tunn-Identity"]
    key = keys.get_signing_key_from_jwt(token).key
    c = jwt.decode(token, key, algorithms=["EdDSA"], audience=HOST, issuer=ISSUER, options={"require": ["exp", "iat", "nbf", "sub", "account_id", "email", "provider"]})
    valid = c.get("email_verified") is True and isinstance(c["account_id"], str) and bool(c["account_id"]) and c["sub"] == c["account_id"]
    if not valid or c["provider"] not in ("github", "magic_link", "google") or c.get("idp") != c["provider"]: raise ValueError("unverified identity")
    return c["email"]
```

## SSO handoff

Supported login callbacks establish a verified tunn account session before the
handoff. GitHub requires a verified primary email; email requires a fresh one-use
magic link. Google stays optional and retains PKCE and authoritative-mailbox
checks. Custom app origins never receive the parent-domain session.
The edge creates an HTTP-only host nonce, signs hostname/path/nonce, and sends
it to the login authority. The authority validates the namespace and account
binding, uses the normal configured login page if needed, and signs a 60-second
audience-bound handoff. The app callback requires that browser nonce, live domain
and account binding, and durable one-use replay consumption across nodes, then
sets a secure HTTP-only host cookie. Redirect responses use no-store and
no-referrer; the callback redirects immediately to a local path and forwards
neither handoff token nor tunn cookies to the app. Authority failures fail closed.
Unrelated accounts complete login then receive 403 unless explicitly shared.
New requests and idle streaming/WebSocket connections recheck live account and
sharing authority. Removing a person, suspending an account, removing a mailbox,
or losing namespace/app-name authority closes idle connections within the
designed five-second bound. Platform logout does not invalidate other app cookies;
they expire after one hour, or revoke through live authority/key changes. Existing
EdDSA assertions can remain valid for their two-minute lifetime.

Background requests after an app session expires receive HTTP 401 with
`Tunn-Auth: login` and a `login_required` JSON response. Apps should reload the
page to start sign-in again.
