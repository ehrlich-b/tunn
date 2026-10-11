# Operator and app contract

`*.apps.ehrlich.dev` is a publisher-owned namespace. A single-label name maps to
that publisher's identically named reserved tunnel; nested names and the bare
`apps.ehrlich.dev` are excluded. Existing concrete domain bindings keep their
original contract. Overlapping exact/wildcard claims are rejected. Every local
or remotely routed request rechecks the tunnel account against the domain owner.
Wildcard app ingress forces a verified Google browser session and exact primary
owner email even for public resources, allow-lists, or bearer grants.

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

Configure Google OAuth client ID/secret on the login authority and its exact
callback `https://tunn.to:443/auth/google/callback` (or the exact configured
`TUNN_PUBLIC_ADDR`). Enable the Google client for the intended users. Set the
owner's primary email to `ehrlich.bryan@gmail.com`; an account alias alone is
insufficient. Keep applications on loopback, publisher credentials durable, and
publisher/app systemd services active. The wildcard CNAME must be DNS-only and
point to `tunn.to`; TXT proof must remain available. Public TCP/80 on every edge
must reach the HTTP-01 listener directly, and TCP/443 must reach tunn TLS.
Existing node-secret/TLS RPC protection distributes challenges and certificates.

REQUIRED-UNRUN: real production CA issuance/renewal after DNS changes, real Google
login as Bryan and another account, and a browser SSO acceptance check across
apps/relay nodes. Local test CA success does not constitute production issuance.

## Certificate authority, storage, and renewal

The established [`golang.org/x/crypto/acme`](https://pkg.go.dev/golang.org/x/crypto/acme)
client performs HTTP-01; no ACME protocol or DNS automation is reimplemented.
Only verified namespaces and owner-reserved app names may order certificates.
A generic edge CNAME is not ownership proof: the unique TXT or unique ownership
CNAME must verify. Proof leases last two hours and refresh hourly. Losing DNS
proof, account entitlement, reservation ownership, or the claim denies new
routing/certificate requests. Deleting the parent deletes its stored app keys.

The login node serializes orders and stores each hostname's certificate and
AES-GCM encrypted private key in SQLite. Any terminating relay requests them
through authenticated internal RPC. Concurrent first requests reuse one order;
no per-node orders or private-key persistence are introduced. On-demand RPC/TLS
selection allows up to three minutes for initial issuance. Cache hits do not
contact ACME. Processing responses without a Location header resume polling
the original order through the ACME library; no JWS/HTTP protocol is hand-coded. The login node renews existing app certificates within 30 days of
expiry during its hourly refresh. Persisted limits count failed attempts:
10 orders per owner/hour, 100 globally/hour, and a one-minute retry delay per
hostname. Existing four reserved-name slots bound each publisher's hostname
fan-out. A valid old certificate remains usable after renewal failure while DNS
proof holds. Authority outage fails closed. Run one active login-node authority;
multiple independent databases would defeat deduplication/rate limits. Replicated
HA authority and edge-side caching are future operational work.

## Identity assertions and key rotation

The edge strips every client-supplied `X-Tunn-Identity` and `X-Tunn-User-Email`,
then injects its own on authenticated wildcard app requests, including HTTP
streaming and WebSocket handshakes. Public platform requests retain neither
spoofable header. The assertion uses EdDSA with `kid`, `iss=https://tunn.to:443`
(or configured login authority), `aud=<hostname>` without port, Google subject
`sub`, `email`, `email_verified=true`, `idp=google`, `iat`, `nbf`, and a two-minute
`exp`. The subject is Google's subject, not an email alias or publisher ID.
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
then switch the active private key on every signing relay; retain the old public
key for at least three minutes after the last old signature (two-minute lifetime
plus JWKS cache/skew); then remove it and the retired private seed. Private keys
are never shared with apps. Keep the previous public key in the ring without
`d`; key IDs must be unique. Update all relays before issuing with a new `kid`.

Ten-line Python verifier (`pip install 'PyJWT[crypto]'`; call at app ingress):

```python
import jwt
ISSUER = "https://tunn.to:443"  # Match TUNN_PUBLIC_ADDR/login authority exactly.
HOST = "dashboard.apps.ehrlich.dev"
keys = jwt.PyJWKClient("https://tunn.to/.well-known/tunn-jwks.json")
def verify(headers):
    token = headers["X-Tunn-Identity"]
    key = keys.get_signing_key_from_jwt(token).key
    c = jwt.decode(token, key, algorithms=["EdDSA"], audience=HOST, issuer=ISSUER, options={"require": ["exp", "iat", "nbf", "sub", "email"]})
    if c.get("email_verified") is not True or c.get("idp") != "google": raise ValueError("unverified identity")
    return c["email"]
```

## SSO handoff

The existing [Google flow](https://developers.google.com/identity/openid-connect/openid-connect)
uses PKCE and verified UserInfo. Only its session records provider, verified
email and subject. Custom app origins never receive the parent-domain session.
The edge creates an HTTP-only host nonce, signs hostname/path/nonce, and sends
it to the login authority. The authority validates the verified domain, requires
a Google session (with a Google-only login page if missing), and signs a
60-second audience-bound handoff. The app callback requires that browser nonce,
live domain binding, and durable one-use replay consumption across nodes, then
sets a secure HTTP-only host cookie. Redirect responses use no-store and
no-referrer; the callback redirects immediately to a local path and forwards
neither handoff token nor tunn cookies to the app. Signing/authority failures
fail closed. Google sessions from other emails complete login then receive 403
at the app. Existing sessions do not automatically become Google sessions.
