# App device access

App credentials give one device access to one reserved wildcard app hostname.
They identify a tunn account; the current account, verified mailbox, sharing,
namespace, reserved name, publisher and resource generation still decide access.
They have no publication or account-management privileges.

Open **Account → App devices**, enter the exact app hostname and choose **Add
device**. An app hostname also provides `/.tunn/devices`, which redirects browser
users to the login authority's Devices page. Scan the invitation, compare the
exact hostname and phrase on both screens, approve in the signed-in browser,
then confirm on the device. A copied QR cannot replace its first frozen claim.
Cancel and create another invitation if the screens differ.

App credentials contain 256 random bits, use the `tunn_app_` prefix, and expire
after 30 days without renewal. The authority stores only SHA-256 digests.
Native apps must keep the response in their OS credential vault. The included
phone browser screen demonstrates confirmation and keeps the credential only
in memory; it does not replace native vault integration or Wingthing pairing.

## Enrollment API

All routes below live on the configured trusted HTTPS login origin. Native
clients must configure that authority independently of the QR, validate TLS and
reject QR URLs with any other authority before making a request. Reject
redirects, omit browser cookies, and never send credentials to a URL supplied by
an invitation. The QR is a URL on that authority:
`/pair/app-device#invitation=<single-use-handle>&hostname=<exact-hostname>`.
Fragment values never reach navigation logs or referrers. The invitation expires
after 5 minutes and contains no app credential.

1. Signed-in browser: CSRF-protected form POST
   `/api/app-devices/invitations` with `hostname` and `csrf_token`. The Devices
   page supplies the session-bound CSRF value. Response: `id`, `invitation`,
   `hostname`, `authority`, `expires_at`, and a locally generated `qr_png` data URL.
2. Device: JSON POST `/api/app-devices/claims` with `invitation`, `hostname`,
   bounded `name`, `code_challenge_method:"S256"`, and a base64url SHA-256
   `code_challenge`. Generate a random 43–128-character PKCE verifier locally.
   Response freezes `claim_id`, device name, exact hostname and comparison phrase.
3. Browser: GET `/api/app-devices/invitations/<id>` retrieves that frozen claim
   using its ordinary account cookie. Explicit form POST
   `/api/app-devices/claims/<claim_id>/approve` sends `csrf_token`, `hostname`,
   exact `phrase`, and `confirmed:true` after comparison. The issuing account
   and mailbox must match; sharing and all app authority are rechecked.
4. Device: JSON POST `/api/app-devices/claims/<claim_id>/redeem` sends
   `code_verifier`, exact `hostname`, `phrase`, and `confirmed:true`. Poll no
   faster than every 5 seconds. Pending browser approval returns 202;
   successful redemption returns 201 with `access_token`, `token_type:"Bearer"`,
   `expires_at`, and `device` metadata. Consumption and device creation are one
   transaction. A lost successful response requires a new enrollment.

Timestamps are Unix milliseconds. Responses use `Cache-Control: no-store`.
Expired, consumed or mismatched enrollment requests return 400; lost account,
scope or sharing authority returns 403; limits return 429 with `Retry-After`;
authority failure returns 503. No enrollment request opens an anonymous app
endpoint or bypasses a wing's own authorization.

## HTTP and WebSocket requests

Send `Tunn-Authorization: Bearer <app-credential>` over HTTPS, including on a
WebSocket upgrade. Keep the application's own `Authorization` header separate.
Compatibility carriers are `Authorization: Bearer tunn_app_…` when upstream
authorization is unused, or Basic username `tunn-app` with the app credential as
password. Do not put credentials in URLs, query strings, logs or analytics.

An explicit app credential overrides browser cookies: invalid, expired or
revoked → 401; valid identity with lost app/account/mailbox authority or wrong
hostname/resource → 403; unavailable authority → 503. No app credential or
browser cookie retains the browser 302 sign-in flow. Duplicate, conflicting or
malformed app carriers fail; unrelated upstream bearer/Basic survives. Relay
credentials and platform cookies are stripped before origin forwarding. An
EdDSA account assertion retains the existing app identity contract.

Go clients can use `tunn.ParseAppInvitation(configuredAuthority, qrURL)` to
reject another authority before network I/O, `tunn.SetAppAuthorization` to bind
HTTP and WebSocket upgrade headers to the exact HTTPS hostname, and
`tunn.AppDeviceHTTPClient` to omit cookies and reject every redirect. Use the
client for enrollment and app requests; a generic HTTP client's redirect policy
may forward custom headers to another origin. Keep TLS verification enabled.

Admission checks the credential before namespace/publisher scope denials and
shares a 2-second deadline across authority lookups. The established stream
keeps its own lifetime. Every admitted device request holds a lease and rechecks the live
device and app policy each second with a 2-second total lookup deadline. Revocation
or an authority outage closes idle HTTP/SSE/WebSocket transport within the
5-second cutoff, including stalled downstream writes and publisher cleanup.
Relays use the same login-node SQLite authority and authenticated
internal RPC; there is no offline grace or positive revocation cache.

Forwarding relays run their own uncached permission watcher and interrupt
downstream HTTP and upgrade writes independently of the publisher relay.
Authenticated relay metadata carries the remaining admission deadline; a
signed early admission response releases that timer before application work.
This preserves long responses and streams while bounding connection setup,
remote admission and offline auditing. Metering charges use the watched stream
context; already-read upload bytes are retained for bounded reconciliation.

Configure the existing node TLS/secret, discovery, visitor signing, domain ownership and
identity signing settings before enabling this flow on multiple relays. Old
relays without the app-device RPC fail closed; deploy a matching relay version.

## Management and limits

The Devices page shows name, account, hostname, created, last use and expiry.
Users can revoke their own devices even after sharing is removed. The hostname
owner can revoke delegated devices even when the publisher is offline.
Verified account merges preserve device management, capacity/rate accounting,
the surviving UUID in assertions and the originating mailbox binding.
CSRF-protected form POST
`/api/app-devices/revoke` takes `hostname`, `device_id`, `csrf_token`;
`/api/app-devices/revoke-all` takes `hostname`, `csrf_token`. A 200 response
reports durable `revoked_at`; revoke-all also consumes pending invitations in
the caller's scope. Add `scope:hostname` for an explicit owner-wide operation or
`scope:self` for the caller's own devices. The page supplies this scope; authority
failure never turns an owner-wide operation into partial success. Browser logout
is separate. Wingthing still needs its own
device revoke for permissions reachable through other transports.

Limits preserve existing stricter quotas: 5 invitations/account/minute,
5 outstanding/account, 10 failed attempts/invitation, 30 claim submissions/source
IP/minute, 30 failed validations/source IP/minute and account/hostname/minute,
20 active credentials/account/hostname, 10 concurrent device requests/streams.
Source addresses come from the socket peer or authenticated relay metadata.
Label/body lengths, rate rows, invitation rows and device rows are bounded;
expired rows and stream leases are cleaned in bounded batches.

Run `make test-app-devices`. For the browser gate, set `TUNN_PLAYWRIGHT_MODULE`
to an installed Playwright module and optionally `TUNN_CHROMIUM_PATH` and
`TUNN_APP_DEVICE_SCREENSHOTS`, then run `make test-app-devices-browser`.
The fixture uses a disposable CA, actual pages/APIs, and a fixture external
identity provider; it is not proof of live native enrollment or mobility.
