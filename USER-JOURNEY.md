# Private web sharing, as built

This journey requires the new server and CLI. The publisher has installed tunn
and already has an HTTP app on localhost:3000. The recipient needs only a
browser. The examples assume both people are already signed into their chosen
Google/GitHub account. Provider account selection, passwords, MFA and any
installation/app setup add steps and human time; they are not measured here.
Google appears only when the operator configures it. GitHub and email login
remain available with their existing configuration.

## First session: CLI sharing

Publisher, six actions:

1. Run `tunn 3000 --name acme-preview` and leave this terminal running. With no
   usable saved credentials, it automatically opens publisher enrollment.
2. In the opened browser, click **Continue with Google** or **Continue with
   GitHub**.
3. Approve the provider's consent if requested.
4. Compare the displayed device code with the terminal and click **Authorize**.
   The terminal prints `https://acme-preview.tunn.to` and says access is private.
5. In a second terminal run `tunn share acme-preview client@example.com`.
   To limit the invitation to a day, use
   `tunn share acme-preview client@example.com --expires 24h`.
6. Copy the resource URL from the publishing terminal and send it to the
   recipient through your existing email/chat tool. tunn sends no invitation.

Recipient, three actions:

1. Open `https://acme-preview.tunn.to` in a clean browser.
2. Click **Continue with Google** or **Continue with GitHub**, using an account
   with the invited address among its verified emails.
3. Approve provider consent if requested. The app opens automatically.

This path has **nine publisher/recipient actions** including provider consent;
consent can be skipped by an already-authorized provider. A copied URL grants
no access to a different signed-in person. Wrong identities get **Access denied**.
Email magic-link login is another existing choice and adds the inbox/link action.
The publisher always retains access, including when the People list is empty.

## The existing dashboard

After publishing, open `https://tunn.to/account`, click **Share access and see who
can open your resources**, then click **acme-preview**. The resource page is also
linked directly in the publishing terminal:
`https://tunn.to/account/sharing?tunnel=acme-preview`.

Type `client@example.com` into **Email**, optionally choose **Expires at (UTC)**,
and click **Share**. Click **Copy link** and send the URL yourself. The page shows
owner, exposure, active people, expiry, existing machine grants, and recent
access identities, decisions and timestamps. `tunn access acme-preview` returns
the resource, people (including revoked/expired records), and machine grants as
JSON. Domain entries seeded by `--allow @company.com` are also shown/removable;
the Share form grants a specific email.

## Second session

If the publisher is still running, it does nothing. After stopping/restarting it,
run exactly `tunn 3000 --name acme-preview` again. Saved rotating publisher
credentials renew automatically, and the resource's People list survives.
Registration's `--allow` only seeds a newly created resource; it never restores
people removed through live sharing.

The recipient opens `https://acme-preview.tunn.to` again. With an unexpired
browser session and live permission, the app opens immediately: **one recipient
action**, or **two total actions** if the publisher restarts. After the seven-day
browser session expires, normal identity login is required; the permission itself
persists until removal/expiry. There is no recipient tunn installation or token.

## Remove access

Run `tunn unshare acme-preview client@example.com` in the publisher's second
terminal. Alternatively, open the resource page and click **Remove access** next
to that person. No tunnel restart is needed. The next request is refused, and
already-open browser HTTP/SSE and WebSocket streams close within **five seconds**.
The watcher checks once per second, allows at most two seconds for authority
lookup, and fails closed if that lookup fails. The audit records revocation or
expiry as the stream's terminal reason. Removing a person does not revoke an
independently issued machine grant or endpoint token; those are separate explicit
sharing credentials managed with the existing grant/token commands.

## Intentional public exposure and compatibility

For a webhook or deliberately public app, run
`tunn 3000 --name acme-preview --public`. Do not combine `--public` with `--allow`
or `--bearer`. To return to private exposure, restart that publication without
`--public`. An active anonymous stream from public mode is also cut off when
exposure returns to private.

New ordinary HTTP CLI publications send exposure version 1 and an explicit mode.
They require a verified owner account and durable sharing authority. The SDK's
empty-access default is also private; set `tunn.Options{Public: true, ...}` for
intentional anonymous access. Explicit existing SDK allow-lists and endpoint
credentials retain their private admission compatibility. A new owner-only
publisher refuses an older relay before becoming ready or delivering requests.
Accountless self-hosted public mode/master-secret publication supports explicit
`--public` exposure. Private owner-only and person-sharing workflows require
configured publisher accounts/OAuth.

Unversioned older clients retain their original empty-list public behavior and
are labelled **legacy-public** when their authenticated account is available.
Upgrade and restart them without `--public` to make them private, or with
`--public` to preserve intentional public access. An old empty-list publisher is
refused if that name already has managed private/explicit exposure. MCP and TCP
commands retain their existing authentication behavior. Name takeover by a
new owner creates a new immutable resource ID; it inherits no browser people
permissions, even if the old owner later reclaims the name.

## Deployment and measured evidence

No server was deployed. Deploy the login-node authority and all relays before
releasing the new CLI/SDK. Initialization creates the `web_resources` table/index;
people records use the existing `meter_grants` table. No manual/backfill migration
is required. Existing public registrations have the deliberate compatibility
behavior above; operators must choose their exposure when upgrading publishers.

To enable Google, configure `TUNN_GOOGLE_CLIENT_ID` and
`TUNN_GOOGLE_CLIENT_SECRET`, with the exact authorized callback
`https://tunn.to/auth/google/callback` (or your configured public host/port).
The flow uses browser-bound state, PKCE S256 and Google's verified-email userinfo;
no identity is taken from a caller-provided email. See
[Google's provider documentation](https://developers.google.com/identity/openid-connect/openid-connect).

Reproduce the clean Chromium acceptance gate with Python/Playwright and its
Chromium installed:

```sh
TUNN_SHARE_BROWSER_PYTHON=/path/to/playwright/python \
  go test -p=1 -count=1 -v ./internal/host -run '^TestWebSharingBrowserJourney$'
```

The fixture uses real TLS ingress, dashboard forms, OAuth state/callback, cookies,
live permissions and audit storage. Only Google's external consent/token service
and the sample app's response are fixtures; recipient requests carry ordinary
browser cookies, with no bypass headers. Separate loopback tests run an actual
gRPC publisher and local origin, plus idle HTTP and WebSocket revocation.
Local scripted times are recorded in `docs/web-sharing-validation.md`. They are
not human sign-in measurements or proof of real Google/GitHub interoperability.
The five outside-recipient production acceptance gate remains unrun.
