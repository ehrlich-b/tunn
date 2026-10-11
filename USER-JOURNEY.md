# Attach a domain, publish an app, open it, sign in

Prerequisites: tunn installed on forge, a durable publisher login belonging to
`ehrlich.bryan@gmail.com`, an existing Pro account, and an app process listening
only on `127.0.0.1:3000`. Keep the app and publisher supervised by systemd.
The existing account and reserved-name limits apply; this change does not alter
plans or billing. The relay prerequisites are in [the operator guide](docs/APPS-DOMAINS.md).

First app: **four one-time domain steps, one publishing step, two browser steps**
(seven steps after prerequisites):

1. Attach and reserve the first app name:
   `tunn domain add '*.apps.ehrlich.dev' --tunnel dashboard`.
   Save the returned `cname_target`; it is the unique ownership proof value.
2. Bryan/coordinator sets the one-time, DNS-only CNAME
   `*.apps.ehrlich.dev → tunn.to` (`proxied=false`, automatic TTL).
   The proposed estate helper command is
   `cf-dns.sh cname '*.apps.ehrlich.dev' tunn.to` after applying
   [the diff](docs/cf-dns-cname.diff). No DNS helper or credentials are run here.
3. Set TXT `_tunn-verification.apps.ehrlich.dev` to the exact `cname_target`
   from step 1. A generic CNAME to the edge routes traffic but cannot prove
   publisher ownership. Leave this TXT in place for hourly ownership checks.
4. Run `tunn domain verify '*.apps.ehrlich.dev'`. This verifies ownership;
   concrete hostname certificates are issued on first connection, not wildcard
   certificates. No DNS API key is needed for HTTP-01 issuance or renewal.
5. Publish `tunn serve --name dashboard http://127.0.0.1:3000` under the same
   account and leave it running. The CLI may also print its `tunn.to` address;
   the app address is `https://dashboard.apps.ehrlich.dev`.
6. Open that app URL. The edge obtains its real certificate, then sends the
   browser to tunn's Google login page.
7. Select **Continue with Google** and sign in as `ehrlich.bryan@gmail.com`.
   Google returns to tunn; a one-use, browser-bound handoff returns to the app.
   The app receives a signed identity JWT and `X-Tunn-User-Email`.

Next app: **two publisher steps and one browser step**: repeat
`tunn domain add '*.apps.ehrlich.dev' --tunnel reports` (idempotently reuses the
claim and reserves that name), publish with `--name reports`, open
`https://reports.apps.ehrlich.dev`. The central Google session is reused; no
new provider login is required while it is valid. Existing Pro reserved-name
limit: four names. Returning to an already signed-in app is **one browser step**.
Google's account picker/consent screens may add interactions to the first login.

Other Google emails receive a 403 after login. Unverified Google emails receive
403 at the provider callback. Email aliases, GitHub/magic-link sessions, endpoint
bearers, and consumer grants cannot bypass the wildcard app gate. Adding a
recipient or publishing with public mode cannot widen this domain's owner-only
policy. The gate compares the verified Google email with the owner's primary
email, without email-bucket or Unicode normalization. Confirm Bryan's primary
account email before attaching the production domain.

Only `/.tunn/sso/callback` is reserved on app origins. Other paths belong to the
app. App cookies remain separate; tunn session cookies are stripped before
forwarding. The central session lasts seven days and app sessions one hour.
