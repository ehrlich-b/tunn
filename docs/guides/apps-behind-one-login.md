# Two apps behind one Google login

This serves `grafana.apps.example.com` and `dash.apps.example.com` through one
relay. Replace `apps.example.com` with a domain you control. Both apps require a
verified tunn account. The publisher account needs Pro.

## Configure Google on the login relay

1. In Google Cloud, select the project, configure the OAuth consent screen and
   add your test accounts if the app is in Testing. Use Internal only for a
   Workspace organization whose members should be able to sign in; otherwise
   use External. Request `openid` and `email`.
2. Create an OAuth client with application type **Web application**. Set the
   authorized redirect URI to exactly:

   ```text
   https://tunn.to/auth/google/callback
   ```

   This is the login relay callback for both apps. No app callback or JavaScript
   origin is needed for this server-side flow. For your own login relay, replace
   `tunn.to` with `TUNN_PUBLIC_ADDR`; omit `:443`, retain any other configured port.
3. Set `TUNN_GOOGLE_CLIENT_ID` and `TUNN_GOOGLE_CLIENT_SECRET` privately on the
   login deployment. For Fly.io, run the following in your own Bash terminal.
   Enter the deployment app name, then paste each value at its hidden prompt.
   The pipe sends the values directly to Fly; it writes no credential file.

   ```bash
   set +x
   read -r -p 'Fly app: ' tunn_app
   read -r -s -p 'Google client ID: ' tunn_google_id; printf '\n'
   read -r -s -p 'Google client secret: ' tunn_google_secret; printf '\n'
   printf 'TUNN_GOOGLE_CLIENT_ID=%s\nTUNN_GOOGLE_CLIENT_SECRET=%s\n' \
     "$tunn_google_id" "$tunn_google_secret" | fly secrets import --app "$tunn_app"
   unset tunn_google_id tunn_google_secret tunn_app
   ```

   An unstaged secret update restarts machines and drops publisher connections.
   Keep independent admin access and let supervised publishers reconnect.
   Do not paste credentials into this repository, a script, chat, or a log.

[DEPLOY.md](../../DEPLOY.md) also names `TUNN_GITHUB_CLIENT_ID` and
`TUNN_GITHUB_CLIENT_SECRET`: preserve them if GitHub should remain available.
Leaving both empty hides that button; preserve SMTP for email fallback.
`TUNN_PUBLIC_ADDR` must remain the existing login authority (`tunn.to:443` here).
Its certificate-renewal settings are `TUNN_CERT_DOMAIN`, `TUNN_FLY_APP`, and
`TUNN_CERT_EMAIL`; keep their existing deployment values. They are settings,
not Google credentials. Keep the existing database and persistent secrets.

Use a Gmail address or an authoritative Workspace mailbox for Google sign-in.
A third-party mailbox attached to a Google account may require a fresh tunn
email link instead. Sign in as the same tunn account that owns the namespace;
adding Google must not silently create a different publisher account.

## Enable custom domains

Use the [app-domain configuration](../APPS-DOMAINS.md#before-deployment):

- Every terminating relay: `TUNN_CUSTOM_DOMAINS=true`, `TUNN_HTTP01_ADDR=:80`,
  the existing `TUNN_JWT_SECRET` and `TUNN_NODE_SECRET`, and
  `TUNN_IDENTITY_KEYS_FILE` pointing to a private Ed25519 JWK ring (mode 0600).
- Login node: persistent SQLite (`TUNN_DB_PATH`, `TUNN_LOGIN_NODE=true`),
  `TUNN_DOMAIN_KEY_SECRET` (base64 of 32 random bytes), `TUNN_ACME_EMAIL`, and
  `TUNN_ACME_DIRECTORY`. Use the CA's staging directory for rehearsal, then
  `https://acme-v02.api.letsencrypt.org/directory` for browser-trusted certificates.
- Preserve `TUNN_CERT_FILE` and `TUNN_KEY_FILE` for the platform authority.
  Public TCP/80 must reach the HTTP-01 listener; TCP/443 must reach tunn TLS.
  Keep a backup of the database with its encryption secret.

Provision these private values through your existing operator tooling. This
repository does not collect them. App certificates are issued per hostname on
first use and renewed by the login authority. A staging certificate will not be
trusted by an ordinary browser.

## Register the apps and publish DNS

From the publisher machine, with Grafana on loopback port 3000 and your second
app on loopback port 8080:

```bash
tunn login
tunn policy login
tunn domain add '*.apps.example.com' --tunnel grafana
tunn domain add '*.apps.example.com' --tunnel dash
```

`tunn login` saves the renewable publisher credential. `tunn policy login`
saves a separate owner credential for domain management, valid for 24 hours.
Approve both as the same owner account. Domain commands use the owner login;
repeat `tunn policy login` after it expires. An existing owner JWT can also be
supplied with `--owner-token-file /private/path/owner-jwt`. For another relay
use `--server your-relay.example.com:443` consistently with its publisher
configuration.

Copy the returned `cname_target` exactly. In your DNS provider create:

| Type | Name | Value |
| --- | --- | --- |
| TXT | `_tunn-verification.apps.example.com` | the returned `cname_target` |
| CNAME | `*.apps.example.com` | `tunn.to.` |

Use DNS-only mode for the CNAME. For your own relay, use its reachable edge
hostname as the CNAME value. Keep the TXT record: ownership is checked again
hourly. Wait for the records to resolve, then run:

```bash
dig +short TXT _tunn-verification.apps.example.com
dig +short CNAME grafana.apps.example.com
tunn domain verify '*.apps.example.com'
tunn domain list
```

Expect `state: ready` and both `grafana` and `dash` in `app_names`. Do not add
separate exact-domain claims inside this wildcard: they overlap it.

## Start both publishers

Run one command per terminal, or supervise each as a service:

```bash
tunn serve --namespace apps.example.com --name grafana http://127.0.0.1:3000
tunn serve --namespace apps.example.com --name dash http://127.0.0.1:8080
```

Both connect to the same daemon. Open `https://grafana.apps.example.com`, choose
Google and sign in. Then open `https://dash.apps.example.com` in the same
browser profile. The second app makes a brief trip through tunn's login
origin and returns without another Google prompt. Each app gets its own secure,
HTTP-only cookie; the login cookie stays on the platform domain.

The gate authorizes the namespace owner. A different account gets 403 unless
you explicitly share access. Apps receive `X-Tunn-User-Email` and a signed
`X-Tunn-Identity`; [verify the assertion](../APPS-DOMAINS.md#identity-assertions-and-key-rotation)
if your app uses it. Keep each app's own authentication enabled until you have
configured and tested its trusted-proxy login. tunn alone does not configure
Grafana's login settings.

## Check the live setup

- Open both URLs in one fresh browser profile. Complete Google sign-in once;
  check that both dashboards load and their certificates match their hostnames.
- Sign out on the platform. Both apps must refuse their old cookies on the
  next request. Retry app login and sign in again to restore access.
- Use another fresh profile and an unshared Google account. Both apps must
  return 403. A copied app link must not grant access.
- If you shared a person into both apps, remove that person's access from both
  apps at `/account/sharing` on the login origin. Their next request must fail
  on each app; idle streams should close within five seconds. An operator's
  account suspension also denies that account on both apps in one action; see
  [account operations](../ACCOUNT-OPERATIONS.md).

Platform sign-out revokes that account's browser sessions on every app host
before clearing the platform cookie. Retained app cookies fail on the next
request, without visiting each host. The gate checks a durable revocation epoch
in its existing live account lookup on every request; there is no revocation
cache or stale-access window. Idle streams recheck once per second and close
within five seconds, including the authority timeout. Signing in again creates
new sessions; other accounts and separately authorized device credentials are
unaffected. If the login authority is unavailable, sign-out returns an error so
you can retry, and app checks fail closed.

Removing access to one app leaves the other app's permission intact. These
checks use tunn sessions, so an app's separate login session is not a substitute
for checking the tunn gate.

The offline regression is `TestTwoDomainLoginJourney`:

```bash
umask 077
go test -p 2 -count=1 -timeout 2m ./internal/host -run '^TestTwoDomainLoginJourney$' -v
```

It starts the production relay in a test subprocess with mocked Google, DNS
and certificate issuance, verifies two app names, and checks one login, stranger
denial, platform sign-out with both app cookies retained, sign-in again in the
same browser, and account-wide suspension. Real Google
consent, public DNS, and production CA issuance/renewal still need the live
checks above.
