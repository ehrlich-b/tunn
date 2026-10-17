# Attach a domain, publish an app, open it, sign in

Prerequisites: tunn installed on your build host, a durable publisher login belonging to
`owner@example.com`, an existing Pro account, and an app process listening
only on `127.0.0.1:3000`. Keep the app and publisher supervised by systemd.
Pro permits 50 app names per custom namespace; the four shared `*.tunn.to`
reservations and ten concurrent tunnels remain independent. Plans and billing
are unchanged. The relay prerequisites are in [the operator guide](docs/APPS-DOMAINS.md).

First app: **four one-time domain steps, one publishing step, two browser steps**
(seven steps after prerequisites):

1. Attach the namespace and register the first app name:
   `tunn domain add '*.apps.example.com' --tunnel dashboard`.
   Save the returned `cname_target`; it is the unique ownership proof value.
2. In your DNS provider, set the one-time, DNS-only CNAME
   `*.apps.example.com → tunn.to` (`proxied=false`, automatic TTL).
3. Set TXT `_tunn-verification.apps.example.com` to the exact `cname_target`
   from step 1. A generic CNAME to the edge routes traffic but cannot prove
   publisher ownership. Leave this TXT in place for hourly ownership checks.
4. Run `tunn domain verify '*.apps.example.com'`. This verifies ownership;
   concrete hostname certificates are issued on first connection, not wildcard
   certificates. No DNS API key is needed for HTTP-01 issuance or renewal.
5. Publish `tunn serve --namespace apps.example.com --name dashboard http://127.0.0.1:3000` under the same
   account and leave it running. The CLI may also print its `tunn.to` address;
   the app address is `https://dashboard.apps.example.com`.
6. Open that app URL. The edge obtains its real certificate, then sends the
   browser to tunn's normal sign-in page.
7. Sign in to the owning personal account using Google or an email link where
   offered by the relay, with a verified mailbox linked to that account.
   The login returns to tunn; a one-use, browser-bound handoff returns to the app.
   The app receives a signed identity JWT and `X-Tunn-User-Email`.

Next app: **two publisher steps and one browser step**: repeat
`tunn domain add '*.apps.example.com' --tunnel reports` (idempotently reuses the
claim and registers that name), publish with `--namespace apps.example.com --name reports`, open
`https://reports.apps.example.com`. The central tunn account session is reused; no
new provider login is required while it is valid. Pro namespace app-name
limit: 50 names, independent of four shared reservations. `tunn domain list`
shows the registered labels and publisher IDs. The 51st name reports that limit;
repeating an existing name still succeeds. Deleting the namespace removes its
app names and keys together, preserving existing shared reservations. Returning to an already signed-in app is **one browser step**.
Provider consent screens or reading the email link may add interactions to the first login.

A different account receives 403 after login unless the owner
explicitly shares the app with that account's verified email. Use the existing
sharing dashboard/person grants or publisher allow-list; removing access or
letting a person grant expire takes effect on new requests and active streams.
Owner aliases already verified into the same account are accepted regardless of
primary email or provider. Unverified GitHub primary emails and non-authoritative
Google third-party emails fail at the provider callback. Public publication,
endpoint bearers and consumer grants do not bypass the wildcard account gate.
Older central/app cookies require one fresh sign-in after this update.

Only `/.tunn/sso/callback` is reserved on app origins. Other paths belong to the
app. App cookies remain separate; tunn session cookies are stripped before
forwarding. The central session lasts seven days and app sessions one hour.

# Native OpenSSH pilot: first and repeat sessions

This is the implemented increment 3 journey, using existing origin keys. Only
the publisher installs tunn. The recipient uses OpenSSH and an email inbox;
there is no tunn executable, account token, ProxyCommand helper, or VPN on the
recipient. The example names the existing origin user `deploy` and resource
`build-host-ssh`. No origin keys or sshd settings are managed by this increment.

## Operator prerequisites (requires a server deployment)

Deploy this commit to the authoritative login relay. Keep its SQLite key registry
and SSH host private key on persistent storage. Enable the existing opt-in SSH
front door by setting `TUNN_SSH_HOST_KEY_FILE` to that key; an empty value keeps
SSH disabled. Generate the key once, never on each restart:

```sh
ssh-keygen -t ed25519 -N '' -f /data/ssh_host_ed25519_key
ssh-keygen -lf /data/ssh_host_ed25519_key.pub
```

Route raw TCP/443 to this login node and place the pilot publisher on the same
relay node. The shared listener still accepts HTTPS. A separate raw listener is
optional (`TUNN_SSH_ADDR=:22`). SMTP must be configured for email enrollment.
Publish the relay host-key fingerprint through an independently trusted channel.
No new database schema or manual migration is required; existing key/link tables
remain unchanged. There is no authenticated SSH routing between relay nodes in
this pilot, and HTTPS-only egress can block raw SSH on 443. External-network
acceptance remains a promotion prerequisite.

## Publisher, first session

Prerequisites: tunn installed on the origin machine, origin sshd reachable at
`127.0.0.1:22`, and Alice's selected public key already authorized for `deploy` by
the origin owner. The owner must arrange origin authorization separately if it
is absent. A relay invitation alone will still produce `Permission denied` at
sshd. Origin host private keys never leave the origin.

1. On the publishing machine, enroll its renewable account credential:

   ```sh
   tunn login
   ```

   Open the displayed verification URL if the browser cannot open on the server.
   Sign in using a method offered by the relay, compare the displayed device
   code with the terminal, and click **Authorize**. For email sign-in, enter the
   publisher's email, request its magic link, and open it from the inbox first.
   The terminal prints `Logged in successfully!`.

2. Publish the configured target and grant Alice's verified email admission:

   ```sh
   tunn tcp --account-only --name build-host-ssh --allow alice@example.com 127.0.0.1:22
   ```

   Keep this foreground process running. Pilot routing must send this publisher
   to the same relay as the SSH front door. If the ordinary cluster address
   cannot guarantee this, use its dedicated pilot hostname with
   `--server pilot.tunn.to:443`, and use `pilot.tunn.to` in all recipient commands.

3. Obtain the origin fingerprint locally:

   ```sh
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

   Give Alice the invitation below, the operator's trusted relay fingerprint,
   and all host-key fingerprints enabled by the origin sshd (if more than one
   algorithm is enabled, include those public keys too). Use a trusted channel
   independent of this relay to convey the origin identity.

   ```text
   build-host-ssh is shared with alice@example.com.
   Use your own SSH key that is already authorized for deploy on this origin.
   Link that same key once using the email command below, then use plain ssh.
   Relay fingerprint: <operator-provided trusted fingerprint>
   Origin fingerprint(s): <origin owner's trusted fingerprint(s)>
   ssh -J tunn@tunn.to:443 deploy@build-host-ssh
   ```

There is no Share button or automatic invitation email in this increment. The
publisher's `--allow` flag and a copied message are the implemented invitation.

## Recipient, first session: six actions after receiving the invitation

Assumes an existing default OpenSSH key that is already authorized by the origin,
no cached host keys, and direct receipt of both trusted fingerprints. Count:
**two commands, two trust confirmations, two browser clicks**. Reading and
comparing each fingerprint is part of its confirmation; email delivery and
owner approval are elapsed waiting time, not counted as clicks.

1. Request one-time key enrollment using plain OpenSSH:

   ```sh
   ssh -T -p 443 tunn@tunn.to login --email alice@example.com
   ```

2. At OpenSSH's first-use relay host-key prompt, compare the fingerprint against
   the operator-provided value; type `yes` only if it matches. The terminal prints
   Alice's email and the fingerprint of the key that actually authenticated.
   It never prints the email bearer link.

3. Open the email link in Alice's inbox within five minutes. This GET displays
   a confirmation page and does not enroll the key; mail scanners cannot enroll
   a key just by opening the link.

4. Compare the page's key fingerprint with the one printed by the SSH command
   and click **Link SSH key**. Confirm only a request Alice initiated for a key
   she controls. The POST enrolls the key and says to reconnect. No separate
   recipient account creation or tunn login is required.

5. Start the inner session:

   ```sh
   ssh -J tunn@tunn.to:443 deploy@build-host-ssh
   ```

6. At the first-use origin host-key prompt, compare against the origin owner's
   supplied fingerprint and type `yes` only if it matches. The origin's sshd
   then authenticates Alice for `deploy`; successful authentication opens its
   shell. A non-granted email fails at the relay even with a registered key.

For a new device without a key, `ssh-keygen -t ed25519` and separate origin-key
approval are additional actions. Passphrase entry or agent unlocking may also
add an action. For a nondefault key, use ordinary OpenSSH configuration for both
the jump and destination, because destination `-i` does not configure the jump:

```sshconfig
Host tunn.to
    User tunn
    Port 443
    IdentityFile ~/.ssh/alice_work_key
    IdentitiesOnly yes
Host build-host-ssh
    User deploy
    IdentityFile ~/.ssh/alice_work_key
    IdentitiesOnly yes
    ProxyJump tunn@tunn.to:443
```

Then the enrollment command above selects that key and `ssh build-host-ssh` uses the
same native transport. Editing this optional config is an additional first-use
action; the default-key command requires no config edit.

## Publisher and recipient, second session

Publisher: if the foreground process is still running, no action is needed.
Otherwise repeat the same `tunn tcp --account-only ...` publication command.
The inherited credential manager renews the publisher's enrolled credential;
revoked publisher enrollment requires a new `tunn login`.

Recipient: **one command**, with the enrolled key available:

```sh
ssh -J tunn@tunn.to:443 deploy@build-host-ssh
```

Both host keys are now pinned by OpenSSH. No recipient tunn token can expire,
and no repeated email link is required. Key removal or a changed resource grant
still denies access. Native transfer tools work through the same route:

```sh
sftp -J tunn@tunn.to:443 deploy@build-host-ssh
scp -o ProxyJump=tunn@tunn.to:443 ./artifact.bin deploy@build-host-ssh:/tmp/artifact.bin
```

## Revocation as built

To remove Alice from this resource, stop the specific foreground publisher with
Ctrl-C, then restart with Alice absent from the allow-list. For an owner-only
endpoint:

```sh
tunn tcp --account-only --name build-host-ssh 127.0.0.1:22
```

Stopping publication cuts its active tunneled sessions; restarting uses a new
resource generation and denies Alice's next connection. There is no live people
editor or separate persistent SSH grant store in this increment; the publisher's
configuration remains the source of endpoint grants. For a supervised publisher,
edit its persisted allow-list before restarting that specific service.

To revoke one enrolled device key, use another linked key in Alice's account:

```sh
ssh -T -p 443 tunn@tunn.to keys list
ssh -T -p 443 tunn@tunn.to keys remove SHA256:KEY_FINGERPRINT
```

If removing the key used for the command, this is its last successful command.
New forwarding channels recheck ownership even on reused jump transports. Active
streams poll the key registry, email grant and resource generation once per
second, with a three-second check timeout; the designed authority-check bound
is five seconds. Authority failure closes the stream. Origin authorization is
separate: removing a relay grant/key does not remove origin authorized_keys or
terminate sessions arriving through another route.
