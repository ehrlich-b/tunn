# Sign-in provider configuration

Configure sign-in providers on the login authority and preserve the existing
SMTP configuration, database, public authority and persistent secrets.

## Email fallback

With SMTP configured, leaving both `TUNN_GITHUB_CLIENT_ID` and
`TUNN_GITHUB_CLIENT_SECRET` empty hides the GitHub button and keeps email sign-in
available. Existing GitHub users can use a previously verified mailbox to reach
their existing account. An address the user cannot receive mail at cannot
complete email sign-in.

On Fly.io, an operator can unset those two secrets in the deployment's app.
An unstaged secret change restarts machines, drops publisher streams and active
connections, and requires supervised publishers to reconnect. Keep independent
administrative access throughout the maintenance window.

## Google sign-in

Register a Google OAuth web client with the exact authorized redirect URI.
For `TUNN_PUBLIC_ADDR=tunn.to:443`, use
`https://tunn.to/auth/google/callback`. Default HTTPS port 443 is omitted;
retain a custom port when one is configured. Set `TUNN_GOOGLE_CLIENT_ID` and
`TUNN_GOOGLE_CLIENT_SECRET` privately, then verify sign-in with a test account.

For another relay, replace the hostname with its configured public authority.
See [release notes](RELEASE-NOTES.md) for configuration and migration behavior
and [self-hosting](docs/self-hosting.md) for installation and recovery.

## Verify account continuity

Check GitHub off/on behavior and email fallback with
`TestLoginGitHubEmailFallback` and
`TestGitHubAccountMagicLinkFallbackForBothVerifiedEmails`. The latter verifies
that a previously verified primary address and alias retain the same account.
`TestCLIDeviceLoginThroughEmailWithoutGitHub` exercises CLI device approval
against a disposable local TLS relay and captured mail.

## Scheduled certificate renewal on macOS

Set `TUNN_CERT_DOMAIN`, `TUNN_FLY_APP` and `TUNN_CERT_EMAIL` for your deployment.
After configuring renewal credentials, `make cert-install-schedule` renders a
private launchd job using the current checkout and your home directory. Keep
that checkout in place while the job is installed. The daily job runs
`renew-certs.sh`, which renews and publishes the certificate for that deployment.
