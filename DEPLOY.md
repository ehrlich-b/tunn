# Email fallback for GitHub sign-in

These are Bryan's production actions. They have not been run by this lane.
Use the existing production checkout and its reviewed Fly configuration; keep
its topology, persistent data, SMTP and other secrets intact. Follow the release
readiness and rollout requirements in [DEPLOY-RUNBOOK.md](DEPLOY-RUNBOOK.md).

1. Disable the suspended GitHub OAuth app:

   ```sh
   fly secrets unset TUNN_GITHUB_CLIENT_ID TUNN_GITHUB_CLIENT_SECRET -a tunn
   ```

2. Optionally add Google sign-in. Create a Google OAuth web client with the
   exact authorized redirect URI `https://tunn.to/auth/google/callback`.
   Keep the valid production `TUNN_PUBLIC_ADDR=tunn.to:443` configuration;
   this branch omits the default HTTPS port in Google redirect URIs. After
   deploying this branch in step 3, set the client credentials privately,
   replacing the placeholders:

   ```sh
   fly secrets set TUNN_GOOGLE_CLIENT_ID=... TUNN_GOOGLE_CLIENT_SECRET=... -a tunn
   ```

3. Deploy this branch from the production checkout with its existing reviewed
   `fly.toml` (use the machine-specific rollout in DEPLOY-RUNBOOK.md for a mesh):

   ```sh
   git switch codex/tunn-login-fallback-20261015
   fly deploy -a tunn
   ```

Email sign-in requires the existing SMTP configuration. After rollout, Bryan
checks that the GitHub button is absent, the fallback line is visible, and
Continue with Email reaches an existing GitHub account using the same verified
mailbox. He also checks `tunn login` through email and explicit device approval.
If Google was added, he checks its sign-in separately.

## Account carryover evidence

`TestGitHubAccountMagicLinkFallbackForBothVerifiedEmails` creates an account
through the GitHub callback with verified primary address A and verified alias B,
then disables GitHub and completes a magic-link login independently for each.
Both A and B reach the same account ID, retain A as primary and retain both
aliases; no second account is created. This applies to addresses that GitHub
previously supplied as verified, not arbitrary addresses on a GitHub profile.
An address the user cannot receive mail at cannot complete email sign-in.

`TestLoginGitHubEmailFallback` covers GitHub off/on.
`TestCLIDeviceLoginThroughEmailWithoutGitHub` runs the CLI login client against
a local TLS relay and captured mail, including confirmation and saved renewable
credentials. The existing email/device flow needs no code fix.
