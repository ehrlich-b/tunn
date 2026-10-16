# Email fallback for GitHub sign-in

These are production steps for the operator to run.
Use the existing production checkout and its reviewed Fly configuration; keep
its topology, persistent data, SMTP and other secrets intact.

1. **Immediate fix: disable the suspended GitHub OAuth app.**
   Step 1 alone restores email sign-in on the current production image (`110485c`)
   with the existing SMTP configuration; no application deployment is required.
   That image accepts both GitHub secrets empty, hides the GitHub button and
   keeps the email form. Existing GitHub users continue with the same verified
   email address to reach their account.

   ```sh
   fly secrets unset TUNN_GITHUB_CLIENT_ID TUNN_GITHUB_CLIENT_SECRET -a tunn
   ```

   This command has no `--stage`: it restarts every machine immediately and
   drops publisher streams and active connections. Bryan should retain
   independent access and allow supervised publishers to reconnect; users
   reopen sessions after the relay is ready.

2. **Optional Google sign-in, after the gated carrier rollout in step 3.**
   Create a Google OAuth web client with the exact authorized redirect URI
   `https://tunn.to/auth/google/callback`. Keep the valid production
   `TUNN_PUBLIC_ADDR=tunn.to:443` configuration; the carrier omits the default
   HTTPS port in Google redirect URIs. After the approved rollout, set the
   client credentials privately, replacing the placeholders:

   ```sh
   fly secrets set TUNN_GOOGLE_CLIENT_ID=... TUNN_GOOGLE_CLIENT_SECRET=... -a tunn
   ```

   This unstaged secret change also restarts machines and interrupts streams.

3. **Fallback line: deferred carrier release, currently blocked.**
   The fallback line and Google callback normalization ship with the integrated
   carrier (`a5122b2` base), which includes schema migrations, private-by-default
   sharing, durable credentials and custom domains beyond production `110485c`.
   This is not a standalone login hotfix.

   Do not deploy this carrier until all four blockers in
   [RELEASE-VALIDATION.md](RELEASE-VALIDATION.md) close. After release approval
   and source handoff, Bryan deploys the
   reviewed carrier using [DEPLOY-RUNBOOK.md](DEPLOY-RUNBOOK.md), including its
   inventory, backup and validation steps. Use the recorded `fly.release.toml`,
   an immutable image digest, and the runbook's machine-specific deploy commands
   with `--only-machines` and `--update-only --ha=false` to preserve the single
   login writer. Roll resource machines first if present, then the login machine.
   Step 1 does not depend on this release.

After step 1, Bryan checks that the GitHub button is absent and Continue with
Email reaches an existing GitHub account using the same verified mailbox, and
checks `tunn login` through email and explicit device approval. The fallback
line appears only after the approved carrier rollout, when email is configured.
If Google was added afterward, he checks its sign-in separately.

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
