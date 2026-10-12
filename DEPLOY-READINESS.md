# Integrated release coordinator checklist

Target branch: `codex/tunn-release-integrated-20261011`, local checkout
`/work/lanes/tunn-release-merge/tunn`. The integrated source head is
`197f5bc6958074685b7f869e3916458a313787de`; the final documentation commit
is its descendant and must preserve its application, test, dependency and
container inputs. See [RELEASE-VALIDATION.md](RELEASE-VALIDATION.md) for current
gate results and immutable evidence. This checklist has not been executed
against production. Nothing was pushed or deployed by the integration lane.

The four remaining deployment blockers are the sharing/domains review verdicts,
a current domain-management credential, DNS, and live acceptance. Complete the
items below in order. Review findings may add required fixes; if they do, merge
committed fixes and repeat validation before promoting that changed source.

## 1. Close the review and artifact gates

- [ ] Obtain `/work/lanes/tunn-share/review/REVIEW.md` and
  `/work/lanes/tunn-apps-domain/review/REVIEW.md`. Record each verdict, reviewed
  SHA and report hash. Missing reports do not establish approval. For BLOCK or
  SHIP-AFTER-FIXES, map every finding to this exact integrated source, resolve
  required fixes and record completed regression checks.
- [ ] Confirm the carrier `8cb0b92505fdaaaf7497005aea7521e84f157ee1`, R2 fix
  `dff48d378b5cd0416c7557c872565aeecd1aa03e`, and SSO fix
  `1c24085d0883084bfab9e6bae830018b00a5c181` are ancestors of the selected
  release: `git merge-base --is-ancestor <sha> HEAD` for each. Require a clean
  working tree and the passing vet, full, full-race, SSO, transport and 20-repeat
  413 gates in RELEASE-VALIDATION.md.
- [ ] Pin the final commit and built image digest. Use this checkout's
  `forgeapp-tunn.diff` and `docs/cf-dns-cname.diff`, rather than older lane
  copies. Publish the integrated CLI/image only through the coordinator's
  authorized release process after the review gate closes.

## 2. Inventory, backup and configuration

- [ ] Follow [DEPLOY-RUNBOOK.md](DEPLOY-RUNBOOK.md), sections 1–3: inventory the
  actual deployed config, machine roles/images, single SQLite login writer,
  resource nodes, mounts, forge publisher unit and credential directory. Save
  the previous image/config; take a consistent SQLite backup, require
  `PRAGMA integrity_check` = `ok`, and export it through private backup tooling.
  Keep independent recovery access and preserve existing signing/node/domain
  secrets, platform certificates and SSH host key.
- [ ] Keep `TUNN_BILLING_ENABLED=false`. For this wildcard release, leave
  `TUNN_OIDC_ORGS_FILE` unset/empty **on every relay**, or provision a private
  mode 0600/0400 file containing `[]`, and restart every relay. No org tenant
  registration is required for this disabled configuration. Confirm org starts
  and callbacks return 404 without state/cookies; personal Google login remains
  enabled. Before any later org enablement, complete real Okta/Entra/Workspace
  tenant acceptance in [docs/org-sso.md](docs/org-sso.md).
- [ ] Configure custom domains, Google OAuth and the exact callback for the
  inventoried login authority. Provision the same private Ed25519 identity ring
  on every terminating relay, persistent encrypted domain storage and its key,
  ACME contact/directory, and the HTTP-01 listener. Materialize private files
  with correct ownership/mode. Keep internal gRPC 50051 private. Verify raw TCP
  80 and 443 plus UDP 443 reach each edge and that only one login authority
  writes the domain database.
- [ ] Build/publish the pinned integrated artifacts and roll existing resource
  relays before the single login writer using the inventoried config and
  DEPLOY-RUNBOOK.md. Preserve durable clients' renewal authority. Require
  health/readiness, public-only JWKS, additive migration integrity and billing
  checkout disabled. Update forge/laptops through the authorized CLI workflow.

## 3. Provision management authority and register the namespace

- [ ] Confirm Bryan's primary account email is `ehrlich.bryan@gmail.com`, the
  account has Pro entitlement and free reserved-name slots for `grafana` and
  `dash` (the account has four shared slots; `forge-ssh` may occupy one).
  Confirm each app listens only on its declared localhost port.
- [ ] Obtain a **current management access JWT** using the approved owner
  authentication workflow, store it in a private file, and set
  `FORGEAPP_TUNN_OWNER_TOKEN_FILE` to its absolute path. Existing durable
  `device_access` publish/connect credentials cannot register/verify domains.
  Preserve forge's existing absolute `TUNN_CONFIG_DIR`; never print or pass
  credential contents as command arguments. Repeat owner authentication if
  the management token expires before registration finishes.
- [ ] After the coordinator's relay rollout and health checks, use the
  integrated CLI to register the wildcard and reserve both matching app labels:

  ```sh
  tunn domain add '*.apps.ehrlich.dev' --tunnel grafana --owner-token-file "$FORGEAPP_TUNN_OWNER_TOKEN_FILE"
  tunn domain add '*.apps.ehrlich.dev' --tunnel dash --owner-token-file "$FORGEAPP_TUNN_OWNER_TOKEN_FILE"
  ```

  Retain the returned public ownership `cname_target`. Do not replace the
  shared wildcard claim with a conflicting concrete domain claim.

## 4. Set and verify DNS

- [ ] Through the approved estate DNS workflow, set `*.apps.ehrlich.dev` CNAME
  to `tunn.to`, DNS only (`proxied=false`), automatic TTL; remove conflicting
  address records. Set `_tunn-verification.apps.ehrlich.dev` TXT to the exact
  returned `cname_target`. The generic routing CNAME alone is not ownership
  proof. Retain TXT for hourly refresh and the two-hour proof lease.
- [ ] Verify authoritative and public DNS answers for the wildcard, concrete
  `grafana.apps.ehrlich.dev` / `dash.apps.ehrlich.dev`, and the TXT record, then
  run:

  ```sh
  tunn domain verify '*.apps.ehrlich.dev' --owner-token-file "$FORGEAPP_TUNN_OWNER_TOKEN_FILE"
  ```

  Record verified ownership; test HTTP-01 reaches every terminating edge.

## 5. Install publishers and finish live acceptance

- [ ] Follow [FORGEAPP-TUNN.md](FORGEAPP-TUNN.md) with this integrated patch:

  ```sh
  cd /work/lanes/forge-apps
  git apply --check /work/lanes/tunn-release-merge/tunn/forgeapp-tunn.diff
  git apply /work/lanes/tunn-release-merge/tunn/forgeapp-tunn.diff
  ./forgeapp install grafana
  ./forgeapp install dash
  ./forgeapp start grafana
  ./forgeapp start dash
  ```

  Require both app and `forgeapp-tunn-<name>` units active; publishers must use
  the matching reserved names, private default exposure and original durable
  credential directory. Check repeat install, start/stop/remove ordering and
  renewal/reconnect. Install success alone does not prove TLS/browser readiness.
- [ ] Exercise disposable staging CA issuance first, then production issuance
  for **both** concrete hostnames using separate production namespace/cache.
  Record trusted certificate names/chains, restart cache reuse and actual
  renewal. No wildcard certificate or DNS API key is needed. Local Pebble
  acceptance does not close production CA/renewal acceptance.
- [ ] In fresh browsers, visit both public app URLs while signed out and
  require Google login. Admit verified `ehrlich.bryan@gmail.com`; deny another
  verified Google account with 403, plus aliases/lookalikes/unverified identities
  and alternate providers. Prove repeat/cross-app login across the actual edges,
  host-bound cookies and one-use handoff, and no parent cookie/token at origins.
- [ ] On each edge prove client identity headers are stripped, injected EdDSA
  assertions have the exact hostname audience/issuer and verify against JWKS,
  and HTTP streaming/WebSocket handshakes retain the owner gate. Confirm direct
  app ingress is blocked. Record denial of cross-owner/bearer/grant attempts,
  shared-resource revocation and default-private versus intended legacy-public
  behavior.
- [ ] Verify the live topology's existing forge SSH, native OpenSSH/SFTP and
  shared HTTPS/SSH port, trusted fingerprints, same-node publisher routing,
  revocation and supervised reconnect. Keep ProxyCommand fallback and separate
  recovery access. Retain prior image/config and follow DEPLOY-RUNBOOK.md's
  rollback sequence: stop new app publishers/block custom ingress before old
  relay code returns; preserve the current additive database and secrets.
- [ ] Attach dated live evidence and final review dispositions, close all four
  blockers in RELEASE-VALIDATION.md, then have the coordinator record release
  acceptance for `https://grafana.apps.ehrlich.dev` and
  `https://dash.apps.ehrlich.dev`.
