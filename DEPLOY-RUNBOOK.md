# Coordinator deployment order

This file is a handoff for Bryan or the pre-approved coordinator. Nothing here has been executed against production. Do not deploy while RELEASE-VALIDATION.md contains unresolved BLOCK/SHIP-AFTER-FIXES findings. Keep billing disabled throughout. Live machine roles, secret names and current images have not been inspected; collect them before choosing the machine IDs below.

## 1. Inventory and consistent backup

Keep independent access to forge: the SSH path being upgraded cannot be the only recovery channel. Record the running publisher binary/unit/environment and credential directory without printing its contents. Record every Fly machine's role/region/image digest, mount and current config. Preserve exact JWT/node/domain-encryption secrets, platform TLS, signing ring and relay SSH host key.

```sh
fly status --app tunn
fly machines list --app tunn
fly volumes list --app tunn
fly releases --app tunn
fly config show --app tunn
fly secrets list --app tunn
```

Save the actual deployed TOML as private `fly.release.rollback.toml` using the coordinator's existing configuration inventory, and an editable copy as `fly.release.toml`. Do not deploy `fly.toml.dist` over unknown live topology. Set `LOGIN_MACHINE_ID` to the inventoried single SQLite writer, `RESOURCE_MACHINE_IDS` to other resource nodes (empty for a single-node deployment), `TUNN_PREVIOUS_IMAGE` to the recorded previous immutable image digest, and record any per-machine differences. `--ha=false --update-only` prevents creation of another login writer. Pilot SSH must reach that login node and the same-node forge publisher; ordinary anycast routing does not establish that property.

```sh
fly ssh console --app tunn --machine "$LOGIN_MACHINE_ID"
```

Inside the selected console, first verify `TUNN_DB_PATH` and mount. With the inventoried path `/data/tunn.db` and a fresh backup filename:

```sh
set -eu
umask 077
test ! -e /data/tunn-release-before.db
sqlite3 /data/tunn.db '.backup /data/tunn-release-before.db'
sqlite3 -readonly /data/tunn-release-before.db 'PRAGMA integrity_check;'
sha256sum /data/tunn-release-before.db
```

Require `ok`; export an encrypted off-machine backup through the normal coordinator backup tooling. Preserve the encrypted domain database together with its encryption secret. Do not copy live SQLite/WAL files or run fixture-init. Preserve additive migration/rollback history throughout recovery.

## 2. Provision production config, files and network

Use RELEASE-NOTES.md's settings table. In the reviewed live config preserve role flags, DB/mounts, control authority, platform certificates, discovery, internal TLS/node secret and existing network handlers. Keep `TUNN_BILLING_ENABLED=false`, price display 5/48; add no Stripe setup. Enable custom domains only with Google OAuth, identity ring, encryption secret/contact and working HTTP-01. Register the exact configured Google callback (template authority `https://tunn.to:443/auth/google/callback`), and exact org callbacks if enabling OIDC. Real org tenants/delegation acceptance is separate and remains required.

Every terminating edge needs raw TCP 443, UDP 443 and raw TCP 80 HTTP-01. In the reviewed config add this service if absent, without force_https or TLS/HTTP handlers:

```toml
[[services]]
  internal_port = 80
  protocol = "tcp"
  auto_stop_machines = false
  auto_start_machines = true
  [[services.ports]]
    port = 80
```

Set `TUNN_CUSTOM_DOMAINS=true`, `TUNN_HTTP01_ADDR=0.0.0.0:80`, `TUNN_IDENTITY_KEYS_FILE=/run/tunn/identity-keys.json`; login node also needs `TUNN_DOMAIN_KEY_SECRET`, `TUNN_ACME_EMAIL` and the ACME directory. Keep port 50051 internal. Provision one persistent SSH host key before enabling `TUNN_SSH_HOST_KEY_FILE=/data/ssh_host_ed25519_key` on the login node; never generate at each restart. Preserve current keys where already configured. Optional port 22 requires separate raw service routing, but shared raw 443 is sufficient for the pilot.

Transfer new values through the private coordinator secret manager. Its private env input must include the existing secrets that must remain stable and only the approved new secrets; exclude actual values from logs/history. Stage the input:

```sh
fly secrets import --app tunn --stage < "$TUNN_RELEASE_SECRETS_FILE"
```

The Fly file secret `TUNN_IDENTITY_RING_FILE` must contain the base64 private JWK file and `--file-secret /run/tunn/identity-keys.json=TUNN_IDENTITY_RING_FILE` materializes it. If enabling org SSO, similarly provision `TUNN_OIDC_ORGS_FILE` and Workspace delegation files privately on every relevant node. Check actual file ownership/mode 0600 before startup; do not assume an image includes secrets. Start with a disposable ACME staging namespace/authority to test issuance; never reuse a cached staging certificate as a production certificate. Then use the production CA and perform production issuance/renewal acceptance after DNS setup in FORGEAPP-TUNN.md.

## 3. Build and roll relays before clients

At the reviewed carrier checkout, coordinator commands (these push an image only when run by the coordinator):

```sh
TUNN_RELEASE_TAG="carrier-$(git rev-parse --short=12 HEAD)"
fly auth docker
docker build --platform linux/amd64 -t "registry.fly.io/tunn:$TUNN_RELEASE_TAG" .
docker push "registry.fly.io/tunn:$TUNN_RELEASE_TAG"
TUNN_RELEASE_IMAGE=$(docker inspect --format '{{index .RepoDigests 0}}' "registry.fly.io/tunn:$TUNN_RELEASE_TAG")
test -n "$TUNN_RELEASE_IMAGE"
```

Record the digest and preserve the prior one. Build uses the merged Go 1.26 Dockerfile; source tests used Go 1.27.2. The container gate is recorded separately in RELEASE-VALIDATION.md. Coordinate approved config/roles per machine; do not turn every resource node into a login node.

For a mesh, upgrade existing resource machines first while legacy clients remain:

```sh
fly deploy --app tunn --config fly.release.toml --image "$TUNN_RELEASE_IMAGE" --only-machines "$RESOURCE_MACHINE_IDS" --update-only --ha=false --strategy rolling --max-concurrent 1 --file-secret /run/tunn/identity-keys.json=TUNN_IDENTITY_RING_FILE
```

Skip that command when there are no separate resource nodes. Then upgrade the authoritative login machine:

```sh
fly deploy --app tunn --config fly.release.toml --image "$TUNN_RELEASE_IMAGE" --only-machines "$LOGIN_MACHINE_ID" --update-only --ha=false --strategy rolling --max-concurrent 1 --file-secret /run/tunn/identity-keys.json=TUNN_IDENTITY_RING_FILE
fly status --app tunn
fly checks list --app tunn
fly logs --app tunn
```

In a single-node deployment the second deploy is the whole relay rollout. Do not start new durable clients until all resources accept durable identities and login issuance is ready. For enabled orgs add their approved `--file-secret` mappings to both commands. Do not ship placeholder files.

## 4. Health, migration and user acceptance

```sh
curl --fail --silent --show-error https://tunn.to/healthz
curl --fail --silent --show-error https://tunn.to/readyz
curl --fail --silent --show-error https://tunn.to/.well-known/tunn-jwks.json
curl --fail --silent --show-error https://tunn.to/pricing
curl --fail --silent --show-error https://tunn.to/ngrok-alternative
curl --fail --silent --show-error https://tunn.to/mcp-to-claude
curl --fail --silent --show-error https://tunn.to/share-dev-server-oauth
```

Health alone does not prove app permission/routing. In the login console inspect table names and PRAGMA integrity_check; confirm additive durable/share/domain/OIDC/key/billing schema, existing account plans/reservations and old session/device-code compatibility without printing tokens. Check an existing anonymous legacy resource remains public, then a disposable upgraded default-private resource refuses anonymous/wrong-person access, admits its owner, grants/revokes a recipient and cuts off an idle stream. Authenticated Free checkout must return 503 with billing disabled, and provider configuration must remain unchanged. Verify old management/device/billing credential boundaries.

Complete FORGEAPP-TUNN.md's DNS/ownership and management-credential setup. Verify real production CA issuance and subsequent renewal, signed-out Google redirect, Bryan admission, another Google account denial, host-bound handoff and signed headers/JWKS on each edge. Do not infer this from fixture success. Org SSO requires disposable real Okta/Entra/Workspace consent/group/overage/offboarding acceptance before advertising it.

Publish the integrated CLI through the coordinator's normal release pipeline; the installer still reads the latest published GitHub release. Upgrade forge's publisher and each laptop separately. On forge use its existing absolute `TUNN_CONFIG_DIR`, perform explicit browser device authorization, retain `tcp --account-only --name forge-ssh 127.0.0.1:22`, and restart its inventoried unit to load durable state. Never print/copy credential contents. Verify repeated renewal without restart and independent laptop reconnect. Native pilot acceptance requires trusted relay/origin host fingerprints, key proof plus email confirmation, SFTP, same-node routing and revocation. Keep existing ProxyCommand fallback.

## 5. Experience and rollback

Replacing an owning relay drops its publisher control stream and active HTTP/WS/TCP/SSH connections. Forge's supervised publisher reconnects once the relay is ready and its loaded credentials are valid. SSH users reopen sessions; browser users reload, and streams resume only if their applications support it. An expired legacy JWT prevents reconnect even if the token file was replaced; upgrade/login/restart the publisher while independent access is available. Successful subsequent durable renewal preserves live streams. A login-only restart can leave separate resource streams alive if authority returns before lease expiry. Permission/renewal authority outages fail closed. First app TLS may wait up to three minutes for issuance; wrong Google users get 403.

Rollback first stops new app publishers and blocks wildcard custom ingress (old code lacks the owner gate), returns org-dependent apps to a safe disabled state, and stops/converts durable clients. Obtain legacy credentials using an old CLI or the updated CLI against an old relay, then restart legacy-compatible publishers. Keep billing disabled and preserve the current database and all additive/journal tables; do not restore a stale backup or drop schema.

Using the saved actual config and immutable image, resource nodes first if present, then the single login writer:

```sh
fly deploy --app tunn --config fly.release.rollback.toml --image "$TUNN_PREVIOUS_IMAGE" --only-machines "$RESOURCE_MACHINE_IDS" --update-only --ha=false --strategy rolling --max-concurrent 1
fly deploy --app tunn --config fly.release.rollback.toml --image "$TUNN_PREVIOUS_IMAGE" --only-machines "$LOGIN_MACHINE_ID" --update-only --ha=false --strategy rolling --max-concurrent 1
```

Skip the empty-resource command. Restore inventoried routing/file-secret mappings as required by that previous image, preserve JWT/node secrets and SSH key, and repeat health/legacy SSH checks. Rolling back server alone causes a durable authentication outage; rolling back custom ingress without disabling app publishers can expose apps. Native jump/org/wildcard features remain unavailable until a fixed forward deploy. For data corruption use the separate coordinator database-recovery procedure after assessing post-backup writes.

Fly command flags were checked against [fly deploy](https://docs.fly.io/flyctl/cmd/fly_deploy) [fly ssh console](https://docs.fly.io/flyctl/cmd/fly_ssh_console), [staged secret import](https://docs.fly.io/flyctl/cmd/fly_secrets_import), and [base64 secret-file configuration](https://docs.fly.io/reference/configuration#files). Machine inventory, secret materialization, external network/Google/CA acceptance and container/platform behavior must be validated by the coordinator on the recorded topology.
