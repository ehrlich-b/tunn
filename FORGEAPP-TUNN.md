# Forge apps through tunn

`forgeapp-tunn.diff` targets `/work/lanes/forge-apps/forgeapp` and is **not applied**. Source CLI SHA-256: `54d2250e28585d33156dd139df9e2de8a1ac9cf9c86c7b5f18cc13240810e81c`. Dry-run application and isolated registration/lifecycle fixtures passed; no live service or provider was called.

## One-time setup

Complete DEPLOY-RUNBOOK.md and its security/live-acceptance gates. Use a Pro account with its verified primary owner email. The ten Pro reserved-name slots are shared across the account; an existing tunnel may consume one. Apps must listen only on their declared localhost port.

The patch defaults to forge's `~/.local/state/tunn-forge-ssh/credentials` directory (0700). It never prints credentials or passes their contents in argv. **Durable `device_access` credentials cannot manage domains.** The credential tests intentionally enforce publish/connect scope. Registration can use the directory's current legacy management `token`; once it contains only durable credentials, supply a separate private current management access JWT file through `FORGEAPP_TUNN_OWNER_TOKEN_FILE`. That authority is a production prerequisite. Do not copy refresh credentials, change token purposes, or broaden device scope. The supervised publisher always uses forge's existing durable directory.

Using a private management-token path, with no credential output:

```sh
export TUNN_CONFIG_DIR="$HOME/.local/state/tunn-forge-ssh/credentials"
export TUNN_SERVER_ADDR=tunn.to:443
export FORGEAPP_TUNN_OWNER_TOKEN_FILE=/absolute/private/management-token
tunn domain add '*.apps.ehrlich.dev' --tunnel dashboard --owner-token-file "$FORGEAPP_TUNN_OWNER_TOKEN_FILE"
```

Retain the returned public `cname_target`. Bryan/coordinator sets:

| Name | Type | Value | Mode |
| --- | --- | --- | --- |
| `*.apps.ehrlich.dev` | CNAME | `tunn.to` | DNS only, `proxied=false`, automatic TTL |
| `_tunn-verification.apps.ehrlich.dev` | TXT | Exact returned `cname_target` | DNS only |

The estate helper proposal is [docs/cf-dns-cname.diff](docs/cf-dns-cname.diff), originating at `/work/lanes/tunn-apps-domain/tunn/docs/cf-dns-cname.diff`. After applying it to the actual estate helper, the coordinator runs `cf-dns.sh cname '*.apps.ehrlich.dev' tunn.to`; TXT creation uses the existing approved DNS workflow because this diff adds only CNAME support. A generic edge CNAME routes traffic but is not ownership proof. Retain the TXT for hourly refresh/two-hour leases, avoid conflicting address records, and expose raw TCP 80/443 to every tunn edge. Each app gets a concrete HTTP-01 certificate; no wildcard certificate or DNS API secret is required.

```sh
tunn domain verify '*.apps.ehrlich.dev' --owner-token-file "$FORGEAPP_TUNN_OWNER_TOKEN_FILE"
```

After installing the integrated CLI through the coordinator artifact workflow:

```sh
cd /work/lanes/forge-apps
git apply --check /work/lanes/tunn-release/tunn/forgeapp-tunn.diff
git apply /work/lanes/tunn-release/tunn/forgeapp-tunn.diff
./forgeapp install dashboard
./forgeapp start dashboard
```

## Install and lifecycle behavior

Install validates the manifest, private credential directory and tunn executable, registers the wildcard with `--tunnel <name>`, then verifies DNS proof. This reuses the same wildcard and reserves the same app label. Calls capture output and failures show a generic actionable error without provider output. Registration failure never reports successful installation. A failed verify may leave a claim/reservation; fix DNS/auth and retry, rather than deleting the wildcard shared by other apps.

It enables the existing `forgeapp-<name>.service` plus `forgeapp-tunn-<name>.service`, preserving install's existing behavior of not starting the app. The publisher runs `tunn serve --name <name> http://127.0.0.1:<port>` with private default exposure and returns `https://<name>.apps.ehrlich.dev`. The wildcard adds the exact-owner verified Google gate even if access is shared or a future publication becomes public.

The publisher has Requires/After/BindsTo/PartOf dependencies on the app, WantedBy the app, Restart=always with RestartPreventExitStatus=78 (tunn exits 78 only when its login cannot renew), and writable access to the original credential directory for locking/refresh. Start checks the localhost listener and starts the publisher; it does not claim browser/TLS readiness. Stop stops the publisher first. Remove disables/removes both units and retains app state and remote reservations. It does not delete the shared wildcard. Port changes require install followed by explicit app/publisher restarts; install alone does not disrupt running services.

Acceptance checks both units, Google redirect while signed out, successful Bryan login and a 403 for another Google identity. Confirm no direct Internet ingress to the localhost app and validate streaming/WebSocket owner enforcement and identity-header stripping. Apps can verify EdDSA against `/.well-known/tunn-jwks.json`, exact issuer and their hostname audience; private seeds never go to apps.

Relay replacement drops tunnels and live SSH. Supervised durable publishers reconnect after readiness; users reopen SSH or reload apps. A running legacy publisher cannot renew by replacing its token file. Keep independent access while upgrading it. On rollback stop these publishers/block custom ingress before old code returns, since the production base lacks the wildcard owner gate. DNS+tunn remains conditional on management authority, security review fixes and real CA/Google acceptance.
