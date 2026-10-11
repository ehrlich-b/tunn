# Integrated tunn release, 2026-10-11

This carrier starts at production `110485c8a479572ef6cbaeda8b20d80ccc326ef2` and uses real merges in dependency order. It is a local release candidate, with checkout disabled; deployment is conditional on the review findings in RELEASE-VALIDATION.md and the acceptance steps in DEPLOY-RUNBOOK.md.

## Source inventory

| Component | Exact fetched commit |
| --- | --- |
| Durable credentials | `4b7364503e428837b6fdb98e8c2ce4605b05da90` |
| Private web sharing | `7f5d6191e9346e50558adf3368eedc7b35d769b9` |
| App domains, owner Google login, identity assertions | `898e609a6494aeea2f9e5ce661ebd688d060e857` |
| Okta, Entra, Workspace SSO | `871cdf86942da2af17688a1be8427db34c77a027` |
| Native OpenSSH jump and six security fixes | `2325a0f1b277a1ee8ecfc21cc73d17b09e1b17ff` |
| Reviewed billing, no-Stripe stage | `4f8e04623772f1586267ab05bf6d659bd2eb3614` |
| Distribution pages | `698f1844fee39b5ae826575691be2ea2657bc903` |

The GitHub SSH clone failed host-key verification; HTTPS cloned the same repository and exact production base. Local sources were fetched into source branches. No source worktree was modified, and no push, deployment, DNS change, service restart, email or provider write was performed.

## Changes people see

Updated CLI and SDK web publications are **private by default**. Owners can open their resources, invite a person with `tunn share NAME EMAIL --expires 8h`, revoke with `tunn unshare NAME EMAIL`, inspect access with `tunn access NAME`, or use Account → Share access. A copied URL grants no permission. `--public` is the deliberate anonymous option. Reconnection retains the current resource generation and does not replay revoked initial grants. Person removal/expiry denies the next request and cancels admitted HTTP/SSE/WebSocket streams within five seconds; unavailable permission authority fails closed. Machine grants retain independent authority.

**Existing public resources on upgrade:** upgrading the relay alone preserves legacy publishers with an empty allow-list as `legacy-public`. Legacy publishers with an allow-list remain private. Updating/restarting a publisher with the new CLI/SDK and no `--public` chooses private exposure. An old publisher cannot silently turn an already private managed resource public. Inventory existing anonymous integrations and explicitly choose their exposure before changing clients. Existing anonymous self-hosted publications require explicit public exposure with the updated client.

Renewable, rotating device credentials keep always-on publishers and account CONNECT clients authorized. Each device logs in independently; files are private, atomically saved and locked across processes. Existing legacy access tokens remain valid until their 24-hour expiry but do not become renewable automatically. Successful renewal preserves live streams. Revoked publishers expire within five minutes, plus up to one minute of allowed relay clock skew; existing authorized laptop CONNECT sessions can drain. Management and billing remain outside durable publish/connect scope.

Verified wildcard app namespaces route a single label to the owner's same-named reserved tunnel. `*.apps.ehrlich.dev` requires exact verified Google primary-owner login even if a publication is public or shared. Aliases, other Google accounts, personal non-Google sessions, org sessions and bearer grants cannot widen this gate. Apps receive stripped-and-replaced `X-Tunn-Identity` (EdDSA, hostname audience, two-minute lifetime) and `X-Tunn-User-Email`; public JWKS contains no private material. App cookies are host-bound; central sign-in is reused through one-use browser-bound handoffs. First hostname access can wait up to three minutes for HTTP-01 issuance. Concrete customer-domain behavior remains separate. Existing Pro entitlement and four reserved-name slots still apply.

Customer Okta, Entra ID and Google Workspace OIDC sign-in supports per-resource mapped group sharing. Company identity is a stable isolated principal, separate from personal accounts with the same email. Org browser sessions last at most 15 minutes; IdP group removal can take that long to affect existing sessions. Removing a tunn grant cuts off live access within the sharing bound. Entra overage uses subject-bound, bounded Microsoft Graph requests; Workspace uses scoped delegated Directory direct membership. Device credentials carry no group authority and remain independently revocable after IdP offboarding. SAML, SCIM, transitive Workspace groups, account linking and live-tenant acceptance are deferred.

The optional native SSH pilot supports `ssh -J tunn@tunn.to:443 USER@forge-ssh` and SFTP using existing origin keys. Key linking requires possession and deliberate verified-email consent. Revocation, stale-link generations, target-oracle denial and identity/channel budgets have regressions. Relay and origin host keys/users are independently verified. Pilot SSH and publisher must reach the same authoritative login node; cross-node jump routing is deferred. Legacy `ProxyCommand tunn connect --stdio --account forge-ssh` remains available.

Billing adds durable reviewed receipts, checkout holds, duplicate-payment quarantine, reviewed entitlement snapshots, legacy Pro preservation and audited local administration. Account and pricing pages show effective quotas and USD $6/month or $60/year; authority outages do not pretend an account is Free. **This release keeps `TUNN_BILLING_ENABLED=false`. No Stripe credentials, prices, links, webhook or portal are created or enabled.** Provider receipts alone do not grant Pro. Future selling requires the separate reviewed fulfillment/acceptance workflow in GO-LIVE.md; payment links do not prevent duplicate provider charges.

Distribution adds sourced comparison and sharing guides, MCP tutorial pages, navigation, CSS, robots and sitemap. The merged comparison retains configuration-derived pricing/quotas. Hosted Claude/ChatGPT interoperability remains a preview requiring real-client acceptance. Installer artifacts require a separate coordinator release; a server deployment alone does not update the CLI.

## Additive migrations and rollback

Startup installs `durable_devices`, `durable_device_used`, `web_resources` and person/group grants in the existing ledger; wildcard certificate/order/settings tables; org OIDC one-use state; and the billing operations, snapshot, checkout/payment, legacy-entitlement and rollback journal schema. Native key registry also adds generation/proof metadata through its idempotent migration. Existing account plans and reservations are preserved on startup; old Pro grants are snapshotted once, and revoked grants are not reimported. No manual SQL backfill or fixture initialization belongs in production.

Back up the authoritative SQLite database consistently, including committed WAL data, before startup migration. Preserve the JWT/node secrets, domain encryption secret, relay SSH host key and signing ring with the database. Run one active login authority. Do not restore a stale database or drop additive tables during rollback. Roll clients back to legacy credentials before the old relay; old servers cannot accept `device_access` or refresh. Baseline rollback also loses managed sharing, org SSO, wildcard owner gates and native jump behavior: disable app publishers/custom ingress during rollback so private apps cannot be exposed by the old implementation. Keep billing disabled and inspect rollback journals before forward migration.

## Production settings and secret files

| Setting | Required use |
| --- | --- |
| `TUNN_ENV=prod`, `TUNN_DOMAIN`, `TUNN_PUBLIC_ADDR` | Preserve platform authority; callback/issuer match exact configured host and port, currently template `tunn.to:443`. |
| `TUNN_LOGIN_NODE`, `TUNN_DB_PATH`, persistent `/data` volume | Preserve inventoried roles/database; exactly one login writer. |
| `TUNN_JWT_SECRET`, `TUNN_NODE_SECRET`, optional `TUNN_CA_CERT` | Existing session/device signatures and authenticated internal TLS/RPC; keep stable and keep port 50051 private. |
| `TUNN_CERT_FILE`, `TUNN_KEY_FILE` or existing paired base64 `TUNN_CERT_DATA`/`TUNN_KEY_DATA` | Platform TLS remains mandatory; ACME app certificates do not replace it. |
| `TUNN_GOOGLE_CLIENT_ID`, `TUNN_GOOGLE_CLIENT_SECRET` | Login-authority Google OAuth; register exact `https://tunn.to:443/auth/google/callback` if preserving that public authority. Authorize intended users and verify Bryan's primary email. |
| `TUNN_CUSTOM_DOMAINS=true`, `TUNN_HTTP01_ADDR=0.0.0.0:80` | Every edge: raw TCP 80 HTTP-01 and raw TCP 443 TLS; retain UDP 443 HTTP/3. DNS-only wildcard CNAME plus unique ownership TXT. |
| `TUNN_DOMAIN_KEY_SECRET`, `TUNN_ACME_EMAIL`, `TUNN_ACME_DIRECTORY` | Login authority: base64 32-byte AES key and contact; staging before production CA. Encrypted app keys and ACME account state persist in SQLite. |
| `TUNN_IDENTITY_KEYS_FILE` | Every custom-domain relay: private Ed25519 JWK ring, mode 0600; matching active seed/public key and common key IDs/JWKS. Rotate atomically, retain old public key for at least three minutes. |
| `TUNN_OIDC_ORGS_FILE` | Optional private 0600/0400 org configuration, identical across relays; exact per-org callback and issuer/tenant/group mapping. Workspace delegated JSON is another private file with only group-read scope. |
| `TUNN_SMTP_HOST/PORT/USER/PASSWORD/FROM` | Existing SMTP for magic-link and SSH enrollment; verify inbox acceptance without leaking credentials. Preserve GitHub OAuth if already configured. |
| `TUNN_SSH_HOST_KEY_FILE`, optional `TUNN_SSH_ADDR` | Persistent relay key enables SSH; raw TCP 443 to the login node, optional separate 22. Never regenerate the key at restart. |
| `TUNN_BILLING_ENABLED=false`, `TUNN_PRO_MONTHLY_USD=6`, `TUNN_PRO_YEARLY_USD=60` | Required no-Stripe stage. Do not add/activate Stripe values; retain any preexisting inventory securely for rollback. |
| `TUNN_CONFIG_DIR` on forge | `/home/ehrlich/.local/state/tunn-forge-ssh/credentials`, private writable directory shared by publishers; never print/copy credential contents. Domain management needs a current separate access credential if this directory contains only durable credentials. |

Use private secret-manager inputs and Fly secret-file materialization; keep populated files and their values outside this repository. See DEPLOY-RUNBOOK.md and FORGEAPP-TUNN.md for executable handoff steps and known gates.
