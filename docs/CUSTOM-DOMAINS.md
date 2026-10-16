# Custom domains and automatic HTTPS

Pro accounts can bind up to four concrete customer DNS names to reserved tunnel
names. Wildcards, IP addresses, URLs and names under the relay's own domain are
rejected. Use ASCII DNS names (punycode for an internationalized name). Each claim
gets a fresh `dv-<random>.<relay-domain>` CNAME target. A previous owner's CNAME
cannot verify a replacement claim, even if the underlying tunnel name is reused.

## Owner flow

```bash
tunn login
tunn domain add work.example.com --tunnel work
# In your DNS provider: work.example.com CNAME <returned cname_target>
tunn domain verify work.example.com
tunn serve --name work 8080
tunn domain list
tunn domain delete work.example.com
```

Add atomically checks the current paid plan and reserves the tunnel name through
the same `reserved_subdomains` table as publisher registration. Existing names
must belong to the account; new names consume one of its ten Pro reservation
slots. Multiple domains can share one reserved tunnel name. Delete removes the
binding, challenge and stored certificate/key; it preserves the independent
tunnel reservation. Remove the CNAME from DNS as part of cleanup.

`verify` checks the exact CNAME and requests a certificate. Allow up to three
minutes. It must return `state: ready` before HTTPS traffic can route. Retry it
after correcting DNS or a failed initial issuance. `list` shows pending/ready
state, the verification target, DNS lease, certificate expiry and a diagnostic
code. It returns no keys or ACME account data. Names remain claimed until the
owner explicitly deletes them, including after downgrade; a downgrade disables
routing and certificate delivery immediately on the next authority check.

Private custom domains accept account JWTs, endpoint tokens, and HTTP consumer
grants through `Tunn-Authorization`. WebSocket/TCP grants remain unsupported.
Bearer credentials and platform cookies are stripped before reaching the
publisher. Browser login cookies belong to the relay domain and cannot span an
unrelated customer domain: use the reserved relay URL for browser login, or a
bearer-aware client on the customer domain. Anonymous browsing works when the
publisher is public. Every path on a customer origin belongs to the publisher;
`/account`, `/auth/*`, `/api/*` and `/health` do not expose platform pages there.

The owner API is `POST /api/domains` with `{"name":"work.example.com",
"tunnel":"work"}`, `GET /api/domains`, `POST /api/domains/<name>/verify`, and
`DELETE /api/domains/<name>`. It accepts owner JWT bearer credentials on the relay
origin, with the same HTTPS/redirect protections as the usage/grants client.
CLI options are `--server`, `--owner-token-file`, and local-test `--insecure`.

## Certificates and anycast

HTTP-01 fits this relay's existing Fly TCP/UDP passthrough TLS topology. Port 80
can deliver the HTTP challenge to whichever relay anycast selects. Each relay
reads only the login authority's exact, host-bound, expiring challenge. Customer
publishers never supply certificate challenge content. TLS-ALPN-01 would require
special `acme-tls/1` certificates and ALPN handling on every TCP ingress and is
unnecessary with a dedicated HTTP challenge listener. Customer wildcards would
require a separate DNS-01 implementation.

Only the login node orders certificates from ACME. The account signing key and
customer private keys are AES-256-GCM encrypted in SQLite with authenticated name
binding. Trusted relay nodes retrieve ready certificate/key pairs over the
existing node-secret-protected internal TLS/gRPC connection for SNI termination;
keys exist in their process memory. SNI and each request independently consult
the authority, so a partition fails closed rather than using a stale route or
certificate. The original relay wildcard certificate remains the platform's
certificate on TCP and QUIC.

The login worker rechecks DNS at startup and hourly. Verified routes have a
two-hour DNS lease; a failed check disables them. It renews certificates when
30 days remain, checking DNS, current paid entitlement and reserved-name
ownership before and after issuance. An ACME renewal failure retains a still-valid
certificate while DNS stays proven; an expired certificate is never served.
In-flight orders cannot recreate a deleted or replaced claim. DNS changes can
remain effective until the next check or lease expiry, rather than instantaneously.
Account email-bucket merges transfer bindings with their reserved names.

## Fly.io operator setup

Configure the following on your own relay deployment.

- Keep TCP 443 and UDP 443 as passthrough to tunn, with the existing base-domain
  wildcard certificate at `TUNN_CERT_FILE` / `TUNN_KEY_FILE`. Customer certificates
  are issued/stored by tunn; they do not require per-domain Fly-managed certs.
- Publish wildcard **A/AAAA** records for `*.<relay-domain>` pointing to the app's
  shared anycast IPs. The unique `dv-*` targets must terminate at address records,
  **not** a CNAME to `app.fly.dev`: `LookupCNAME` verifies the canonical target.
  Customers create CNAMEs to their exact returned `dv-*` hostname. Disable DNS
  proxying/flattening that hides this CNAME. DNS provider zones that prohibit apex
  CNAMEs must use a customer subdomain. CAA must permit the configured CA.
- Set `TUNN_CUSTOM_DOMAINS=true` and `TUNN_HTTP01_ADDR=0.0.0.0:80` on every relay.
  Add the commented TCP port-80 service from `fly.toml.dist` with no TLS handler
  or forced HTTPS redirect. Only ACME challenge paths are served on that port.
- On the login node, configure `TUNN_ACME_EMAIL`, `TUNN_ACME_DIRECTORY`, and secret
  `TUNN_DOMAIN_KEY_SECRET` (base64 encoding of 32 random bytes). The directory
  must use HTTPS. Enabling this feature opts the operator into the CA's ACME
  account terms. Use the CA's staging directory for isolated deployment acceptance
  before production issuance; staging certificates are not browser-trusted.
- Persist `TUNN_DB_PATH` on the login node's `/data` volume; back up the database
  **and** its encryption secret. Reuse that secret after restart. Changing it
  without a key migration makes existing ACME/customer keys unreadable and
  startup fails. Protect internal TLS, `TUNN_NODE_SECRET`, and discovery just as
  for metering; all nodes must share one authoritative login database.
- Plan limits are always enforced for accounts. Optional nonnegative
  `TUNN_OWNER_MONTHLY_REQUESTS` / `TUNN_OWNER_MONTHLY_BYTES` only tighten them.
  Alert on failed renewals, DNS leases, ledger outages and certificate expiry.
  The account view and `tunn usage` include active reservations; they are payload
  accounting, not a reconciliation of Fly's framing/transit/egress invoice.

## Offline verification

The domain suite uses a fake DNS resolver and in-memory ACME directory. The fake
CA verifies JWS signatures, fetches the shared HTTP-01 challenge, and signs the
actual CSR. TLS handshake and internal gRPC tests use memory pipes; no external
DNS, ACME or Fly call is part of these tests.

```bash
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local make test-domains-contract
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go vet ./...
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./...
```
