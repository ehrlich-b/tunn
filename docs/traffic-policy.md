# Request headers and rate limits

An endpoint owner can configure request header edits and request rate limits.
Sign in with `tunn login` to publish an HTTP endpoint. Use a separate owner
sign-in with `tunn policy login` to configure it:

```sh
tunn http 8080 --name api
# In a second terminal:
tunn policy login
tunn policy set api --file policy.json
tunn policy get api
tunn policy clear api
```

`policy.json`:

```json
{
  "headers": {
    "remove": ["X-Debug"],
    "rewrite": [{"name": "X-Service", "value": "api"}],
    "add": [{"name": "X-Deployment", "value": "preview"}]
  },
  "rate_limits": {
    "per_ip": {"requests_per_minute": 60, "burst": 10},
    "per_account": {"requests_per_minute": 600, "burst": 50}
  }
}
```

Omit either limit to leave that dimension unlimited. `per_ip` is one bucket per
client IP at this endpoint. `per_account` is one aggregate bucket for traffic
charged to the endpoint's owning account **at this endpoint**, including anonymous
visitors and all consumer credentials. It does not identify visitor accounts or
combine other endpoint names. Both buckets must admit the request atomically;
a rejection consumes neither bucket.

`requests_per_minute` is the continuous refill rate, between 1 and 1,000,000.
`burst` is total bucket capacity, between 1 and 10,000, and is initially full.
For 60 RPM with burst 10, ten requests can arrive immediately; thereafter one
request token refills each second. This is not a fixed calendar-minute counter.
Denied requests receive HTTP `429`, `Retry-After` rounded up to seconds until
both buckets have a token, and `Tunn-Limit-Reason` (`policy_ip_rate`,
`policy_account_rate`, or `policy_capacity`). Retry after that delay; other
visitors can consume tokens meanwhile.

The relay authenticates the request and checks access before evaluating policy.
Unauthenticated or unauthorized private requests do not consume policy tokens.
Policies run before origin dispatch and cover buffered HTTP, streamed HTTP/SSE,
WebSocket handshakes, and HTTP MCP endpoints. Each initial HTTP request costs
one token; stream chunks, WebSocket frames, and MCP messages within a single
request do not cost additional tokens. An admitted request retains its token cost
if a later quota check, upstream authentication check, or origin call fails.
Existing account quotas, consumer grant budgets, access checks, and credential
sanitation continue to apply. Raw TCP/CONNECT endpoints are excluded.

Header names are case-insensitive. Remove deletes every value; rewrite replaces
all values (and creates the field if absent); add appends one value to the existing
field. An individual field may appear only once across all operations. Edits apply
to requests sent to the origin, after tunn consumes platform credentials. The
original request object is not changed. Response headers are unaffected.

There are at most 64 edits, 128 bytes per field name, 4,096 bytes per value, and
16 KiB per JSON policy. Unknown JSON fields, trailing JSON, invalid field names,
and control characters are rejected. Authentication/cookie fields, relay identity
and forwarding fields, Host, framing and hop-by-hop fields, Origin, and WebSocket
negotiation fields are reserved. Owner edits cannot inject or remove tunn
credentials, identity assertions, or IP metadata. If a visitor nominates an edited
field in `Connection`, the relay rejects the request with `400` before forwarding.

The IP comes from the network peer or verified cluster relay metadata. Public
`Forwarded`, `X-Forwarded-For`, and `X-Real-IP` values never select a bucket.
IPv4-mapped IPv6 addresses share their IPv4 bucket. Behind an untrusted external
proxy, users share that proxy's peer bucket; forwarding headers are not an opt-in
trust mechanism.

## Owner API

Use the platform HTTPS origin with an owner login JWT in `Authorization: Bearer`.
Endpoint access tokens, consumer grants, MCP access tokens, and browser cookies
cannot read or configure policies. A supplied `Origin` must match the platform
origin for mutations. A different owner receives `404` for an existing name.

| Method | Path | Request | Success |
|---|---|---|---|
| GET | `/api/endpoints/NAME/policy` | none | `200` current JSON policy |
| PUT | `/api/endpoints/NAME/policy` | complete JSON policy | `200` canonical stored policy |
| DELETE | `/api/endpoints/NAME/policy` | none | `200` empty policy |

PUT replaces the entire policy. Missing dimensions become unlimited. Invalid
updates return `400` and preserve the previous configuration. Unsupported methods
return `405`. A missing or differently owned registered endpoint returns `404`;
account or policy authority failure returns `503`. Mutations share the existing
owner limit of 60 registration/sharing/policy mutations per minute; exceeding it
returns `429` with `Retry-After: 60`.

`tunn policy login` uses the existing browser-authorized account-management
exchange and stores a separate, private `policy-owner.json` in the tunn config
directory. This credential has account administration authority, lasts 24 hours,
and is bound to the relay selected at login. It never changes publisher or CONNECT
credentials. Repeat owner login after expiry; the CLI never refreshes or upgrades
a scoped device token into account authority. A device token from ordinary
`tunn login` cannot manage policies. Supply an existing management JWT explicitly
with `--owner-token-file` if needed.

CLI commands also accept `--server`, `--owner-token-file`, and `--insecure`.
Owner login accepts `--server` and `--insecure`; it requires HTTPS, including in
local development.
Use normal TLS verification for hosted relays. HTTP is accepted only on loopback
for local development; credentials are not sent through redirects.

## Persistence and relay upgrades

Policies and token debt are stored at the existing SQLite login-node authority.
All publishing relays share its atomic decisions. Reconnects and authority
restarts retain policy and debt. PUT settles existing debt at the previous rate
and applies the replacement rate from the update time; repeating PUT does not
refill an active bucket. Clearing the policy removes its buckets. A name claimed
by a different owner receives a new resource generation with no inherited policy.
MCP policy records do not change MCP permissions or create web sharing access.

Storage is bounded to 1,024 active buckets per endpoint (including its aggregate
bucket) and 100,000 globally. Fully refilled buckets expire. Active debt is never
evicted to admit a new IP; at capacity new buckets receive `429` and
`Retry-After: 60`. Bucket IP keys are SHA-256 digests, not stored raw addresses.

Upgrade the login authority and **all** publishing relays before enabling policies.
Older publishing relays do not evaluate this feature. Updated relays fail closed
with `503` when their authority lacks the policy RPC or is unavailable, including
for account-managed endpoints with an empty policy. Authority calls have a
five-second deadline. An ambiguous admission is not retried automatically or
forwarded to the origin; a committed token may remain consumed.

Self-hosted endpoints authenticated without an account have no owner-managed
policy record. They retain existing forwarding and quota behavior.

Local validation: `make test-policy` checks durable admission, owner API and CLI,
request forwarding, the authenticated internal RPC, and a disposable TLS relay
with a real publisher and HTTP origin. Hosted account acceptance and cluster
upgrade acceptance must be completed separately.

## Combining policies

Webhook signatures are verified against incoming headers and raw body bytes before
origin header edits. Header edits cannot supply or erase sender verification.
Web inspector history retains sanitized incoming headers; confirmed replay reruns
the current header/rate, IP, sharing, quota and webhook checks. App-device admission
shares its existing total deadline with both IP and request-policy authorities.
