# Verify webhooks at the edge

Publish an HTTP endpoint with `--verify-webhook` to check every request before
it reaches your local app. Requests with missing, malformed or invalid signatures
return **401** with a static reason. Keep your application's authorization,
signature checks and event deduplication enabled.

tunn checks private access, account status and quota admission before reading the
webhook body. Those checks keep their existing responses, such as 403 for denied
access or 429 for an exhausted allowance. Verification reads count toward usage
once, including bodies whose signatures fail; rejected requests never reach the
origin.

## Keep the signing secret in a private file

Use the **webhook signing secret**, not an API key or a tunn access token. Obtain
it from the sender's webhook configuration. Create the file without placing its
contents in command arguments or shell history:

```sh
umask 077
mkdir -p "$HOME/.tunn/endpoints"
chmod 700 "$HOME/.tunn/endpoints"
# Enter the signing secret at the prompt; finish with Enter, then Ctrl-D.
cat > "$HOME/.tunn/endpoints/orders.key"
chmod 600 "$HOME/.tunn/endpoints/orders.key"
```

The input must be a private regular file; symlinks and files readable by other
users are rejected. A terminal line ending is removed. tunn copies the key into
`~/.tunn/endpoints/<name>.webhook-secret` using atomic writes, directory mode 0700
and file mode 0600. `TUNN_CONFIG_DIR` selects an absolute alternate configuration
directory. Keys never appear in tunn logs. The relay needs the HMAC key to verify
signatures: it receives it over the publisher's authenticated TLS connection and
keeps it in the active endpoint's memory, without storing it in its database.
Use a relay you trust and keep TLS verification enabled.

## Publish for your provider

Start your local HTTP handler on port 8080, then choose **one** command below.
`--public` allows webhook senders to reach the endpoint; signature verification
still applies. Omit `--public` to retain tunn's private access requirements in
addition to the webhook signature. Every path on this endpoint requires a signed
request; publish another endpoint for browser pages and health checks.

```sh
# Stripe: use the endpoint's whsec_ signing secret.
tunn 8080 --name=orders --public --verify-webhook=stripe \
  --webhook-secret-file="$HOME/.tunn/endpoints/orders.key"

# GitHub: use the secret configured on this webhook.
tunn 8080 --name=orders --public --verify-webhook=github \
  --webhook-secret-file="$HOME/.tunn/endpoints/orders.key"

# Slack: use the app's signing secret.
tunn 8080 --name=orders --public --verify-webhook=slack \
  --webhook-secret-file="$HOME/.tunn/endpoints/orders.key"

# Shopify: use the app's client secret for HTTPS webhook deliveries.
tunn 8080 --name=orders --public --verify-webhook=shopify \
  --webhook-secret-file="$HOME/.tunn/endpoints/orders.key"

# Generic HMAC: use the same secret in your sender and this endpoint.
tunn 8080 --name=orders --public --verify-webhook=hmac-sha256 \
  --webhook-secret-file="$HOME/.tunn/endpoints/orders.key" \
  --webhook-tolerance=5m
```

Configure the sender's destination using the URL printed by tunn and the path
handled by your app, for example `https://<printed-name>.tunn.to/webhook`.
Stop and restart this command to apply a new provider, secret or tolerance. Each
reconnect reloads the stored `<name>.webhook-secret` file. Disconnecting removes
the active policy; future publications must specify the flags again. An older
relay without webhook verification causes the publisher to fail before ready.
This policy is available for HTTP CLI publications; TCP, MCP and SSH publications
do not accept it.

| Provider | Signature header | Signed bytes |
| --- | --- | --- |
| Stripe | `Stripe-Signature: t=<seconds>,v1=<hex>` | `<seconds>.<raw body>` |
| GitHub | `X-Hub-Signature-256: sha256=<hex>` | raw body |
| Slack | `X-Slack-Signature: v0=<hex>` | `v0:<X-Slack-Request-Timestamp>:<raw body>` |
| Shopify | `X-Shopify-Hmac-SHA256: <base64>` | raw body |
| Generic | `X-Webhook-Signature: sha256=<hex>` | `<X-Webhook-Timestamp>.<raw body>` |

All use HMAC-SHA256 with a constant-time comparison. Stripe accepts any matching
`v1` entry. Required headers must have one field value; duplicate headers are
rejected. Bodies are preserved exactly, including whitespace and binary bytes.

## Generic HMAC sender: copy-paste test

With the generic endpoint running, replace the URL and run this script. It signs
exactly the bytes it sends and loads the same private source file:

```sh
export WEBHOOK_URL='https://<printed-name>.tunn.to/webhook'
python3 - <<'PY'
import hashlib, hmac, os, pathlib, time, urllib.request
secret = (pathlib.Path.home() / '.tunn/endpoints/orders.key').read_bytes()
secret = secret.removesuffix(b'\n').removesuffix(b'\r')
body = b'{"event":"example"}\n'
stamp = str(int(time.time()))
signature = hmac.new(secret, stamp.encode() + b'.' + body, hashlib.sha256).hexdigest()
request = urllib.request.Request(os.environ['WEBHOOK_URL'], data=body, headers={
    'Content-Type': 'application/json',
    'X-Webhook-Timestamp': stamp,
    'X-Webhook-Signature': 'sha256=' + signature,
})
with urllib.request.urlopen(request) as response:
    print(response.status)
PY

# Missing signatures return 401 without reaching your app.
curl -i -X POST "$WEBHOOK_URL" --data-binary '{"event":"unsigned"}'
```

The signed request returns your application's status. A wrong signing secret,
changed body or stale timestamp returns 401. The reason never echoes a secret,
signature or request payload.

## Limits, retries and replay

Stripe, Slack and generic HMAC timestamps must be within 5 minutes of the relay's
clock, including timestamps in the future. Set `--webhook-tolerance` to whole
seconds between `1s` and `1h`. A zero tolerance is rejected. Keep sender and relay
clocks synchronized. GitHub and Shopify's body signatures do not bind a timestamp;
a custom tolerance is rejected for them. These providers need application-level
deduplication to resist replay. Timestamp checks also permit duplicates inside
the tolerance window; deduplicate all providers by event/delivery ID.

Timestamp freshness is checked again after the body has been read and verified.
A slow upload that finishes outside the tolerance is rejected before forwarding.

Verification buffers at most 1 MiB and permits at most 100 simultaneous
verifications per endpoint. Reading the body has a 10-second deadline. Oversized
bodies, body-read failures, capacity denials, CONNECT and upgrade requests return
401. Successful delivery retains tunn's existing access, account and quota checks.
Provider retries still reach your handler if their signatures pass; handle events
idempotently and return your application's acknowledgement after processing.

Provider references: [Stripe](https://docs.stripe.com/events/manage-webhook-endpoints#signature-errors),
[GitHub](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries),
[Slack](https://docs.slack.dev/authentication/verifying-requests-from-slack/),
[Shopify](https://shopify.dev/docs/apps/build/webhooks/verify-deliveries).

Stored signing keys are scoped to the canonical HTTPS relay origin, endpoint,
provider and publisher account identity. Registration and reconnect verify the
selected file belongs to that publication. Default HTTPS ports identify the same
origin. Repeating a publication with the same binding rotates that key; a
publication on another relay, provider or account uses a separate file. Existing
unscoped stored files are not loaded automatically; supply the source secret file
again after upgrading.

## Verified local webhook journey

Run `make test-webhook-journey` twice. It builds the current CLI and starts a
TLS relay, publisher and signature-checking origin on loopback only. The
publisher runs `tunn 3000 --public --inspect --inspect-body` with disposable
self-hosted authentication. Python 3, Go and OpenSSL are required; nothing is
installed. Port 3000 must be available.

These are provider-style signed fixtures, not deliveries from live provider
accounts. The origin checks the raw received bytes independently of the sender:

| Provider | Signature checked at origin | Freshness |
| --- | --- | --- |
| Stripe | `Stripe-Signature`: `t=` and `v1=`, HMAC-SHA256 of timestamp + `.` + raw body | 300 seconds |
| GitHub | `X-Hub-Signature-256`: `sha256=` + HMAC-SHA256 of raw body | No signed timestamp |
| Slack | `X-Slack-Signature`: `v0=` + HMAC-SHA256 of `v0:` + timestamp + `:` + raw body | 300 seconds |

The published algorithms are documented by
[Stripe](https://docs.stripe.com/webhooks/signature),
[GitHub](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
and [Slack](https://docs.slack.dev/authentication/verifying-requests-from-slack/).

Every provider passes every row of this matrix:

| Raw body | Delivery | Inspector replay |
| --- | --- | --- |
| 1 byte | Signature verifies; handler returns 500 | After fixing handler, identical request verifies and returns 200 |
| 1 MiB | Signature verifies; returns 200 | Truncated capture refuses preparation; no dispatch |
| Binary, all byte values | Signature verifies; returns 200 | Identical request verifies; returns 200 |
| Gzip bytes with Content-Encoding | Signature verifies without decompressing; returns 200 | Identical request verifies; returns 200 |
| Non-UTF-8 bytes | Signature verifies without decoding; returns 200 | Identical request verifies; returns 200 |

Every matrix request includes two `X-Delivery` fields (one contains a comma),
a percent-encoded path and query, and repeated query keys. Replay assertions
compare the complete origin-observed header multimap, raw request URI and body,
and require the inspector's `replay_of` label. A correctly signed Stripe request
with a timestamp ten minutes old reaches the origin and receives 401. A modified
signature is also rejected by the origin.

`--inspect-body` explicitly retains at most 64 KiB. Signature headers, custom
headers and query values stay redacted and must be reconstructed deliberately.
For repeated redacted fields the local inspector API accepts `header_values`,
a map of header names to ordered string arrays, alongside the complete scalar
`headers` map (each repeated field's scalar is its last value). Arrays must match
the captured cardinality; captured representation values cannot change. The
current browser form accepts scalar fields; use the local API or
`ReplayWithRequest` for repeated custom fields. Each replay requires a fresh
one-use action from `/api/events/{id}/prepare`, followed by
`/api/events/{id}/replay` with that action and the reconstructed fields.
Repeated values remain sanitized in subsequent captures and are evicted with
their event. Metadata exports retain their existing redaction behavior.

`TestInspectorCapturesFieldOnlyHeaders` retains coverage for both wire adapters.
`TestInspectorReplaysRepeatedHeaders` covers both adapters, exact repeated-field
replay, refusal of incomplete reconstruction and redaction after replay.
`TestInspectorRepeatedHeaderSafeguards` checks ordered safe values, credential
redaction, malformed replacements, copying and bounded eviction. Existing
truncation tests continue to refuse incomplete captures.

Set `TUNN_WEBHOOK_EVIDENCE` to an existing directory to retain a unique run's
process logs and `receipt.json` with body hashes and per-case results. Set
`TUNN_WEBHOOK_WORK` to choose the temporary build/fixture directory. Payloads and
signing credentials are disposable fixtures; the receipt retains no raw body.
