package host

const ipRestrictionsHTML = `<style>pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1 class="page-title">IP restrictions</h1>
<p>Restrict endpoint visitors by IPv4 and IPv6 CIDR before credentials, browser sign-in, or sharing. This applies to HTTP, WebSockets, SSE, MCP and HTTP/2 CONNECT.</p>
<h2>Set an account default</h2><pre>tunn ip-policy set --account --allow 203.0.113.0/24,2001:db8::/32 --deny 203.0.113.42/32</pre>
<h2>Set an endpoint policy</h2><pre>tunn ip-policy set my-app --allow 198.51.100.0/24
tunn ip-policy get my-app
tunn ip-policy clear my-app</pre>
<p>An explicit endpoint policy replaces the account default. Clear it to restore inheritance. Deny wins over allow. A nonempty allow list requires a matching network; an empty allow list permits addresses except those denied. Setting both lists empty permits all addresses for that scope. Use /32 for one IPv4 address and /128 for one IPv6 address. Up to 64 CIDRs are accepted in each list; host bits are masked.</p>
<p>Use <a href="/account/ip-policy">Account → IP restrictions</a> to edit either scope. You can configure an endpoint name before publishing it; only endpoints owned by your account use that policy. A different owner reclaiming the name does not inherit your rules.</p>
<h2>Owner API</h2><p>Use an owner login JWT in the Authorization bearer header on the platform origin. Consumer grants and endpoint tokens cannot manage policies.</p>
<p>Current <code>tunn login</code> saves renewable publisher device credentials, which cannot manage policies. Use the account UI, or pass an owner JWT file to every CLI command with <code>--owner-token-file /path/to/owner.jwt</code>. Obtain an owner JWT by POSTing <code>/api/device/code</code>, opening the returned verification_uri_complete and authorizing in the browser, then polling <code>/api/device/token?code=DEVICE_CODE</code> at the returned interval without durable=1. Save the successful access_token in a private file (mode 0600). It expires after 24 hours; repeat authorization when it expires. Keep credentials out of command arguments and shared logs.</p>
<pre>GET    /api/ip-policy             # account default
PUT    /api/ip-policy/my-app      # endpoint policy
DELETE /api/ip-policy/my-app      # inherit account default</pre>
<p>PUT replaces both lists with a JSON object containing allow_cidrs and deny_cidrs arrays. Example:</p><pre>{"allow_cidrs":["203.0.113.0/24"],"deny_cidrs":["203.0.113.42/32"]}</pre>
<p>The response includes allow_cidrs, deny_cidrs, inherited and configured when nonzero. A configured empty endpoint policy still overrides a restrictive default. Invalid input returns 400; unauthorized access returns 401/403; capacity or update limits return 429; authority outages return 503. Policies support 64 endpoint scopes per account and share the owner update throttle.</p>
<h2>Client IP and recovery</h2><p>The relay uses the socket peer address or HMAC-authenticated metadata from another relay node. Public Forwarded, X-Forwarded-For, X-Real-IP and Fly-Client-IP headers cannot bypass a policy. A reverse proxy must preserve the real socket client IP; arbitrary reverse proxy headers are not trusted.</p>
<p>A rejected visitor gets a 403 IP restriction page before authentication. An unknown client address is denied when rules are present. Owner sign-in and management remain reachable even from a blocked network. Rules apply to new requests, including reconnects; existing streams keep their original admission. If account identities merge, policies move with the account; conflicting rules for the same scope block both IP families until the owner edits that scope.</p>`
