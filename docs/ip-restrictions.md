# IP restrictions

`tunn ip-policy set --account --allow 203.0.113.0/24,2001:db8::/32` sets
an account default. `tunn ip-policy set my-app --deny 203.0.113.42/32` sets an
endpoint policy. `tunn ip-policy get my-app` shows the effective policy;
`tunn ip-policy clear my-app` restores the account default.

Current `tunn login` saves renewable publisher device credentials, which cannot
manage account policies. Use the account UI, or supply a separate owner JWT:
`tunn ip-policy get --account --owner-token-file /path/to/owner.jwt`.
To obtain an owner JWT through the existing owner authorization flow, POST
`/api/device/code` on your relay's platform origin, open the returned
`verification_uri_complete` and authorize it in the browser. Poll
`/api/device/token?code=DEVICE_CODE` at the returned interval, without `durable=1`.
Save the successful response's `access_token` in a private file (mode 0600).
Do not paste credentials into command arguments or shared logs. This owner
token expires after 24 hours; repeat authorization when it expires. The owner
file option works with get, set and clear, including `--server` for self-hosting.

An endpoint policy replaces the default. Deny wins; a nonempty allow list
requires a match. Empty lists permit all IPs. Use /32 for one IPv4 address and
/128 for one IPv6 address. Both lists accept at most 64 CIDRs, normalized to
network addresses. IPv4-mapped IPv6 addresses are evaluated as IPv4.

The account page links to `/account/ip-policy`, with endpoint selection,
validation errors, save feedback and a restore-inheritance action.

Owner login bearer credentials can GET, PUT and DELETE `/api/ip-policy` (the
account default) or `/api/ip-policy/NAME` (an endpoint). PUT accepts
`{"allow_cidrs":["203.0.113.0/24"],"deny_cidrs":[]}` and replaces both lists.
GET/PUT/DELETE return the effective policy, with `inherited` and `configured`
flags when true. False flags and empty lists can be omitted. Browser mutations
require the platform origin; the account UI also requires session-bound CSRF.
Consumer grants and endpoint capabilities cannot change rules.

Policies belong to account UUIDs and endpoint names. Names may be configured
before publication, with at most 64 endpoint scopes per account. A different
owner reclaiming a name does not inherit rules. Account merges retain all
policies; conflicting scopes block both families until edited by the owner.

Every new HTTP, WebSocket, SSE, MCP and CONNECT request checks policy before
visitor credentials, domain app sign-in or sharing. Existing streams retain
their admission. Platform management/sign-in and public MCP discovery metadata
remain reachable. Denied visitors see 403; unavailable policy authority fails
closed with 503. Unknown client IPs fail closed when any rule is configured.

The source is the socket peer or authenticated relay forwarding metadata.
Public forwarding headers (including Fly-Client-IP) are ignored. Deploy behind
an edge that preserves socket client IPs; untrusted reverse-proxy headers are
not a supported client IP source. Configure both families where clients use
IPv6. IP restrictions supplement application authentication.
