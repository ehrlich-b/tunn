# Temporary private-tool grants

This milestone adds independently revocable, expiring credentials for the
literal HTTP `/mcp` route of an account-owned endpoint. It has been verified on
synthetic loopback services on macOS. It has not been deployed.

## Owner workflow

Publish a native HTTP MCP server with `tunn mcp`, then use the saved account
login to create a separate grant for each client. Options precede the endpoint:

```sh
tunn grant create --for client-a --expires 30m --requests 20 --out ./client-a.token build-tools
tunn grant create --for client-b --expires 30m --requests 20 --out ./client-b.token build-tools
tunn grant list build-tools
tunn grant revoke <client-b-grant-id>
```

The credential goes only into the requested new file, created with mode 0600.
An existing path is refused before creation. Metadata, including the grant ID,
prints as JSON without the credential. The relay stores only its SHA-256 digest.
The one-time credential is not recoverable through listing. If saving fails
after creation, the error supplies the grant ID so the owner can revoke it.

The client sends the file's value in `Authorization: Bearer <grant-token>` or
`Tunn-Authorization: Bearer <grant-token>`. The dedicated header permits a
separate application Authorization credential. Tunn removes its own signed JWTs,
endpoint tokens, grants and authentication cookies before forwarding.

`--server https://relay.example`, `--owner-token-file <file>` and
`--ca-cert <PEM>` support a self-hosted relay without disabling certificate
verification. Client control requests refuse redirects. These commands operate
on the selected relay; this implementation work exercised temporary test
databases and fixture credentials only.

The account page links `/api/grants` for owner-visible JSON metadata. Its fields
include label, endpoint, creation/expiry, request limit, used count and revoked
state. `/api/usage` exposes completion events and per-grant caller counters as
`grant:<id>`, without attributing a shared capability to a human identity.

## Admission and revocation semantics

- Grant creation requires verified account access and an active registration
  owned by that account. Central registry metadata must declare HTTP or MCP;
  raw TCP, unknown and older registrations are rejected. Owner API mutations
  require a bearer access token. Cookies alone cannot create or revoke grants.
- Grants are bound to an owner and endpoint name. A replacement endpoint owned
  by another account cannot reuse the old grant. Merged accounts retain the
  grant's owner and usage history through canonical account aliases.
- Only literal `/mcp` is permitted. Other routes, encoded path variants, and
  raw CONNECT are denied before forwarding. The publisher can map this literal
  public path to a different configured upstream MCP path.
- The lifetime is 1 second through 30 days and the request limit is 1 through
  1,000,000. Every admitted HTTP request consumes one slot, including MCP
  initialization, notifications, discovery and control traffic. This is an
  admission allowance, not a tool-call count or monetary charge.
- SQLite reserves the slot atomically before forwarding. Concurrent calls cannot
  exceed the allowance. A single bounded storage retry reuses a server-generated
  request ID. Caller-supplied IDs cannot bypass allowance. Consumption persists
  across reconnects and database reopen; admitted failures are not refunded.
- Explicit malformed, expired, exhausted or revoked grants cannot fall back to
  a cookie, shared endpoint token or account bearer. Invalid credentials receive
  401; expiry/revocation receive 403 when MCP OAuth is disabled, and 401 with
  resource discovery when it is enabled; exhausted allowance receives 429. Storage
  admission failure receives 503 and forwards nothing.
- Once revocation acknowledges, later admissions are denied. Already-admitted
  work may finish, including an admitted long response. Expiry follows the same
  admission boundary. Revocation does not terminate active requests or upstream
  sessions. Denials consume no grant slots or forwarded bytes. Owner bandwidth
  limits are checked before consuming a grant slot.

## Verification and limits

`make test-grants` exercises atomic concurrent allowance, persistence, account
merges, owner/RPC trust boundaries, route scope, explicit credential precedence,
cookie/JWT redaction, ambiguous retry, CLI file safety and redirect refusal.
`make check TEST_ARGS='-timeout=120s -count=1'` runs the complete race-enabled suite.

The native MCP fixture supplies read-only search/read tools over an in-memory
synthetic build corpus. It does not read the actual repository or filesystem.
Both official SDKs perform seven calls, find a missing generated TypeScript
schema step and produce six matching citations through actual local TLS gRPC
publishing and a second HTTP routing node. Revocation blocks one client while
the other continues, including after publisher reconnect. The owner sees
separate consumption and attributed completion records.

Set up the pinned Python SDK with
`make -f scripts/integration-tests/build-investigation/Makefile setup-python`,
then run `make test-build-workflow`. Go-only relay coverage is included in the
ordinary suite; the two-language test is explicit so a Python installation is
not required for every Go contributor. [Recorded evidence](../scripts/integration-tests/build-investigation/EVIDENCE.md)
includes commands, protocol versions, citations and bounded timing observations.
Race-instrumented relay connection-to-answer timings were approximately 73 ms
for Go and 122 ms for Python in one run; installation, compilation and hosted
agent setup are excluded.

The investigator logic is deterministic. [MCP OAuth](MCP-OAUTH.md) now provides
local discovery, owner consent and static public-client authorization. Hosted
ChatGPT/Claude onboarding, actual application registrations, public reachability
and model-driven reasoning remain unverified. The HTTP fixture is stateless; grants do not isolate arbitrary
upstream MCP sessions, enforce tool names/arguments or make a mutable server
read-only. The older shared stdio adapter still has session and cancellation
limitations and is not the basis for this milestone. Grant/admission rows have
no automatic retention policy yet. The completion ledger retains its documented
bounded retry limits; the durable admission counter is the authority for the
request allowance.
