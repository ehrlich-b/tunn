# Testing Guide

## Quick Start: Local Testing

```bash
./test-local.sh
```

This script:
- Builds the binary
- Starts a test web server on port 8000
- Starts the proxy in dev mode (mock OIDC)
- Prints instructions for manual testing

## WebSocket regression suite

Run the repository gates and full loopback WebSocket stack:

```bash
make vet
make test
make test-websocket
```

`test-websocket` uses a local TLS relay with the actual gRPC publisher and a
WebSocket echo fixture. It covers text/binary and 1 MiB frames, fragmentation,
control frames and both close handshakes, 100 simultaneous sockets and slot
reuse, upgrade auth denial/allow, token HTTP access and live rotation/revocation,
forwarded headers and credential stripping, local HTTPS upstreams, idle expiry,
partial-frame cleanup, and configurable keepalive. No public relay or external
identity provider is contacted.

For environments that prohibit socket binds, keep those gates intact and run:

```bash
make test-websocket-unit
make test-websocket-memory
```

The memory variant runs the same WebSocket stack tests over `net.Pipe`, including
TLS and gRPC. It validates the application path while preserving the default
loopback suite for an unrestricted environment. Socket-bound tests in the full
suite still require loopback permission. Focus an individual memory regression
with `make test-websocket-memory WS_TESTS=TestWebSocketPartialFrameIdle`.

Real OpenClaw and mobile-client acceptance remain manual; see the
[OpenClaw guide draft](docs/guides/openclaw.md).

## Manual Testing

### Terminal 1: Start the proxy

```bash
TUNN_ENV=dev ./bin/tunn -mode=host
```

### Terminal 2: Login

```bash
TUNN_SERVER_ADDR=localhost:8443 ./bin/tunn --dev login
```

Follow the device flow - open the URL in browser, log in with mock OIDC.
Codes last ten minutes. The CLI prints their expiry time and replaces expired
codes automatically while waiting; open the newest link printed in the terminal.

### Terminal 3: Start tunnel

```bash
TUNN_SERVER_ADDR=localhost:8443 ./bin/tunn --dev 8080 --allow test@example.com
```

Copy the tunnel URL that's printed.

### Terminal 4: Test in browser

1. Open the tunnel URL
2. You'll be redirected to login
3. Log in with the SAME email from step 2
4. If your email is on the allow-list, you'll see the page

## Test Scenarios

### Authorized Access

1. Login as `alice@example.com`
2. Create tunnel: `tunn 8080 --allow alice@example.com`
3. Visit tunnel -> should see page

### Unauthorized Access

1. Login as `alice@example.com`
2. Create tunnel: `tunn 8080 --allow bob@example.com`
3. Visit tunnel -> should see "Access Denied"

### Domain Wildcard

1. Login as `alice@company.com`
2. Create tunnel: `tunn 8080 --allow @company.com`
3. Visit tunnel -> should see page

### Creator Auto-Allowed

1. Login as `alice@example.com`
2. Create tunnel: `tunn 8080` (no --allow flag)
3. Visit tunnel -> should see page (creator is always allowed)

## Docker Testing

```bash
docker compose -f docker-compose.test.yml up --build
```

Starts proxy and test web server in containers.

## Integration Tests

The authenticated MCP lifecycle has a self-contained local test:

```bash
make integration-test-lifecycle
```

It starts an isolated TLS relay, mock login provider, SQLite database, and
echo-only stdio fixture. It requires explicit device authorization, then tests
endpoint-token access, discovery, tool policy, live token rotation, relay
reconnect, a 25-second timeout, recovery, and child-process failure. Traffic goes
directly to loopback; no DNS changes, browser, developer login-token file, or
external service is needed. Scratch state lives under `.scratch/`; private logs
are retained there on failure. The test takes about 30 seconds after the build.

Expiring, revocable per-consumer grants are implemented and tested by the
metering gates below. MCP OAuth discovery, PKCE and consent are covered by
the [connector contract](MCP-CONNECTOR.md). Synthetic local clients do not
establish acceptance by ChatGPT, Claude, or another hosted UI.

## Production dogfood regressions

All fixtures are local and use no production credentials. Run the defaults,
proxy login/HTTP2 CONNECT/gRPC, 100 MiB upload-boundary and device-code tests:

```bash
GOTOOLCHAIN=go1.26.9 GOPROXY=off GOSUMDB=off make build vet test-dogfood
```

If socket binds are prohibited, run `make test-dogfood-memory` with the same
environment. It uses the same TLS/HTTP2/gRPC proxy fixture over in-memory
sockets, plus the SQLite and forwarding regressions. The default loopback gate
still must run in an unrestricted coordinator environment; it never skips a
denied listener. Full validation remains `make test` there.

```bash
make test-lifecycle-contract # In-process regressions, including race detection
make test                   # Full suite; requires loopback sockets
make check                  # Existing format/tidy/race gate; requires loopback
make vet
make lint                   # Requires golangci-lint v2
```

Sandboxes that deny loopback listeners can run the contract tests, vet, and
lint, but must run the full suite and end-to-end test outside that sandbox.

```bash
# All integration tests
./scripts/integration-tests/run-all.sh

# Individual tests
./scripts/integration-tests/smoke-test.sh
./scripts/integration-tests/device-login-test.sh
./scripts/integration-tests/auth-flow-test.sh
```

## Troubleshooting

### "not logged in"

Run `tunn login` first to get a JWT token.

### "Invalid tunnel key"

Set `WELL_KNOWN_KEY=tunn-free-v1-2025` or pass `--tunnel-key=tunn-free-v1-2025`.

### "Access Denied"

The email you logged in with is not on the tunnel's allow-list.

### Certificate errors

Dev mode uses self-signed certs. Click "Advanced" -> "Proceed" in browser.

### DNS not resolving

Use the full nip.io URL: `https://abc123.tunn.local.127.0.0.1.nip.io:8443`

## Metered HTTP grants (local only)

`make test-metering-contract` runs the new SQLite, HTTP forwarding fixtures,
owner CLI/transport and memory-backed internal gRPC tests with race detection;
it needs no loopback listener. Existing relevant auth/proxy regressions also run.
`make integration-test-metering` builds and starts a real TLS relay, publisher,
and synthetic HTTP target on literal loopback IPs. It exercises CLI issuance,
independent quotas, request/byte boundary counts, expiry, revocation, rate limits,
and relay restart durability. All credentials and SQLite files are disposable
fixtures under `.scratch`; it uses no live service or wildcard DNS.

A sandbox that rejects TCP/UDP binds cannot run that E2E or the full `make check`.
Keep those tests intact and run both commands on the coordinator host. The
accounting definitions and commercial reconciliation limits are in
[docs/METERING.md](docs/METERING.md).

## Inspector contracts and browser journey

```sh
make -j1 test-inspect-contract                       # No listener; race fixtures
make -j1 test-inspect-contract INSPECT_MODE=loopback # Actual local HTTP target
make -j1 test-inspect-contract INSPECT_MODE=browser  # Actual Chrome UI, mocked API
```

The offline mode covers credential/header/cookie/query/body sentinels, 50-event
eviction, the exact 64 KiB boundary, incomplete bodies, concurrent captures,
original-target binding, explicit reconstruction, cancel, one-use/double-click
admission, replay status/failure and export-drop counters. HTTP target dispatch
uses `net.Pipe`, with no listener or external service. Loopback mode retains
real listener tests and fails if listeners are denied. Browser mode uses the
actual HTML/JS with generated redacted snapshots and a disposable Chrome profile
under `.scratch`; browser absence or launch denial is not a passing skip. It
checks inspect/select/replay/result/error, rendered sentinels, captured HTML as
data, and unsupported SSE/WS/CONNECT/truncated states. It does not certify a
hosted relay or phone browser. See [inspection.md](docs/inspection.md).
