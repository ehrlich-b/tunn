# Embed tunn in Python

This source package exposes `publish` / `publish_handler` and asyncio
`publish_async` / `publish_handler_async`. It starts one local helper process
per tunnel. The helper imports this revision's Go SDK, so relay authentication,
sharing, quotas, reconnects, HTTP/SSE and WebSocket transport use the existing
publisher. No package or helper is published to a registry.

## Install from this checkout

Python 3.11+ and the Go toolchain required by `go.mod` are needed for source
builds. From the repository root:

```sh
make build-python-helper
python -m pip install -e './sdk/python[asgi]'
```

The editable package finds `bin/tunn-python-bridge` in this checkout. For an
installed package outside the checkout, either set `TUNN_PYTHON_HELPER` to an
absolute path to that revision's helper or build a wheel with its helper:

```sh
python -m pip install build
make python-wheel
python -m pip install sdk/python/dist/*.whl
```

The wheel is platform-specific; build it on the target operating system and
architecture. The helper protocol is revision-specific. Rebuild both together;
do not point a newer package at an older helper. Origin publication needs no
Python dependencies. The `asgi` extra supplies Uvicorn, a managed WSGI adapter and WebSocket support
for handler publication. The helper is never built, downloaded or installed
implicitly by an application call.

## Publish an existing HTTP server

```python
import os
from tunn import Credentials, Options, publish

options = Options(
    origin="http://127.0.0.1:8080",
    name="python-app",
    credentials=Credentials(
        auth_token=os.environ["TUNN_AUTH_TOKEN"],
        tunnel_key=os.environ.get("TUNN_TUNNEL_KEY", ""),
    ),
    allowed_emails=("alice@example.com",),
)
with publish(options) as tunnel:
    print(tunnel.wait_ready(timeout=15))
    tunnel.wait()
```

The application supplies credentials explicitly; the SDK reads no login cache,
opens no login flow and creates no account. Empty credentials follow the relay's
configuration. Do not put secrets in command arguments. `Credentials` and
`Options` have redacted representations; helper diagnostics and remote errors
are excluded from SDK errors/events. Application handlers own their logging.

Tunnels are **private by default**. With no allow-list or endpoint token, the
relay must support `web-sharing-v1` and authenticate an owner. Use
`allowed_emails=("alice@example.com", "@example.org")` for relay sharing or
`Credentials(endpoint_token="tunn_ep_...")` for an existing endpoint bearer
credential. Only its SHA-256 digest reaches the relay. `public=True` explicitly
enables anonymous HTTP access and cannot be combined with either private
setting. Platform ingress uses `Tunn-Authorization`; application
`Authorization` remains separate. `require_upstream_auth=True` requires a
remaining application header, which the application must validate.

## Publish a Python MCP server

Install the source package as above and `python -m pip install 'mcp>=1,<2'`.
This example uses the MCP SDK's v1 Streamable HTTP application:

```python
import asyncio
import os
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from tunn import Credentials, Options, publish_handler_async

# Match your relay's exact public hostname; retain Host and Origin guards.
public_host = "python-mcp." + os.environ.get("TUNN_DOMAIN", "tunn.to")
mcp = FastMCP(
    "python-tunnel", stateless_http=True, json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[public_host],
        allowed_origins=["https://" + public_host],
    ),
)

@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b

async def main():
    app = mcp.streamable_http_app()
    # Keep MCP's task group alive for the entire tunnel lifetime.
    async with mcp.session_manager.run():
        options = Options(
            name="python-mcp",
            credentials=Credentials(
                auth_token=os.environ["TUNN_AUTH_TOKEN"],
                tunnel_key=os.environ.get("TUNN_TUNNEL_KEY", ""),
                endpoint_token=os.environ["TUNN_ENDPOINT_TOKEN"],
            ),
        )
        async with await publish_handler_async(app, options) as tunnel:
            print((await tunnel.wait_ready(timeout=15)) + "/mcp")
            await tunnel.wait()

if __name__ == "__main__":
    asyncio.run(main())
```

Use an existing endpoint token authorized for this publisher; the SDK does not
provision it. A bearer-aware MCP client can supply
`Tunn-Authorization: Bearer <endpoint-token>`. Hosted connector OAuth onboarding
is a separate relay journey; this example does not add an MCP OAuth issuer or
claim hosted connector acceptance. Keep your MCP transport's DNS rebinding and
Origin validation enabled. Configure its accepted public hostname deliberately
if your MCP version requires it; do not disable those checks.

## Lifecycle and handler ownership

Both start functions return after local validation and helper startup.
`wait_ready(timeout)` waits for the first relay registration. Its timeout or
cancellation affects that wait alone. `wait(timeout)` retains the terminal
result; `close()` cancels and joins owned resources and succeeds on intentional
shutdown. Repeated/concurrent close is safe. A completed failure stays visible
through wait/close. `cancel()` stops the lifetime and retains a `TunnelError`
with code `cancelled`. Supply a `threading.Event` to sync `cancel_event` or an
`asyncio.Event` to async `cancel_event`. `lifetime_timeout` bounds the lifetime
and retains `deadline_exceeded`. Cancelling a coroutine that calls start closes
any resources already started. Cancelling a wait leaves the tunnel alive;
use `async with` to close it when the owning application task exits.

`name` is stable across reconnects. `url` retains the last confirmed URL;
`status.state` reports current connectivity. `events()` is a single-consumer
iterator (an async iterator on AsyncTunnel), retaining at most 16 events and
always retaining the final `closed` event. States match Go: `connecting`,
`ready`, `reconnecting`, `failed`, `closed`. Events expose only public URL,
safe error category and retry delay. Sync methods support concurrent threads;
async methods belong to the loop where the tunnel was started.

`publish_handler(handler, Options(), interface="wsgi")` accepts a WSGI callable;
the default `interface="asgi"` accepts an ASGI callable. Async handler
publication runs the callable on the caller's loop; sync publication owns one
background loop/thread. The adapter binds an ephemeral **loopback TCP port**,
which is reachable by other local processes. It does not open an external
listener. Unlike Go's handler pipe, it is not an in-process transport. Closing
the tunnel closes the owned listener and requests cancellation of active ASGI
requests. Caller-owned origin servers and other tunnels stay alive. Uvicorn
receives no signal handlers or logging configuration from this package.

The application owns ASGI lifespan: the adapter does not invoke lifespan
startup/shutdown. Enter the application's lifespan context yourself, as the MCP
example does. Handlers must cooperate with cancellation. Python cannot stop
WSGI threads or application code that ignores cancellation. WSGI callbacks can
check `environ["tunn.cancelled"]`, a `threading.Event`, during cooperative work.
Closing waits for WSGI workers to return, closes their response iterables, and
joins the adapter's thread pool. Uncooperative callbacks can delay close. Sync handler callbacks must not call blocking methods on
the same tunnel from its background loop. ASGI/WSGI response behavior follows
the chosen server's support; ASGI response trailers and WSGI WebSockets have no
promise. HTTP origin mode retains the Go SDK's transport contract.

## Options, errors and checks

`ReconnectPolicy()` uses 5 consecutive retries, initial 1 second, maximum
30 seconds, with Go's equal jitter. An explicit `max_attempts=0` disables
retries. The budget resets after 30 seconds of stable connection. Connection
and registration default to 10 seconds; HTTP requests/streaming response
headers default to 30 seconds. WebSocket limits default to 300 seconds idle,
30 seconds keepalive and 8 MiB messages. `TLSOptions(root_ca_pem=..., server_name=...)`
sets independent verified relay/origin trust; default TLS uses system roots.
There is no TLS-verification bypass option.

`TunnelError.code` is `invalid_options`, `connection_failed`,
`registration_rejected`, `protocol_violation`, `helper_unavailable`,
`handler_failed`, `cancelled` or `deadline_exceeded`. Wait timeouts raise
`TimeoutError`. Remote strings and underlying errors never appear in these
errors. No implicit credential refresh is performed.

From the repository root, install the test dependencies with
`python -m pip install -e './sdk/python[test]'`, then run:

```sh
make test-python-unit
make test-python-contract
make test-sdk-contract
```

The contract gate requires a real disposable loopback TLS/gRPC/HTTP relay;
listener denial fails it. All fixture credentials/accounts are disposable.
No production connection, registry publication, deployment, control-plane write
or paid acceptance is implied. TCP publishing, service installation, inspector,
MCP child supervision, login/cache management and provisioning are outside this
binding. See [the Go contract](../../docs/go-sdk.md) for transport limits.
