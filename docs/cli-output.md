# Terminal output

Sign in and choose who can open your local app:

```sh
tunn login
tunn 3000                              # only you
tunn 3000 --allow=alex@example.com      # invite a person
tunn 3000 --allow=@example.com          # invite an email domain
tunn 3000 --public                     # anyone with the link
```

The terminal prints aligned `url`, `to`, `allowed` and `others` readings. `allowed` lists the `--allow` emails and you, or only you; people invited earlier with `tunn share` keep access, and `tunn access NAME` lists them. Visitors outside the list get a 403 at the edge. Endpoint tokens appear as a separate `token` reading when enabled. A private tunnel started without `--allow` suggests `tunn share NAME EMAIL`, which never echoes local URL credentials. Every hint uses the `tunn 3000` form.

`Online` follows a local HEAD check. A reachable relay with an unreachable app shows `Local app unreachable`, then a route check with one aligned row per hop (browser, edge, tunn on laptop, local target) and the check command for the requested target last. Readiness repeats every 15 seconds while the relay is connected; forwarded requests can update it between checks. Each state transition has a timestamp. Ctrl+C stops the tunnel.

Human request rows show completion time, method, redacted path, HTTP result and elapsed time. JSON keeps the request start time in `at`. Below 70 columns the time column is dropped and its cells go to the path. Long paths collapse the query first, then the middle, so the last segment stays readable; every request fits one row at 40 columns, and a narrow 413 row adds the cap on an indented line. Help and hint text wraps at spaces. Bytes remain in the stop summary and JSON. A 413 row names the 100 MiB edge cap as a reference: an application can reject a body at a different size. Uploads rejected at the edge do not reach the forwarded-request table; the edge's HTTP response names the actual limit. Headers and bodies stay out of terminal output. `--inspect-body` retains bodies only with explicit `--inspect`.

```sh
tunn hosts
tunn service status
tunn hosts --json
tunn 3000 --json
```

`hosts`, `list`, and `status` list account machines and tunnels. `status serve`, `status incident`, and `status resolve` keep their status-page commands. Its connection reading describes the edge; local app health remains unchecked. Current access scope is public, private or unknown when authority is unavailable. Older relays that omit access show unknown plus a command to check it. `service status` reads the local service manager; a missing service points to `tunn service install`. Operator probe collection uses `tunn status --help`.

`--json` writes one object per line to stdout. Failures go to stderr as JSON. No colors, human headings or cursor controls are added. Inventory keeps its array schema, with optional `access` and `endpoint_token` fields per endpoint. An endpoint that stopped sending heartbeats adds `cause` and `next_action`; app health remains unknown. The restart command must run on the named source machine. Route and state events omit request-only measurements; every request includes the numeric measurement fields even when zero.

| Field | Meaning |
|---|---|
| `type` | `route`, `state` or `request` |
| `url`, `target` | Returned HTTPS URL and local target |
| `access` | `public` or `private` on route events |
| `endpoint_token` | True when endpoint tokens are enabled |
| `requested_emails` | Requested startup invitations; check current access separately |
| `state`, `message`, `detail`, `command` | State and its next action |
| `cause`, `next_action` | Failure cause and one command or URL; `command` remains available |
| `http_status` | Original HTTP status of a failed inventory request |
| `retry_delay_ms` | Actual retry delay in milliseconds |
| `at` | Request start or transition time in RFC 3339 format |
| `method`, `path`, `status` | Method, redacted path and HTTP code (zero means unknown) |
| `duration_ms` | Elapsed milliseconds; zero means below one millisecond |
| `request_bytes`, `response_bytes` | Body bytes observed by the publisher |
| `active_streams` | Other streams still open when this request completed |

`NO_COLOR`, `TERM=dumb` and redirected stdout disable colors. Redirected human output uses a fixed width; hints, state transitions and summaries go to stderr. Terminal colors follow the terminal palette, with cyan links, bold titles and dim timestamps. Completed rows remain after reconnects; the local inspector's bounded history starts again.

`tunn --version` and `tunn version` print the embedded build version without loading configuration or signing in. Invalid flags still fail. Release builds set the tag with `-ldflags "-X main.version=<tag>"`.

Run `make test-installer-offline` to build a local release fixture, install it through the verified `/dl` layout, check both version commands and confirm that a bad checksum leaves existing installations intact. The fixture transport reads only local files and makes no network requests.

Failures name the cause and show one command or URL. Missing or expired login points to `tunn login`, preserving `TUNN_CONFIG_DIR` when set. Human service logs name the resolved credential directory in `TUNN_CONFIG_DIR=... tunn login`, then tell you to restart the service. Publishers keep service exit status 78 when login cannot renew. In JSON mode that failure is a JSON object, including failures during startup renewal. `--json` reports a missing login immediately. HTTP publisher JSON uses `auth_missing` for a missing login and `auth_expired` for an expired or rejected login. Inventory keeps `auth_expired` for missing credentials and HTTP 401 or 403; `cause` and `http_status` distinguish them. Limits keep the relay's tunnel count and point to the configured relay's account page.

A closed local port says to start the app on the shown address, then prints `curl -I` for that address. Relay failures name a refused connection, DNS failure or timeout when known and print a bounded `curl` check for the configured relay. These commands verify the app or connection after repair. While reconnecting, tunn keeps its existing backoff; the check command does not start a second tunnel. URL credentials and queries stay out of recovery commands. `tunn http --help` covers these failures.
