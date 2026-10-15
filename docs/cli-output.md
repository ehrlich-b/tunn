# Terminal output

Sign in and choose who can open your local app:

```sh
tunn login
tunn 3000                              # only you
tunn 3000 --allow=alex@example.com      # invite a person
tunn 3000 --allow=@example.com          # invite an email domain
tunn 3000 --public                     # anyone with the link
```

The terminal prints the returned URL, local target and access scope. Requested emails describe startup flags; `tunn access NAME` reports the current invitations. A named tunnel can retain its existing access rules across restarts. Endpoint tokens appear as a separate access method when enabled. Targets with URL credentials or a query use `tunn share NAME EMAIL` guidance so the local URL is not echoed.

`Online` follows a local HEAD check. A reachable relay with an unreachable app shows `Local app unreachable` and a check command for the requested target. Route checks distinguish the connected edge/client from the unchecked browser. Readiness repeats every 15 seconds while the relay is connected; forwarded requests can update it between checks. Each state transition has a timestamp. Ctrl+C stops the tunnel.

Request rows show start time, method, redacted path, HTTP result and elapsed time. Every request fits one row at 40 columns; narrow paths and long methods shorten with `~`. Bytes remain in the stop summary and JSON. A 413 row names the 100 MiB edge cap as a reference: an application can reject a body at a different size. Uploads rejected at the edge do not reach the forwarded-request table; the edge's HTTP response names the actual limit. Headers and bodies stay out of terminal output. `--inspect-body` retains bodies only with explicit `--inspect`.

```sh
tunn hosts
tunn service status
tunn hosts --json
tunn 3000 --json
```

`hosts` lists account machines and tunnels. Its connection reading describes the edge; local app health remains unchecked. Current access scope is public, private or unknown when authority is unavailable. Older relays that omit access show unknown plus a command to check it. `service status` reads the local service manager; a missing service points to `tunn service install`. Operator probe collection uses `tunn status --help`.

`--json` writes one object per line to stdout. Failures go to stderr as JSON. No colors, human headings or cursor controls are added. Inventory keeps its array schema, with optional `access` and `endpoint_token` fields per endpoint. Route and state events omit request-only measurements; every request includes the numeric measurement fields even when zero.

| Field | Meaning |
|---|---|
| `type` | `route`, `state` or `request` |
| `url`, `target` | Returned HTTPS URL and local target |
| `access` | `public` or `private` on route events |
| `endpoint_token` | True when endpoint tokens are enabled |
| `requested_emails` | Requested startup invitations; check current access separately |
| `state`, `message`, `detail`, `command` | State and its next action |
| `retry_delay_ms` | Actual retry delay in milliseconds |
| `at` | Request start or transition time in RFC 3339 format |
| `method`, `path`, `status` | Method, redacted path and HTTP code (zero means unknown) |
| `duration_ms` | Elapsed milliseconds; zero means below one millisecond |
| `request_bytes`, `response_bytes` | Body bytes observed by the publisher |
| `active_streams` | Other streams still open when this request completed |

`NO_COLOR`, `TERM=dumb` and redirected stdout disable colors. Redirected human output uses a fixed width; hints, state transitions and summaries go to stderr. Terminal colors follow the terminal palette; the orange URL accent uses truecolor only with a reported light or dark background. Completed rows remain after reconnects; the local inspector's bounded history starts again.
