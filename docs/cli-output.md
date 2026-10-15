# Terminal output

Sign in, run your local app, then start a tunnel:

```sh
tunn login
tunn http 3000
```

The URL requires sign-in. You and invited people can open it. To allow anyone with the link:

```sh
tunn http 3000 --public
```

The terminal prints the returned URL, local target and access scope. `Online` follows a local HEAD check. A reachable relay with an unreachable app shows `Local app unreachable`. The check repeats every 15 seconds while the relay is connected; forwarded requests can update the app state between checks. State lines date each transition. The last transition is current. Ctrl+C stops the tunnel.

Request rows show method, redacted path, HTTP result, elapsed time, bytes in/out and open streams. Paths shorten to fit the terminal; the JSON path remains complete. These are requests forwarded to the local app. Requests rejected at the edge, including uploads over its limit, do not reach this view. The HTTP response names the upload limit. Headers and bodies stay out of terminal output. `--inspect-body` retains bodies only with explicit `--inspect`.

```sh
tunn hosts
tunn service status
tunn hosts --json
tunn http 3000 --json
```

`hosts` lists account machines. Its connection reading describes the edge; local app health and access are not returned by that inventory. `service status` reads the local service manager. `tunn status` runs a probe collector for operators.

`http --json` writes one JSON object per line to stdout. Route, state and request events use `type`. Failures go to stderr as JSON objects. There are no colors, cursor controls or human headings. Inventory JSON keeps the existing array schema. `--json` cannot be combined with `--qr`.

| Field | Meaning |
|---|---|
| `type` | `route`, `state` or `request` |
| `url`, `target`, `access` | Returned HTTPS URL, local target and access scope |
| `state`, `message`, `detail`, `command` | State and its next action |
| `retry_delay_ms` | The active client's retry delay in milliseconds |
| `at` | Request start or state transition time in RFC 3339 format |
| `method`, `path`, `status` | HTTP method, redacted request path and result code |
| `duration_ms` | Elapsed time in milliseconds; zero is below one millisecond |
| `request_bytes`, `response_bytes` | Body bytes observed by the publisher |
| `active_streams` | Open streams when this request completed |

Fields that do not apply are omitted. Zero numeric fields are omitted; a request with no `status` has an unknown result. Unknown or interrupted responses have `state: "error"`; a completed HTTP 500 retains `status: 500`.

`NO_COLOR`, `TERM=dumb` and redirected output disable colors. A narrow terminal stacks request facts. Completed rows remain in the terminal after reconnects; the local inspector's bounded history starts again.
