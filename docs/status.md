# Relay status and observed history

`/status` is a public, read-only page. `/status.json` exposes the same data with
UTC timestamps. `/docs/status` explains the measurements. No availability SLA
is offered. Probes cover the selected relay ingress and its readiness checks;
they do not verify every region, sign-in provider, customer tunnel or application.

## Run a collector

Use a separate machine/process and persistent **local** disk, independent of
relay restarts. Do not use the relay account database or a shared network volume.
Build with `make build`, create a private writable directory, then run:

```sh
install -d -m 700 ./status-data
./bin/tunn status serve --listen 127.0.0.1:8091 --db ./status-data/status.db --probe https://tunn.to
```

The collector performs GET `/healthz` and `/readyz` immediately, then every minute.
Each request has a five-second timeout, normal certificate verification and no
redirect following. Only HTTP 200 is success. Network/TLS errors, timeouts and
non-200 responses count as failures. `/healthz` tests relay liveness; `/readyz`
also checks listener and storage readiness. An HTTPS origin is recommended;
HTTP is supported for local fixtures or trusted operator networks. URLs cannot
include credentials, paths, query parameters or fragments. The database is
bound to the probe origin: changing it requires a new database.

Configure `TUNN_STATUS_URL=http://127.0.0.1:8091` on **each relay** if the collector
is local, or use its operator-selected reachable origin. The relay fetches only
`/status` or `/status.json`; it forwards no cookies, credentials or query strings.
It allows three seconds and one MiB per response. Keep the collector close
enough to the relay to satisfy that deadline. No public incident write route
exists. Put collector HTTP behind TLS and a read-only reverse proxy if remote.
Its `/status` route can also be served at a separate status origin for outages:
`tunn.to/status` itself depends on tunn.to ingress and cannot remain reachable
when that ingress is down. Unconfigured/unreachable collectors return HTTP 503
and an unknown page, rather than a healthy claim. Observed relay failure still
returns HTTP 200 for the successfully rendered status page.

## Read the history

The dedicated SQLite database uses WAL and a five-second busy timeout. It stores
at most one observation per UTC minute, retaining the worst probe result if a
collector restart records that minute twice. Measurements older than 90 days
are deleted on each successful observation; the public chart shows today and
the preceding 89 UTC calendar days. No backfill occurs. Restart with the same
volume to retain history. If the collector stops, the last state becomes unknown
after 150 seconds; missing minutes never count as healthy. The page refreshes
every minute, so a browser can lag that transition by up to one refresh.

A daily bar is down if any liveness probe failed, degraded if only readiness
failed, healthy if every expected minute was observed and healthy, partial if
healthy observations have gaps, or unknown if no observations exist. Counts
show observed minutes, expected elapsed minutes and healthy observed minutes.
These are sampled measurements, not proof of continuous availability or an
availability percentage. Collector downtime and relay downtime are distinct.
No customer metadata, probe origin, failure text, credentials or account data
are included in the public response.

## Local incident notes

Only an operator with filesystem access to the status database can add or
resolve notes. Commands modify this local database; no API or account is used.
Review the exact public text before executing on a live collector.

```sh
./bin/tunn status incident --db ./status-data/status.db --title 'Relay readiness degraded' --note 'Investigating delayed readiness. Next update in 15 minutes.'
# The command prints an incident ID. Resolve that ID with the flags first:
./bin/tunn status resolve --db ./status-data/status.db --note 'Readiness recovered. Monitoring continues.' 1
```

Titles are limited to 120 bytes and notes to 2,000 bytes, rendered as escaped
plain text. Resolution replaces the current note and records a UTC timestamp;
this is a current incident summary, not an append-only postmortem system. Open
incidents remain visible even when older than the window. Resolved notes older
than 90 days are pruned with observations. The page shows up to 100 notes, open
first, then newest. No notes does not mean no outages.

## Acceptance before deployment

Run `make test-status`, `make check` and `make vet`. On a disposable relay/collector,
check healthy → readiness failure → liveness failure → recovery, collector stop
→ stale/unknown, restart with retained history and incident resolution. Use a
separate database for fixtures. Actual deployment, external reachability, outage
acceptance and 90 elapsed days of observations must be checked by an operator.
