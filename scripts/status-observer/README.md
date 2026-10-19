# Public endpoint observations

Python 3.9+ on Linux; no packages or credentials required. Each run sends four
GET requests to `https://tunn.to`: `/healthz`, `/readyz`, `/`, `/dl/latest.json`.
Redirects and ambient proxies are disabled. HTTP 200 is success; other statuses,
timeouts, DNS and TLS errors are observations of failure. Latency measures response
headers, not body download or content correctness. Nothing is sent to write APIs.

## Install as a user service

Choose an absolute persistent data directory on local disk, owned by the service
user. From this directory:

```sh
install -d "$HOME/.local/lib/tunn-status" "$HOME/.config/tunn-status" "$HOME/.config/systemd/user"
install -m 644 observer.py "$HOME/.local/lib/tunn-status/observer.py"
install -m 644 ./*.service ./*.timer "$HOME/.config/systemd/user/"
# Set this to the assigned persistent observation directory before proceeding.
test -n "$STATUS_DATA_DIR"
install -d -m 700 "$STATUS_DATA_DIR"
printf 'STATUS_DATA_DIR="%s"\n' "$STATUS_DATA_DIR" > "$HOME/.config/tunn-status/environment"
chmod 600 "$HOME/.config/tunn-status/environment"
systemctl --user daemon-reload
systemctl --user enable --now tunn-status.timer tunn-status-rollup.timer
systemctl --user start tunn-status.service
systemctl --user list-timers 'tunn-status*'
```

The operator must enable lingering for this user (`loginctl enable-linger USER`)
or arrange an equivalent user manager at boot. Verify `loginctl show-user USER
-p Linger` says `yes`; enabling a user timer alone does not ensure boot startup.
The two timers are persistent: reboot catch-up starts one observation and rolls
up all closed days. Missed minutes remain gaps; they are never backfilled as
successful probes. Ensure the host clock is synchronized. No installation or
service activation is performed by the tests.

## Storage and reports

`raw/YYYY-MM-DD.jsonl` rotates at UTC midnight without moving, truncating,
compressing or deleting earlier files. Each result is appended and fsynced,
including failures. Keep the entire data directory across upgrades and reboots;
there is no automatic retention deletion. At four rows per minute expect about
2 MB daily. A shared advisory lock prevents overlapping commands. A torn JSONL
tail stops collection for investigation rather than rewriting evidence.

```sh
python3 observer.py rollup --data-dir "$STATUS_DATA_DIR"
python3 observer.py report --data-dir "$STATUS_DATA_DIR"
```

Closed UTC days are written once to `daily/YYYY-MM-DD.json`. The first day is
partial; later missing days have zero coverage. Existing summaries are untouched.
Reports always recompute from raw records, show the first observation's UTC start
date, elapsed days, and days remaining to 30 (rounded up). An empty directory has
no start date and 30 days remaining. The start is never set by installation.

Each endpoint shows observed uptime, coverage, missing/failed minutes, conservative
availability including gaps, and successful-request p50/p95/max header latency.
Duplicate samples cannot conceal outages: any failure makes that minute failed.
The current minute is included. Malformed records are counted and prevent a
complete 30-day claim. `thirty_days_complete` requires 30 elapsed days and no
missing minutes from the first sample through the report time. This is evidence
from one host, not a guarantee of worldwide availability.

The default report comparison is 99.9% availability and p95 headers <=1000 ms;
these are operational targets, not a commercial promise. Override with
`--availability` and `--latency-ms`. `slo_met` compares the accumulated window;
check `thirty_days_complete` separately before claiming 30 days of evidence.

Run tests with `python3 -m unittest discover -s scripts/status-observer -v` from
the repository root. Tests use an HTTP loopback fake server and temporary data.
`--base-url http://127.0.0.1:PORT` is for isolated tests only: keep test observations
in a separate directory. The production units always use the fixed public origin.
