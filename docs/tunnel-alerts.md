# Tunnel email alerts

Alerts are off by default. After you enable them, when a reserved tunnel has
connected successfully and then stays offline for 10 minutes, tunn emails the
account's primary email address through the relay's
existing SMTP configuration. A recovery email follows when the publisher
connects again. Names that have never connected do not generate email.

Open **Account → Tunnel email alerts** (`/account/tunnel-alerts`) to enable
**Email alerts for my account**, disable alerts, change the offline threshold
(1 second to 7 days), or
request alerts after clean shutdowns too. Clean shutdowns are suppressed by
default. When both publisher and relay advertise `graceful-stop-v1`, only an
explicit `GracefulStop` message proves a clean shutdown. Every other registration
end is an outage candidate, including cancellation, EOF without that message,
terminal credential-refresh failure, transport loss and relay timeouts. The relay
records the registration's stop reason before cleanup and uses that reason for
the availability report. An expired login still alerts if the publisher cannot
authenticate again. Internal failures never send `GracefulStop`. When both sides
also advertise `failure-stop-v1`, a terminal credential rejection sends a
distinct failure message so the relay can include the diagnosis in the email.

Legacy publishers without `graceful-stop-v1` retain clean client cancellation and
EOF handling. SSH SIGINT, stdin Ctrl-C/Ctrl-D, session closure, cancel-forward,
requested expiry and MCP stdio EOF are clean stops too, even without a shutdown
message.
SSH stdin EOF alone keeps the existing `ssh -n` tunnel running; closing its
session afterwards is a clean stop. These paths generate no default outage or
recovery email. A dropped SSH or HTTP/2 socket still counts as transport loss.

Each tunnel can attempt at most one email per hour, including recovery, so a
recovery email can wait for that window. Repeated brief reconnects during that
window are consolidated. Failed SMTP attempts retain the hourly slot and retry
later while that notification still applies. Email delivery needs SMTP on the
login node; replicas report availability to that node and do not send email.

The relay checks every 30 seconds. A lost relay process is detected after
90 seconds without an availability heartbeat, then the account's offline
threshold applies. Availability, settings and mail rate limits survive login
node restarts. A stale publisher cannot mark its replacement offline.

Emails identify the tunnel and outage time in UTC, include the last known relay
diagnosis when available, and show `tunn status` and the relay-specific
`tunn login` command. Refresh the login on the publishing machine and restart
the same saved publisher command. The relay never receives your local target
address and therefore cannot reconstruct that command.

Run `make test-tunnel-alerts` for fake-mailer, login-node RPC, migration,
durability and real-client clean-stop coverage. These tests send no real email.

Verified account merges retain outage history, publisher generations, delivered
notifications and hourly budgets. If both accounts saved preferences, opt-out
wins, the longer threshold applies, and clean-stop alerts require both accounts
to have opted in. Otherwise the saved preferences carry over. Existing
publishers keep reporting through their original account identity.

Older login nodes without the alert RPC still release tunnel registrations on
disconnect; alerts become available when the login node supports them.
