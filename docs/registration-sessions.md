# Publisher registration sessions

The login node serializes name admission, active counts, availability reports,
lease expiry and release under the same storage lock. Admission verifies the
canonical authenticated account, durable name ownership and account limits,
then binds the active name to the relay connection's random session identity.
A same-owner registration is still denied while another session is active.
A successful registration also returns its random session identity to the client.
The client remembers it only for this Run and sends it on subsequent registrations,
including registrations through another relay. Under the same admission lock,
the login node distinguishes a continuation only if the previous session equals
the active generation and the canonical authenticated owner equals its owner.
That denial carries `publisher_session_pending`; it grants no admission and
never releases or replaces the old claim. The client uses its existing reconnect
backoff until the original relay confirms conditional release. A missing or wrong
previous session, another owner, or a newer active generation remains an ordinary
terminal conflict. The local duplicate check applies the same distinction.
A first-attempt client ignores the pending code without a prior successful session.
This permits cross-relay recovery before the original relay's maintenance retry,
without treating arbitrary name conflicts as transient or admitting two routes.

After removing its local route and cancelling its heartbeat worker, the relay
releases **its own session** before joining that worker and attempting the final
availability report. Release succeeds only when the backend confirms conditional cleanup;
a stale session is already absent and cannot remove a replacement. A reporting
failure remains logged as a reporting failure. Release does not fabricate an
offline report or alter durable ownership. Release and final reporting share the
existing ten-second cleanup budget, so an unavailable backend cannot multiply
that teardown wait. If conditional release itself fails,
the relay logs the failure and retains a name/session release obligation in
memory. Route removal and publication of that obligation share the local route
lock. Teardown attempts conditional release even when the connection's availability
hint is false. A failed initial up report therefore cannot strand a claim with
no availability row for expiry to collect.

The proxy's maintenance loop retries outstanding releases with bounded RPC
contexts until confirmed, independently of another publisher. Authenticated
admission also drains obligations for its name before claiming a new session;
a still-failing release returns the existing temporary ownership-service error.
Only sessions this relay removed or never installed are eligible. A name conflict
alone never creates an obligation. Delayed and concurrent releases carry the old
session and cannot erase a live replacement or its availability. An RPC error,
unavailable hint, or successful report cannot stand in for a confirmed release.
Recovery requires storage to return and the relay to retain its in-memory
obligations; relay loss during a storage outage is outside this recovery guarantee.

An admission RPC error is ambiguous: the login node may have committed or may
still be processing the request. The relay attempts conditional release of that
session with an independent context and the existing ten-second cleanup bound,
even if the publisher has cancelled. It logs release failures and retains the
original registration failure; an RPC error alone never proves cleanup.
The login node records released name/session pairs under the admission lock,
including sessions not yet admitted. Admission rejects every retired session,
even after a replacement has registered and disconnected. A release that races
admission therefore either removes that session or prevents its later commit.
Releasing another session cannot alter the current active claim or ownership.

Every early registration failure uses the same conditional release. Local route
removal checks connection identity. Availability reports are fenced by the
admission session even before the replacement's first up report, and old
availability expiry cannot clear a newer admission. The last versioned session
is retained after release to prevent late heartbeats from reviving a retired
registration; a subsequent versioned admission replaces that fence. The last
session marker and the released session pairs remain in memory for the login
node's lifetime, matching the lifetime of active claims. Retired pairs grow with
session releases; they cannot safely expire while an old admission may arrive.

Upgrade the login node before resource relays. Separate session RPC methods
fail closed on older login nodes without making an unversioned claim. Session
echoes confirm that admission and conditional release were understood. Embedded
backends without the optional TunnelSessions interface keep their legacy
behavior and do not receive this recovery guarantee. Legacy registration remains
available for names without versioned history; it cannot discard an established
session fence. Unversioned cleanup of a live versioned name returns an error.

The client continues to treat all other name conflicts as terminal. Authentication,
namespace checks, durable reservations, liveness admission and visitor access
policy remain part of the normal registration and request paths.

The cross-relay regression holds the original relay's maintenance until the real
client has received an exact-generation denial from a second independent relay
and entered reconnect backoff. There is no initial availability row to expire.
Only then does maintenance start; the client recovers through the second relay.
Late old releases and availability reports preserve its new online generation.
Delivered-report and Unimplemented-reporting controls retain their behavior.
Older login nodes that do not understand the continuation field cannot classify
this case; upgrade the login node and relays before relying on cross-relay recovery.
The original relay must still survive to retry its in-memory release obligation.
This narrow guarantee does not qualify a full outage campaign or explain the
historical durable-login settle failure.

Availability and admission have separate lifetimes. The 90-second heartbeat
lease marks availability offline; it never releases versioned admission. A
matching still-admitted heartbeat restores availability for the same session.
Likewise down/graceful reports cannot free a versioned claim while its route
remains installed. Only explicit generation-conditional release after route
removal frees admission. The relay refuses release while that session's local
route is installed, including retry attempts. Failed release retains exclusion
until the surviving relay confirms its retry. Legacy unversioned availability
cleanup retains its existing behavior.

The two-relay controlled-stream regression advances the storage clock by 91
seconds, expires availability, heartbeats the original session and tries a
replacement. It verifies actual HTTP forwarding and availability identity,
then removes/releases the original and admits the replacement. It also covers
release without confirmed removal, failed release/retry, concurrent expiry,
heartbeat, teardown and replacement, and delayed retired-generation reports.
Relay-crash reclamation still requires separate authority and route fencing;
retaining admission deliberately favors exclusion when removal is unconfirmed.
