# Forwarded stream lifetime

Every relay forwarding an endpoint response rechecks current admission through
its authenticated cluster connection once per second. A check has a two-second
deadline; denied permission, unavailable authority or a missing peer capability
interrupts the downstream response. HTTP/2 and HTTP/3 deadlines apply to the
individual stream. An upgraded connection is closed individually.

Permission checks do not dispatch origin requests, reserve request rate buckets,
or add usage records. IP and request rate policies keep their admission semantics.
Bytes already delivered or admitted to downstream transport buffers cannot be
retracted. Nodes serving forwarded traffic must all support the permission RPC
before promotion; mixed versions fail closed on continuing responses.
