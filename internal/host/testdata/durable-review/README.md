# Legacy migration fixture

`110485c.db` was generated from base `110485c`. It contains 20 original tables
and 20 existing rows, including account aliases, a merge, authorized and pending
device codes, used magic links, and operations, metering and MCP records. Tests
copy it into a temporary directory and compare all original schemas and rows
after initializing the durable schema twice. The fixture is never opened for
writes in place.

`110485c-tokens.json` was signed using that base version's JWT dependency and a
fixture signing key. Its legacy `access` and `session` claims have fixed issuance
(1791710000) and expiry (4000000000) timestamps so the regression remains usable.
These timestamps describe test data rather than production credential lifetimes.

All credentials and identities in these files are local test fixtures.
