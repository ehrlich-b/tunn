# Integration decisions and provenance

Both pinned inputs were merged with history retained. `git cherry` marked all
nine SDK commits and all four dogfix commits as new against the pinned base;
there were no patch-equivalent commits to omit. Their merge bases and exact
patch dispositions are in the frozen `inventory.json`.

W7's appended response acceptance targets and the base's appended edge targets
both survive. In `proxyToLocal`, the baseline named HTTP status constants survive
while the W7 successor returns errors. Only the outer `handleWebProxy` HTTP
boundary aborts a started truncated response. The terminal-response fix
`8a85ab8183665baf0ba89f04778fce7986c85e64` occurs exactly once in ancestry.
No grant/OAuth policy was authored; the pinned authorizer and SDK handler remain
byte-identical to the baseline.

The first candidate compilation found two auto-merge interactions, recorded
before correction in `.scratch/receipts/integration-failure.json` and the first
checkpoint receipt. The base's empty environment development case and dogfix's
empty environment production case both survived, causing a duplicate switch
case. The candidate retains secure production defaults for empty `TUNN_ENV`,
explicit development aliases and unknown-environment rejection. The existing
production-default regression now expects that intentional default change.
The dogfix early 413 branch also needed an explicit nil error return after W7
changed `proxyToLocal`'s signature. Its status, metering reason and early upload
refusal remain unchanged.

The five baseline production test lanes are configuration, account/billing,
authorization, edge/recovery and startup/readiness. The frozen inventory names
reachable commits and exact existing consumers for every lane; it is not an
assertion that the complete native lane ran here. Full outside-host gates and
the supplied brief's reported W7 outside pass remain distinct evidence.

All work is on the standalone candidate branch. No source checkout supplying
an input was edited, and no input ref was moved. No deployment files, tags,
main branch, production state or installed runtime were changed. Scratch
caches, binaries, logs and receipts are deliberately untracked. The final
handoff receipt, bundle and digests identify the local artifact Bryan can test.

## Upload/response reconciliation

The integrated fidelity gate exposed an incompatibility between the two
finished inputs. Dogfix `b557bb262f9e5b0d2382ee40e07864b56f93cf09` made
`proxyStreamingHTTPOverGRPC` wait for an unknown-length request body to finish
before committing response metadata. W7's upload-after-prefix/terminal and
failed-upload consumers require a response prefix while the request upload is
still active. The resumed run reproduced all three reported failures over
memory connections, including the 30-second 502 from
`TestProxyToLocalReturnsResponseErrors`. Integration commit `67302f1` imported
the wait; `f1fc4d4` only corrected a return value and did not introduce it.

The smallest reproducer is `make -j1 test-candidate-upload-contract`, a
memory-only upload/response selector, now extended to cover both contracts.
The original failure evidence in `compatibility.json` and
`.scratch/receipts/compatibility-finding.json` remains immutable.

The response startup wait now observes both upload completion and response
events. A nonempty response prefix starts immediately while an unknown-length
upload remains active. An empty or bodyless success waits for upload validation,
so an early upstream 200 or 204 cannot hide an oversized upload. Known oversized
uploads still fail before forwarding. Failures detected before headers return
413 for the upload cap; after a delivered prefix, the HTTP boundary aborts the
response and the consumer receives `unexpected EOF`. A completed streamed
response still owns cleanup of an unfinished upload, as required by W7.

Response startup retains at most one event and passes it directly to the body
writer, preserving data/trailer order without buffering either stream. The
writer also enables net/http full duplex: otherwise HTTP/1 keep-alive drains
the remaining request body before flushing headers and recreates the deadlock.
The new crossed-pipe chunked HTTP/1 fixture requires the consumer to read its
prefix before finishing the upload. Removing only `EnableFullDuplex` makes that
fixture time out; the patched handler completes with the application trailer.

`response_upload_limit_test.go` also verifies actual downstream 413 responses
for unknown oversized uploads and downstream truncation when the upload crosses
the cap only after the consumer acknowledges its prefix. Existing W7 and dogfix
tests remain unchanged. Current verification supplements the historical
failure in `upload-reconciliation.json`; the full fidelity gate is
`make -j1 test-http-fidelity`. Full loopback/native acceptance remains an
ordinary-host gate under this row's brief.
