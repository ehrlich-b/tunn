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
