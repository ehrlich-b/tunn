# Outside candidate acceptance

The candidate combines base `642c06e7d4c28213fcb9a5a9850a6abfd111ab0b`,
W7 successor `8a85ab8183665baf0ba89f04778fce7986c85e64`, and dogfix
`53d5d13234e66e5d60f705221989423f2b0f84b6`. The immutable capability inventory
is `inventory.json`. The original refs and their source checkouts stay intact.
No deployed v37 identity or deployed-client success follows from these sources.

## Finite local entry point

From this clone, with its privately staged offline Go caches:

```sh
python3 scripts/candidate-acceptance.py --install-layout \
  --output .scratch/receipts/final.json
```

This runs inspected memory-only targets sequentially, with two threads and
low-priority scheduling. It strips ambient tunn/Fly credentials and proxy
configuration, roots Go outputs, config directories and all temporary files
inside this clone's `.scratch`, and disables module downloads, telemetry and
workspace resolution. Every test gate must execute at least one test, with no
failed or skipped tests. It builds and hashes the binary, inspects Go build
identity without executing that binary, and builds into two paths containing
spaces. Its JSON receipt ties exact pins, source SHA, commands, test counts,
log hashes and binary hash together. Missing outside cells remain
`REQUIRED-UNRUN`; they are not inferred from compilation.

`make -j1 test-candidate-cross` tests the complete serialized resource/issuer
metadata, DCR, PKCE consent/code exchange and one streamed `tools/call` task.
It compares the complete JSON-RPC bytes and both ordinary application cookies
with a direct handler oracle. It also verifies platform credential removal,
terminal trailers and that a publisher cannot overwrite `Tunn-Request-ID`.

The `candidatefixture` build tag exposes the already-existing SDK/core memory
dial seam **only in fixture builds**. It adds no normal-build public API. The
SDK remains an HTTP publisher: the host fixture explicitly classifies its
registered test endpoint as MCP before running the OAuth consumer. These are
test prerequisites, not proof of exported MCP publishing or native SDK
connectivity. The ordinary-host SDK contract remains required independently.

`test-candidate-cross` also delivers public refusals for another owner, moved
endpoint ownership, expired grant, revoked OAuth client, consumed request quota
and wrong resource path. Invalid tokens are sent alongside a valid owner
cookie to verify they cannot fall back to that cookie. Refusals do not reach
the SDK application or expose platform cookies/credentials. Fixture state uses
the existing storage and metering engines rather than a second policy engine.

`make -j1 test-candidate-consumer` archives the committed candidate into a
clone-private offline module cache and imports it from a second fresh module
without `replace` or workspace fallback. It exercises buffered and streamed
wire generations, performs a sum task, compares every JSON-RPC result byte and
both cookies with the direct oracle, then closes after the first result. The
streamed application must observe cancellation, and the SDK must emit exactly
one Closed event. Its TLS uses an explicit fixture trust root.

## Ordinary-host matrix

Bryan/coordinator must use an isolated clone and staged private caches on an
ordinary host. These commands are provided for that host; the worker must not
execute them. Run one heavy target at a time, with two threads and `make -j1`.
Each target must produce actual nonzero test counts. Preserve its logs alongside
the source SHA, binary hash and `final.json` being accepted.

| Cell | Exact command / evidence | Worker result |
| --- | --- | --- |
| Full source suite and race | `make -j1 check` | REQUIRED-UNRUN: native listeners/children |
| SDK relay/auth/HTTP/WS | `make -j1 test-sdk-contract` | REQUIRED-UNRUN: loopback |
| Immutable exported importer | `make -j1 test-sdk-response-consumer-live` | REQUIRED-UNRUN: actual SDK program |
| HTTPS OAuth lifecycle | `make -j1 test-auth-loopback` | REQUIRED-UNRUN: loopback TLS |
| Inspector browser | `make -j1 test-inspect-browser` | REQUIRED-UNRUN: Chromium |
| Native install/recovery | `make -j1 test-install-recovery BUILD_OUTPUT=.scratch/bin/tunn BINARY_DIR=.scratch/bin` | REQUIRED-UNRUN: built binary/children |
| Two paths with spaces | Native sequence below, config hashes before/after | REQUIRED-UNRUN: native execution |
| Candidate client activation | Bryan controls candidate activation on disposable/authorized state | REQUIRED-UNRUN: no deployed evidence |
| T+65 reconnect and revoke | Bryan records actual client identity, reconnect and revoked refusal | REQUIRED-UNRUN: elapsed-time/deployed evidence |
| Next-day useful task | Bryan retains complete serialized tools/call result | REQUIRED-UNRUN: next-day consumer evidence |
| W7 original receipts | Supply immutable original review, 02:35 failure and successor outside-sandbox pass | REQUIRED-UNRUN: receipts absent from committed refs |

The legacy proxy generation's header map can lose multiplicity; its fidelity
matrix records this supported limitation instead of claiming exact old-peer
cookies. No generic 101 upgrade, informational response, kernel transport,
installed runtime or live-provider guarantee is added here.

## Useful task and rollback prerequisite

The fresh local consumer command is:

```sh
make -j1 test-candidate-cross
make -j1 test-candidate-consumer
```

Run these through `candidate-acceptance.py` for isolated credentials, cache
settings and scheduling. Both use synthetic local identities, verified memory
TLS and finite deadlines. No command in this sequence connects to `tunn.to` or
loads an account token from an ambient user directory. The source default is
secure `tunn.to:443`; native task commands must override that default explicitly.
The source-only CLI test verifies the exact flag parser used by:

```sh
TUNN_SERVER_ADDR=127.0.0.1:10443 TUNN_CONFIG_DIR="$PWD/.scratch/outside/config" \
  .scratch/tunn http://127.0.0.1:18080 --name useful-task \
  --allow owner@example.com --secret synthetic-candidate-secret \
  --tunnel-key synthetic-key
```

That final command is **ordinary-host only** and needs a disposable local relay
with a matching test certificate/trust root and synthetic credentials. It is
not a hosted-client command and must not be run with ambient production state.

For a native installation rehearsal, first preserve a known-good binary hash,
its signed/configured identity, and byte-exact private config/token copies in
the disposable acceptance root. Do not overwrite an installed runtime. Both
installation paths are inside the acceptance clone's `.scratch`:

```sh
make -j1 build BUILD_OUTPUT="$PWD/.scratch/installation/first install with spaces/tunn"
make -j1 build BUILD_OUTPUT="$PWD/.scratch/installation/second install with spaces/tunn"
```

The local gate compiles these exact output paths and parses unchanged private
host YAML with missing optional token/credential paths. On the ordinary host,
use each binary's `host check --config <explicit-private-path>` against the same
preserved YAML, then `host install --dry-run --os <host-platform> --config
<explicit-private-path>`; retain complete output and compare config hashes.
All optional credentials are synthetic and explicitly rooted. Do not activate
services. `test-install-recovery` contains the existing native rehearsal.

Before any future deployment, Bryan must identify the exact candidate binary
and independently preserve the last accepted deployed artifact and config.
Production mutation commands are outside this row; local commits/bundles are
not rollback evidence for a deployed machine. No production or installed
runtime was changed here.

## Current product readiness

The original pinned integration failed the unknown-length upload/response
contract. The resumed candidate reconciles response progress with the upload
limit; see `integration.md` and `upload-reconciliation.json`. The historical
failure and pinned-source comparison remain preserved in `compatibility.json`.
Both the full memory fidelity gate and the upload regression gate must pass
before promotion. Full `go test ./...`, loopback/native acceptance and deployed
client gates remain **REQUIRED-UNRUN** here because the brief prohibits those
runtime gates in this worker. Compiling all test packages does not pass the
full test gate. The useful task, authorization matrix, source build, installer
preparation and independent importers remain separate local evidence.
