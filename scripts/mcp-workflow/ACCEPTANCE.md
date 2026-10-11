# First useful task and next-day acceptance

This packet is prepared entirely offline at the pinned baseline. It does not
claim an installed or deployed candidate. The supplied staged MCP guide says
live Claude.ai and ChatGPT acceptance has not run; the GTM demo asks for one
chosen client and records its exact name/version. Neither staged document
identifies a selected client, supported account/plan, current connector UI or
client version. Exact selected-client setup is REQUIRED-UNRUN for that reason.
Do not invent those fields or call either client accepted from fixture results.

The generic setup already documented at this pin is: keep the publisher running,
copy its printed Connector URL to the selected client's remote MCP connector
settings, sign in through tunn's existing login, and approve its consent form.
No new OAuth implementation or separate production grant provisioning is needed.
The connector URL must have the exact resource path /mcp. Production discovery,
registration, S256 PKCE, consent, audience restrictions and grant revocation are
reused by the in-memory rehearsal. Fixture email delivery is simulated; the
production consent and token handlers perform the remaining steps.

## Offline worker command

After clone-local cache staging, run `make -j1 mcp-workflow`. This creates a new
private scratch root, compiles the stdio reader and independent client test
binary without executing the server, runs bounded memory-only tests, and emits
one secret-free receipt. The command records source, module, toolchain, server
binary and client identities plus acceptance states. It rejects any endpoint
or token options in default mode. Previous receipt roots cannot be overwritten.

The temporary Go overlay compiles only an SDK dial adapter and host tests. It
adds no checked-in host/SDK API. The adapter chooses the existing CLI MCP path
and memory dial seams; every useful request enters the production authorization
handler and actual protobuf streaming path. Both JSON and finite SSE bodies are
compared against direct structured outputs and exact source citations.

## Outside-worker local rehearsal — Bryan only

Use this exact source checkout and private caches. Build with
`make -j1 build-mcp-project-reader`; the binary is
`.scratch/mcp-workflow/bin/mcp-project-reader`. In an ordinary host, publish the
stdio service using the already-documented CLI form (no worker execution):

```sh
tunn mcp --name project-reader --tools project_list,project_read,project_search -- .scratch/mcp-workflow/bin/mcp-project-reader --root "$PWD/examples/mcp-project-reader/fixtures/harbor/day1"
```

The pinned `TestMCPCommandShorthand` and added overlay `TestWave8ReaderCommand`
gates check these exact arguments, tool names, root and explicit `--` separator. A coordinator still needs to record the actual tunn
binary path/hash/version, local stdio child launch, readiness and printed URL;
compilation and command parsing do not pass the built-server/loopback gate.
This is a manual operator packet, not authority for an agent to mutate production.
Bryan runs any publishing step himself under the production-operations rule.

Use the first question in TASK.md and compare the answer to HN-104, with exact
source spans. Record setup active/wall time, client name/version/account support,
transport, candidate SHA/binary hash, scoped resource identity, tool exposure,
consent outcome, expected and observed issue, source hashes, and citation checks.
Authorization artifacts, browser cookies, login links, codes, tokens, prompts
containing private text and complete diagnostic response bodies stay out of
receipts. Do not turn a successful HTTP response into a useful-task claim.

Test a missing/offline local service, wrong connector URL, revoked client grant,
expired grant and caller cancellation. The owner disconnect action is described
in the pinned MCP guide; Bryan must perform actual production revocation himself.
The in-memory failures do not establish hosted-client behavior. Grant expiry is
one hour with no refresh token; repeat the consent path after expiry. Never
silently use the owner cookie or another endpoint after a denial.

When Bryan separately selects direct external fixture verification, the command
below makes only finite read calls and checks returned data against the supplied
fixture before saving it. It requires both explicit external mode and opt-in;
it never fetches authorization credentials or performs login/consent itself.
Keep the OAuth token in a private, non-symlink file; never put it in shell flags.
The worker does not select this mode.

```sh
python3 scripts/mcp-workflow/rehearse.py --mode external-host --allow-external --endpoint 'https://project-reader.RELAY-DOMAIN/mcp' --token-file '/PRIVATE/PATH/mcp-token' --fixture harbor/day1
```

## Distinct next-day task

On a later calendar day, Bryan manually restarts the reader against the immutable
`fixtures/harbor/day2` root and uses the distinct next-day question in TASK.md.
The answer changes to HN-108 because release 0.4.2 ships HN-104. Record the new
fixture hashes, actual calendar day, client/version, setup/reconnect time,
consent/expiry experience, actual useful answer and citations. Running both
fixtures in one software test is PASS for changed-fixture behavior only.
Actual next-day use remains REQUIRED-UNRUN.

The Ridge continuation contains duplicate README basenames, composed and
decomposed Unicode, and no eligible issue. Correct behavior is an explicit
`no_actionable_issue`, while an absent literal search returns `no_matches`.
The oracle requires complete source evidence; a truncated search cannot prove
an answer absent.

## Client-visible failures

| Actual typed failure | Instruction |
| --- | --- |
| `service_unavailable` (502/503/504 or transport failure) | Keep the local reader and publisher running; retry after readiness. |
| `access_denied` (401/403, including expired/revoked grant or wrong resource) | Check the exact Connector URL and repeat consent after expiry/revocation. |
| `wrong_endpoint` (404) | Check the printed /mcp URL; a disconnected publisher returns 503 at this pin. |
| `incomplete_response` | Discard partial answers/citations and retry the whole finite call after recovery. |
| `tool_error` | Correct tool/path/bounded arguments; the error is not an empty successful answer. |
| `canceled` | Discard partial evidence; start a new call only if the caller still wants it. |
| `protocol_error` | Discard the answer and check the recorded protocol/client compatibility. |

Sources read: pinned examples/sdk-handler, SDK tests, MCP echo fixture,
internal/host/mcp_oauth.go and auth tests, docs/mcp-connectors.md; supplied
astra-plans-20261010/tunn-gtm/GTM.md demo and plan-48h/PLAN-48H.md first/repeat criteria.
No fresh upstream, hosted compatibility documentation or provider was fetched.
