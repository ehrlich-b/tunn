# Synthetic private build investigation

This fixture exposes a small, invented build workspace over Streamable HTTP MCP.
`build.search` returns matching paths and line numbers. `build.read` returns only
exact paths in the in-memory corpus; it never opens real files or runs commands.

Two independently implemented clients use the official Go SDK **v1.7.0** (the
repository's pinned dependency) and Python SDK **1.27.2** (the adjacent dependency
lock). Both search a compiler failure, read the build log, search the generation
command, and read CI/package/documentation/ignore evidence. They make seven tool
calls and emit six citations with the same actionable diagnosis. They reject
contradictory evidence rather than always emitting the fixture answer.

The investigator logic is deterministic. These are real SDK transport clients,
not hosted LLM agent applications. This verifies SDK protocol compatibility and
useful multi-call evidence transfer; it does not prove that ChatGPT, Claude, or
any other hosted agent can connect or reason through the task.

## Run locally

From the repository root:

```sh
make -f scripts/integration-tests/build-investigation/Makefile setup-python
make -f scripts/integration-tests/build-investigation/Makefile test
GOCACHE=/tmp/tunn-go-cache bash scripts/integration-tests/build-investigation/run-local.sh
GOCACHE=/tmp/tunn-go-cache make -f scripts/integration-tests/build-investigation/Makefile test-relay
```

On a restricted Mac workspace, provide a writable Go cache and approve local
loopback listeners. The script cleans up its server and temporary reports. It
prints both JSON reports, including negotiated protocol, first-tool latency, and
useful-answer latency. These timings start after process startup, include SDK
connection and remote tool requests, and exclude installation/build time.

`test-relay` adds a real local TLS gRPC publisher, a second TLS HTTP routing node,
authenticated login-node storage RPC, and two distinct ephemeral grants created
through the owner's HTTP API. It checks matching useful answers, exact owner
admission counts, no credentials reaching the upstream service, revocation with
a valid cookie present, continued access through the other grant, and preserved
usage/revocation after publisher disconnect/reconnect. Test credentials and
certificates are temporary and never printed. The normal Go suite runs the same
relay assertions with two Go clients; the optional two-SDK test requires the
`TUNN_PYTHON` environment variable to name the pinned Python environment.

See [EVIDENCE.md](EVIDENCE.md) for recorded commands, observations, and timing
limits. Protocol setup requests consume HTTP allowance too: the verified run
used eight admissions for Go and ten for Python for seven tool calls each.

## Investigate through a local Tunn relay

Start the fixture with `./bin/build-investigation serve`, then publish its printed
loopback URL using `tunn mcp <URL>` against a synthetic local relay. Both clients
accept a bearer token **file**, avoiding credentials in command-line arguments.
They accept `Authorization` (default) or `Tunn-Authorization`, a test CA, and an
HTTP Host override for loopback relay routing. For example:

```sh
./bin/build-investigation investigate \
  --endpoint https://localhost:18444/mcp \
  --host build.tunn.test:18444 --ca-cert /tmp/demo-ca.pem \
  --token-file /tmp/go-synthetic-grant.token
scripts/integration-tests/build-investigation/.venv/bin/python \
  scripts/integration-tests/build-investigation/client.py \
  --endpoint https://localhost:18444/mcp \
  --host build.tunn.test:18444 --ca-cert /tmp/demo-ca.pem \
  --token-file /tmp/python-synthetic-grant.token
```

Both clients reject HTTP redirects so credentials remain bound to the configured
endpoint. No TLS-verification bypass is provided. The URL hostname must match the test
certificate. Separate token files allow independently revocable grants to be
tested when the relay implements them. The fixture itself is read-only and
sessionless; authorization and grant admission belong to Tunn's relay.

Official SDK references: [Go SDK](https://github.com/modelcontextprotocol/go-sdk)
and [Python SDK](https://github.com/modelcontextprotocol/python-sdk). The lock
preserves the exact Python packages used in this run; it does not install them
into the user's global Python environment.
