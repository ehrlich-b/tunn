# Local MCP OAuth evidence, 2026-10-03

This records the opt-in hosted-client onboarding implementation on
`feature/hosted-mcp-onboarding`, based on private-tool checkpoint `aeb0933`.
All services, certificates, accounts, codes, grants and databases in these
tests are disposable synthetic fixtures. No live ingress, hosted account
connection, persistent credential, deployment or paid API was changed or used.

## Aggregate verification

From `/Users/ehrlich/repos/tunn-ingress-usage`:

```sh
GOCACHE=/tmp/tunn-go-cache make check test-build-workflow test-mcp-oauth-workflow build \
  TEST_ARGS='-timeout=120s -count=1'
```

Passed with exit zero. This ran format/module checks, the complete race-enabled
suite, both explicit official Go/Python relay workflows and the CLI build.
The host aggregate package passed in 4.181 seconds in this run.
Local output: `/tmp/tunn-hosted-mcp-final-check.log`.

Focused `make test-mcp-oauth` passed after the blank-node-secret hardening:
`/tmp/tunn-hosted-oauth-secret-boundary.log`.

The compiled `./bin/tunn mcp check http://example.invalid/mcp` returned
`ready:false`, an actionable literal-HTTPS-/mcp diagnostic and exit one without
making a network request. Checker tests separately cover verified local HTTPS
success, redirect refusal, precise issuer opt-in, metadata/challenge parsing,
body limits and unexpected locations. The checker uses no saved credentials.

## Useful-answer and accounting evidence

The OAuth integration creates two static-client authorizations through a manual
consent/PKCE harness, then passes the resulting opaque grants to the official
Go SDK v1.7.0 and Python SDK 1.27.2. They call the same native Streamable HTTP
read-only server through two actual local HTTP relay nodes, authenticated
login-node storage RPC and a TLS gRPC publisher.

Both clients perform seven tool calls and produce six matching evidence paths
for the synthetic missing-generated-schema diagnosis. The paths are
`logs/build-4821.log`, `package.json`, `ci/build.yml`, `docs/build.md`,
`.gitignore` and `src/app.ts`. The existing native grant workflow also remains
green with the two SDKs and their different negotiated protocol versions.

Measured OAuth-run admissions: Go 8 for the first investigation and 16 after
a second successful investigation following publisher reconnect; Python 10.
Each grant retains a 100-admission cap. Owner metadata and per-grant completion
counters match these admissions exactly. The revoked Python grant produces two
durable denied completions, including after reconnect, without consuming slots
or forwarding requests. A proven-valid owner cookie cannot rescue that explicit
revoked grant. The upstream fixture rejects leaked platform credentials.

| Observation | Root run | Independent repeat |
| --- | ---: | ---: |
| First Go connection to useful answer | 67.487 ms | 67.155 ms |
| Python connection to useful answer | 113.304 ms | 113.457 ms |
| Entire OAuth setup, answers, revoke and reconnect fixture | 554.985 ms | 552.213 ms |

These are single race-instrumented loopback observations, not a benchmark or
hosted-app latency estimate. SDK installation, compilation, human setup,
browser login, external network and model reasoning are excluded from the
connection-to-answer timings. The Python process startup is included in the
overall fixture duration.

## Independent review

A separate reviewer inspected identity, PKCE, exact callback/resource-code
binding, owner/protocol registry checks, atomic code consumption and grant
creation, malformed input handling, CSRF, discovery routing, secret redaction,
and accounting. Review findings were fixed before completion, including
fail-closed internal RPC authentication when the configured node secret is
blank. The reviewer reported no remaining blocking findings for the opt-in,
single-authority milestone and made no repository edits.

The independent aggregate race run plus two-SDK workflow passed:
`/tmp/tunn-hosted-oauth-independent-settled.log`. A subsequent independent run
of the strengthened exact-accounting workflow passed:
`/tmp/tunn-hosted-oauth-independent-accounting.log`. `git diff --check` passed.

## Remaining acceptance boundary

The consent HTML and checker diagnostics are exercised by tests. No actual
browser render, SameSite browser behavior, ChatGPT/Claude UI setup or their
OAuth implementations have been exercised. The investigators are deterministic;
there is no proof of hosted model-driven reasoning or account-plan availability.

Authorization codes bind the canonical full resource URI. Existing grants
retain logical owner+endpoint scope with literal `/mcp`, not a separately stored
issuer/domain/port audience. No refresh flow or dynamic client registration is
provided. Grants cannot isolate arbitrary upstream sessions or make mutable
tools read-only.

No suitable existing public test route was established from the inspected
repository, and no application UI was available for inspection through the
supported browser tooling in this task. This does not prove that such a route
or connection is absent from Bryan's accounts. The prepared
[hosted acceptance scope](HOSTED-MCP-ACCEPTANCE.md) identifies the exact remaining
host/exposure/account inputs and temporary access approval needed before that
external run. Current instructions forbid creating that exposure or access.
