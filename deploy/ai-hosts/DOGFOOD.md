# Dogfood checklist and recorded gates

## Offline preparation in this branch

- [x] Linux user unit for three publishers, restart limits, process-group shutdown.
- [x] WSL foreground fallback with the same commands, permissions, locks, and logs.
- [x] Per-host isolated account/endpoint files, mode 0600, private directories.
- [x] Exact email-protected loopback dashboard and reviewed stdio MCP tool policy.
- [x] Local health and read-only remote SSH/MCP/dashboard canary.
- [x] Before/after receipts reject stale endpoint tokens following publisher restart.
- [x] Credential forwarding, auth logging, and login storage fixes with Go regressions.
- [x] `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local make vet` passed locally.
- [x] `make test-ai-hosts-security` passed the socket-free Go regressions.
- [x] `make test-ai-hosts` passed offline unit and Bash syntax checks.
- [x] All 17 kit unit checks and optional `shellcheck deploy/ai-hosts/wsl-run.sh` passed.
- [x] `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local make build` passed locally.
- [ ] Full `make test` (`go test ./...`) passes in a socket-capable checkout.
- [ ] Target unit verification passes; `systemd-analyze` is unavailable on this Mac.

The full test command was attempted unchanged. This execution environment
rejects loopback socket binds with `operation not permitted`, causing existing
inspector/stream integration tests to panic and networked MCP bridge tests to
fail. These failures are environmental evidence, not a green release gate.
No tests were skipped, loosened, or marked successful. No network service,
login, token copy, production mutation, SSH call, or hosted canary was run.

Run the final gates from the repository root with dependencies already cached:

```sh
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local make vet test test-ai-hosts-security test-ai-hosts
```

`make test-ai-hosts` imports all kit modules, runs synthetic file/transport/
supervisor tests, and checks `wsl-run.sh` with `bash -n`. It has no hosted or
loopback network dependency. Unit files should additionally be checked on the
target with `systemd-analyze --user verify` as documented in the runbook.

## Handoff gate (Bryan and coordinator)

- [ ] Read [SECURITY.md](SECURITY.md); accept the supervised test limits.
- [ ] Re-run the full test gates and verify patched relay/client compatibility.
- [ ] Confirm an existing account can admit six tunnels; no automated billing change.
- [ ] Stage kit files and architecture-correct CLI binaries on forge and rig.
- [ ] Configure real verified email, correct dashboard port/path, executable paths,
      wingthing working directory, and reviewed exact tool names on each host.
- [ ] Verify SSH keys/users and compare both host-key fingerprints through trusted
      consoles; provision Mac aliases `forge-tunn` and `rig-tunn` in known_hosts.
- [ ] Bryan completes each host's login with explicit prod and isolated config paths.
- [ ] Bryan starts the three publishers; coordinator runs local `health`.
- [ ] Bryan transfers endpoint token files privately to the Mac, mode 0600.
- [ ] Bryan authorizes the separate Mac login for the dashboard check.

## End-to-end canary (repeat for each host)

Use the full command in [README.md](README.md), choosing a free loopback port,
the actual SSH hostname, the exact MCP tool list, and a dashboard page marker.

- [ ] `--phase before`: missing/wrong SSH and MCP credentials return 401.
- [ ] A new `tunn connect` binds the chosen loopback listener; the pinned SSH
      command returns the expected marker and hostname with the explicit key.
- [ ] Authenticated MCP `server/discover` advertises the supported protocol;
      `tools/list` matches the exact reviewed tool names with no pagination.
- [ ] Anonymous dashboard request requires login; authenticated read-only GET
      returns 200 and the expected page marker.
- [ ] Record the baseline receipt, containing only config and token digests.
- [ ] Bryan restarts all three publishers (or stops/restarts the WSL runner).
- [ ] Local `health` passes; Bryan transfers new SSH and MCP token files.
- [ ] `--phase after` accepts different token digests and repeats every check
      with a fresh connector. Old SSH connections are expected to end at restart.
- [ ] Confirm foreground WSL stop/Ctrl-C leaves no publisher child groups; systemd
      stops the entire service control group. Re-run health to observe failure.

Do not check boxes from synthetic unit tests. Actual canary execution requires
Bryan's credentials and approved host operation window. The script performs
only remote reads and a fixed SSH command; it never logs in, restarts publishers,
changes billing, transfers credentials, or rotates tokens. A changed token
digest by itself does not prove which operator command produced it; retain
Bryan's restart timing alongside the canary results.

## Next decision

After both host canaries pass, decide whether to invest in revocable machine
login, restart-safe endpoint credentials, broader MCP policy, and relay request
admission limits before unattended deployment. Keep host service/relay changes
as exact commands for Bryan; do not execute production mutations as an agent.
