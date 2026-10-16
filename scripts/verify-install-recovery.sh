#!/usr/bin/env bash
# Fixture acceptance never installs a service, authenticates, or downloads.
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$repo_root"

if [[ "${1:-}" == "--native-plan" && $# == 1 ]]; then
    sed -n '/^## Native validation/,$p' docs/install-recovery.md
    exit 0
fi
if [[ "${1:-}" != "--fixtures" || $# != 1 ]]; then
    echo "Usage: bash scripts/verify-install-recovery.sh --fixtures|--native-plan" >&2
    exit 2
fi

mkdir -p .scratch/tmp .scratch/go-build .scratch/gomod .scratch/npm .scratch/bin
export TMPDIR="$repo_root/.scratch/tmp"
export GOTMPDIR="$TMPDIR"
export GOCACHE="$repo_root/.scratch/go-build" GOMODCACHE="$repo_root/.scratch/gomod"
export npm_config_cache="$repo_root/.scratch/npm" npm_config_offline=true
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-p=2 GOMAXPROCS=2
export PYTHONDONTWRITEBYTECODE=1
export BINARY_DIR="$repo_root/.scratch/bin" TUNN_TEST_BINARY="$repo_root/.scratch/bin/tunn"

resource=(nice -n 15)
if [[ "$(uname -s)" == Darwin ]]; then
    resource=(taskpolicy -b nice -n 15)
fi

"${resource[@]}" make -j1 build test-install-recovery
echo "PASS install/recovery fixtures: fake launchd/systemd/Task Scheduler; private TLS/SQLite; no native activation."
