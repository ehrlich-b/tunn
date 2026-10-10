#!/usr/bin/env bash
# Foreground fallback for a WSL distro without a running systemd user manager.
set -euo pipefail
umask 077
kit_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$kit_dir/runner.py" all --config "${1:-$HOME/.config/tunn-ai-hosts/host.json}"
