#!/bin/sh
set -eu
if [ "${TUNN_DESK_RUNNER:-}" != 1 ]; then
  echo 'This must be run by the desk runner (TUNN_DESK_RUNNER=1).' >&2
  exit 1
fi
if [ "${1:-}" = --dry-run ]; then
  echo 'Would install the report puller and enable the user timer.'
  exit 0
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
install -d "$HOME/.local/bin" "$HOME/.config/systemd/user"
install -m 755 "$root/scripts/reports-pull.py" "$HOME/.local/bin/tunn-reports-pull"
install -m 644 "$root/release/tunn-reports.service" "$root/release/tunn-reports.timer" "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now tunn-reports.timer
