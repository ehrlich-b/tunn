#!/bin/sh
# Run the real CLI probe using a generated Go overlay in a disposable directory.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tunn-allow.XXXXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cd "$root"
go build -p 2 -o "$tmp/tunn" .
python3 - "$root" "$tmp/overlay.json" <<'PY'
import json, os, sys
root, path = sys.argv[1:]
with open(path, 'w') as f:
    json.dump({'Replace': {os.path.join(root, 'internal/host/allow_added_later_probe_test.go'): os.path.join(root, 'internal/host/testdata/allow_added_later_probe_test.go')}}, f)
PY
TUNN_ALLOW_BINARY="$tmp/tunn" TUNN_ALLOW_EXPECT=after go test -p 2 -overlay "$tmp/overlay.json" -count=1 -timeout=120s -run '^TestAllowAddedLaterCLIProbe$' -v ./internal/host
