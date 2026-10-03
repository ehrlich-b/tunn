#!/usr/bin/env bash
# Run two independent official SDK clients against a loopback synthetic MCP service.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$PROJECT_DIR"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tunn-build-investigation.XXXXXX")"
SERVICE_PID=""
cleanup() {
    if [[ -n "$SERVICE_PID" ]]; then
        kill "$SERVICE_PID" 2>/dev/null || true
        wait "$SERVICE_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

make -f scripts/integration-tests/build-investigation/Makefile build
./bin/build-investigation serve >"$WORK_DIR/service.log" 2>&1 &
SERVICE_PID=$!
for attempt in $(seq 1 100); do
    if [[ -s "$WORK_DIR/service.log" ]]; then break; fi
    if ! kill -0 "$SERVICE_PID" 2>/dev/null; then cat "$WORK_DIR/service.log" >&2; exit 1; fi
    sleep 0.05
done
ENDPOINT="$(head -n 1 "$WORK_DIR/service.log")"
if [[ "$ENDPOINT" != http://127.0.0.1:* ]]; then cat "$WORK_DIR/service.log" >&2; exit 1; fi
./bin/build-investigation investigate --endpoint "$ENDPOINT" >"$WORK_DIR/go.json"
scripts/integration-tests/build-investigation/.venv/bin/python scripts/integration-tests/build-investigation/client.py \
    --endpoint "$ENDPOINT" >"$WORK_DIR/python.json"
python3 - "$WORK_DIR/go.json" "$WORK_DIR/python.json" <<'PY'
import json, sys
reports = [json.load(open(path)) for path in sys.argv[1:]]
assert {report["client"] for report in reports} == {"official-go-sdk@v1.7.0", "official-python-sdk@1.27.2"}
for report in reports:
    assert report["tool_calls"] == 7, report
    assert len(report["evidence"]) == 6, report
    assert "before npm run build" in report["recommendation"], report
assert reports[0]["diagnosis"] == reports[1]["diagnosis"]
assert reports[0]["evidence"] == reports[1]["evidence"]
print(json.dumps({"scope": "loopback synthetic service; deterministic SDK clients; no hosted LLM", "reports": reports}, indent=2))
PY
