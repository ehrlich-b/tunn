#!/bin/bash
# Deploy a local TLS relay and verify the tunn 2.0 MCP and raw-TCP paths.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/fixtures"

DOMAIN="tunn.local.127.0.0.1.nip.io"
HTTP_PORT=18444
INTERNAL_GRPC_PORT=50052
MOCK_OIDC_PORT=19001
TCP_TARGET_PORT=19998
TCP_LISTEN_PORT=19997
MCP_TUNNEL_ID="ai-e2e"
TCP_TUNNEL_ID="tcp-e2e"

WORK_DIR="$(mktemp -d)"
CONFIG_DIRECTORY="$WORK_DIR/config"
MCP_TOKEN_FILE="$CONFIG_DIRECTORY/endpoints/$MCP_TUNNEL_ID.token"
TCP_TOKEN_FILE="$CONFIG_DIRECTORY/endpoints/$TCP_TUNNEL_ID.token"
PROXY_PID=""
MCP_PID=""
TCP_TARGET_PID=""
TCP_PUBLISHER_PID=""
TCP_CONNECTOR_PID=""

log() {
    printf '[AI E2E] %s\n' "$1"
}

wait_for_log() {
    local file="$1"
    local pattern="$2"
    local label="$3"
    local pid="$4"
    local attempt
    for attempt in $(seq 1 100); do
        if grep -q "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            printf '%s exited before becoming ready\n' "$label" >&2
            return 1
        fi
        sleep 0.1
    done
    printf 'timed out waiting for %s\n' "$label" >&2
    return 1
}

wait_for_log_count() {
    local file="$1"
    local pattern="$2"
    local expected="$3"
    local label="$4"
    local pid="$5"
    local attempt
    local count
    for attempt in $(seq 1 150); do
        count="$(grep -c "$pattern" "$file" 2>/dev/null || true)"
        if [ "$count" -ge "$expected" ]; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            printf '%s exited before event %s\n' "$label" "$expected" >&2
            return 1
        fi
        sleep 0.1
    done
    printf 'timed out waiting for %s event %s\n' "$label" "$expected" >&2
    return 1
}

wait_for_file() {
    local file="$1"
    local label="$2"
    local pid="$3"
    local attempt
    for attempt in $(seq 1 100); do
        if [ -s "$file" ]; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            printf '%s exited before writing %s\n' "$label" "$file" >&2
            return 1
        fi
        sleep 0.1
    done
    printf 'timed out waiting for %s token file\n' "$label" >&2
    return 1
}

wait_for_proxy() {
    local attempt
    for attempt in $(seq 1 100); do
        if curl -sk --max-time 1 "https://localhost:$HTTP_PORT/health" | grep -q ok; then
            return 0
        fi
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            printf 'relay exited before becoming ready\n' >&2
            return 1
        fi
        sleep 0.1
    done
    printf 'relay health check failed\n' >&2
    return 1
}

start_proxy() {
    TUNN_ENV=dev \
    TUNN_PUBLIC_MODE=true \
    TUNN_DOMAIN="$DOMAIN" \
    TUNN_HTTP2_ADDR=":$HTTP_PORT" \
    TUNN_HTTP3_ADDR=":$HTTP_PORT" \
    TUNN_INTERNAL_GRPC_PORT=":$INTERNAL_GRPC_PORT" \
    TUNN_MOCK_OIDC_ADDR=":$MOCK_OIDC_PORT" \
    TUNN_MOCK_OIDC_ISSUER="http://localhost:$MOCK_OIDC_PORT" \
    TUNN_NODE_ADDRESSES="" \
    ./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem \
        >>"$WORK_DIR/proxy.log" 2>&1 &
    PROXY_PID=$!
    wait_for_proxy
}

cleanup() {
    local status=$?
    local pid
    if [ "$status" -ne 0 ]; then
        for file in "$WORK_DIR"/*.log; do
            if [ -f "$file" ]; then
                printf '\n--- %s ---\n' "$(basename "$file")" >&2
                tail -n 80 "$file" >&2
            fi
        done
    fi
    for pid in "$TCP_CONNECTOR_PID" "$TCP_PUBLISHER_PID" "$TCP_TARGET_PID" "$MCP_PID" "$PROXY_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$TCP_CONNECTOR_PID" "$TCP_PUBLISHER_PID" "$TCP_TARGET_PID" "$MCP_PID" "$PROXY_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$WORK_DIR"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$PROJECT_DIR"

log "starting local TLS relay"
start_proxy

log "publishing stdio MCP server with an echo-only tool policy"
TUNN_ENV=dev \
TUNN_SERVER_ADDR="localhost:$HTTP_PORT" \
TUNN_PUBLIC_MODE=true \
TUNN_CONFIG_DIR="$CONFIG_DIRECTORY" \
./bin/tunn mcp --name "$MCP_TUNNEL_ID" --allow e2e@example.invalid --tools echo -- \
    python3 "$FIXTURE_DIR/mcp-echo-server.py" \
    >"$WORK_DIR/mcp.log" 2>&1 &
MCP_PID=$!
wait_for_log "$WORK_DIR/mcp.log" "tunnel registered successfully" "MCP publisher" "$MCP_PID"
wait_for_file "$MCP_TOKEN_FILE" "MCP publisher" "$MCP_PID"
python3 -c 'import os,stat,sys; mode=stat.S_IMODE(os.stat(sys.argv[1]).st_mode); assert mode == 0o600, oct(mode)' "$MCP_TOKEN_FILE"
MCP_TOKEN="$(tr -d '\r\n' < "$MCP_TOKEN_FILE")"

MCP_URL="https://$MCP_TUNNEL_ID.$DOMAIN:$HTTP_PORT/mcp"
UNAUTHENTICATED_STATUS="$(curl -sk --max-time 5 \
    -o "$WORK_DIR/unauthenticated.json" \
    -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}' \
    "$MCP_URL")"
if [ "$UNAUTHENTICATED_STATUS" != "401" ]; then
    printf 'unauthenticated MCP status was %s, expected 401\n' "$UNAUTHENTICATED_STATUS" >&2
    exit 1
fi

curl -sk --fail --max-time 5 \
    -D "$WORK_DIR/initialize.headers" \
    -o "$WORK_DIR/initialize.json" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Tunn-Authorization: Bearer $MCP_TOKEN" \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"tunn-e2e","version":"1"}}}' \
    "$MCP_URL"
MCP_SESSION_ID="$(awk 'tolower($1) == "mcp-session-id:" {gsub("\r", "", $2); print $2}' "$WORK_DIR/initialize.headers" | tail -n 1)"
if [ -z "$MCP_SESSION_ID" ]; then
    printf 'MCP initialize returned no session ID\n' >&2
    exit 1
fi
python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["result"]["serverInfo"]["name"] == "tunn-e2e"' "$WORK_DIR/initialize.json"

curl -sk --fail --max-time 5 \
    -o "$WORK_DIR/tools.json" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Mcp-Session-Id: $MCP_SESSION_ID" \
    -H "Tunn-Authorization: Bearer $MCP_TOKEN" \
    --data '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
    "$MCP_URL"
python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert [tool["name"] for tool in value["result"]["tools"]] == ["echo"]' "$WORK_DIR/tools.json"

curl -sk --fail --max-time 5 \
    -o "$WORK_DIR/call.json" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Mcp-Session-Id: $MCP_SESSION_ID" \
    -H "Tunn-Authorization: Bearer $MCP_TOKEN" \
    --data '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}' \
    "$MCP_URL"
python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["result"]["content"][0]["text"] == "tunn-e2e:hello"' "$WORK_DIR/call.json"

curl -sk --fail --max-time 5 \
    -o "$WORK_DIR/denied-call.json" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Mcp-Session-Id: $MCP_SESSION_ID" \
    -H "Tunn-Authorization: Bearer $MCP_TOKEN" \
    --data '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"dangerous","arguments":{"secret":"must-not-cross"}}}' \
    "$MCP_URL"
python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["error"]["code"] == -32001' "$WORK_DIR/denied-call.json"
log "private MCP auth, filtered discovery, allowed call, and local rejection passed"

log "rotating the live MCP endpoint token"
OLD_MCP_TOKEN="$MCP_TOKEN"
MCP_TOKEN="$(TUNN_ENV=dev TUNN_CONFIG_DIR="$CONFIG_DIRECTORY" \
    ./bin/tunn token --rotate "$MCP_TUNNEL_ID" 2>"$WORK_DIR/rotation.log")"
if [ -z "$MCP_TOKEN" ] || [ "$MCP_TOKEN" = "$OLD_MCP_TOKEN" ]; then
    printf 'MCP token rotation did not produce a distinct token\n' >&2
    exit 1
fi

OLD_TOKEN_STATUS=""
for attempt in $(seq 1 50); do
    OLD_TOKEN_STATUS="$(curl -sk --max-time 5 \
        -o "$WORK_DIR/old-token.json" \
        -w '%{http_code}' \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json' \
        -H "Mcp-Session-Id: $MCP_SESSION_ID" \
        -H "Tunn-Authorization: Bearer $OLD_MCP_TOKEN" \
        --data '{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}' \
        "$MCP_URL")"
    if [ "$OLD_TOKEN_STATUS" = "401" ]; then
        break
    fi
    sleep 0.1
done
if [ "$OLD_TOKEN_STATUS" != "401" ]; then
    printf 'old MCP token remained valid after rotation\n' >&2
    exit 1
fi

curl -sk --fail --max-time 5 \
    -o "$WORK_DIR/rotated-token.json" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Mcp-Session-Id: $MCP_SESSION_ID" \
    -H "Tunn-Authorization: Bearer $MCP_TOKEN" \
    --data '{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}' \
    "$MCP_URL"
python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert [tool["name"] for tool in value["result"]["tools"]] == ["echo"]' "$WORK_DIR/rotated-token.json"
log "live token rotation revoked the old capability and accepted the new one"

log "publishing and consuming a raw TCP echo service"
python3 "$FIXTURE_DIR/tcp-echo.py" server 127.0.0.1 "$TCP_TARGET_PORT" \
    >"$WORK_DIR/tcp-target.log" 2>&1 &
TCP_TARGET_PID=$!
wait_for_log "$WORK_DIR/tcp-target.log" "ready" "TCP target" "$TCP_TARGET_PID"

TUNN_ENV=dev \
TUNN_SERVER_ADDR="localhost:$HTTP_PORT" \
TUNN_PUBLIC_MODE=true \
TUNN_CONFIG_DIR="$CONFIG_DIRECTORY" \
./bin/tunn tcp --name "$TCP_TUNNEL_ID" --allow e2e@example.invalid "127.0.0.1:$TCP_TARGET_PORT" \
    >"$WORK_DIR/tcp-publisher.log" 2>&1 &
TCP_PUBLISHER_PID=$!
wait_for_log "$WORK_DIR/tcp-publisher.log" "tunnel registered successfully" "TCP publisher" "$TCP_PUBLISHER_PID"
wait_for_file "$TCP_TOKEN_FILE" "TCP publisher" "$TCP_PUBLISHER_PID"
python3 -c 'import os,stat,sys; mode=stat.S_IMODE(os.stat(sys.argv[1]).st_mode); assert mode == 0o600, oct(mode)' "$TCP_TOKEN_FILE"

TUNN_ENV=dev \
TUNN_DOMAIN="$DOMAIN" \
TUNN_SERVER_ADDR="localhost:$HTTP_PORT" \
TUNN_PUBLIC_MODE=true \
TUNN_CONFIG_DIR="$CONFIG_DIRECTORY" \
./bin/tunn connect --listen "127.0.0.1:$TCP_LISTEN_PORT" --token-file "$TCP_TOKEN_FILE" \
    "https://$TCP_TUNNEL_ID.$DOMAIN:$HTTP_PORT" \
    >"$WORK_DIR/tcp-connector.log" 2>&1 &
TCP_CONNECTOR_PID=$!
wait_for_log "$WORK_DIR/tcp-connector.log" "tcp://127.0.0.1:$TCP_LISTEN_PORT" "TCP connector" "$TCP_CONNECTOR_PID"

python3 "$FIXTURE_DIR/tcp-echo.py" client 127.0.0.1 "$TCP_LISTEN_PORT" "hello-over-connect" \
    >"$WORK_DIR/tcp-result.log"
grep -q '^tunn-e2e:hello-over-connect$' "$WORK_DIR/tcp-result.log"

python3 "$FIXTURE_DIR/tcp-echo.py" burst 127.0.0.1 "$TCP_LISTEN_PORT" 8 \
    >"$WORK_DIR/tcp-concurrency.log"
grep -q '^8 concurrent connections passed$' "$WORK_DIR/tcp-concurrency.log"
log "private raw TCP round trip and concurrent connections passed"

log "restarting the relay to verify publisher recovery"
kill "$PROXY_PID"
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
start_proxy
wait_for_log_count "$WORK_DIR/mcp.log" "tunnel registered successfully" 2 "MCP publisher" "$MCP_PID"
wait_for_log_count "$WORK_DIR/tcp-publisher.log" "tunnel registered successfully" 2 "TCP publisher" "$TCP_PUBLISHER_PID"

curl -sk --fail --max-time 5 \
    -o "$WORK_DIR/reconnected-mcp.json" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Mcp-Session-Id: $MCP_SESSION_ID" \
    -H "Tunn-Authorization: Bearer $MCP_TOKEN" \
    --data '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"text":"after-reconnect"}}}' \
    "$MCP_URL"
python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["result"]["content"][0]["text"] == "tunn-e2e:after-reconnect"' "$WORK_DIR/reconnected-mcp.json"

python3 "$FIXTURE_DIR/tcp-echo.py" client 127.0.0.1 "$TCP_LISTEN_PORT" "after-reconnect" \
    >"$WORK_DIR/reconnected-tcp.log"
grep -q '^tunn-e2e:after-reconnect$' "$WORK_DIR/reconnected-tcp.log"
log "MCP and TCP publishers recovered after relay restart"

log "local AI ingress deployment passed"
