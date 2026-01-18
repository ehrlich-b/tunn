#!/bin/bash
# Multi-Node gRPC Test: Two nodes discovering tunnels across the mesh
# Tests cross-node tunnel discovery and proxying

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_DIR"

# Configuration (using high ports to avoid conflicts)
DOMAIN="tunn.local.127.0.0.1.nip.io"
NODE1_PORT=18443
NODE2_PORT=18444
NODE1_INTERNAL=50051
NODE2_INTERNAL=50052
TARGET_PORT=19999
TUNNEL_ID="multinode-test"
TOKEN="test-token-for-integration"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    [ -n "$NODE1_PID" ] && kill -9 $NODE1_PID 2>/dev/null || true
    [ -n "$NODE2_PID" ] && kill -9 $NODE2_PID 2>/dev/null || true
    [ -n "$CLIENT_PID" ] && kill -9 $CLIENT_PID 2>/dev/null || true
    [ -n "$TARGET_PID" ] && kill -9 $TARGET_PID 2>/dev/null || true
    [ -n "$TARGET_DIR" ] && rm -f "$TARGET_DIR/index.html" 2>/dev/null || true
    [ -n "$TARGET_DIR" ] && rmdir "$TARGET_DIR" 2>/dev/null || true
    sleep 2  # Wait for ports to be released
}
trap cleanup EXIT

# Step 1: Build binary
log_info "Building binary..."
make build

# Step 2: Generate certificates if needed
if [ ! -f "./certs/cert.pem" ]; then
    log_info "Generating test certificates..."
    ./scripts/gen-test-certs.sh
fi

# Step 3: Start test HTTP server
log_info "Starting test HTTP server on :$TARGET_PORT..."
TARGET_DIR=$(mktemp -d)
echo "Hello from multi-node test!" > "$TARGET_DIR/index.html"
cd "$TARGET_DIR"
python3 -m http.server $TARGET_PORT &
TARGET_PID=$!
cd "$PROJECT_DIR"
sleep 1

if ! curl -s "http://localhost:$TARGET_PORT/" > /dev/null; then
    log_error "Target HTTP server failed to start"
    exit 1
fi
log_info "Target server running (PID: $TARGET_PID)"

# Shared secret for node-to-node authentication
NODE_SECRET="integration-test-secret"

# Step 4: Start Node 1
log_info "Starting Node 1 on :$NODE1_PORT (internal :$NODE1_INTERNAL)..."
TUNN_ENV=dev \
  TUNN_PUBLIC_MODE=true \
  TUNN_DOMAIN=$DOMAIN \
  TUNN_HTTP2_ADDR=:$NODE1_PORT \
  TUNN_HTTP3_ADDR=:$NODE1_PORT \
  TUNN_INTERNAL_GRPC_PORT=:$NODE1_INTERNAL \
  TUNN_NODE_ADDRESSES="$DOMAIN:$NODE2_INTERNAL" \
  TUNN_NODE_SECRET="$NODE_SECRET" \
  TUNN_PUBLIC_ADDR="localhost:$NODE1_PORT" \
  TUNN_MOCK_OIDC_ADDR="" \
  TUNN_CA_CERT=./certs/ca.pem \
  ./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem &
NODE1_PID=$!
sleep 2

if ! curl -sk "https://localhost:$NODE1_PORT/health" | grep -q "ok"; then
    log_error "Node 1 failed to start"
    exit 1
fi
log_info "Node 1 running (PID: $NODE1_PID)"

# Step 5: Start Node 2
log_info "Starting Node 2 on :$NODE2_PORT (internal :$NODE2_INTERNAL)..."
TUNN_ENV=dev \
  TUNN_PUBLIC_MODE=true \
  TUNN_DOMAIN=$DOMAIN \
  TUNN_HTTP2_ADDR=:$NODE2_PORT \
  TUNN_HTTP3_ADDR=:$NODE2_PORT \
  TUNN_INTERNAL_GRPC_PORT=:$NODE2_INTERNAL \
  TUNN_NODE_ADDRESSES="$DOMAIN:$NODE1_INTERNAL" \
  TUNN_NODE_SECRET="$NODE_SECRET" \
  TUNN_PUBLIC_ADDR="localhost:$NODE2_PORT" \
  TUNN_MOCK_OIDC_ADDR="" \
  TUNN_CA_CERT=./certs/ca.pem \
  ./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem &
NODE2_PID=$!
sleep 2

if ! curl -sk "https://localhost:$NODE2_PORT/health" | grep -q "ok"; then
    log_error "Node 2 failed to start"
    exit 1
fi
log_info "Node 2 running (PID: $NODE2_PID)"

# Step 6: Connect tunnel client to Node 1
log_info "Connecting tunnel client to Node 1..."
TUNN_ENV=dev \
  TUNN_SERVER_ADDR=localhost:$NODE1_PORT \
  TUNN_PUBLIC_MODE=true \
  ./bin/tunn $TARGET_PORT --id=$TUNNEL_ID  &
CLIENT_PID=$!
sleep 2

# Step 7: Test direct access via Node 1
log_info "Test 1: Access tunnel via Node 1 (direct)..."
TUNNEL_URL_NODE1="https://$TUNNEL_ID.$DOMAIN:$NODE1_PORT/"
log_info "Requesting: $TUNNEL_URL_NODE1"
RESP1=$(curl -sk "$TUNNEL_URL_NODE1")

if echo "$RESP1" | grep -q "Hello from multi-node test!"; then
    log_info "PASS: Node 1 direct access works"
else
    log_error "FAIL: Node 1 direct access failed"
    log_error "Response: $RESP1"
    exit 1
fi

# Step 8: Test cross-node access via Node 2
log_info "Test 2: Access tunnel via Node 2 (cross-node discovery)..."
TUNNEL_URL_NODE2="https://$TUNNEL_ID.$DOMAIN:$NODE2_PORT/"
log_info "Requesting: $TUNNEL_URL_NODE2"
RESP2=$(curl -sk "$TUNNEL_URL_NODE2")

if echo "$RESP2" | grep -q "Hello from multi-node test!"; then
    log_info "PASS: Node 2 cross-node discovery works"
else
    log_error "FAIL: Node 2 cross-node discovery failed"
    log_error "Response: $RESP2"
    exit 1
fi

# Step 9: Kill Node 1, verify Node 2 returns error
log_info "Test 3: Kill Node 1, verify tunnel unavailable via Node 2..."
kill $NODE1_PID
NODE1_PID=""
sleep 2

HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TUNNEL_URL_NODE2")

if [ "$HTTP_CODE" = "502" ] || [ "$HTTP_CODE" = "503" ] || [ "$HTTP_CODE" = "504" ]; then
    log_info "PASS: Node 2 correctly returns $HTTP_CODE when tunnel owner is down"
else
    log_error "FAIL: Expected 502/503/504, got $HTTP_CODE"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  MULTI-NODE TEST PASSED${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
exit 0
