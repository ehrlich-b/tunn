#!/bin/bash
# Smoke test: Single node, PUBLIC_MODE, basic tunnel flow
# Tests that a request through the tunnel reaches the target server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_DIR"

# Configuration (using high ports to avoid conflicts)
DOMAIN="tunn.local.127.0.0.1.nip.io"
HTTP_PORT=18443
TARGET_PORT=19999
TUNNEL_ID="smoke-test"
TOKEN="test-token-for-integration"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."
    [ -n "$PROXY_PID" ] && kill -9 $PROXY_PID 2>/dev/null || true
    [ -n "$CLIENT_PID" ] && kill -9 $CLIENT_PID 2>/dev/null || true
    [ -n "$TARGET_PID" ] && kill -9 $TARGET_PID 2>/dev/null || true
    rm -f "$TARGET_DIR/index.html" 2>/dev/null || true
    rmdir "$TARGET_DIR" 2>/dev/null || true
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
echo "Hello from smoke test!" > "$TARGET_DIR/index.html"
cd "$TARGET_DIR"
python3 -m http.server $TARGET_PORT &
TARGET_PID=$!
cd "$PROJECT_DIR"
sleep 1

# Verify target server is running
if ! curl -s "http://localhost:$TARGET_PORT/" > /dev/null; then
    log_error "Target HTTP server failed to start"
    exit 1
fi
log_info "Target server running (PID: $TARGET_PID)"

# Step 4: Start proxy server
log_info "Starting proxy server on :$HTTP_PORT (PUBLIC_MODE=true)..."
ENV=dev \
  TOKEN=$TOKEN \
  PUBLIC_MODE=true \
  DOMAIN=$DOMAIN \
  HTTP2_ADDR=:$HTTP_PORT \
  HTTP3_ADDR=:$HTTP_PORT \
  MOCK_OIDC_ADDR=:19000 \
  MOCK_OIDC_ISSUER="http://localhost:19000" \
  NODE_ADDRESSES="" \
  ./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem &
PROXY_PID=$!
sleep 2

# Verify proxy is running
if ! curl -sk "https://localhost:$HTTP_PORT/health" | grep -q "ok"; then
    log_error "Proxy server failed to start"
    exit 1
fi
log_info "Proxy server running (PID: $PROXY_PID)"

# Step 5: Start tunnel client
log_info "Connecting tunnel client (ID: $TUNNEL_ID)..."
ENV=dev \
  SERVER_ADDR=localhost:$HTTP_PORT \
  PUBLIC_MODE=true \
  ./bin/tunn $TARGET_PORT --id=$TUNNEL_ID &
CLIENT_PID=$!
sleep 2

# Step 6: Test tunnel access
log_info "Testing tunnel access..."
TUNNEL_URL="https://$TUNNEL_ID.$DOMAIN:$HTTP_PORT/"
log_info "Requesting: $TUNNEL_URL"

RESPONSE=$(curl -sk "$TUNNEL_URL")

if echo "$RESPONSE" | grep -q "Hello from smoke test!"; then
    log_info "Response received: $RESPONSE"
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  SMOKE TEST PASSED${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    exit 0
else
    log_error "Unexpected response: $RESPONSE"
    log_error "Expected: Hello from smoke test!"
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  SMOKE TEST FAILED${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    exit 1
fi
