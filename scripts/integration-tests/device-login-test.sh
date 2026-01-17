#!/bin/bash
# Device Login E2E Test: Full device code flow via mock OIDC
# Tests: POST /api/device/code -> browser simulation -> GET /api/device/token

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_DIR"

# Configuration (using high ports to avoid conflicts)
DOMAIN="tunn.local.127.0.0.1.nip.io"
HTTP_PORT=18443
MOCK_OIDC_PORT=19000
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
    [ -n "$PROXY_PID" ] && kill $PROXY_PID 2>/dev/null || true
    [ -n "$COOKIE_JAR" ] && rm -f "$COOKIE_JAR" 2>/dev/null || true
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

# Step 3: Start proxy server (with mock OIDC, no PUBLIC_MODE)
log_info "Starting proxy server with mock OIDC (PUBLIC_MODE=false)..."
ENV=dev \
  TOKEN=$TOKEN \
  PUBLIC_MODE=false \
  DOMAIN=$DOMAIN \
  HTTP2_ADDR=:$HTTP_PORT \
  HTTP3_ADDR=:$HTTP_PORT \
  MOCK_OIDC_ADDR=:$MOCK_OIDC_PORT \
  MOCK_OIDC_ISSUER="http://localhost:$MOCK_OIDC_PORT" \
  PUBLIC_ADDR="localhost:$HTTP_PORT" \
  NODE_ADDRESSES="" \
  ./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem &
PROXY_PID=$!
sleep 3

# Verify proxy is running
if ! curl -sk "https://localhost:$HTTP_PORT/health" | grep -q "ok"; then
    log_error "Proxy server failed to start"
    exit 1
fi
log_info "Proxy server running (PID: $PROXY_PID)"

# Step 4: Request device code
log_info "Requesting device code..."
DEVICE_RESP=$(curl -sk -X POST "https://localhost:$HTTP_PORT/api/device/code")
log_info "Device response: $DEVICE_RESP"

DEVICE_CODE=$(echo "$DEVICE_RESP" | grep -o '"device_code":"[^"]*"' | cut -d'"' -f4)
USER_CODE=$(echo "$DEVICE_RESP" | grep -o '"user_code":"[^"]*"' | cut -d'"' -f4)

if [ -z "$DEVICE_CODE" ] || [ -z "$USER_CODE" ]; then
    log_error "Failed to get device code from response"
    exit 1
fi

log_info "Device code: $DEVICE_CODE"
log_info "User code: $USER_CODE"

# Step 5: Verify polling returns authorization_pending
log_info "Verifying polling returns authorization_pending..."
POLL_RESP=$(curl -sk "https://localhost:$HTTP_PORT/api/device/token?code=$DEVICE_CODE")
log_info "Poll response: $POLL_RESP"

if ! echo "$POLL_RESP" | grep -q "authorization_pending"; then
    log_error "Expected authorization_pending, got: $POLL_RESP"
    exit 1
fi
log_info "Correctly received authorization_pending"

# Step 6: Simulate browser login flow
log_info "Simulating browser login flow..."
COOKIE_JAR=$(mktemp)

# 6a. Visit /login with user code (stores device code in session, redirects to mock OIDC)
log_info "Visiting /login?code=$USER_CODE..."
curl -sk -c "$COOKIE_JAR" -b "$COOKIE_JAR" -L \
    "https://localhost:$HTTP_PORT/login?code=$USER_CODE" \
    -o /dev/null -w "%{url_effective}\n"

# The above should have:
# 1. Hit /login?code=USER_CODE
# 2. Stored device_user_code in session
# 3. Redirected to mock OIDC /authorize
# 4. Mock OIDC redirected back to /auth/callback with code and state
# 5. /auth/callback authorized the device code

# Step 7: Poll again - should get JWT now
log_info "Polling for token after browser auth..."
sleep 1
POLL_RESP=$(curl -sk "https://localhost:$HTTP_PORT/api/device/token?code=$DEVICE_CODE")
log_info "Poll response: $POLL_RESP"

ACCESS_TOKEN=$(echo "$POLL_RESP" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
    log_error "Did not receive access token"
    log_error "Response: $POLL_RESP"
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  DEVICE LOGIN TEST FAILED${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    exit 1
fi

log_info "Received JWT token!"
log_info "Token (first 50 chars): ${ACCESS_TOKEN:0:50}..."

# Step 8: Verify JWT is valid by decoding the payload (base64)
log_info "Verifying JWT structure..."
# JWT format: header.payload.signature
JWT_PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d'.' -f2)
# Add padding if needed
while [ $((${#JWT_PAYLOAD} % 4)) -ne 0 ]; do
    JWT_PAYLOAD="${JWT_PAYLOAD}="
done
DECODED_PAYLOAD=$(echo "$JWT_PAYLOAD" | base64 -d 2>/dev/null || true)

if echo "$DECODED_PAYLOAD" | grep -q '"email"'; then
    log_info "JWT payload verified: $DECODED_PAYLOAD"
else
    log_warn "Could not verify JWT payload (base64 decode may have failed)"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  DEVICE LOGIN TEST PASSED${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
exit 0
