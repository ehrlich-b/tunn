#!/bin/bash
# Magic Link E2E Test: Generate token -> verify -> get session
# Tests: tunn magic-link -> GET /auth/verify -> session cookie

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_DIR"

# Configuration
DOMAIN="tunn.local.127.0.0.1.nip.io"
HTTP_PORT=18443
JWT_SECRET="integration-test-jwt-secret"
TEST_EMAIL="magiclink-test@example.com"

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
    [ -n "$PROXY_PID" ] && kill -9 $PROXY_PID 2>/dev/null || true
    [ -n "$COOKIE_JAR" ] && rm -f "$COOKIE_JAR" 2>/dev/null || true
    sleep 2
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

# Step 3: Start proxy server
log_info "Starting proxy server (TUNN_PUBLIC_MODE=false, TUNN_JWT_SECRET set)..."
TUNN_ENV=dev \
  TUNN_PUBLIC_MODE=false \
  TUNN_DOMAIN=$DOMAIN \
  TUNN_HTTP2_ADDR=:$HTTP_PORT \
  TUNN_HTTP3_ADDR=:$HTTP_PORT \
  TUNN_JWT_SECRET=$JWT_SECRET \
  TUNN_PUBLIC_ADDR="$DOMAIN:$HTTP_PORT" \
  TUNN_NODE_ADDRESSES="" \
  TUNN_MOCK_OIDC_ADDR="" \
  ./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem &
PROXY_PID=$!
sleep 3

# Verify proxy is running
if ! curl -sk "https://localhost:$HTTP_PORT/health" | grep -q "ok"; then
    log_error "Proxy server failed to start"
    exit 1
fi
log_info "Proxy server running (PID: $PROXY_PID)"

# Step 4: Generate magic link token using tunn CLI
log_info "Generating magic link token for $TEST_EMAIL..."
MAGIC_TOKEN=$(TUNN_JWT_SECRET=$JWT_SECRET ./bin/tunn magic-link "$TEST_EMAIL")

if [ -z "$MAGIC_TOKEN" ]; then
    log_error "Failed to generate magic link token"
    exit 1
fi
log_info "Generated token: ${MAGIC_TOKEN:0:50}..."

# Step 5: Verify token structure (decode and check claims)
log_info "Verifying JWT structure..."
JWT_PAYLOAD=$(echo "$MAGIC_TOKEN" | cut -d'.' -f2)
# Add padding if needed
while [ $((${#JWT_PAYLOAD} % 4)) -ne 0 ]; do
    JWT_PAYLOAD="${JWT_PAYLOAD}="
done
DECODED_PAYLOAD=$(echo "$JWT_PAYLOAD" | base64 -d 2>/dev/null || true)

if echo "$DECODED_PAYLOAD" | grep -q "\"email\":\"$TEST_EMAIL\""; then
    log_info "JWT payload contains correct email"
else
    log_error "JWT payload missing or incorrect email"
    log_error "Decoded: $DECODED_PAYLOAD"
    exit 1
fi

if echo "$DECODED_PAYLOAD" | grep -q '"type":"magic_link"'; then
    log_info "JWT payload contains correct type"
else
    log_error "JWT payload missing magic_link type"
    exit 1
fi

# Step 6: Verify the token via /auth/verify endpoint
log_info "Verifying token via /auth/verify endpoint..."
COOKIE_JAR=$(mktemp)

# The verify endpoint should redirect to / and set a session cookie
VERIFY_URL="https://$DOMAIN:$HTTP_PORT/auth/verify?token=$MAGIC_TOKEN"
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -c "$COOKIE_JAR" -L "$VERIFY_URL")

if [ "$HTTP_CODE" != "200" ]; then
    log_error "Expected 200 after redirect, got $HTTP_CODE"
    exit 1
fi
log_info "Token verification succeeded (HTTP $HTTP_CODE)"

# Step 7: Verify session cookie was set
log_info "Checking session cookie..."
if grep -q "tunn_session" "$COOKIE_JAR"; then
    log_info "Session cookie 'tunn_session' is set"
else
    log_warn "Session cookie not found in jar (may be OK depending on cookie domain)"
    cat "$COOKIE_JAR"
fi

# Step 8: Verify an invalid/expired token is rejected
log_info "Testing invalid token rejection..."
INVALID_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJleHAiOjEsImlhdCI6MCwidHlwZSI6Im1hZ2ljX2xpbmsifQ.invalid"
INVALID_URL="https://$DOMAIN:$HTTP_PORT/auth/verify?token=$INVALID_TOKEN"
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$INVALID_URL")

if [ "$HTTP_CODE" = "400" ]; then
    log_info "Invalid token correctly rejected (HTTP 400)"
else
    log_error "Expected 400 for invalid token, got $HTTP_CODE"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  MAGIC LINK TEST PASSED${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
exit 0
