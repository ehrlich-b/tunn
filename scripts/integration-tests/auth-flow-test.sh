#!/bin/bash
# Full Auth Flow Test: Allow-list enforcement and domain wildcards
# Tests: unauthenticated redirect, authenticated access, allow-list denial

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_DIR"

# Configuration (using high ports to avoid conflicts)
DOMAIN="tunn.local.127.0.0.1.nip.io"
HTTP_PORT=18443
MOCK_OIDC_PORT=19000
TARGET_PORT=19999
TUNNEL_ID="auth-test"
TOKEN="test-token-for-integration"
# Mock OIDC returns dev@example.com
ALLOWED_EMAIL="dev@example.com"
ALLOWED_DOMAIN="@example.com"

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
    [ -n "$CLIENT_PID" ] && kill -9 $CLIENT_PID 2>/dev/null || true
    [ -n "$TARGET_PID" ] && kill -9 $TARGET_PID 2>/dev/null || true
    [ -n "$COOKIE_JAR" ] && rm -f "$COOKIE_JAR" 2>/dev/null || true
    [ -n "$TARGET_DIR" ] && rm -f "$TARGET_DIR/index.html" 2>/dev/null || true
    [ -n "$TARGET_DIR" ] && rmdir "$TARGET_DIR" 2>/dev/null || true
    # Restore original token if we backed it up, otherwise remove test token
    if [ -f ~/.tunn/token.bak ]; then
        mv ~/.tunn/token.bak ~/.tunn/token
    else
        rm -f ~/.tunn/token 2>/dev/null || true
    fi
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
echo "Hello from auth test!" > "$TARGET_DIR/index.html"
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

# Step 4: Create a test JWT for the tunnel client
# The client needs a JWT to register tunnels when server has PUBLIC_MODE=false
log_info "Creating test JWT for tunnel client..."
# Back up existing token if any
[ -f ~/.tunn/token ] && mv ~/.tunn/token ~/.tunn/token.bak
TEST_JWT_SECRET="dev-jwt-secret-do-not-use-in-prod"
# Create a simple JWT with email claim (header.payload.signature)
# Header: {"alg":"HS256","typ":"JWT"} base64url: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
# Payload: {"email":"tunnel-creator@example.com","exp":9999999999}
JWT_HEADER="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
# Payload with far-future expiry
JWT_PAYLOAD=$(echo -n '{"email":"tunnel-creator@example.com","exp":9999999999,"iat":1700000000,"iss":"tunn","sub":"tunnel-creator@example.com"}' | base64 | tr '+/' '-_' | tr -d '=')
# For testing, we'll use a pre-computed signature that matches the dev secret
# Actually, we need to compute HMAC-SHA256 - let's use openssl
SIGNING_INPUT="${JWT_HEADER}.${JWT_PAYLOAD}"
JWT_SIGNATURE=$(echo -n "$SIGNING_INPUT" | openssl dgst -sha256 -hmac "$TEST_JWT_SECRET" -binary | base64 | tr '+/' '-_' | tr -d '=')
TEST_JWT="${SIGNING_INPUT}.${JWT_SIGNATURE}"
log_info "Test JWT created"

# Save the JWT to ~/.tunn/token for the client to use
mkdir -p ~/.tunn
echo -n "$TEST_JWT" > ~/.tunn/token
log_info "Test JWT saved to ~/.tunn/token"

# Step 5: Start proxy server (with auth enabled)
log_info "Starting proxy server with auth enabled..."
TUNN_ENV=dev \
  TUNN_PUBLIC_MODE=false \
  TUNN_DOMAIN=$DOMAIN \
  TUNN_HTTP2_ADDR=:$HTTP_PORT \
  TUNN_HTTP3_ADDR=:$HTTP_PORT \
  TUNN_MOCK_OIDC_ADDR=:$MOCK_OIDC_PORT \
  TUNN_MOCK_OIDC_ISSUER="http://localhost:$MOCK_OIDC_PORT" \
  TUNN_PUBLIC_ADDR="$DOMAIN:$HTTP_PORT" \
  TUNN_NODE_ADDRESSES="" \
  ./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem &
PROXY_PID=$!
sleep 3

if ! curl -sk "https://localhost:$HTTP_PORT/health" | grep -q "ok"; then
    log_error "Proxy server failed to start"
    exit 1
fi
log_info "Proxy server running (PID: $PROXY_PID)"

# Step 6: Connect tunnel client with allow-list
log_info "Connecting tunnel client with allow-list: $ALLOWED_EMAIL..."
TUNN_ENV=dev \
  TUNN_SERVER_ADDR=localhost:$HTTP_PORT \
  TUNN_PUBLIC_MODE=false \
  ./bin/tunn $TARGET_PORT --id=$TUNNEL_ID --allow=$ALLOWED_EMAIL  &
CLIENT_PID=$!
sleep 2

TUNNEL_URL="https://$TUNNEL_ID.$DOMAIN:$HTTP_PORT/"

# Test 1: Unauthenticated request should redirect to login
log_info "Test 1: Unauthenticated request should redirect to login..."
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TUNNEL_URL")

if [ "$HTTP_CODE" = "302" ]; then
    log_info "PASS: Unauthenticated request redirects (302)"
else
    log_error "FAIL: Expected 302 redirect, got $HTTP_CODE"
    exit 1
fi

# Test 2: Authenticate via mock OIDC and access tunnel
log_info "Test 2: Authenticate and access tunnel..."
COOKIE_JAR=$(mktemp)

# First, go through the login flow to get a session
# Use the domain for proper cookie handling
log_info "Performing mock OIDC login..."
curl -sk -c "$COOKIE_JAR" -b "$COOKIE_JAR" -L \
    "https://$DOMAIN:$HTTP_PORT/auth/login" \
    -o /dev/null

# Now try to access the tunnel with the session cookie
log_info "Accessing tunnel with session cookie..."
RESP=$(curl -sk -b "$COOKIE_JAR" "$TUNNEL_URL")

if echo "$RESP" | grep -q "Hello from auth test!"; then
    log_info "PASS: Authenticated request succeeds"
else
    log_error "FAIL: Authenticated request did not return expected content"
    log_error "Response: $RESP"
    exit 1
fi

# Test 3: Domain wildcard matching
log_info "Test 3: Testing domain wildcard (@example.com)..."

# Kill the current client and start a new one with domain wildcard
kill $CLIENT_PID 2>/dev/null || true
sleep 1

TUNNEL_ID2="auth-test-domain"
TUNN_ENV=dev \
  TUNN_SERVER_ADDR=localhost:$HTTP_PORT \
  TUNN_PUBLIC_MODE=false \
  ./bin/tunn $TARGET_PORT --id=$TUNNEL_ID2 --allow=$ALLOWED_DOMAIN  &
CLIENT_PID=$!
sleep 2

TUNNEL_URL2="https://$TUNNEL_ID2.$DOMAIN:$HTTP_PORT/"

# Access with same session (dev@example.com should match @example.com)
RESP2=$(curl -sk -b "$COOKIE_JAR" "$TUNNEL_URL2")

if echo "$RESP2" | grep -q "Hello from auth test!"; then
    log_info "PASS: Domain wildcard matching works"
else
    log_error "FAIL: Domain wildcard matching failed"
    log_error "Response: $RESP2"
    exit 1
fi

# Test 4: Access denial for non-allowed email
log_info "Test 4: Testing access denial for non-allowed user..."

# Create a tunnel that only allows a different email
kill $CLIENT_PID 2>/dev/null || true
sleep 1

TUNNEL_ID3="auth-test-denied"
TUNN_ENV=dev \
  TUNN_SERVER_ADDR=localhost:$HTTP_PORT \
  TUNN_PUBLIC_MODE=false \
  ./bin/tunn $TARGET_PORT --id=$TUNNEL_ID3 --allow=other@different.com  &
CLIENT_PID=$!
sleep 2

TUNNEL_URL3="https://$TUNNEL_ID3.$DOMAIN:$HTTP_PORT/"

# Access with same session (dev@example.com should NOT match other@different.com)
HTTP_CODE3=$(curl -sk -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "$TUNNEL_URL3")

if [ "$HTTP_CODE3" = "403" ]; then
    log_info "PASS: Access correctly denied for non-allowed user (403)"
else
    log_error "FAIL: Expected 403 Forbidden, got $HTTP_CODE3"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  AUTH FLOW TEST PASSED${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
exit 0
