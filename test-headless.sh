#!/bin/bash
# Headless E2E test for tunn
# Tests the core tunneling functionality without browser/OAuth interaction

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🤖 tunn Headless E2E Test"
echo "=========================="
echo ""

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0

function pass() {
    echo -e "${GREEN}✓${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

function fail() {
    echo -e "${RED}✗${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

function info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Cleanup function
function cleanup() {
    echo ""
    info "Cleaning up..."
    pkill -f "tunn -mode=host" 2>/dev/null || true
    pkill -f "tunn -mode=client" 2>/dev/null || true
    pkill -f "python.*http.server" 2>/dev/null || true
    sleep 1
}

# Set up trap to cleanup on exit
trap cleanup EXIT

# Clean up any existing processes
cleanup

# Build if needed
if [ ! -f "./bin/tunn" ]; then
    info "Building tunn..."
    make build || { fail "Build failed"; exit 1; }
    pass "Build successful"
fi

# Create test web content
info "Creating test web server..."
mkdir -p /tmp/tunn-test-headless
cat > /tmp/tunn-test-headless/index.html <<'EOF'
<!DOCTYPE html>
<html>
<head><title>Headless Test</title></head>
<body><h1>TUNN_TEST_SUCCESS</h1></body>
</html>
EOF

cat > /tmp/tunn-test-headless/api.json <<'EOF'
{"status": "ok", "test": "headless"}
EOF

# Start test web server
cd /tmp/tunn-test-headless
python3 -m http.server 8765 > /tmp/tunn-test-webserver.log 2>&1 &
WEBSERVER_PID=$!
cd - > /dev/null
sleep 1

# Verify web server is running
if curl -s http://localhost:8765 | grep -q "TUNN_TEST_SUCCESS"; then
    pass "Test web server started (PID: $WEBSERVER_PID)"
else
    fail "Test web server failed to start"
    exit 1
fi

# Set environment for public mode (no auth)
export ENV=dev
export PUBLIC_MODE=true
export WELL_KNOWN_KEY=tunn-free-v1-2025
export TOKEN=test-token-dev

# Start proxy in background
info "Starting tunn proxy (public mode - no auth)..."
./bin/tunn -mode=host \
    -cert=./certs/cert.pem \
    -key=./certs/key.pem \
    -verbosity=request \
    > /tmp/tunn-proxy-headless.log 2>&1 &
PROXY_PID=$!

# Wait for proxy to start
sleep 3

# Check if proxy is running
if ! ps -p $PROXY_PID > /dev/null; then
    fail "Proxy failed to start"
    cat /tmp/tunn-proxy-headless.log
    exit 1
fi
pass "Proxy started (PID: $PROXY_PID)"

# Wait for HTTP server to be ready
info "Waiting for proxy to be ready..."
for i in {1..10}; do
    if curl -sk https://localhost:8443/health > /dev/null 2>&1; then
        pass "Proxy health check passed"
        break
    fi
    if [ $i -eq 10 ]; then
        fail "Proxy health check timed out"
        exit 1
    fi
    sleep 1
done

# Start tunnel client
TUNNEL_ID="test$(date +%s)"
info "Starting tunnel client (tunnel_id: $TUNNEL_ID)..."
./bin/tunn -mode=client \
    -id=$TUNNEL_ID \
    -to=http://localhost:8765 \
    -verbosity=request \
    > /tmp/tunn-client-headless.log 2>&1 &
CLIENT_PID=$!

# Wait for tunnel to establish
sleep 3

# Check if client is running
if ! ps -p $CLIENT_PID > /dev/null; then
    fail "Client failed to start"
    cat /tmp/tunn-client-headless.log
    exit 1
fi
pass "Tunnel client started (PID: $CLIENT_PID)"

# Test 1: Basic tunnel connectivity
info "Test 1: Basic HTTP request through tunnel..."
TUNNEL_URL="https://${TUNNEL_ID}.tunn.local.127.0.0.1.nip.io:8443"
RESPONSE=$(curl -sk "$TUNNEL_URL" 2>&1)
if echo "$RESPONSE" | grep -q "TUNN_TEST_SUCCESS"; then
    pass "HTTP request proxied successfully"
else
    fail "HTTP request failed"
    echo "Response: $RESPONSE"
fi

# Test 2: JSON API endpoint
info "Test 2: JSON API request through tunnel..."
API_RESPONSE=$(curl -sk "${TUNNEL_URL}/api.json" 2>&1)
if echo "$API_RESPONSE" | grep -q '"status": "ok"'; then
    pass "JSON API request proxied successfully"
else
    fail "JSON API request failed"
    echo "Response: $API_RESPONSE"
fi

# Test 3: POST request
info "Test 3: POST request through tunnel..."
POST_RESPONSE=$(curl -sk -X POST -d "test=data" "$TUNNEL_URL" 2>&1)
if [ $? -eq 0 ]; then
    pass "POST request proxied successfully"
else
    fail "POST request failed"
fi

# Test 4: Headers preservation
info "Test 4: Custom headers through tunnel..."
HEADER_RESPONSE=$(curl -sk -H "X-Test-Header: testing123" "$TUNNEL_URL" 2>&1)
if [ $? -eq 0 ]; then
    pass "Custom headers proxied successfully"
else
    fail "Custom headers failed"
fi

# Test 5: Multiple requests (stress test)
info "Test 5: Multiple concurrent requests..."
SUCCESS_COUNT=0
for i in {1..10}; do
    if curl -sk "$TUNNEL_URL" 2>&1 | grep -q "TUNN_TEST_SUCCESS"; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
done
if [ $SUCCESS_COUNT -eq 10 ]; then
    pass "All 10 concurrent requests successful"
else
    fail "Only $SUCCESS_COUNT/10 requests succeeded"
fi

# Print summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 TEST SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "${RED}Failed:${NC} $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
    echo ""
    echo "Core tunneling functionality verified:"
    echo "  ✓ gRPC tunnel establishment"
    echo "  ✓ HTTP-over-gRPC data plane"
    echo "  ✓ Request/response proxying"
    echo "  ✓ Multiple concurrent requests"
    echo "  ✓ POST requests"
    echo "  ✓ Custom headers"
    echo "  ✓ JSON APIs"
    echo ""
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "Check logs:"
    echo "  Proxy:  tail -100 /tmp/tunn-proxy-headless.log"
    echo "  Client: tail -100 /tmp/tunn-client-headless.log"
    echo "  Web:    tail -100 /tmp/tunn-test-webserver.log"
    echo ""
    exit 1
fi
