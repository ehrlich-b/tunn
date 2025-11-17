#!/bin/bash
# Local E2E testing script for tunn
# This script sets up a complete local testing environment

set -e

echo "🧪 tunn Local E2E Test"
echo "====================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if binary exists
if [ ! -f "./bin/tunn" ]; then
    echo "❌ Binary not found. Building..."
    make build
fi

# Kill any existing tunn processes
echo "🧹 Cleaning up existing processes..."
pkill -f "tunn -mode=host" || true
pkill -f "tunn -mode=client" || true
pkill -f "python.*SimpleHTTPServer" || true
pkill -f "python.*http.server" || true

# Wait for cleanup
sleep 2

# Create test directory with index.html
echo "📝 Creating test web content..."
mkdir -p /tmp/tunn-test-web
cat > /tmp/tunn-test-web/index.html <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>tunn E2E Test</title>
    <style>
        body { font-family: monospace; padding: 40px; background: #1a1a1a; color: #00ff00; }
        .success { color: #00ff00; font-size: 24px; }
    </style>
</head>
<body>
    <h1 class="success">✅ tunn E2E Test - SUCCESS!</h1>
    <p>If you're seeing this, the tunnel is working!</p>
    <p>Request details:</p>
    <pre id="details"></pre>
    <script>
        document.getElementById('details').textContent =
            'URL: ' + window.location.href + '\n' +
            'User Agent: ' + navigator.userAgent;
    </script>
</body>
</html>
EOF

# Start test web server
echo "🌐 Starting test web server on :8000..."
cd /tmp/tunn-test-web
python3 -m http.server 8000 > /tmp/tunn-webserver.log 2>&1 &
WEBSERVER_PID=$!
cd - > /dev/null

# Wait for web server
sleep 2
if ! curl -s http://localhost:8000 > /dev/null; then
    echo "❌ Failed to start web server"
    exit 1
fi
echo -e "${GREEN}✓${NC} Test web server running (PID: $WEBSERVER_PID)"

# Set environment variables for dev mode
export ENV=dev
export WELL_KNOWN_KEY=tunn-free-v1-2025
export TOKEN=test-token-dev  # Dummy token for host mode

# Start proxy in background
echo "🚀 Starting tunn proxy (dev mode)..."
./bin/tunn -mode=host \
    -cert=./certs/cert.pem \
    -key=./certs/key.pem \
    > /tmp/tunn-proxy.log 2>&1 &
PROXY_PID=$!

# Wait for proxy to start
echo "⏳ Waiting for proxy to initialize..."
sleep 3

if ! ps -p $PROXY_PID > /dev/null; then
    echo "❌ Proxy failed to start. Check /tmp/tunn-proxy.log"
    tail -20 /tmp/tunn-proxy.log
    exit 1
fi
echo -e "${GREEN}✓${NC} Proxy running (PID: $PROXY_PID)"

# Check if mock OIDC is responding
echo "🔐 Checking mock OIDC server..."
for i in {1..10}; do
    if curl -s http://localhost:9000/.well-known/openid-configuration > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Mock OIDC server ready"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "❌ Mock OIDC server not responding"
        exit 1
    fi
    sleep 1
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 MANUAL TESTING STEPS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${BLUE}Step 1: Login${NC}"
echo "  Run in another terminal:"
echo -e "  ${YELLOW}./bin/tunn -mode=login${NC}"
echo ""
echo -e "${BLUE}Step 2: Start tunnel${NC}"
echo "  Run in another terminal:"
echo -e "  ${YELLOW}./bin/tunn -mode=client -to localhost:8000 --allow test@example.com${NC}"
echo ""
echo -e "${BLUE}Step 3: Visit tunnel${NC}"
echo "  Copy the tunnel URL from step 2 (https://xxxxx.tunn.local.127.0.0.1.nip.io)"
echo "  Open in browser and login with mock OIDC"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 Logs:"
echo "  Proxy:      tail -f /tmp/tunn-proxy.log"
echo "  Web Server: tail -f /tmp/tunn-webserver.log"
echo ""
echo "🛑 To stop all services:"
echo "  kill $PROXY_PID $WEBSERVER_PID"
echo "  or just Ctrl+C and run: pkill -f tunn"
echo ""
echo "Press Ctrl+C to stop proxy and web server..."

# Wait for interrupt
trap "echo ''; echo '🛑 Shutting down...'; kill $PROXY_PID $WEBSERVER_PID 2>/dev/null; echo '✓ Stopped'; exit 0" INT TERM

# Keep script running
tail -f /tmp/tunn-proxy.log
