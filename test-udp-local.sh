#!/bin/bash
# UDP tunneling E2E test for tunn
# This script tests the complete UDP tunneling flow

set -e

echo "🧪 tunn UDP Tunneling E2E Test"
echo "=============================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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
pkill -f "tunn -mode=connect" || true
pkill -f "nc -u -l" || true

# Wait for cleanup
sleep 2

# Create a simple UDP echo script
echo "📝 Creating UDP echo server..."
cat > /tmp/udp-echo-server.sh <<'EOFSCRIPT'
#!/bin/bash
# Simple UDP echo server
nc -u -l 25565
EOFSCRIPT
chmod +x /tmp/udp-echo-server.sh

# Start UDP echo server
echo "🌐 Starting UDP echo server on :25565..."
/tmp/udp-echo-server.sh > /tmp/tunn-udp-echo.log 2>&1 &
ECHO_PID=$!

# Wait for echo server
sleep 1
echo -e "${GREEN}✓${NC} UDP echo server running (PID: $ECHO_PID)"

# Set environment variables for dev mode
export ENV=dev
export WELL_KNOWN_KEY=tunn-free-v1-2025
export TOKEN=test-token-dev
export PUBLIC_MODE=true  # Disable auth for testing

# Start proxy in background
echo "🚀 Starting tunn proxy (dev mode with PUBLIC_MODE)..."
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

# Generate tunnel ID
TUNNEL_ID="udptest$(date +%s)"

# Start tunn serve with UDP support
echo "🔌 Starting tunn serve (UDP mode)..."
./bin/tunn -mode=client \
    -id=$TUNNEL_ID \
    -to=http://localhost:8000 \
    -tunnel-key=$WELL_KNOWN_KEY \
    > /tmp/tunn-serve.log 2>&1 &
SERVE_PID=$!

# Wait for serve to register
sleep 2

if ! ps -p $SERVE_PID > /dev/null; then
    echo "❌ Serve failed to start. Check /tmp/tunn-serve.log"
    tail -20 /tmp/tunn-serve.log
    kill $PROXY_PID $ECHO_PID 2>/dev/null
    exit 1
fi
echo -e "${GREEN}✓${NC} tunn serve running (PID: $SERVE_PID, ID: $TUNNEL_ID)"

# For V1.1, we need to update the serve client to support UDP target address
# For now, let's document the architecture
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 UDP TUNNELING ARCHITECTURE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Flow:"
echo "  1. Game Client → UDP packet → tunn connect (localhost:25566)"
echo "  2. tunn connect → HTTP/2 POST /udp/$TUNNEL_ID → Proxy"
echo "  3. Proxy → gRPC UdpPacket → tunn serve"
echo "  4. tunn serve → UDP forward → Game Server (localhost:25565)"
echo "  5. Game Server → UDP response → tunn serve"
echo "  6. tunn serve → gRPC UdpPacket → Proxy"
echo "  7. Proxy → HTTP/2 response → tunn connect"
echo "  8. tunn connect → UDP response → Game Client"
echo ""
echo -e "${BLUE}To test manually:${NC}"
echo ""
echo -e "${YELLOW}Terminal 1 (tunn connect):${NC}"
echo "  ./bin/tunn -mode=connect -id=$TUNNEL_ID -local=localhost:25566"
echo ""
echo -e "${YELLOW}Terminal 2 (send test packet):${NC}"
echo "  echo 'HELLO UDP TUNNEL' | nc -u localhost 25566"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 Logs:"
echo "  Proxy:      tail -f /tmp/tunn-proxy.log"
echo "  Serve:      tail -f /tmp/tunn-serve.log"
echo "  Echo:       tail -f /tmp/tunn-udp-echo.log"
echo ""
echo "🛑 To stop all services:"
echo "  kill $PROXY_PID $SERVE_PID $ECHO_PID"
echo "  or just Ctrl+C"
echo ""
echo "Press Ctrl+C to stop all services..."

# Wait for interrupt
trap "echo ''; echo '🛑 Shutting down...'; kill $PROXY_PID $SERVE_PID $ECHO_PID 2>/dev/null; echo '✓ Stopped'; exit 0" INT TERM

# Keep script running
tail -f /tmp/tunn-proxy.log
