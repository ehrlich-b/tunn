#!/bin/bash
# Run all integration tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "========================================"
echo "  Running Integration Tests"
echo "========================================"
echo ""

FAILED=0

# Kill any leftover processes and wait for ports to be released
cleanup_ports() {
    pkill -9 -f "bin/tunn" 2>/dev/null || true
    pkill -9 -f "python3 -m http.server" 2>/dev/null || true
    sleep 2
}

run_test() {
    local name=$1
    local script=$2

    # Clean up before each test
    cleanup_ports

    echo -e "${YELLOW}Running: $name${NC}"
    if "$SCRIPT_DIR/$script"; then
        echo -e "${GREEN}PASSED: $name${NC}"
        echo ""
    else
        echo -e "${RED}FAILED: $name${NC}"
        echo ""
        FAILED=1
    fi
}

# Run tests in order of complexity
run_test "Smoke Test" "smoke-test.sh"
run_test "Device Login E2E" "device-login-test.sh"
run_test "Multi-Node gRPC" "multi-node-test.sh"
run_test "Auth Flow" "auth-flow-test.sh"

echo ""
echo "========================================"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}  All Integration Tests Passed${NC}"
else
    echo -e "${RED}  Some Integration Tests Failed${NC}"
fi
echo "========================================"
echo ""

exit $FAILED
