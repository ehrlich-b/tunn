# Integration Test Framework

This document describes how to run end-to-end integration tests for tunn on a single machine. These tests are intentionally contrived (flags you'd never use in production, all processes on localhost) but prove correctness of the network protocols.

## Goals

1. **Device Login E2E** - Full device code flow: CLI → server → browser simulation → JWT
2. **Node-to-Node gRPC** - Two proxy nodes discovering tunnels across the mesh
3. **Full Tunnel Flow** - HTTP request → proxy → gRPC → client → local server → back

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Single Machine (localhost)                           │
│                                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                │
│  │  Proxy Node1 │────▶│  Proxy Node2 │     │  Test HTTP   │                │
│  │  :8443       │◀────│  :8444       │     │  Server :9999│                │
│  │  internal:50051    │  internal:50052    │               │                │
│  └───────┬──────┘     └───────┬──────┘     └───────▲──────┘                │
│          │                    │                     │                       │
│          │ gRPC tunnel        │                     │ HTTP                  │
│          ▼                    │                     │                       │
│  ┌──────────────┐            │              ┌──────┴──────┐                │
│  │  tunn client │────────────┘              │  curl/test  │                │
│  │  (tunnel     │                           │  client     │                │
│  │   creator)   │                           └─────────────┘                │
│  └──────────────┘                                                          │
│                                                                              │
│  ┌──────────────┐                                                           │
│  │  tunn login  │ ◀──── Browser simulation (curl to /api/device/*)         │
│  │  (CLI auth)  │                                                           │
│  └──────────────┘                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Test 1: Device Login End-to-End

Tests the full device code flow without a real browser.

### Components

1. **Proxy server** - Running with mock OIDC or GitHub OAuth disabled
2. **CLI login process** - `tunn login` waiting for auth
3. **Browser simulation** - curl commands simulating browser OAuth flow

### Flow

```
1. CLI: POST /api/device/code
   Response: { device_code: "xxx", user_code: "ABC-123", verification_uri_complete: "..." }

2. CLI: Starts polling GET /api/device/token?code=xxx (every 3s)
   Response: { error: "authorization_pending" }

3. Browser sim: GET /login?code=ABC-123
   - Server stores device_user_code in session
   - Redirects to /auth/login

4. Browser sim: Simulate OAuth callback
   - In dev mode with mock OIDC, we can call /auth/callback?code=mock&state=xxx
   - Server marks device code as authorized

5. CLI: GET /api/device/token?code=xxx
   Response: { access_token: "jwt...", token_type: "Bearer" }

6. CLI: Saves JWT to ~/.tunn/token
```

### Test Script

```bash
#!/bin/bash
set -e

PROXY_ADDR="localhost:8443"
TEST_EMAIL="test@example.com"

# Start proxy in background
ENV=dev PUBLIC_MODE=false JWT_SECRET=test-secret \
  ./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem &
PROXY_PID=$!
sleep 2

cleanup() {
  kill $PROXY_PID 2>/dev/null || true
}
trap cleanup EXIT

# Step 1: Request device code
DEVICE_RESP=$(curl -sk -X POST "https://$PROXY_ADDR/api/device/code")
DEVICE_CODE=$(echo "$DEVICE_RESP" | jq -r '.device_code')
USER_CODE=$(echo "$DEVICE_RESP" | jq -r '.user_code')

echo "Device code: $DEVICE_CODE"
echo "User code: $USER_CODE"

# Step 2: Verify polling returns authorization_pending
POLL_RESP=$(curl -sk "https://$PROXY_ADDR/api/device/token?code=$DEVICE_CODE")
if [[ $(echo "$POLL_RESP" | jq -r '.error') != "authorization_pending" ]]; then
  echo "FAIL: Expected authorization_pending"
  exit 1
fi

# Step 3: Simulate browser login flow
# First, get session cookie by visiting /login with device code
COOKIE_JAR=$(mktemp)
curl -sk -c "$COOKIE_JAR" "https://$PROXY_ADDR/login?code=$USER_CODE" -L

# Step 4: Simulate OAuth callback (mock OIDC returns test email)
# In dev mode, /auth/callback with mock OIDC sets the session
curl -sk -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  "https://$PROXY_ADDR/auth/callback?code=mock_auth_code&state=test" -L

# Step 5: Poll again - should get JWT now
POLL_RESP=$(curl -sk "https://$PROXY_ADDR/api/device/token?code=$DEVICE_CODE")
ACCESS_TOKEN=$(echo "$POLL_RESP" | jq -r '.access_token')

if [[ "$ACCESS_TOKEN" == "null" || -z "$ACCESS_TOKEN" ]]; then
  echo "FAIL: Did not receive access token"
  echo "Response: $POLL_RESP"
  exit 1
fi

echo "SUCCESS: Received JWT token"
echo "Token (first 50 chars): ${ACCESS_TOKEN:0:50}..."

rm -f "$COOKIE_JAR"
```

### Known Limitations

- Mock OIDC doesn't fully simulate GitHub OAuth
- State parameter validation may need to be mocked
- Session cookies require proper domain handling on localhost

### Using Mock OIDC for E2E

The codebase includes a mock OIDC server for dev mode. Integration tests use curl to simulate the browser flow through mock OIDC:

1. Start proxy with `ENV=dev` (enables mock OIDC on port 9000)
2. `POST /api/device/code` → get device_code and user_code
3. `GET /login?code=USER_CODE` with cookie jar → stores device code in session, redirects to mock OIDC
4. Follow redirects through mock OIDC → callback sets session and authorizes device code
5. `GET /api/device/token?code=DEVICE_CODE` → returns JWT

No special test endpoints needed - the mock OIDC server handles the OAuth simulation.

---

## Test 2: Node-to-Node gRPC Communication

Tests that two proxy nodes can discover tunnels across the mesh.

### Components

1. **Proxy Node 1** - Port 8443, internal gRPC on 50051
2. **Proxy Node 2** - Port 8444, internal gRPC on 50052
3. **Tunnel client** - Connected to Node 1
4. **Test HTTP server** - The tunnel target
5. **Test HTTP client** - Makes request via Node 2

### Configuration

Both nodes need to know about each other via `NODE_ADDRESSES`.

**Node 1:**
```bash
ENV=dev \
PUBLIC_MODE=true \
INTERNAL_GRPC_PORT=:50051 \
NODE_ADDRESSES=localhost:50052 \
PUBLIC_ADDR=localhost:8443 \
./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem
```

**Node 2:**
```bash
ENV=dev \
PUBLIC_MODE=true \
INTERNAL_GRPC_PORT=:50052 \
NODE_ADDRESSES=localhost:50051 \
PUBLIC_ADDR=localhost:8444 \
./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem \
  # Need to override ports somehow - may need code changes
```

### Problem: Single Binary Port Binding

Current code hardcodes `:8443` for HTTP. For multi-node on localhost, we need:
- `HTTP2_ADDR` environment variable or flag
- `HTTP3_ADDR` environment variable or flag

**Required Code Change:**
```go
// In proxy.go, make ports configurable:
HTTP2Addr: getEnvOrDefault("HTTP2_ADDR", ":8443"),
HTTP3Addr: getEnvOrDefault("HTTP3_ADDR", ":8443"),
```

### Flow

```
1. Start test HTTP server on :9999
   python -m http.server 9999

2. Start Node 1 on :8443, internal :50051
   NODE_ADDRESSES=localhost:50052

3. Start Node 2 on :8444, internal :50052
   NODE_ADDRESSES=localhost:50051

4. Connect tunnel client to Node 1
   SERVER_ADDR=localhost:8443 ./bin/tunn 9999 --id=testapp

5. Verify tunnel works via Node 1
   curl -k https://testapp.tunn.local.127.0.0.1.nip.io:8443/
   Expected: Response from python server

6. Verify tunnel works via Node 2 (cross-node discovery)
   curl -k https://testapp.tunn.local.127.0.0.1.nip.io:8444/
   Expected: Node 2 queries Node 1 via internal gRPC, proxies request

7. Kill Node 1, verify Node 2 returns 503 (tunnel not found)
```

### Test Script

```bash
#!/bin/bash
set -e

DOMAIN="tunn.local.127.0.0.1.nip.io"
NODE1_PORT=8443
NODE2_PORT=8444
NODE1_INTERNAL=50051
NODE2_INTERNAL=50052
TARGET_PORT=9999
TUNNEL_ID="integration-test"

cleanup() {
  echo "Cleaning up..."
  kill $NODE1_PID $NODE2_PID $TARGET_PID $CLIENT_PID 2>/dev/null || true
}
trap cleanup EXIT

# Start test HTTP server
echo "Starting test HTTP server on :$TARGET_PORT"
python3 -m http.server $TARGET_PORT &
TARGET_PID=$!
sleep 1

# Start Node 1
echo "Starting Node 1 on :$NODE1_PORT (internal :$NODE1_INTERNAL)"
ENV=dev PUBLIC_MODE=true \
  HTTP2_ADDR=:$NODE1_PORT \
  INTERNAL_GRPC_PORT=:$NODE1_INTERNAL \
  NODE_ADDRESSES=localhost:$NODE2_INTERNAL \
  PUBLIC_ADDR=localhost:$NODE1_PORT \
  DOMAIN=$DOMAIN \
  ./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem &
NODE1_PID=$!
sleep 2

# Start Node 2
echo "Starting Node 2 on :$NODE2_PORT (internal :$NODE2_INTERNAL)"
ENV=dev PUBLIC_MODE=true \
  HTTP2_ADDR=:$NODE2_PORT \
  INTERNAL_GRPC_PORT=:$NODE2_INTERNAL \
  NODE_ADDRESSES=localhost:$NODE1_INTERNAL \
  PUBLIC_ADDR=localhost:$NODE2_PORT \
  DOMAIN=$DOMAIN \
  ./bin/tunn -mode=host -cert=./certs/cert.pem -key=./certs/key.pem &
NODE2_PID=$!
sleep 2

# Connect tunnel client to Node 1
echo "Connecting tunnel client to Node 1"
ENV=dev SERVER_ADDR=localhost:$NODE1_PORT \
  ./bin/tunn $TARGET_PORT --id=$TUNNEL_ID --skip-tls-verify &
CLIENT_PID=$!
sleep 2

# Test 1: Access tunnel via Node 1 (direct)
echo "Test 1: Access tunnel via Node 1 (direct)"
RESP=$(curl -sk "https://$TUNNEL_ID.$DOMAIN:$NODE1_PORT/")
if [[ -z "$RESP" ]]; then
  echo "FAIL: No response from Node 1"
  exit 1
fi
echo "PASS: Node 1 direct access works"

# Test 2: Access tunnel via Node 2 (cross-node)
echo "Test 2: Access tunnel via Node 2 (cross-node discovery)"
RESP=$(curl -sk "https://$TUNNEL_ID.$DOMAIN:$NODE2_PORT/")
if [[ -z "$RESP" ]]; then
  echo "FAIL: No response from Node 2 (cross-node failed)"
  exit 1
fi
echo "PASS: Node 2 cross-node discovery works"

# Test 3: Kill Node 1, verify Node 2 returns error
echo "Test 3: Kill Node 1, verify tunnel unavailable via Node 2"
kill $NODE1_PID
sleep 2
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TUNNEL_ID.$DOMAIN:$NODE2_PORT/")
if [[ "$HTTP_CODE" != "503" ]]; then
  echo "FAIL: Expected 503, got $HTTP_CODE"
  exit 1
fi
echo "PASS: Node 2 correctly returns 503 when tunnel owner is down"

echo ""
echo "All integration tests passed!"
```

---

## Test 3: Full Tunnel Flow with Auth

Tests the complete flow: login → create tunnel → access with allow-list.

### Flow

```
1. Start proxy with auth enabled (PUBLIC_MODE=false)
2. Run device login flow (Test 1)
3. Create tunnel with allow-list
   tunn 9999 --allow test@example.com,@company.com
4. Access tunnel without auth → should redirect to /auth/login
5. Access tunnel with valid session → should work
6. Access tunnel with unauthorized email → should get 403
```

### Test Script

```bash
#!/bin/bash
set -e

# ... (combines Test 1 device login + tunnel creation + auth checks)

# After device login, create tunnel
./bin/tunn 9999 --id=authtest --allow test@example.com &
CLIENT_PID=$!
sleep 2

# Test without auth - should redirect
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://authtest.$DOMAIN:8443/")
if [[ "$HTTP_CODE" != "302" ]]; then
  echo "FAIL: Expected redirect (302), got $HTTP_CODE"
  exit 1
fi
echo "PASS: Unauthenticated request redirects to login"

# Test with valid session (reuse cookie jar from login)
HTTP_CODE=$(curl -sk -b "$COOKIE_JAR" -o /dev/null -w "%{http_code}" "https://authtest.$DOMAIN:8443/")
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "FAIL: Expected 200 with valid session, got $HTTP_CODE"
  exit 1
fi
echo "PASS: Authenticated request succeeds"

# Test domain wildcard
# Create tunnel with domain wildcard, login as user@company.com
# ... (similar flow)
```

---

## Required Code Changes

To support these integration tests on a single machine:

### 1. Configurable HTTP Ports (DONE)

**File:** `internal/config/config.go`

Added `HTTP2_ADDR` and `HTTP3_ADDR` environment variables with `:8443` default.

**File:** `internal/host/proxy.go`

Updated to use `cfg.HTTP2Addr` and `cfg.HTTP3Addr` from config.

### 2. Self-Signed Cert Generation Script

**File:** `scripts/gen-test-certs.sh`

```bash
#!/bin/bash
# Generate self-signed certs for localhost testing with wildcard SAN

DOMAIN="tunn.local.127.0.0.1.nip.io"
CERT_DIR="./certs"

mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$CERT_DIR/key.pem" \
  -out "$CERT_DIR/cert.pem" \
  -subj "/CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN,DNS:*.$DOMAIN,IP:127.0.0.1"

# Also create CA cert (same as server cert for simplicity)
cp "$CERT_DIR/cert.pem" "$CERT_DIR/ca.pem"

echo "Generated certs in $CERT_DIR"
```

---

## Running Tests

### Prerequisites

1. Build the binary: `make build`
2. Generate test certs: `./scripts/gen-test-certs.sh`
3. Install dependencies: `jq`, `curl`, `python3`

### Quick Smoke Test

```bash
make integration-test-smoke
# Runs: proxy + client + curl, PUBLIC_MODE=true
```

### Full Integration Test

```bash
make integration-test
# Runs: all tests including auth and multi-node
```

### CI Integration

Add to `.github/workflows/test.yml`:

```yaml
integration-test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v5
      with:
        go-version: '1.23'
    - run: make build
    - run: ./scripts/gen-test-certs.sh
    - run: make integration-test
```

---

## Test Matrix

| Test | Auth | Multi-Node | Validates |
|------|------|------------|-----------|
| Smoke | PUBLIC_MODE | Single | Basic tunnel flow |
| Device Login | Full | Single | CLI auth E2E |
| Multi-Node | PUBLIC_MODE | 2 nodes | gRPC mesh, tunnel discovery |
| Full Auth | Full | Single | Allow-list, domain wildcards |
| Full E2E | Full | 2 nodes | Everything |

---

## Debugging

### Verbose Logging

```bash
./bin/tunn -mode=host -verbosity=trace
```

### Check Internal gRPC

```bash
# Use grpcurl to query internal service
grpcurl -insecure localhost:50051 list
grpcurl -insecure localhost:50051 internalv1.InternalService/FindTunnel
```

### Network Issues

```bash
# Check what's listening
lsof -i :8443
lsof -i :50051

# Test internal connectivity
curl -k https://localhost:8443/health
```
