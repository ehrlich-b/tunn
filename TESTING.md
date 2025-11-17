# tunn E2E Testing Guide

This guide covers local end-to-end testing for the tunn tunnel system.

## Quick Start: Local Testing (Recommended)

The simplest way to test the full flow locally without Docker.

### 1. Run the test script

```bash
./test-local.sh
```

This script will:
- Build the tunn binary
- Start a test web server on port 8000
- Start the tunn proxy in dev mode (with mock OIDC)
- Give you instructions for manual testing

### 2. Follow the on-screen instructions

The script will show you exactly what to run in separate terminals:

**Terminal 2: Login**
```bash
./bin/tunn -mode=login
```

Follow the device flow:
1. Copy the verification URL
2. Open in browser
3. Enter the user code
4. Login with mock OIDC (any email works)

**Terminal 3: Start tunnel**
```bash
./bin/tunn -mode=client -to localhost:8000 --allow test@example.com
```

Copy the tunnel URL that's printed (e.g., `https://abc123.tunn.local.127.0.0.1.nip.io`)

**Terminal 4: Visit in browser**
1. Paste the tunnel URL into your browser
2. You'll be redirected to login
3. Login with the SAME email you used in step 2
4. If your email is on the allow-list, you'll see the test page!

### 3. Watch the logs

In Terminal 1 (where test-local.sh is running), you'll see all the proxy logs showing:
- HTTP requests coming in
- Auth checks
- gRPC messages being sent/received
- Responses being proxied

## Docker Compose Testing (Isolated Environment)

For a more production-like environment using containers.

### Prerequisites

```bash
# Make sure Docker and Docker Compose are installed
docker --version
docker compose version
```

### 1. Build and start services

```bash
docker compose -f docker-compose.test.yml up --build
```

This starts:
- `proxy`: The tunn proxy server (dev mode with mock OIDC)
- `test-web`: A simple Python HTTP server serving test content

### 2. Login (on host machine)

```bash
# Build the binary first
make build

# Run login
./bin/tunn -mode=login
```

The login will connect to the mock OIDC server running in Docker (exposed on port 9000).

### 3. Start a tunnel (on host machine)

```bash
./bin/tunn -mode=client \
    -to http://localhost:8000 \
    --allow test@example.com
```

Note: This connects to the proxy in Docker (port 8443) but tunnels to a local web server.

### 4. Visit the tunnel URL

Open the tunnel URL in your browser and test the flow.

## Test Scenarios

### Scenario 1: Authorized Access ✅

1. Login as `alice@example.com`
2. Create tunnel with `--allow alice@example.com`
3. Visit tunnel → should see test page

### Scenario 2: Unauthorized Access ❌

1. Login as `alice@example.com`
2. Create tunnel with `--allow bob@example.com` (note: different email)
3. Visit tunnel → should see "Access Denied"

### Scenario 3: Multiple Allowed Emails ✅

1. Login as `alice@example.com`
2. Create tunnel with `--allow alice@example.com,bob@example.com`
3. Visit tunnel → should see test page
4. In incognito window, login as `bob@example.com`
5. Visit same tunnel → should also see test page

### Scenario 4: Creator Auto-Allowed ✅

1. Login as `alice@example.com`
2. Create tunnel with NO `--allow` flag
3. Visit tunnel as alice → should see test page (creator is auto-allowed)

## Architecture Being Tested

```
Browser
   ↓
   1. Visit https://abc123.tunn.local.127.0.0.1.nip.io
   ↓
Proxy (check session)
   ↓
   2. No session → redirect to /auth/login
   ↓
Google OAuth (mock OIDC in dev)
   ↓
   3. User logs in, session created with email
   ↓
Proxy (check allow-list)
   ↓
   4. Email on allow-list? → Continue
   ↓
Proxy sends HttpRequest via gRPC
   ↓
Client receives HttpRequest
   ↓
   5. Client makes HTTP request to localhost:8000
   ↓
Client sends HttpResponse via gRPC
   ↓
Proxy receives HttpResponse
   ↓
   6. Proxy forwards response to browser
   ↓
Browser displays page ✅
```

## What's Being Verified

- ✅ **gRPC Control Plane**: Tunnel registration, health checks
- ✅ **gRPC Data Plane**: HTTP request/response proxying
- ✅ **OAuth Flow**: Device flow (CLI) and browser flow
- ✅ **Session Management**: Cookie-based sessions across subdomains
- ✅ **Email Allow-Lists**: Per-tunnel access control
- ✅ **WELL_KNOWN_KEY**: Tunnel creation authorization
- ✅ **TLS**: HTTPS with self-signed certs (dev mode)
- ✅ **Wildcard DNS**: nip.io for subdomain routing
- ✅ **Mock OIDC**: Local OAuth simulation

## Troubleshooting

### "Failed to load JWT token"

You need to run `tunn login` first to get a JWT token.

### "Invalid tunnel key"

Make sure `WELL_KNOWN_KEY=tunn-free-v1-2025` is set in your environment, or pass `-tunnel-key=tunn-free-v1-2025` to the client.

### "Access Denied"

The email you logged in with is not on the tunnel's allow-list. Check:
1. What email did you use during login?
2. What emails are in the `--allow` flag?
3. Remember: creator email is auto-added to allow-list

### "Tunnel not found"

The tunnel client might not be running, or it disconnected. Check:
1. Is the client terminal still running?
2. Check proxy logs for connection status

### Certificate errors in browser

You're using self-signed certs in dev mode. Click "Advanced" → "Proceed to site" in your browser.

### DNS not resolving

Make sure you're using the full nip.io URL:
- ✅ `https://abc123.tunn.local.127.0.0.1.nip.io`
- ❌ `https://abc123.tunn.local`

## Cleanup

### Local testing

Just Ctrl+C in the terminal running `test-local.sh`, or:

```bash
pkill -f tunn
pkill -f "python.*http.server"
```

### Docker testing

```bash
docker compose -f docker-compose.test.yml down
```

## Next Steps

Once local E2E testing passes, you're ready for:

1. **Fly.io Deployment**: Deploy the proxy to production
2. **Real Google OAuth**: Replace mock OIDC with accounts.google.com
3. **Custom Domain**: Set up tunn.to DNS
4. **Rate Limiting**: Add per-IP bandwidth quotas
5. **Monitoring**: Add metrics and logging

## Success Criteria

E2E testing is successful when:

- ✅ You can login and get a JWT
- ✅ You can start a tunnel and see the public URL
- ✅ You can visit the tunnel URL in a browser
- ✅ You get redirected to login
- ✅ After login, you're redirected back to the tunnel
- ✅ If authorized, you see the proxied content
- ✅ If unauthorized, you see "Access Denied"
- ✅ The test page loads correctly with all assets
- ✅ Proxy logs show the full request/response flow
