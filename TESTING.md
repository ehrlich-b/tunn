# Testing Guide

## Quick Start: Local Testing

```bash
./test-local.sh
```

This script:
- Builds the binary
- Starts a test web server on port 8000
- Starts the proxy in dev mode (mock OIDC)
- Prints instructions for manual testing

## Manual Testing

### Terminal 1: Start the proxy

```bash
ENV=dev ./bin/tunn -mode=host
```

### Terminal 2: Login

```bash
./bin/tunn login
```

Follow the device flow - open the URL in browser, log in with mock OIDC.

### Terminal 3: Start tunnel

```bash
./bin/tunn 8080 --allow test@example.com
```

Copy the tunnel URL that's printed.

### Terminal 4: Test in browser

1. Open the tunnel URL
2. You'll be redirected to login
3. Log in with the SAME email from step 2
4. If your email is on the allow-list, you'll see the page

## Test Scenarios

### Authorized Access

1. Login as `alice@example.com`
2. Create tunnel: `tunn 8080 --allow alice@example.com`
3. Visit tunnel -> should see page

### Unauthorized Access

1. Login as `alice@example.com`
2. Create tunnel: `tunn 8080 --allow bob@example.com`
3. Visit tunnel -> should see "Access Denied"

### Domain Wildcard

1. Login as `alice@company.com`
2. Create tunnel: `tunn 8080 --allow @company.com`
3. Visit tunnel -> should see page

### Creator Auto-Allowed

1. Login as `alice@example.com`
2. Create tunnel: `tunn 8080` (no --allow flag)
3. Visit tunnel -> should see page (creator is always allowed)

## Docker Testing

```bash
docker compose -f docker-compose.test.yml up --build
```

Starts proxy and test web server in containers.

## Integration Tests

```bash
# All integration tests
./scripts/integration-tests/run-all.sh

# Individual tests
./scripts/integration-tests/smoke-test.sh
./scripts/integration-tests/device-login-test.sh
./scripts/integration-tests/auth-flow-test.sh
```

## Troubleshooting

### "not logged in"

Run `tunn login` first to get a JWT token.

### "Invalid tunnel key"

Set `WELL_KNOWN_KEY=tunn-free-v1-2025` or pass `--tunnel-key=tunn-free-v1-2025`.

### "Access Denied"

The email you logged in with is not on the tunnel's allow-list.

### Certificate errors

Dev mode uses self-signed certs. Click "Advanced" -> "Proceed" in browser.

### DNS not resolving

Use the full nip.io URL: `https://abc123.tunn.local.127.0.0.1.nip.io:8443`
