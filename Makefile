# Makefile for tunn project

# Variables
APP_NAME := tunn
BINARY_NAME := tunn
BUILD_DIR ?= bin
BINARY_DIR ?= $(BUILD_DIR)
GO_TEST_FLAGS ?=
GO_BUILD_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64
GO_FILES := $(wildcard *.go)
DOCKER_IMAGE := $(APP_NAME):latest
FLY_APP_NAME := $(APP_NAME)
.DEFAULT_GOAL := all

.PHONY: test-tunnel-alerts
test-tunnel-alerts:
	go test $(GO_TEST_FLAGS) -race -p 2 -timeout=120s -v -run '^TestTunnelAlerts' ./internal/host ./internal/store

.PHONY: test-app-devices test-app-devices-browser
test-app-devices:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=180s -run '^TestAppDevice' ./internal/host ./sdk
test-app-devices-browser:
	go test $(GO_TEST_FLAGS) -race -count=1 -timeout=120s -run '^TestAppDeviceBrowserJourney$$' ./internal/host

.PHONY: test-ops-config test-ops-store test-ops-host test-ops-host-unit test-ops-logs test-ops-scripts test-ops-regression test-ops
test-ops-config:
	go test $(GO_TEST_FLAGS) -p 2 -parallel=2 -count=1 -timeout=60s ./internal/config
test-ops-store:
	go test $(GO_TEST_FLAGS) -p 2 -parallel=2 -count=1 -timeout=90s -run '^TestOps' ./internal/store
test-ops-host:
	go test $(GO_TEST_FLAGS) -p 2 -parallel=2 -count=1 -timeout=90s -run '^TestOps' ./internal/host
test-ops-host-unit:
	go test $(GO_TEST_FLAGS) -p 2 -parallel=2 -count=1 -timeout=90s -run '^TestOpsRelay' ./internal/host
test-ops-logs:
	go test $(GO_TEST_FLAGS) -p 2 -parallel=2 -count=1 -timeout=60s ./internal/common
test-ops-scripts:
	go test $(GO_TEST_FLAGS) -p 2 -parallel=2 -count=1 -timeout=60s -run '^TestOps' .
test-ops-regression:
	go test $(GO_TEST_FLAGS) -p 2 -parallel=2 -count=1 -timeout=180s ./internal/config ./internal/store ./internal/storage ./internal/common ./internal/metering
test-ops:
	$(MAKE) -j1 test-ops-regression test-ops-host test-ops-scripts

.PHONY: all build clean proto fmt tidy verify check vet lint test test-publisher-security test-verbose test-mcp test-websocket test-websocket-memory test-websocket-unit test-lifecycle-contract test-metering-contract test-domains-contract test-coverage test-race integration-test integration-test-smoke integration-test-ai integration-test-lifecycle integration-test-metering docker docker-build docker-run cert-setup cert-renew cert-install-schedule fly-create fly-init fly-secrets fly-certs fly-deploy fly-logs fly-status analytics-hour analytics-day analytics-live help test-install-recovery

# Default target
all: build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p "$(dir $(BUILD_OUTPUT))"
	go build -ldflags="-s -w" -o "$(BUILD_OUTPUT)" .

BUILD_OUTPUT ?= $(BINARY_DIR)/$(BINARY_NAME)

.PHONY: proto-internal test-account-operations
proto-internal:
	protoc --go_out=. --go-grpc_out=. --go_opt=module=github.com/ehrlich-b/tunn --go-grpc_opt=module=github.com/ehrlich-b/tunn proto/internal.proto

test-account-operations:
	go test -race -v -count=1 -parallel=2 -timeout=120s -run '^TestAccountOperations' ./internal/store ./internal/storage ./internal/metering ./internal/host .

# Supply the immutable domains commit to verify integration ancestry.
# A missing pin or unmerged domains head is a failed promotion gate.
.PHONY: test-account-operations-combined
test-account-operations-combined:
	@test -n "$$TUNN_DOMAINS_HEAD" || { echo "REQUIRED: set TUNN_DOMAINS_HEAD to the integrated domains commit"; exit 1; }
	@test "$$(git rev-parse --verify "$$TUNN_DOMAINS_HEAD^{commit}")" = "$$TUNN_DOMAINS_HEAD" || { echo "REQUIRED: provide the full immutable domains commit SHA"; exit 1; }
	git merge-base --is-ancestor "$$TUNN_DOMAINS_HEAD" HEAD
	go test -race -count=1 -parallel=2 -timeout=180s -run '^TestAccountOperationsCombinedLifecycle$$' ./internal/host
	$(MAKE) -j1 test-account-operations test-metering-contract

# Generate protobuf and gRPC code
proto:
	@echo "Generating protobuf code..."
	protoc --go_out=. --go-grpc_out=. proto/tunnel.proto
	protoc --go_out=. --go-grpc_out=. proto/internal.proto
	protoc --go_out=. --go-grpc_out=. --go_opt=module=github.com/ehrlich-b/tunn --go-grpc_opt=module=github.com/ehrlich-b/tunn proto/metering.proto
	protoc --go_out=. --go-grpc_out=. --go_opt=module=github.com/ehrlich-b/tunn --go-grpc_opt=module=github.com/ehrlich-b/tunn proto/domains.proto
	@mkdir -p pkg/proto/tunnelv1 pkg/proto/internalv1
	@if [ -d github.com ]; then \
		mv github.com/ehrlich-b/tunn/pkg/proto/tunnelv1/*.pb.go pkg/proto/tunnelv1/ 2>/dev/null || true; \
		mv github.com/ehrlich-b/tunn/pkg/proto/internalv1/*.pb.go pkg/proto/internalv1/ 2>/dev/null || true; \
		rm -rf github.com; \
	fi
	@echo "Protobuf code generated in pkg/proto/tunnelv1/ and pkg/proto/internalv1/"

# Format Go code
fmt:
	@echo "Formatting Go code..."
	go fmt ./...
	gofmt -w sdk/testdata/consumer/*.go sdk/testdata/response-consumer/*.go

# Tidy dependencies
tidy:
	@echo "Tidying Go modules..."
	go mod tidy

# Verify: format check and tests
verify: fmt test
	@echo "Verification complete!"

# Comprehensive check: format, tidy, test with race detection
check: test-deploy-guard fmt tidy test-race
	@echo "All checks passed!"

vet:
	go vet ./...

# Production dogfood regressions; the default proxy fixture requires loopback.
.PHONY: test-dogfood test-dogfood-memory
test-dogfood:
	go test $(GO_TEST_FLAGS) -race -count=1 -timeout=90s -run '^(TestDogfood|TestProxyEnvironment|TestProxyCONNECT|TestProxySOCKS|TestLoadConfig)' ./internal/client ./internal/host ./internal/store ./internal/relaytransport ./internal/config

# Same TLS/HTTP2/gRPC proxy flow over memory sockets; no skipped assertions.
test-dogfood-memory:
	go test $(GO_TEST_FLAGS) -race -count=1 -timeout=90s -run '^TestDogfood' ./internal/client -args -dogfood-proxy-memory
	go test $(GO_TEST_FLAGS) -race -count=1 -timeout=90s -run '^(TestDogfood|TestProxyEnvironment|TestProxyCONNECT|TestProxySOCKS|TestLoadConfig)' ./internal/host ./internal/store ./internal/relaytransport ./internal/config

# Explicitly rooted artifact/service/TLS/SQLite fixtures; never native activation.
test-install-recovery: build
	go test $(GO_TEST_FLAGS) -count=1 -timeout=90s -run '^(TestConfig|TestService.*|TestHostRuntimePrivateCredentialFixtures|TestHostRuntimeConfiguredCredentialRootSurvivesRestart|TestHostRuntimeTokensSurviveRestart)$$' ./internal/hostmode
	PYTHONDONTWRITEBYTECODE=1 TUNN_TEST_BINARY="$(abspath $(BINARY_DIR)/$(BINARY_NAME))" python3 -m unittest discover -s deploy/install -p 'test_*.py'

test-publisher-security:
	go test -run '^(TestLogin|TestGetTokenPath|TestSaveAndLoadToken|TestLoadTokenNotFound|TestSaveTokenCreatesDirectory|TestCookieAuthenticatedRequestDoesNotForwardPlatformCredentials|TestMalformedAuthorizationIsNotLogged|TestHandleWebProxy|TestPublicTunnelStripsTunnAuthorization|TestProxyHTTPOverGRPC|TestSaveAndLoadEndpointToken|TestRotateEndpointTokenReplacesFile|TestWatchEndpointTokenSendsDigestOnly)' ./internal/client ./internal/host

lint:
	golangci-lint run

# Build for different platforms
build-all: build-linux build-mac build-windows

build-linux:
	@echo "Building for Linux..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY_NAME)-linux .

build-mac:
	@echo "Building for macOS..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY_NAME)-mac .

build-windows:
	@echo "Building for Windows..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY_NAME).exe .

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME) $(BINARY_NAME)-linux $(BINARY_NAME)-mac $(BINARY_NAME).exe
	rm -rf ./bin

# Testing targets
.PHONY: test-hostmode test-hostmode-loopback test-hostmode-compile
test-hostmode:
	go test $(GO_TEST_FLAGS) -race -timeout=90s -run '^(TestConfig|TestService.*|TestBoundedLogs|TestReconnectBackoffBounds|TestHostStore.*|TestHostAPI.*|TestHostStream.*|TestHostModeGate.*|TestHostHealth.*|TestHostClient.*|TestHostCLI.*|TestHostRuntime.*|TestOpenClaw.*)$$' ./internal/hostmode ./internal/client ./internal/store ./internal/host .
	go test $(GO_TEST_FLAGS) -race -timeout=60s ./internal/store ./internal/config ./internal/common

# Real TLS/gRPC, private HTTP/MCP/TCP/Unix, readiness, reconnect and shutdown.
# Requires loopback and Unix sockets; never skips when listeners are denied.
test-hostmode-loopback:
	go test $(GO_TEST_FLAGS) -race -count=1 -timeout=90s -run '^TestLoopbackHostMode$$' ./internal/host

test-hostmode-compile:
	go test $(GO_TEST_FLAGS) -run '^$$' ./...

test:
	@echo "Running tests..."
	go test ./...

.PHONY: test-sso
test-sso:
	go test $(GO_TEST_FLAGS) -race -count=1 -timeout=240s -run '^Test(OrgOIDC|OIDC|OrgGroup|OrgLogin|OrgSSO|OrgDiscovery|Review|ReturnToBrowserNormalization|SanitizeReturnTo|Google|DomainSSO|DomainApp)' ./internal/host ./internal/config ./internal/metering .
.PHONY: test-distribution
test-distribution:
	go test $(GO_TEST_FLAGS) -count=1 -timeout=90s -run '^TestDistribution' . ./internal/host

test-verbose:
	@echo "Running tests with verbose output..."
	go test -v ./...

test-mcp:
	@echo "Running MCP bridge tests..."
	go test -v -timeout=20s ./internal/mcpbridge

# Full loopback TLS relay, publisher, WebSocket fixture, and frame regressions.
test-websocket:
	go test -race -v -count=1 -timeout=90s -run 'TestWebSocket|TestServeWebSocket|TestForwardedHTTP' . ./internal/common ./internal/client ./internal/host

test-websocket-unit:
	go test -race -count=1 -timeout=20s -run 'TestServeWebSocket|TestWebSocketFrames|TestWebSocketFrame|TestWebSocketFragmented|TestForwardedHTTP|TestProxyHTTPOverGRPC|TestHandleWebProxy|TestPublicTunnel|TestGetAuthFromTunnelBearer|TestAllowList|TestEmailBucket' . ./internal/common ./internal/host

WS_TESTS ?= TestWebSocket
test-websocket-memory:
	go test -race -v -count=1 -timeout=90s -run '$(WS_TESTS)' ./internal/host -args -websocket-memory

# In-process lifecycle regressions also run in sandboxes without loopback.
test-lifecycle-contract:
	go test -race -v -timeout=20s -run '^(TestNormalizeEmail|TestBridgeLifecycle)' ./internal/common ./internal/mcpbridge

# Memory TLS/gRPC lifecycle fixtures, plus a genuinely separate Go importer.
# No registry resolution: dependencies must already exist in the offline cache.
.PHONY: test-sdk-unit test-sdk-contract test-sdk-consumer test-http-fidelity
test-sdk-unit:
	GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test $(GO_TEST_FLAGS) -race -count=1 -timeout=45s ./sdk

test-sdk-consumer:
	mkdir -p .scratch/sdk-consumer
	cp sdk/testdata/consumer/*.go .scratch/sdk-consumer/
	printf 'module tunn-sdk-consumer\n\ngo 1.25.0\n\nrequire github.com/ehrlich-b/tunn v0.0.0\n\nreplace github.com/ehrlich-b/tunn => ../..\n' > .scratch/sdk-consumer/go.mod
	cp go.sum .scratch/sdk-consumer/go.sum
	cd .scratch/sdk-consumer && GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test $(GO_TEST_FLAGS) -mod=mod -race -count=1 -timeout=20s ./...
	GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test ./examples/sdk-handler ./examples/sdk-origin

# Memory HTTP semantics and explicit protobuf old/new compatibility fixtures.
test-http-fidelity:
	GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test $(GO_TEST_FLAGS) -race -count=1 -v -parallel=2 -timeout=60s -run '^TestHTTPFidelity' ./sdk ./internal/common ./internal/client ./internal/host ./pkg/proto/tunnelv1

# Acceptance includes the actual relay/auth/HTTP/WS loopback stack. Never
# skip or substitute the unit target when TCP listeners are unavailable.
test-sdk-contract: test-sdk-unit test-sdk-consumer
	GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -race -count=1 -v -parallel=2 -timeout=90s -run '^TestSDK' ./internal/host

.PHONY: run-sdk-handler run-sdk-origin
run-sdk-handler:
	go run ./examples/sdk-handler

run-sdk-origin:
	go run ./examples/sdk-origin

# Durable store, buffered/streamed relay fixtures, owner CLI and internal RPCs;
# these tests do not bind TCP/UDP sockets or call hosted services.
test-metering-contract:
	go test -race -v -timeout=60s ./internal/metering
	go test -race -v -timeout=60s ./internal/config
	go test -race -v -timeout=60s -run '^(TestMetering|TestMeterIdle|TestAccountPlan|TestAccountUsageView|TestBufferedResponseReserves|TestWebSocketFrames|TestWebSocketBoundary|TestTransportTCP|TestConnectReports|TestProxyHTTPOverGRPC|TestLegacyClientKeepsBufferedHTTPPath|TestTunnelConnectionLimitRejectsPendingStream|TestHandleWebProxy|TestPublicTunnelStripsTunnAuthorization|TestGetAuthFromTunnelBearer|TestCheckJWT|TestAllowListCheck|TestEmailBucketAllowListCheck)' . ./internal/host ./internal/client

# Fake DNS/ACME, memory TLS/gRPC, owner API/client and CLI parsing; no sockets.
test-domains-contract:
	go test -race -timeout=60s ./internal/domains
	go test -race -timeout=60s -run '^(TestDomain|TestParseDomain)' . ./internal/host ./internal/client

test-coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report saved to coverage.html"

test-race:
	@echo "Running tests with race detection..."
	go test -p 2 -race -timeout=1200s $(GO_TEST_FLAGS) ./...

# Offline production authorization matrix and lifecycle regressions.
# The serial SQLite-backed matrices need the full-suite budget under the race
# detector; keep every principal and route in the same required gate.
.PHONY: test-auth-contract
AUTH_TESTS ?= ^TestProdAuth(JWT|Route|Publisher|Endpoint|Grant|Email|MCPOAuth|OAuthState|Tunnel|InternalRPC)
test-auth-contract:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=600s -run '$(AUTH_TESTS)' ./internal/host

# Real loopback HTTPS; required even when a socket-restricted runner cannot run it.
.PHONY: test-auth-loopback
test-auth-loopback:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=60s -run '^TestProdAuthLoopback' ./internal/host

# Existing authorization regressions, memory RPC authorities and token utilities.
.PHONY: test-auth-regression
test-auth-regression:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=180s -run '^(TestCheckJWT|TestGetAuthFromTunnelBearer|TestGetJWTSigningKey|TestSecurity|TestMCPOAuth|TestMeteringOwnerAPI|TestMeteringInternal|TestDomainRPC|TestDomainAPI|TestHostAPI|TestHostStream|TestHostModeGate|TestTunnelServer|TestAccountOperationsAllIngress|TestAccountOperationsPublisher|TestAccountOperationsReplica|TestAuthMiddleware|TestExtractEmailFromJWT|TestNormalizeEmail)' ./internal/host ./internal/common

# Integration tests (require build + certs)
integration-test: build
	@echo "Running all integration tests..."
	@if [ ! -f "./certs/cert.pem" ]; then ./scripts/gen-test-certs.sh; fi
	./scripts/integration-tests/run-all.sh

integration-test-smoke: build
	@echo "Running smoke test..."
	@if [ ! -f "./certs/cert.pem" ]; then ./scripts/gen-test-certs.sh; fi
	./scripts/integration-tests/smoke-test.sh

integration-test-ai: build
	@echo "Running AI ingress end-to-end test..."
	@if [ ! -f "./certs/cert.pem" ]; then ./scripts/gen-test-certs.sh; fi
	./scripts/integration-tests/ai-ingress-test.sh

# Authenticated local MCP lifecycle; no DNS, browser, or hosted services needed.
integration-test-lifecycle: build
	@if [ ! -f "./certs/cert.pem" ]; then ./scripts/gen-test-certs.sh; fi
	python3 ./scripts/integration-tests/lifecycle-test.py

# Literal loopback addresses, local SQLite, and synthetic owner credentials only.
integration-test-metering: build
	@if [ ! -f "./certs/cert.pem" ]; then ./scripts/gen-test-certs.sh; fi
	python3 ./scripts/integration-tests/metering-test.py

# Docker targets
docker: docker-build

docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

docker-run:
	@echo "Running Docker container..."
	docker run --rm -p 443:443 $(DOCKER_IMAGE)

# Certificate management
cert-setup:
	@echo "Setting up SSL certificates..."
	./setup-certs.sh

cert-renew:
	@echo "Renewing SSL certificates..."
	./renew-certs.sh

cert-install-schedule:
	@mkdir -p "$(HOME)/Library/LaunchAgents" "$(HOME)/.config/tunn"
	@umask 077; python3 scripts/cert-renewal-plist.py --install
	@launchctl bootout "gui/$$(id -u)/com.ehrlich.tunn-cert-renewal" >/dev/null 2>&1 || true
	@launchctl bootstrap "gui/$$(id -u)" "$(HOME)/Library/LaunchAgents/com.ehrlich.tunn-cert-renewal.plist"
	@echo "Installed daily certificate renewal check."

.PHONY: test-cert-renewal-schedule
test-cert-renewal-schedule:
	python3 scripts/test_cert_renewal_schedule.py

# Create certs directory structure
certs-dir:
	@echo "Creating certificates directory..."
	mkdir -p certs

# Fly.io deployment
#
# First-time:
#   1. make fly-create    (create app, allocate IPs, volume)
#   2. make fly-secrets   (set all secrets + certs)
#   3. make fly-deploy    (deploy)
#
# Subsequent deploys: make fly-deploy
# Certificate renewal: make cert-renew (DNS, Fly secret update, restart, and
# live verification are handled as one operation).

fly-create:
	@echo "Creating Fly.io application..."
	fly apps create $(FLY_APP_NAME)
	fly ips allocate-v4 -a $(FLY_APP_NAME) -y
	fly ips allocate-v6 -a $(FLY_APP_NAME)
	fly volumes create tunn_data --size 1 --region iad -a $(FLY_APP_NAME) -y
	@echo ""
	@echo "App created! Now run: make fly-secrets"

fly-secrets:
	@echo "=== Setting Fly.io Secrets ==="
	@echo ""
	@# Check certs exist first (need sudo to access letsencrypt dir)
	@if ! sudo test -f "/etc/letsencrypt/live/tunn.to/fullchain.pem"; then \
		echo "ERROR: TLS certs not found. Run certbot first:"; \
		echo "  sudo certbot certonly --manual --preferred-challenges dns -d tunn.to -d '*.tunn.to'"; \
		exit 1; \
	fi
	@# Collect all inputs
	@read -p "GitHub Client ID: " gh_id && \
	read -p "GitHub Client Secret: " gh_secret && \
	read -p "Resend API Key: " resend_key && \
	JWT_SECRET=$$(openssl rand -hex 32) && \
	NODE_SECRET=$$(openssl rand -hex 32) && \
	echo "" && \
	echo "Generated JWT_SECRET: $$JWT_SECRET" && \
	echo ">>> SAVE THIS TO YOUR PASSWORD MANAGER <<<" && \
	echo "" && \
	echo "Uploading secrets..." && \
	sudo cat /etc/letsencrypt/live/tunn.to/fullchain.pem | base64 | tr -d '\n' > /tmp/cert.b64 && \
	sudo cat /etc/letsencrypt/live/tunn.to/privkey.pem | base64 | tr -d '\n' > /tmp/key.b64 && \
	fly secrets set \
		TUNN_JWT_SECRET="$$JWT_SECRET" \
		TUNN_NODE_SECRET="$$NODE_SECRET" \
		TUNN_GITHUB_CLIENT_ID="$$gh_id" \
		TUNN_GITHUB_CLIENT_SECRET="$$gh_secret" \
		TUNN_SMTP_USER="resend" \
		TUNN_SMTP_PASSWORD="$$resend_key" \
		TUNN_CERT_DATA="$$(cat /tmp/cert.b64)" \
		TUNN_KEY_DATA="$$(cat /tmp/key.b64)" \
		-a $(FLY_APP_NAME) && \
	rm -f /tmp/cert.b64 /tmp/key.b64
	@echo ""
	@echo "Secrets set! Now run: make fly-deploy"

fly-certs:
	@$(MAKE) cert-renew

fly-deploy: check-downloads
	@echo "Deploying to Fly.io..."
	fly deploy

fly-logs:
	fly logs -a $(FLY_APP_NAME)

fly-status:
	@fly status -a $(FLY_APP_NAME)
	@echo ""
	@echo "IPs (point DNS here):"
	@fly ips list -a $(FLY_APP_NAME)

# Run local server with .env
run: build
	@if [ ! -f .env ]; then echo "ERROR: .env not found. Copy .env.dist to .env and fill in values."; exit 1; fi
	@if [ ! -f "./certs/cert.pem" ]; then ./scripts/gen-test-certs.sh; fi
	@echo "Starting tunn server..."
	@set -a && source .env && set +a && ./bin/tunn -mode=host

# Run Stripe webhook listener for local dev
# Copy the whsec_... output to .env as TUNN_STRIPE_WEBHOOK_SECRET
stripe-listen:
	@if [ ! -f .env ]; then echo "ERROR: .env not found."; exit 1; fi
	@echo "Starting Stripe webhook listener..."
	@echo "Copy the webhook signing secret (whsec_...) to your .env file"
	@echo ""
	@set -a && source .env && set +a && \
		PORT=$${TUNN_HTTP2_ADDR:-$${TUNN_ADDR:-:8443}} && \
		PORT=$${PORT#:} && \
		stripe listen --forward-to https://localhost:$$PORT/webhooks/stripe --skip-verify

# Dev environment
dev:
	@echo "Running in development mode..."
	go run main.go -mode client

# Install local build to /usr/local/bin (requires sudo)
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp "$(BINARY_DIR)/$(BINARY_NAME)" /usr/local/bin/

# Analytics - count events from logs (bots vs humans separated)
analytics-hour:
	@echo "=== Last Hour ==="
	@printf "Homepage (human): " && fly logs -a tunn --no-tail | grep "homepage human" | tail -3600 | wc -l | tr -d ' '
	@printf "Homepage (bot):   " && fly logs -a tunn --no-tail | grep "homepage bot" | tail -3600 | wc -l | tr -d ' '
	@printf "Install script:   " && fly logs -a tunn --no-tail | grep "install script download" | tail -3600 | wc -l | tr -d ' '
	@printf "GitHub auths:     " && fly logs -a tunn --no-tail | grep "authenticated via GitHub" | tail -3600 | wc -l | tr -d ' '
	@printf "Tunnels created:  " && fly logs -a tunn --no-tail | grep "tunnel registered" | tail -3600 | wc -l | tr -d ' '

analytics-day:
	@echo "=== Last 24 Hours ==="
	@printf "Homepage (human): " && fly logs -a tunn --no-tail | grep "homepage human" | wc -l | tr -d ' '
	@printf "Homepage (bot):   " && fly logs -a tunn --no-tail | grep "homepage bot" | wc -l | tr -d ' '
	@printf "Install script:   " && fly logs -a tunn --no-tail | grep "install script download" | wc -l | tr -d ' '
	@printf "GitHub auths:     " && fly logs -a tunn --no-tail | grep "authenticated via GitHub" | wc -l | tr -d ' '
	@printf "Tunnels created:  " && fly logs -a tunn --no-tail | grep "tunnel registered" | wc -l | tr -d ' '

analytics-live:
	@fly logs -a tunn | grep -E "homepage human|homepage bot|install script|authenticated via|tunnel registered"

# Show unique IPs hitting the homepage (useful for spotting attacks)
analytics-ips:
	@echo "=== Unique IPs (last 24h) ==="
	@fly logs -a tunn --no-tail | grep -E "homepage (human|bot)" | sed 's/.*ip=//' | sed 's/ .*//' | sort | uniq -c | sort -rn | head -20

# Show help
help:
	@echo "Makefile for $(APP_NAME) - Available targets:"
	@echo ""
	@echo "Build & Code Generation:"
	@echo "  make build         - Build the binary for current OS"
	@echo "  make build-all     - Build for Linux, macOS, and Windows"
	@echo "  make proto         - Generate protobuf and gRPC code"
	@echo "  make clean         - Remove build artifacts"
	@echo ""
	@echo "Code Quality:"
	@echo "  make fmt           - Format Go code"
	@echo "  make tidy          - Tidy Go module dependencies"
	@echo "  make verify        - Format code and run tests"
	@echo "  make check         - Comprehensive check (fmt, tidy, test-race)"
	@echo ""
	@echo "Testing:"
	@echo "  make test               - Run unit tests"
	@echo "  make test-verbose       - Run tests with verbose output"
	@echo "  make test-coverage      - Run tests with coverage report"
	@echo "  make test-race          - Run tests with race detection"
	@echo "  make integration-test   - Run all integration tests"
	@echo "  make integration-test-smoke - Run smoke test only"
	@echo ""
	@echo "Docker:"
	@echo "  make docker        - Build Docker image"
	@echo "  make docker-run    - Run Docker container locally"
	@echo ""
	@echo "Fly.io Deployment (first-time, in order):"
	@echo "  make fly-create    - Create Fly app and allocate IPs"
	@echo "  make fly-init      - Generate and set JWT secret"
	@echo "  make fly-secrets   - Set GitHub and SMTP secrets (interactive)"
	@echo "  make fly-certs     - Renew and deploy TLS certificate (alias of cert-renew)"
	@echo "  make fly-deploy    - Deploy to Fly.io"
	@echo ""
	@echo "Fly.io Maintenance:"
	@echo "  make fly-logs      - Show Fly.io logs"
	@echo "  make fly-status    - Show app status and IPs"
	@echo ""
	@echo "Analytics:"
	@echo "  make analytics-hour - Event counts (last hour)"
	@echo "  make analytics-day  - Event counts (last 24h)"
	@echo "  make analytics-live - Live event stream"
	@echo ""
	@echo "Local Development:"
	@echo "  make run           - Run local server with .env"
	@echo "  make stripe-listen - Run Stripe webhook listener"
	@echo ""
	@echo "Other:"
	@echo "  make dev           - Run in development mode"
	@echo "  make install       - Install binary to /usr/local/bin"
	@echo "  make help          - Show this help message"

# Bounded, offline inspector fixtures: the default mode never binds a listener.
# Browser mode uses an installed Chrome with a disposable .scratch profile.
INSPECT_MODE ?= offline
.PHONY: test-inspect-contract test-inspect-offline test-inspect-loopback test-inspect-browser
ifeq ($(INSPECT_MODE),offline)
test-inspect-contract: test-inspect-offline
else ifeq ($(INSPECT_MODE),loopback)
test-inspect-contract: test-inspect-offline test-inspect-loopback
else ifeq ($(INSPECT_MODE),browser)
test-inspect-contract: test-inspect-offline test-inspect-browser
else
test-inspect-contract:
	@echo "INSPECT_MODE must be offline, loopback, or browser"; exit 1
endif

test-inspect-offline:
	go test -race -count=1 -timeout=30s -run '^TestInspectContract' ./internal/client ./internal/host
	go test -count=1 -timeout=20s -run '^TestParseServeFlagsInspect' .
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/integration-tests/inspect-syntax.py internal/client/inspector.html

test-inspect-loopback:
	go test -race -count=1 -timeout=30s -run '^TestInspector' ./internal/client

test-inspect-browser:
	go test -count=1 -timeout=20s -run '^TestInspectBrowserFixture$$' ./internal/client -args -inspect-browser-fixture="$(CURDIR)/.scratch/inspect-browser.html"
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/integration-tests/inspect-syntax.py internal/client/inspector.html .scratch/inspect-browser.html
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/integration-tests/inspect-browser.py .scratch/inspect-browser.html
# SSH API checks use only in-process or loopback clients.
.PHONY: test-ssh
test-ssh:
	go test -race -count=1 -timeout=90s ./internal/sshfront ./internal/cliopts
	go test -race -count=1 -timeout=90s -run 'TestSSH|TestParseServe|TestServeWebSocket' ./internal/host .

# Offline edge correctness: shared TCP/443, SSH commands, DNS/ACME/TLS and
# disposable install/renewal fixtures. Never invokes a live renewal tool.
.PHONY: test-edge-contract test-edge-renewal test-edge-openssh
test-edge-contract:
	$(MAKE) -j1 test-ssh test-domains-contract
	go test -race -count=1 -timeout=90s -run '^TestEdge|^TestIntegrationSSH' ./internal/host
	$(MAKE) -j1 test-install-recovery

test-edge-renewal:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/install -p 'test_edge_renewal.py'

# Native acceptance: real loopback TCP, OpenSSH, verified host key and TLS.
test-edge-openssh:
	go test -race -count=1 -timeout=45s -run '^TestLoopbackEdgeOpenSSHAndHTTPSSharePort$$' ./internal/host

# Fresh importer of an immutable committed SDK snapshot. No replace directive,
# workspace, registry download or network runtime is permitted in this gate.
.PHONY: test-sdk-response-consumer test-sdk-response-consumer-live
test-sdk-response-consumer:
	@set -eu; consumer_dir=$$(PYTHONDONTWRITEBYTECODE=1 python3 scripts/stage-sdk-response-consumer.py); \
	$(MAKE) -j1 -C "$$consumer_dir" test build verify-module; \
	printf '%s\n' "$$consumer_dir/response-consumer" > .scratch/sdk-response-consumer/binary-path

# Ordinary-host only: starts a disposable loopback relay and runs the external
# exported-API program. A missing binary or denied listener fails, never skips.
test-sdk-response-consumer-live: test-sdk-response-consumer
	TUNN_RESPONSE_CONSUMER_BINARY="$$(cat .scratch/sdk-response-consumer/binary-path)" GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test -race -count=1 -v -parallel=2 -timeout=45s -run '^TestSDKExternalResponseConsumer$$' ./internal/host

# Machine-readable evidence for the shared response matrix. Missing cells,
# skips, failed/race-unavailable tests and zero-test runs all fail this gate.
.PHONY: test-http-conformance
test-http-conformance: test-http-conformance-inventory
	@mkdir -p .scratch/http-conformance
	@run_dir=$$(mktemp -d .scratch/http-conformance/run.XXXXXX) || exit 1; events="$$run_dir/events.jsonl"; \
	GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go test $(GO_TEST_FLAGS) -json -race -count=1 -parallel=2 -timeout=60s -run '^TestHTTPFidelity' ./sdk ./internal/common ./internal/client ./internal/host ./pkg/proto/tunnelv1 > "$$events"; result=$$?; \
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/http-conformance-inventory.py --events "$$events" --test-exit "$$result"

.PHONY: test-http-conformance-inventory
test-http-conformance-inventory:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_http_conformance_inventory.py'

# The full ordinary-host suite can compile the same exported-only program from
# the checkout. The separate live importer gate supplies its immutable module
# binary explicitly and exercises that stronger import boundary.
.PHONY: build-sdk-response-consumer
build-sdk-response-consumer:
	@test -n "$(SDK_RESPONSE_CONSUMER_OUTPUT)" || { echo "REQUIRED: set SDK_RESPONSE_CONSUMER_OUTPUT to a scratch path"; exit 1; }
	GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go build -o "$(SDK_RESPONSE_CONSUMER_OUTPUT)" ./sdk/testdata/response-consumer

# Offline cross-feature fixtures. The SDK dial seam is test-only; public API
# transport acceptance stays with test-sdk-contract on an ordinary host.
.PHONY: test-candidate-cross
test-candidate-cross:
	go test $(GO_TEST_FLAGS) -tags=candidatefixture -json -race -count=1 -parallel=2 -timeout=90s -run '^TestCandidate' ./internal/host

.PHONY: format-candidate test-candidate-cli test-candidate-dogfix test-candidate-build-info
format-candidate:
	gofmt -w candidate_cli_test.go internal/host/candidate_integration_test.go sdk/candidate_fixture.go sdk/testdata/candidate-consumer/consumer_test.go
test-candidate-cli:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=60s -run '^TestCandidate' .
test-candidate-dogfix:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=60s -run '^TestDogfood' ./internal/client -args -dogfood-proxy-memory
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=60s -run '^TestDogfood' ./internal/host ./internal/store
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=60s ./internal/relaytransport ./internal/config
test-candidate-build-info:
	go version -m "$(BUILD_OUTPUT)"

.PHONY: test-candidate-consumer
test-candidate-consumer:
	@set -eu; consumer_dir=$$(PYTHONDONTWRITEBYTECODE=1 python3 scripts/candidate-stage-consumer.py); \
	$(MAKE) -j1 -C "$$consumer_dir" test GOFLAGS="$(GOFLAGS) -tags=candidatefixture"; \
	$(MAKE) -j1 -C "$$consumer_dir" verify-module; \
	printf '%s\n' "$$consumer_dir" > .scratch/sdk-response-consumer/second-consumer-path

# Baseline regression checks for account/billing, edge and startup. Config
# witnesses run in test-candidate-dogfix; auth runs in test-auth-contract.
.PHONY: test-candidate-baseline
test-candidate-baseline:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=120s -run '^(TestAccounts|TestBilling|TestReservations|TestMerge|TestAccountOperations)' ./internal/store ./internal/storage
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=120s ./internal/metering
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=120s -run '^(TestEdgeHostRouting|TestEdgeHTTP01|TestEdgeTLS|TestStripeSignature|TestStripeSignedPayload|TestStripeLifecycle|TestGitHubComplete|TestGitHubProvider|TestGitHubInvalid|TestMagicLinkComplete|TestMagicLinkRequestValidation|TestMagicLinkMailFailure|TestMagicLinkReplayAuthority|TestOpsRelayOfflineReadiness|TestOpsRelayReadinessRejects|TestOpsRelayHealth)' ./internal/host

# Memory-only regression gate for upload limits and concurrent response progress.
.PHONY: test-candidate-upload-contract
test-candidate-upload-contract:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=45s -run '^(TestHTTPFidelity(UploadTerminalSchedules|UploadFailureAbortsResponse|WireUploadEOFAbortsResponse|UnknownUploadLimitBeforeEmptyResponse|UploadLimitAfterPrefixAbortsResponse|ChunkedUploadProgressAfterPrefix)|TestProxyToLocalReturnsResponseErrors|TestDogfoodUpload)' ./internal/host

.PHONY: proto-tools test-webhook
# Pinned generators for reproducible protocol changes.
proto-tools:
	GOBIN=$(CURDIR)/../tools go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.10
	GOBIN=$(CURDIR)/../tools go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

test-webhook:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=180s -run '^TestWebhook' ./internal/webhook ./internal/client ./internal/host ./internal/cliopts .

# Owner IP policy checks use bounded fixtures and the authenticated authority.
.PHONY: proto-ip-policy test-ip-policy
proto-ip-policy:
	PATH="$(CURDIR)/.scratch/tools:$$PATH" protoc --go_out=. --go-grpc_out=. --go_opt=module=github.com/ehrlich-b/tunn --go-grpc_opt=module=github.com/ehrlich-b/tunn proto/metering.proto
test-ip-policy:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=120s -run '^TestIPPolicy' ./internal/ippolicy ./internal/metering ./internal/store ./internal/host ./internal/client .

# Same diagnostic client against TLS relay, OAuth ledger and real stdio child.
.PHONY: test-connector-journey
test-connector-journey:
	go test $(GO_TEST_FLAGS) -race -count=1 -v -parallel=2 -timeout=120s -run '^(TestConnector|TestMCPCommand|TestParseMCP|TestMCPOAuth|TestProdAuthMCP|TestProdAuthLoopback)' . ./internal/mcpcheck ./internal/host

# External probe history and operator-only incident notes.
.PHONY: test-status test-client-image client-image-local
test-status:
	go test $(GO_TEST_FLAGS) -race -p 2 -parallel=2 -count=1 -timeout=90s -run '^TestStatus' ./internal/status ./internal/host ./internal/config .
test-client-image:
	@test -n "$$TUNN_TEST_CLIENT_IMAGE" || { echo "REQUIRED: set TUNN_TEST_CLIENT_IMAGE to the locally built candidate image"; exit 1; }
	go test $(GO_TEST_FLAGS) -tags client_image -race -count=1 -timeout=60s -run '^TestStatusDockerClient' -v ./internal/host
client-image-local:
	@mkdir -p "$(BUILD_DIR)"
	docker buildx build --platform linux/amd64,linux/arm64 --file Dockerfile.client --output type=oci,dest=$(BUILD_DIR)/tunn-client.oci.tar .

# Node package, exported tarball consumer, and actual Go relay/auth/HTTP stack.
.PHONY: test-js-sdk test-js-sdk-contract
test-js-sdk:
	cd sdk/js && npm run check

test-js-sdk-contract: test-js-sdk
	TUNN_JS_SDK_CONSUMER="$(CURDIR)/sdk/js/test/go-relay-consumer.mjs" go test $(GO_TEST_FLAGS) -race -count=1 -v -parallel=2 -timeout=120s -run '^TestJavaScriptSDKRelay$$' ./internal/host

# Cross-feature policy ordering, raw webhook bodies and private authorization.
.PHONY: test-parity-policy
test-parity-policy:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=120s -run '^TestParity' ./internal/host

# Durable policy, owner API/CLI and authenticated relay forwarding regressions.
.PHONY: proto-policy test-policy
proto-policy:
	protoc --go_out=. --go-grpc_out=. --go_opt=module=github.com/ehrlich-b/tunn --go-grpc_opt=module=github.com/ehrlich-b/tunn proto/metering.proto

test-policy:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=90s ./internal/trafficpolicy ./internal/metering
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=120s -run '^(TestPolicy|TestProdAuthRoute|TestProdAuthInternalRPC|TestDomainAccountOwnerResourceRevocation|TestForwardedHTTP|TestMetering)' ./internal/host ./internal/client .

.PHONY: test-device-admission
test-device-admission:
	go test -race -count=1 -timeout=60s -run '^TestDeviceAdmission' ./internal/host

.PHONY: test-device-purpose
test-device-purpose:
	go test -race -count=1 -timeout=90s -run '^TestDevicePurpose' ./internal/host

# Owner-only, metadata-only web inspector and replay through normal ingress.
.PHONY: test-web-inspector test-web-inspector-browser
test-web-inspector:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=120s -run '^Test(WebInspector|InspectionHistory)' ./internal/inspection ./internal/client ./internal/host
	$(MAKE) -j1 test-inspect-offline
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/integration-tests/inspect-syntax.py internal/host/templates/inspector.html

test-web-inspector-browser:
	@test -n "$$TUNN_INSPECT_PLAYWRIGHT_MODULE" || { echo 'REQUIRED-UNRUN: set TUNN_INSPECT_PLAYWRIGHT_MODULE to installed Playwright'; exit 1; }
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=90s -run '^TestWebInspectorBrowserJourney$$' ./internal/host

# Python binding: the helper imports the same Go SDK as application consumers.
PYTHON ?= python3
PYTHON_HELPER_OUTPUT ?= $(BINARY_DIR)/tunn-python-bridge
.PHONY: build-python-helper test-python-unit test-python-contract python-wheel format-python-helper
build-python-helper:
	mkdir -p "$(dir $(PYTHON_HELPER_OUTPUT))"
	go build -o "$(PYTHON_HELPER_OUTPUT)" ./sdk/python/bridge
format-python-helper:
	gofmt -w sdk/python/bridge/*.go internal/host/python_sdk_test.go
test-python-unit: build-python-helper
	PYTHONPATH=sdk/python/src TUNN_PYTHON_HELPER="$(abspath $(PYTHON_HELPER_OUTPUT))" $(PYTHON) -m unittest discover -s sdk/python/tests -v
test-python-contract: build-python-helper
	PYTHONPATH="$(abspath sdk/python/src)" TUNN_PYTHON="$(PYTHON)" TUNN_PYTHON_HELPER="$(abspath $(PYTHON_HELPER_OUTPUT))" go test $(GO_TEST_FLAGS) -tags=pythonsdk -race -count=1 -v -parallel=2 -timeout=120s -run '^TestPythonSDK' ./internal/host
python-wheel: build-python-helper
	mkdir -p sdk/python/src/tunn/_bin
	cp "$(PYTHON_HELPER_OUTPUT)" sdk/python/src/tunn/_bin/tunn-python-bridge
	cd sdk/python && $(PYTHON) -m build --wheel

# Cross-feature signature, replay inputs and shared admission deadlines.
.PHONY: test-all-features
test-all-features:
	go test $(GO_TEST_FLAGS) -race -count=1 -parallel=2 -timeout=120s -run '^TestAll' ./internal/host
.PHONY: test-forwarded-permission
test-forwarded-permission:
	go test -race -v -count=1 -timeout=90s -run '^TestForwardedPermission' ./internal/host

.PHONY: test-stream-lifetime
test-stream-lifetime:
	go test -race -v -count=1 -parallel=2 -timeout=120s -run '^Test(ForwardedAdmission|PublisherStream)' ./internal/host
.PHONY: generate-installer
generate-installer:
	python3 scripts/generate-installer.py

# Build and install a checksummed release using only local fixture files.
.PHONY: test-installer-offline
test-installer-offline:
	nice -n 10 python3 scripts/integration-tests/installer-offline.py

.PHONY: check-downloads test-deploy-guard
check-downloads:
	nice -n 10 go run -p 2 ./cmd/check-downloads downloads

test-deploy-guard:
	nice -n 10 go test -p 2 ./internal/downloads ./cmd/check-downloads -run "Staged|DeployGuard" -count=1

# Loopback TLS/gRPC relay, publisher, delayed origin and paired latency samples.
.PHONY: test-request-timing
test-request-timing:
	go test $(GO_TEST_FLAGS) -p 2 -count=1 -v -timeout=2m -run '^TestRequestTiming' ./internal/inspection ./internal/client ./internal/host ./internal/terminal

.PHONY: test-account-tunnels-browser
test-account-tunnels-browser:
	go test $(GO_TEST_FLAGS) -p 2 -count=1 -timeout=120s -run '^TestAccountTunnelsBrowserJourney$$' ./internal/host

.PHONY: demo-mcp
demo-mcp:
	python3 scripts/demo/mcp-first-call.py

# Loopback-only relay comparison; keep binaries and results outside the checkout.
BENCH_ARGS ?= --work-dir $(CURDIR)/../relay-bench-work --output $(CURDIR)/../evidence
.PHONY: bench-relay
bench-relay:
	nice -n 10 python3 scripts/bench/relay-bench.py $(BENCH_ARGS)

.PHONY: test-mcp-clients
test-mcp-clients:
	python3 scripts/integration-tests/mcp-real-clients/run.py

.PHONY: demo-install-to-tool
demo-install-to-tool:
	python3 scripts/demo/install-to-tool.py

# Signed raw-body delivery and deliberate local inspector replay, without providers.
.PHONY: test-webhook-journey
test-webhook-journey:
	python3 scripts/integration-tests/webhook-journey.py

# Checkout-built installer, Free named previews and local checkout redirect.
.PHONY: test-install-to-offer
test-install-to-offer:
	nice -n 10 python3 scripts/integration-tests/install-to-offer.py
# Headless pricing-to-Pro checkout; local email delivery and payment evidence only.
.PHONY: test-pay-journey
test-pay-journey:
	nice -n 10 python3 scripts/integration-tests/pay-journey.py
