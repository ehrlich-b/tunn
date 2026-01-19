# Makefile for tunn project

# Variables
APP_NAME := tunn
BINARY_NAME := tunn
GO_BUILD_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64
GO_FILES := $(wildcard *.go)
DOCKER_IMAGE := $(APP_NAME):latest
FLY_APP_NAME := $(APP_NAME)

.PHONY: all build clean proto fmt tidy verify check test test-verbose test-coverage test-race integration-test integration-test-smoke docker docker-build docker-run cert-setup cert-renew fly-create fly-init fly-secrets fly-certs fly-deploy fly-logs fly-status help

# Default target
all: build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	go build -ldflags="-s -w" -o ./bin/$(BINARY_NAME) .

# Generate protobuf and gRPC code
proto:
	@echo "Generating protobuf code..."
	protoc --go_out=. --go-grpc_out=. proto/tunnel.proto
	protoc --go_out=. --go-grpc_out=. proto/internal.proto
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

# Tidy dependencies
tidy:
	@echo "Tidying Go modules..."
	go mod tidy

# Verify: format check and tests
verify: fmt test
	@echo "Verification complete!"

# Comprehensive check: format, tidy, test with race detection
check: fmt tidy test-race
	@echo "All checks passed!"

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
test:
	@echo "Running tests..."
	go test ./...

test-verbose:
	@echo "Running tests with verbose output..."
	go test -v ./...

test-coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report saved to coverage.html"

test-race:
	@echo "Running tests with race detection..."
	go test -race ./...

# Integration tests (require build + certs)
integration-test: build
	@echo "Running all integration tests..."
	@if [ ! -f "./certs/cert.pem" ]; then ./scripts/gen-test-certs.sh; fi
	./scripts/integration-tests/run-all.sh

integration-test-smoke: build
	@echo "Running smoke test..."
	@if [ ! -f "./certs/cert.pem" ]; then ./scripts/gen-test-certs.sh; fi
	./scripts/integration-tests/smoke-test.sh

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
# Cert renewal (every 90 days): make fly-certs && make fly-deploy

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
	@echo "Updating TLS certs..."
	@if ! sudo test -f "/etc/letsencrypt/live/tunn.to/fullchain.pem"; then \
		echo "ERROR: Certs not found. Run: sudo certbot renew"; \
		exit 1; \
	fi
	@sudo cat /etc/letsencrypt/live/tunn.to/fullchain.pem | base64 | tr -d '\n' > /tmp/cert.b64
	@sudo cat /etc/letsencrypt/live/tunn.to/privkey.pem | base64 | tr -d '\n' > /tmp/key.b64
	fly secrets set \
		TUNN_CERT_DATA="$$(cat /tmp/cert.b64)" \
		TUNN_KEY_DATA="$$(cat /tmp/key.b64)" \
		-a $(FLY_APP_NAME)
	@rm -f /tmp/cert.b64 /tmp/key.b64
	@echo "Certs updated! Run: make fly-deploy"

fly-deploy:
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
	sudo cp $(BINARY_NAME) /usr/local/bin/

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
	@echo "  make fly-certs     - Set TLS certs from certbot"
	@echo "  make fly-deploy    - Deploy to Fly.io"
	@echo ""
	@echo "Fly.io Maintenance:"
	@echo "  make fly-logs      - Show Fly.io logs"
	@echo "  make fly-status    - Show app status and IPs"
	@echo ""
	@echo "Local Development:"
	@echo "  make run           - Run local server with .env"
	@echo "  make stripe-listen - Run Stripe webhook listener"
	@echo ""
	@echo "Other:"
	@echo "  make dev           - Run in development mode"
	@echo "  make install       - Install binary to /usr/local/bin"
	@echo "  make help          - Show this help message"
