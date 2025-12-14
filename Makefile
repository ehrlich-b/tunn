# Makefile for tunn project

# Variables
APP_NAME := tunn
BINARY_NAME := tunn
GO_BUILD_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64
GO_FILES := $(wildcard *.go)
DOCKER_IMAGE := $(APP_NAME):latest
FLY_APP_NAME := $(APP_NAME)

.PHONY: all build clean proto fmt tidy verify check test test-verbose test-coverage test-race docker docker-build docker-run cert-setup cert-renew fly-setup fly-deploy fly-logs help

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
		mv github.com/behrlich/tunn/pkg/proto/tunnelv1/*.pb.go pkg/proto/tunnelv1/ 2>/dev/null || true; \
		mv github.com/behrlich/tunn/pkg/proto/internalv1/*.pb.go pkg/proto/internalv1/ 2>/dev/null || true; \
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
fly-setup:
	@echo "Setting up Fly.io application..."
	fly apps create $(FLY_APP_NAME) || true

fly-deploy:
	@echo "Deploying to Fly.io..."
	fly deploy --local-only

fly-logs:
	@echo "Showing Fly.io logs..."
	fly logs

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
	@echo "  make test          - Run all tests"
	@echo "  make test-verbose  - Run tests with verbose output"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make test-race     - Run tests with race detection"
	@echo ""
	@echo "Docker:"
	@echo "  make docker        - Build Docker image"
	@echo "  make docker-run    - Run Docker container locally"
	@echo ""
	@echo "Deployment:"
	@echo "  make cert-setup    - Set up SSL certificates"
	@echo "  make cert-renew    - Renew SSL certificates"
	@echo "  make fly-setup     - Set up Fly.io application"
	@echo "  make fly-deploy    - Deploy to Fly.io"
	@echo "  make fly-logs      - Show Fly.io logs"
	@echo ""
	@echo "Other:"
	@echo "  make dev           - Run in development mode"
	@echo "  make install       - Install binary to /usr/local/bin"
	@echo "  make help          - Show this help message"
