# Makefile for tunn project

# Variables
APP_NAME := tunn
BINARY_NAME := tunn
GO_BUILD_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64
GO_FILES := $(wildcard *.go)
DOCKER_IMAGE := $(APP_NAME):latest
FLY_APP_NAME := $(APP_NAME)

.PHONY: all build clean docker docker-build docker-run cert-setup cert-renew fly-setup fly-deploy fly-logs help

# Default target
all: build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	go build -ldflags="-s -w" -o $(BINARY_NAME) .

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
	fly deploy

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
	@echo "  make build         - Build the binary for current OS"
	@echo "  make build-all     - Build for Linux, macOS, and Windows"
	@echo "  make clean         - Remove build artifacts"
	@echo "  make docker        - Build Docker image"
	@echo "  make docker-run    - Run Docker container locally"
	@echo "  make cert-setup    - Set up SSL certificates"
	@echo "  make cert-renew    - Renew SSL certificates"
	@echo "  make fly-setup     - Set up Fly.io application"
	@echo "  make fly-deploy    - Deploy to Fly.io"
	@echo "  make fly-logs      - Show Fly.io logs"
	@echo "  make dev           - Run in development mode"
	@echo "  make install       - Install binary to /usr/local/bin"
	@echo "  make help          - Show this help message"
