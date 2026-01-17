#!/bin/sh
# tunn installer
# Usage: curl -fsSL https://tunn.to/install.sh | sh

set -e

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    darwin|linux) ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Get latest release version
LATEST=$(curl -fsSL https://api.github.com/repos/ehrlich-b/tunn/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$LATEST" ]; then
    echo "Failed to get latest release version"
    exit 1
fi

BINARY="tunn-${OS}-${ARCH}"
URL="https://github.com/ehrlich-b/tunn/releases/download/${LATEST}/${BINARY}"

# Determine install location
if [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
elif [ -d "$HOME/.local/bin" ]; then
    INSTALL_DIR="$HOME/.local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

echo "Downloading tunn ${LATEST} for ${OS}/${ARCH}..."
curl -fsSL "$URL" -o "$INSTALL_DIR/tunn"
chmod +x "$INSTALL_DIR/tunn"

echo ""
echo "tunn installed to $INSTALL_DIR/tunn"

# Check if install dir is in PATH
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "Add $INSTALL_DIR to your PATH to use tunn" ;;
esac

echo ""
echo "Run 'tunn --help' to get started"
