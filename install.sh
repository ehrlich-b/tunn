#!/bin/sh
# Usage: curl -fsSL https://tunn.to/install.sh | sh
set -e

retry() {
    printf '%s\n' '[x] Install failed' "$1" 'curl -fsSL https://tunn.to/install.sh | sh' >&2
    exit 1
}
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) printf '[x] Unsupported architecture %s\nInstall on amd64 or arm64.\n' "$ARCH" >&2; exit 1 ;;
esac
case "$OS" in
    darwin|linux) ;;
    *) printf '[x] Unsupported OS %s\nInstall on macOS or Linux.\n' "$OS" >&2; exit 1 ;;
esac
LATEST=$(curl -fsSL https://api.github.com/repos/ehrlich-b/tunn/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
[ -n "$LATEST" ] || retry 'Release unavailable. Check your network, then retry.'
BINARY="tunn-${OS}-${ARCH}"
URL="https://github.com/ehrlich-b/tunn/releases/download/${LATEST}/${BINARY}"
if [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR" || retry 'Cannot create the install directory.'
fi
printf '[i] Downloading tunn %s (%s/%s)\n' "$LATEST" "$OS" "$ARCH"
DOWNLOAD=$(mktemp "$INSTALL_DIR/.tunn.XXXXXX") || retry 'Cannot write to the install directory.'
trap 'rm -f "$DOWNLOAD"' EXIT HUP INT TERM
curl -fsSL "$URL" -o "$DOWNLOAD" || retry 'Download failed. Check your network, then retry.'
chmod 755 "$DOWNLOAD" || retry 'Cannot mark the download executable.'
mv -f "$DOWNLOAD" "$INSTALL_DIR/tunn" || retry 'Cannot install tunn. Check directory permissions.'
printf '\n[ok] Installed tunn %s\n' "$LATEST"
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) printf '\nAdd tunn to PATH\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" ;;
esac
printf '\nSign in\ntunn login\n\nRun your app on port 3000, then\ntunn http 3000\n'
