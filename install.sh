#!/bin/sh
set -eu
INFO='[i]'
OK='[ok]'
if [ -t 1 ] && [ -z "${NO_COLOR+x}" ] && [ "${TERM:-dumb}" != dumb ]; then
    INFO=$(printf '\033[34m[i]\033[0m')
    OK=$(printf '\033[32m[ok]\033[0m')
fi
DOWNLOAD_BASE="${TUNN_DOWNLOAD_BASE:-https://tunn.to/dl}"
INSTALL_DIR="${TUNN_INSTALL_DIR:-$HOME/.local/bin}"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; esac
case "$OS" in linux|darwin) ;; *) echo "Unsupported OS: $OS" >&2; exit 1 ;; esac
BINARY="tunn-${OS}-${ARCH}"
WORK=$(mktemp -d)
INSTALL_TMP=""
cleanup() { rm -rf "$WORK"; if [ -n "$INSTALL_TMP" ]; then rm -f "$INSTALL_TMP"; fi; }
trap cleanup EXIT
fetch() {
    curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 --retry 2 --max-filesize 268435456 -o "$2" "$1" 2>/dev/null
}
download_release() {
    META="${DOWNLOAD_BASE%/}/latest.json"
    fetch "$META" "$WORK/meta" || return 1
    [ "$(wc -c < "$WORK/meta" | tr -d ' ')" -le 1048576 ] || return 1
    # The release feed supplies the tag. Only path-safe stable
    # tags are accepted; an installer never selects a preview or draft.
    TAG=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$WORK/meta" | head -1)
    printf '%s\n' "$TAG" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || return 1
    if grep -Eq '"(draft|prerelease)"[[:space:]]*:[[:space:]]*true' "$WORK/meta"; then return 1; fi
    ASSET_BASE="${DOWNLOAD_BASE%/}/${TAG}"
    fetch "$ASSET_BASE/$BINARY" "$WORK/binary" || return 1
    [ "$(wc -c < "$WORK/binary" | tr -d ' ')" -le 268435456 ] || return 1
    fetch "$ASSET_BASE/SHA256SUMS" "$WORK/sums" || return 1
    [ "$(wc -c < "$WORK/sums" | tr -d ' ')" -le 1048576 ] || return 1
    MATCHES=$(awk -v binary="$BINARY" '$2 == binary || $2 == "*" binary { print $1 }' "$WORK/sums")
    [ "$(printf '%s\n' "$MATCHES" | awk 'NF { n++ } END { print n+0 }')" -eq 1 ] || return 1
    EXPECTED=$MATCHES
    printf '%s\n' "$EXPECTED" | LC_ALL=C grep -Eq '^[0-9a-fA-F]{64}$' || return 1
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "$WORK/binary" | awk '{print $1}')
    else
        ACTUAL=$(shasum -a 256 "$WORK/binary" | awk '{print $1}')
    fi
    [ "$ACTUAL" = "$(printf '%s' "$EXPECTED" | tr '[:upper:]' '[:lower:]')" ] || return 1
    chmod 0755 "$WORK/binary"
    return 0

}
if ! download_release; then
    echo "Unable to download a verified tunn release; please try again later." >&2
    exit 1
fi
mkdir -p "$INSTALL_DIR" || {
    echo "error: cannot create ${INSTALL_DIR}; choose a writable TUNN_INSTALL_DIR (no automatic sudo)" >&2
    exit 1
}
INSTALL_TMP=$(mktemp "${INSTALL_DIR}/.tunn-install.XXXXXX") || {
    echo "error: cannot write ${INSTALL_DIR}; choose a writable TUNN_INSTALL_DIR (no automatic sudo)" >&2
    exit 1
}
cp "$WORK/binary" "$INSTALL_TMP"
chmod 0755 "$INSTALL_TMP"
mv "$INSTALL_TMP" "${INSTALL_DIR}/tunn"
INSTALL_TMP=""
COLS="${COLUMNS:-80}"
if [ "$COLS" -lt 50 ] 2>/dev/null; then
    printf '%s Verified tunn %s\n    for %s/%s\n' "$INFO" "$TAG" "$OS" "$ARCH"
else
    printf '%s Verified tunn %s (%s/%s)\n' "$INFO" "$TAG" "$OS" "$ARCH"
fi
printf '\n%s Installed tunn %s\n' "$OK" "$TAG"
case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) printf '\nAdd tunn to PATH\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" ;;
esac
printf '\nSign in\ntunn login\n\nRun your app on port 3000, then\ntunn 3000\n'
