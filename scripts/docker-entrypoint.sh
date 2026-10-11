#!/bin/sh
set -eu
umask 077

cert_file=${TUNN_CERT_FILE:-/app/certs/fullchain.pem}
key_file=${TUNN_KEY_FILE:-/app/certs/privkey.pem}
cert_tmp=
key_tmp=
trap 'rm -f -- "$cert_tmp" "$key_tmp"' EXIT
trap 'exit 1' HUP INT TERM

fail() { printf '%s\n' "$1" >&2; exit 1; }

if [ -n "${TUNN_CERT_DATA:-}" ] || [ -n "${TUNN_KEY_DATA:-}" ]; then
  [ -n "${TUNN_CERT_DATA:-}" ] && [ -n "${TUNN_KEY_DATA:-}" ] || fail 'TUNN_CERT_DATA and TUNN_KEY_DATA must be configured together'
  [ "$cert_file" != "$key_file" ] || fail 'TUNN_CERT_FILE and TUNN_KEY_FILE must differ'
  mkdir -p -- "$(dirname -- "$cert_file")" "$(dirname -- "$key_file")"
  cert_tmp=$(mktemp "$cert_file.tmp.XXXXXX")
  key_tmp=$(mktemp "$key_file.tmp.XXXXXX")
  printf '%s' "$TUNN_CERT_DATA" | base64 -d > "$cert_tmp" || fail 'TUNN_CERT_DATA must contain valid base64'
  printf '%s' "$TUNN_KEY_DATA" | base64 -d > "$key_tmp" || fail 'TUNN_KEY_DATA must contain valid base64'
  [ -s "$cert_tmp" ] && [ -s "$key_tmp" ] || fail 'TUNN_CERT_DATA and TUNN_KEY_DATA must decode to nonempty files'
  mv -f -- "$cert_tmp" "$cert_file"
  mv -f -- "$key_tmp" "$key_file"
fi

[ -f "$cert_file" ] && [ -r "$cert_file" ] && [ -s "$cert_file" ] || fail 'TUNN_CERT_FILE must name a readable, nonempty certificate'
[ -f "$key_file" ] && [ -r "$key_file" ] && [ -s "$key_file" ] || fail 'TUNN_KEY_FILE must name a readable, nonempty private key'
export TUNN_CERT_FILE="$cert_file" TUNN_KEY_FILE="$key_file"
exec /app/tunn -mode=host "$@"
