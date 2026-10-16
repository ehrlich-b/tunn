#!/bin/sh
# Read-only deployment check. The operator must review before live use.
set -eu
umask 077

usage() { printf '%s\n' 'Usage: scripts/smoke-prod.sh https://RELAY_HOST[:PORT] [--http3]' >&2; exit 2; }
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
if [ "$#" -eq 2 ] && [ "$2" != '--http3' ]; then usage; fi
command -v curl >/dev/null 2>&1 || { printf '%s\n' 'curl is required' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'python3 is required for URL validation' >&2; exit 2; }
base=$(python3 - "$1" <<'PY'
import sys
from urllib.parse import urlsplit
try:
    value = sys.argv[1]
    url = urlsplit(value)
    if any(c.isspace() or ord(c) < 32 for c in value) or url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None or url.path not in ('', '/') or url.query or url.fragment or (url.port is not None and not 1 <= url.port <= 65535):
        raise ValueError()
    print('https://' + url.netloc)
except ValueError:
    print('Base URL must be an HTTPS origin without credentials, a path, query, or fragment', file=sys.stderr)
    sys.exit(2)
PY
) || exit 2

work=$(mktemp -d "${TMPDIR:-/tmp}/tunn-smoke.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM

check() {
  protocol=$1
  expected_version=$2
  method=$3
  path=$4
  if [ "$method" = HEAD ]; then
    result=$(curl --disable "$protocol" --silent --show-error --proto '=https' --connect-timeout 5 --max-time 15 --head --output "$work/body" --write-out '%{http_code} %{http_version}' "$base$path") || { printf '%s\n' "FAIL $method $path ($expected_version): TLS or transport error" >&2; exit 1; }
  else
    result=$(curl --disable "$protocol" --silent --show-error --proto '=https' --connect-timeout 5 --max-time 15 --request GET --output "$work/body" --write-out '%{http_code} %{http_version}' "$base$path") || { printf '%s\n' "FAIL $method $path ($expected_version): TLS or transport error" >&2; exit 1; }
  fi
  [ "$result" = "200 $expected_version" ] || { printf '%s\n' "FAIL $method $path: expected 200 HTTP/$expected_version, received $result" >&2; exit 1; }
  if [ "$path" = /health ] || [ "$path" = /readyz ]; then
    [ "$(cat "$work/body")" = ok ] || { printf '%s\n' "FAIL $path: unexpected health body" >&2; exit 1; }
  fi
  printf '%s\n' "PASS $method $path HTTP/$expected_version"
}

for version in 1.1 2; do
  if [ "$version" = 1.1 ]; then option=--http1.1; else option=--http2; fi
  check "$option" "$version" GET /health
  check "$option" "$version" GET /readyz
  check "$option" "$version" GET /
  check "$option" "$version" HEAD /install.sh
done
if [ "${2:-}" = --http3 ]; then
  check --http3-only 3 GET /health
  check --http3-only 3 GET /readyz
fi
