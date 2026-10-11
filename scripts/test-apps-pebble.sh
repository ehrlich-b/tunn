#!/usr/bin/env bash
# Isolated local test CA and challenge responder; no deployment or DNS credentials.
set -euo pipefail
umask 022
cd "$(dirname "$0")/.."
fixture_dir=$(mktemp -d)
fixture_container="tunn-apps-pebble-$$"
cleanup() { docker rm -f "$fixture_container" >/dev/null 2>&1 || true; rm -rf "$fixture_dir"; }
trap cleanup EXIT
image=ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199
docker create --name "$fixture_container" "$image" >/dev/null
docker cp "$fixture_container:/test/config/pebble-config.json" "$fixture_dir/config.json"
docker cp "$fixture_container:/test/certs/pebble.minica.pem" "$fixture_dir/root.pem"
docker rm "$fixture_container" >/dev/null
python3 - "$fixture_dir/config.json" <<'PY'
import json,sys
path=sys.argv[1]
c=json.load(open(path));p=c['pebble']
p.update(listenAddress='127.0.0.1:24000',managementListenAddress='127.0.0.1:24001',httpPort=25002)
json.dump(c,open(path,'w'))
PY
# Host networking is local to this Linux acceptance environment. Test DNS resolves
# the app hostname to loopback only inside Pebble; no estate DNS is changed.
docker run -d --name "$fixture_container" --network host \
  -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
  -v "$fixture_dir/config.json:/test/config/apps.json:ro" "$image" \
  -config /test/config/apps.json -dnsserver 127.0.0.1:28053 >/dev/null
for attempt in $(seq 1 40); do
  if curl -fsS --cacert "$fixture_dir/root.pem" https://localhost:24000/dir >/dev/null 2>&1; then break; fi
  sleep 0.25
done
if ! TUNN_PEBBLE_DIRECTORY=https://localhost:24000/dir TUNN_PEBBLE_ROOT="$fixture_dir/root.pem" \
  GOTOOLCHAIN=${GOTOOLCHAIN:-auto} go test -count=1 -v -run '^TestPebbleWildcardHTTP01$' ./internal/domains; then
  docker logs "$fixture_container" >&2
  exit 1
fi
