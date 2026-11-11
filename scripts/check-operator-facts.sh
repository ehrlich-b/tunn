#!/usr/bin/env bash
# Run locally with the intended service environment loaded; no provider calls.
set -eu
for name in TUNN_OPERATING_NAME TUNN_MERCHANT_DISPLAY_NAME TUNN_SUPPORT_WINDOW; do
  value=${!name-}
  if [[ -n ${value//[[:space:]]/} ]]; then
    printf '%s: supplied; Bryan must confirm against current records\n' "$name"
  else
    printf '%s: unavailable statement will render\n' "$name"
  fi
done
value=${TUNN_MCP_VERIFIED-}
if [[ -n ${value//[[:space:]]/} ]]; then
  printf 'TUNN_MCP_VERIFIED: supplied; Bryan must confirm clients and dates against end-to-end results\n'
else
  printf 'TUNN_MCP_VERIFIED: unset or blank; Experimental statement will render\n'
fi
printf 'Maintainer: Bryan Ehrlich\nReview, merge to main, and use the existing deployment procedure under Bryan.\n'
