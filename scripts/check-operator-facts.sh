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
printf 'Maintainer: Bryan Ehrlich\nReview, merge to main, and use the existing deployment procedure under Bryan.\n'
