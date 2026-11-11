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
# Match Go strings.TrimSpace (Unicode White_Space), even with LC_ALL=C.
# UTF-8 byte escapes avoid locale-dependent Bash Unicode escape expansion.
for space in $'\xc2\x85' $'\xc2\xa0' $'\xe1\x9a\x80' \
  $'\xe2\x80\x80' $'\xe2\x80\x81' $'\xe2\x80\x82' $'\xe2\x80\x83' \
  $'\xe2\x80\x84' $'\xe2\x80\x85' $'\xe2\x80\x86' $'\xe2\x80\x87' \
  $'\xe2\x80\x88' $'\xe2\x80\x89' $'\xe2\x80\x8a' $'\xe2\x80\xa8' \
  $'\xe2\x80\xa9' $'\xe2\x80\xaf' $'\xe2\x81\x9f' $'\xe3\x80\x80'; do
  value=${value//"$space"/}
done
if [[ -n ${value//[$' \t\n\v\f\r']/} ]]; then
  printf 'TUNN_MCP_VERIFIED: supplied; Bryan must confirm clients and dates against end-to-end results\n'
else
  printf 'TUNN_MCP_VERIFIED: unset or blank; Experimental statement will render\n'
fi
printf 'Maintainer: Bryan Ehrlich\nReview, merge to main, and use the existing deployment procedure under Bryan.\n'
