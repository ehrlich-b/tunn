#!/usr/bin/env bash
set -Eeuo pipefail

# Renew tunn.to with Certbot's Cloudflare DNS plugin, publish the certificate
# through Fly secrets, and verify the live endpoint. Secrets are read from the
# environment or macOS Keychain and are never stored in the repository.

DOMAIN="${TUNN_CERT_DOMAIN:-tunn.to}"
FLY_APP="${TUNN_FLY_APP:-tunn}"
CERT_EMAIL="${TUNN_CERT_EMAIL:-ehrlich.bryan@gmail.com}"
CERTBOT_ROOT="${TUNN_CERTBOT_ROOT:-${HOME}/.config/tunn/certbot}"
CERTBOT_CONFIG_DIR="${CERTBOT_ROOT}/config"
CERTBOT_WORK_DIR="${CERTBOT_ROOT}/work"
CERTBOT_LOGS_DIR="${CERTBOT_ROOT}/logs"
CLOUDFLARE_CREDENTIALS="${CERTBOT_ROOT}/cloudflare.ini"

for command_name in certbot curl flyctl jq openssl security; do
	if ! command -v "${command_name}" >/dev/null 2>&1; then
		echo "ERROR: required command not found: ${command_name}" >&2
		exit 1
	fi
done

load_cloudflare_token() {
	if [[ -n "${TUNN_CLOUDFLARE_API_TOKEN:-}" ]]; then
		printf '%s' "${TUNN_CLOUDFLARE_API_TOKEN}"
		return
	fi

	security find-generic-password \
		-a "${DOMAIN}" \
		-s tunn-cloudflare-dns-api-token \
		-w 2>/dev/null
}

load_fly_token() {
	if [[ -n "${FLY_API_TOKEN:-}" ]]; then
		printf '%s' "${FLY_API_TOKEN}"
		return
	fi

	local token
	token="$(security find-generic-password -a "${FLY_APP}" -s tunn-fly-api-token -w 2>/dev/null || true)"
	if [[ -n "${token}" ]]; then
		printf '%s' "${token}"
		return
	fi

	token="$(flyctl auth token 2>/dev/null || true)"
	if [[ -n "${token}" ]]; then
		printf '%s' "${token}"
		return
	fi

	# flyctl no longer consumes some legacy config files, but their tokens are
	# still valid. This fallback avoids printing the token or copying it.
	local legacy_config="${HOME}/.fly/config.yml"
	if [[ -f "${legacy_config}" ]]; then
		sed -n 's/^access_token: *//p' "${legacy_config}" | tr -d '"' | head -n 1
	fi
}

cleanup() {
	if [[ -f "${CLOUDFLARE_CREDENTIALS}" ]]; then
		rm -f -- "${CLOUDFLARE_CREDENTIALS}"
	fi
}
trap cleanup EXIT

umask 077
mkdir -p "${CERTBOT_CONFIG_DIR}" "${CERTBOT_WORK_DIR}" "${CERTBOT_LOGS_DIR}"
chmod 700 "${CERTBOT_ROOT}" "${CERTBOT_CONFIG_DIR}" "${CERTBOT_WORK_DIR}" "${CERTBOT_LOGS_DIR}"

CLOUDFLARE_TOKEN="$(load_cloudflare_token)"
if [[ -z "${CLOUDFLARE_TOKEN}" ]]; then
	echo "ERROR: Cloudflare token not found in TUNN_CLOUDFLARE_API_TOKEN or macOS Keychain" >&2
	exit 1
fi
printf 'dns_cloudflare_api_token = %s\n' "${CLOUDFLARE_TOKEN}" >"${CLOUDFLARE_CREDENTIALS}"
chmod 600 "${CLOUDFLARE_CREDENTIALS}"

CERTBOT_PATH_ARGS=(
	--config-dir "${CERTBOT_CONFIG_DIR}"
	--work-dir "${CERTBOT_WORK_DIR}"
	--logs-dir "${CERTBOT_LOGS_DIR}"
)
DNS_ARGS=(
	--dns-cloudflare
	--dns-cloudflare-credentials "${CLOUDFLARE_CREDENTIALS}"
	--dns-cloudflare-propagation-seconds 15
)

if [[ -d "${CERTBOT_CONFIG_DIR}/live/${DOMAIN}" ]]; then
	echo "Checking whether ${DOMAIN} is due for renewal..."
	certbot renew \
		--non-interactive \
		--cert-name "${DOMAIN}" \
		"${DNS_ARGS[@]}" \
		"${CERTBOT_PATH_ARGS[@]}"
else
	echo "Issuing the initial certificate for ${DOMAIN}..."
	certbot certonly \
		--non-interactive \
		--agree-tos \
		--no-eff-email \
		--email "${CERT_EMAIL}" \
		--cert-name "${DOMAIN}" \
		-d "${DOMAIN}" \
		-d "*.${DOMAIN}" \
		"${DNS_ARGS[@]}" \
		"${CERTBOT_PATH_ARGS[@]}"
fi

LINEAGE="${CERTBOT_CONFIG_DIR}/live/${DOMAIN}"
CERT_PATH="${LINEAGE}/fullchain.pem"
KEY_PATH="${LINEAGE}/privkey.pem"

if ! openssl x509 -in "${CERT_PATH}" -noout -checkend 2592000 >/dev/null; then
	echo "ERROR: resulting certificate expires within 30 days" >&2
	exit 1
fi

CERT_PUBLIC_KEY="$(openssl x509 -in "${CERT_PATH}" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | shasum -a 256 | awk '{print $1}')"
KEY_PUBLIC_KEY="$(openssl pkey -in "${KEY_PATH}" -pubout -outform DER 2>/dev/null | shasum -a 256 | awk '{print $1}')"
if [[ "${CERT_PUBLIC_KEY}" != "${KEY_PUBLIC_KEY}" ]]; then
	echo "ERROR: certificate and private key do not match" >&2
	exit 1
fi

LOCAL_SERIAL="$(openssl x509 -in "${CERT_PATH}" -noout -serial | cut -d= -f2)"
LIVE_SERIAL="$(openssl s_client -connect "${DOMAIN}:443" -servername "${DOMAIN}" </dev/null 2>/dev/null | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2 || true)"
if [[ -n "${LIVE_SERIAL}" && "${LOCAL_SERIAL}" == "${LIVE_SERIAL}" ]]; then
	echo "Live certificate is already current; no Fly restart needed."
	exit 0
fi

TUNN_FLY_TOKEN="$(load_fly_token)"
if [[ -z "${TUNN_FLY_TOKEN}" ]]; then
	echo "ERROR: Fly token not found in FLY_API_TOKEN, macOS Keychain, or flyctl config" >&2
	exit 1
fi

CERT_DATA="$(base64 <"${CERT_PATH}" | tr -d '\n')"
KEY_DATA="$(base64 <"${KEY_PATH}" | tr -d '\n')"

echo "Publishing renewed certificate to Fly app ${FLY_APP}..."
printf 'TUNN_CERT_DATA=%s\nTUNN_KEY_DATA=%s\nTUNN_CLOUDFLARE_API_TOKEN=%s\n' \
	"${CERT_DATA}" "${KEY_DATA}" "${CLOUDFLARE_TOKEN}" | \
	FLY_API_TOKEN="${TUNN_FLY_TOKEN}" flyctl secrets import -a "${FLY_APP}"

for attempt in {1..15}; do
	LIVE_SERIAL="$(openssl s_client -connect "${DOMAIN}:443" -servername "${DOMAIN}" </dev/null 2>/dev/null | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2 || true)"
	if [[ "${LOCAL_SERIAL}" == "${LIVE_SERIAL}" ]] && curl --fail --silent --show-error --max-time 10 -o /dev/null "https://${DOMAIN}/"; then
		openssl x509 -in "${CERT_PATH}" -noout -subject -issuer -dates
		echo "Certificate deployed and ${DOMAIN} is healthy."
		exit 0
	fi
	sleep 2
done

echo "ERROR: Fly updated, but the expected certificate did not become healthy" >&2
exit 1
