#!/bin/bash

# --- Sanity Checks & Configuration ---
set -euo pipefail

# Define constant paths
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(dirname "$SCRIPT_DIR")"
readonly LETSENCRYPT_PATH="${ROOT_DIR}/silver-config/data/certbot/keys/etc/live/$(grep -m 1 '^domain:' "${ROOT_DIR}/../conf/silver.yaml" | sed 's/domain: //' | xargs)"
readonly THUNDER_CERTS_PATH="${ROOT_DIR}/silver-config/data/thunder/certs"

mkdir -p "${THUNDER_CERTS_PATH}"

cp "${LETSENCRYPT_PATH}/fullchain.pem" "${THUNDER_CERTS_PATH}/server.cert"
cp "${LETSENCRYPT_PATH}/privkey.pem" "${THUNDER_CERTS_PATH}/server.key"

# Set ownership to user ID 802 (thunder user in container)
sudo chown 802:802 ${THUNDER_CERTS_PATH}/server.key ${THUNDER_CERTS_PATH}/server.cert
chmod 600 ${THUNDER_CERTS_PATH}/server.key
chmod 644 ${THUNDER_CERTS_PATH}/server.cert

echo -e "Thunder certificates copied and permissions set"
