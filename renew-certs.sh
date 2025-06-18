#!/bin/bash
set -e

echo "[+] Renewing Let's Encrypt wildcard certificate for *.tunn.to..."

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
  echo "[ERROR] Certbot is not installed."
  echo "Run this command to install it:"
  echo "  sudo apt-get update && sudo apt-get install -y certbot"
  exit 1
fi

DOMAIN="tunn.to"

# Renew certificates
certbot renew

# Copy the certificates
mkdir -p certs
sudo cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem certs/
sudo cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem certs/
sudo chown $(whoami) certs/*.pem

# Set proper permissions
chmod 600 certs/*.pem

echo "[+] Certificate renewal complete!"
echo "[+] Remember to rebuild your Docker image:"
echo "    docker build -t tunn:latest ."
