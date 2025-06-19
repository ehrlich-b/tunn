#!/bin/bash
set -e

# Create certificates directory if it doesn't exist
mkdir -p certs

echo "[+] Setting up wildcard Let's Encrypt certificate for *.tunn.to"

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
  echo "[ERROR] Certbot is not installed."
  echo "Run this command to install it:"
  echo "  sudo apt-get update && sudo apt-get install -y certbot"
  exit 1
fi

# Ask for email (for urgent renewal and security notices)
read -p "Enter your Gmail address: " EMAIL
if [[ ! "$EMAIL" == *"@gmail.com" ]]; then
  EMAIL="${EMAIL}@gmail.com"
fi

DOMAIN="tunn.to"

echo "[+] Running certbot with DNS challenge for *.${DOMAIN}..."
echo "[!] You will need to create TXT records in DNS."
echo "[!] Note: Wildcard certificates require DNS validation."

# Run certbot with manual DNS challenge
sudo certbot certonly --manual --preferred-challenges dns \
  --agree-tos --email "$EMAIL" -d "*.${DOMAIN}" -d "${DOMAIN}"

# Copy certificates to the certs directory
echo "[+] Copying certificates to certs directory..."
sudo cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem certs/
sudo cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem certs/
sudo chown $(whoami) certs/*.pem

# Set proper permissions
chmod 600 certs/*.pem

echo "[+] Certificate setup complete!"
echo "[+] Remember to rebuild your Docker image:"
echo "    docker build -t tunn:latest ."
