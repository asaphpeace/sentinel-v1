#!/bin/bash
set -e

echo "=== Sentinel VPS Setup ==="

# ── Docker ────────────────────────────────────────────────────────────────────
echo "[1/6] Installing Docker..."
curl -fsSL https://get.docker.com | sh
usermod -aG docker "$USER"

# ── Caddy ─────────────────────────────────────────────────────────────────────
echo "[2/6] Installing Caddy..."
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | tee /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install -y caddy

# ── Clone repo ────────────────────────────────────────────────────────────────
echo "[3/6] Cloning repository..."
git clone https://github.com/asaphpeace/sentinel-v1.git /opt/sentinel
cd /opt/sentinel

# ── Environment file ──────────────────────────────────────────────────────────
echo "[4/6] Creating .env file..."
cp .env.example .env

echo ""
echo "================================================================"
echo "  ACTION REQUIRED: fill in your .env file before continuing."
echo "  Run:  nano /opt/sentinel/.env"
echo "  Then re-run this script with:  bash setup-vps.sh --continue"
echo "================================================================"
echo ""

if [[ "$1" != "--continue" ]]; then
    exit 0
fi

# ── Caddy config ──────────────────────────────────────────────────────────────
echo "[5/6] Configuring Caddy..."
cp /opt/sentinel/Caddyfile /etc/caddy/Caddyfile
systemctl enable caddy
systemctl reload caddy

# ── First deploy ──────────────────────────────────────────────────────────────
echo "[6/6] Building and starting containers..."
cd /opt/sentinel
docker compose up -d --build

echo ""
echo "=== Setup complete ==="
echo "App should be running at https://app.mailsentry.co.za"
echo "Check status with: docker compose ps"
echo "View logs with:    docker compose logs -f"
