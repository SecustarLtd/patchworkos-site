#!/bin/bash
set -e

echo "=== Deploying Patchwork OS Update ==="

# Stash or preserve database if needed
echo "[1/4] Pulling latest changes from Git..."
git pull origin main

echo "[2/4] Installing dependencies..."
npm ci --only=production

echo "[3/4] Ensuring backups directory exists..."
mkdir -p backups

echo "[4/4] Reloading PM2 process..."
if command -v pm2 &> /dev/null; then
    pm2 reload ecosystem.config.cjs || pm2 start ecosystem.config.cjs
    echo "PM2 reload complete."
elif command -v docker &> /dev/null && [ -f "docker-compose.yml" ]; then
    docker compose up -d --build
    echo "Docker deployment complete."
fi

echo "=== Deployment Successfully Completed ==="
