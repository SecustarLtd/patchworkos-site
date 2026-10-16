#!/usr/bin/env bash
set -Eeuo pipefail

# Patchwork OS VPS bootstrapper (Ubuntu/Debian)
#
# Domain + HTTPS:
#   DOMAIN=app.example.com LETSENCRYPT_EMAIL=admin@example.com bash deploy-vps.sh
#
# IP-only deployment:
#   bash deploy-vps.sh
#
# Optional overrides:
#   REPO_URL=https://github.com/SecustarLtd/patchworkos-site.git
#   APP_DIR=/opt/patchworkos
#   BRANCH=main

REPO_URL="${REPO_URL:-https://github.com/SecustarLtd/patchworkos-site.git}"
APP_DIR="${APP_DIR:-/opt/patchworkos}"
BRANCH="${BRANCH:-main}"
DOMAIN="${DOMAIN:-}"
LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-}"
NGINX_SITE="/etc/nginx/sites-available/patchworkos"

log() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
fail() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

if [[ "${EUID}" -ne 0 ]]; then
  fail "Run this script as root: sudo bash deploy-vps.sh"
fi

if ! command -v apt-get >/dev/null 2>&1; then
  fail "This script supports Ubuntu and Debian VPS hosts."
fi

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    fail "Docker Compose is not installed."
  fi
}

log "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl git nginx certbot python3-certbot-nginx docker.io openssl

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  apt-get install -y docker-compose-v2 2>/dev/null \
    || apt-get install -y docker-compose-plugin 2>/dev/null \
    || apt-get install -y docker-compose
fi

systemctl enable --now docker nginx

log "Installing or updating Patchwork OS"
if [[ -d "${APP_DIR}/.git" ]]; then
  git -C "${APP_DIR}" fetch origin "${BRANCH}"
  git -C "${APP_DIR}" checkout "${BRANCH}"
  git -C "${APP_DIR}" pull --ff-only origin "${BRANCH}"
elif [[ -e "${APP_DIR}" ]]; then
  fail "${APP_DIR} exists but is not a Git checkout. Move it or set APP_DIR to another path."
else
  git clone --branch "${BRANCH}" --single-branch "${REPO_URL}" "${APP_DIR}"
fi

cd "${APP_DIR}"
mkdir -p data/backups
chmod 750 data data/backups

# Migrate an older installation that kept SQLite beside server.js.
if [[ -f patchwork.db && ! -f data/patchwork.db ]]; then
  log "Migrating the existing SQLite database into the persistent data directory"
  cp -a patchwork.db data/patchwork.db
fi

if [[ -n "${DOMAIN}" ]]; then
  APP_URL="https://${DOMAIN}"
  SERVER_NAME="${DOMAIN}"
else
  PUBLIC_IP="$(curl -4fsS --max-time 10 https://api.ipify.org || true)"
  APP_URL="http://${PUBLIC_IP:-localhost}"
  SERVER_NAME="_"
fi

if [[ ! -f .env ]]; then
  log "Creating production environment file"
  umask 077
  JWT_SECRET="$(openssl rand -hex 64)"
  CREDENTIALS_SECRET_KEY="$(openssl rand -hex 32)"
  cat > .env <<EOF
NODE_ENV=production
PORT=3000
JWT_SECRET=${JWT_SECRET}
CREDENTIALS_SECRET_KEY=${CREDENTIALS_SECRET_KEY}
APP_BASE_URL=${APP_URL}

# Add billing credentials when ready.
PAYSTACK_SECRET_KEY=
PAYSTACK_PUBLIC_KEY=
PAYSTACK_GROWTH_PLAN_CODE=
PAYSTACK_ENTERPRISE_PLAN_CODE=
PAYSTACK_PROVISION_PLANS=false
EOF
  chmod 600 .env
else
  log "Keeping the existing ${APP_DIR}/.env"
fi

log "Building and starting the application"
compose up -d --build --remove-orphans

log "Waiting for the application health endpoint"
healthy=false
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:3000/api/health >/dev/null; then
    healthy=true
    break
  fi
  sleep 2
done

if [[ "${healthy}" != true ]]; then
  compose logs --tail=100 patchworkos
  fail "The application did not become healthy. Logs are shown above."
fi

log "Configuring Nginx"
cat > "${NGINX_SITE}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${SERVER_NAME};

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 60s;
    }
}
EOF

ln -sfn "${NGINX_SITE}" /etc/nginx/sites-enabled/patchworkos
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  log "Allowing SSH and web traffic through UFW"
  ufw allow OpenSSH
  ufw allow 'Nginx Full'
fi

if [[ -n "${DOMAIN}" && -n "${LETSENCRYPT_EMAIL}" ]]; then
  log "Requesting a Let's Encrypt certificate"
  certbot --nginx --non-interactive --agree-tos --redirect \
    --email "${LETSENCRYPT_EMAIL}" -d "${DOMAIN}"
elif [[ -n "${DOMAIN}" ]]; then
  printf '\nHTTPS skipped: rerun with LETSENCRYPT_EMAIL after DNS points to this VPS.\n'
fi

log "Deployment complete"
printf 'Application: %s\n' "${APP_URL}"
printf 'Directory:   %s\n' "${APP_DIR}"
printf 'Status:      cd %s && docker compose ps\n' "${APP_DIR}"
printf 'Logs:        cd %s && docker compose logs -f --tail=100\n' "${APP_DIR}"
