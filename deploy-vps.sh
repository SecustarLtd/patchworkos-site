#!/usr/bin/env bash
set -Eeuo pipefail

# Patchwork OS VPS bootstrapper (Ubuntu/Debian).
# Keep this file in the project root and run it from there.
#
# Domain + HTTPS (patchworkos.com is the default domain):
#   LETSENCRYPT_EMAIL=admin@example.com bash deploy-vps.sh
#
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SCRIPT_DIR}"
DOMAIN="${DOMAIN:-patchworkos.com}"
# Accept either a hostname or a pasted URL such as https://patchworkos.com/.
DOMAIN="${DOMAIN#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"
LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-}"
PATCHWORK_HOST_PORT="${PATCHWORK_HOST_PORT:-3107}"
export PATCHWORK_HOST_PORT
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
apt-get install -y ca-certificates curl git nginx certbot python3-certbot-nginx openssl

if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker"
  if apt-cache show docker-ce >/dev/null 2>&1; then
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin \
      || apt-get install -y docker.io
  else
    apt-get install -y docker.io
  fi
fi

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  apt-get install -y docker-compose-plugin 2>/dev/null \
    || apt-get install -y docker-compose-v2 2>/dev/null \
    || apt-get install -y docker-compose 2>/dev/null \
    || true
fi

systemctl enable --now docker nginx

log "Deploying from project root: ${APP_DIR}"
cd "${APP_DIR}"
[[ -f docker-compose.yml ]] || fail "docker-compose.yml was not found in ${APP_DIR}. Keep deploy-vps.sh in the project root."
[[ -f server.js ]] || fail "server.js was not found in ${APP_DIR}. Keep deploy-vps.sh in the project root."
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
PAYSTACK_SUBACCOUNT_CODE=ACCT_c0ajy946qg0z5w1
PAYSTACK_PROVISION_PLANS=false
EOF
  chmod 600 .env
else
  log "Ensuring required variables exist in ${APP_DIR}/.env"
  if ! grep -q '^PAYSTACK_SUBACCOUNT_CODE=' .env; then
    echo "PAYSTACK_SUBACCOUNT_CODE=ACCT_c0ajy946qg0z5w1" >> .env
  fi
  if ! grep -qE '^JWT_SECRET=[a-zA-Z0-9]+' .env; then
    log "Generating missing or empty JWT_SECRET in .env"
    sed -i '/^JWT_SECRET=/d' .env
    echo "JWT_SECRET=$(openssl rand -hex 64)" >> .env
  fi
  if ! grep -qE '^CREDENTIALS_SECRET_KEY=[a-zA-Z0-9]+' .env; then
    log "Generating missing or empty CREDENTIALS_SECRET_KEY in .env"
    sed -i '/^CREDENTIALS_SECRET_KEY=/d' .env
    echo "CREDENTIALS_SECRET_KEY=$(openssl rand -hex 32)" >> .env
  fi
  if ! grep -q '^APP_BASE_URL=' .env; then
    echo "APP_BASE_URL=${APP_URL}" >> .env
  fi
  if ! grep -q '^PORT=' .env; then
    echo "PORT=3000" >> .env
  fi
  if ! grep -q '^NODE_ENV=' .env; then
    echo "NODE_ENV=production" >> .env
  fi
fi

log "Building and starting the application"
compose up -d --build --force-recreate

if [[ -s data/patchwork.db ]]; then
  if ! docker exec patchworkos test -s /app/data/patchwork.db 2>/dev/null; then
    docker cp data/patchwork.db patchworkos:/app/data/patchwork.db 2>/dev/null || true
    compose restart patchworkos 2>/dev/null || true
  fi
fi

log "Waiting for the application health endpoint"
healthy=false
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${PATCHWORK_HOST_PORT}/api/health" >/dev/null; then
    healthy=true
    break
  fi
  sleep 2
done

if [[ "${healthy}" != true ]]; then
  log "Container logs:"
  compose logs --tail=100 patchworkos
  log "Container status inspection:"
  docker inspect patchworkos --format='Status={{.State.Status}} ExitCode={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}} Error={{.State.Error}}' 2>/dev/null || true
  fail "The application did not become healthy. Logs and container state are shown above."
fi

log "Checking that the domain is not already owned by another Nginx site"
while IFS= read -r existing_site; do
  [[ "${existing_site}" == "${NGINX_SITE}" ]] && continue
  [[ "${existing_site}" == "/etc/nginx/sites-enabled/patchworkos" ]] && continue
  fail "${DOMAIN} is already referenced by ${existing_site}. Refusing to interfere with another site."
done < <(grep -Rsl --include='*' "server_name.*${DOMAIN}" /etc/nginx/sites-available /etc/nginx/conf.d 2>/dev/null || true)

log "Configuring an isolated Nginx site"
cat > "${NGINX_SITE}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${SERVER_NAME};

    client_max_body_size 50M;

    location / {
        proxy_pass http://127.0.0.1:${PATCHWORK_HOST_PORT};
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
