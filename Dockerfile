FROM node:22-bookworm-slim

WORKDIR /app

# Install native build tools required by better-sqlite3
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
# Compile native addons inside the target image instead of using a downloaded
# prebuild that may require CPU instructions unavailable on some VPS hosts.
RUN npm_config_build_from_source=true npm ci --omit=dev

COPY . .

EXPOSE 3000

ENV NODE_ENV=production
ENV PORT=3000

ENTRYPOINT []
CMD ["node", "server.js"]
