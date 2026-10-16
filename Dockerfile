FROM node:20-bookworm-slim

WORKDIR /app

# Install native build tools required by better-sqlite3
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000

ENV NODE_ENV=production
ENV PORT=3000

ENTRYPOINT []
CMD ["node", "server.js"]
