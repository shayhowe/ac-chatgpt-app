# ── Build stage ───────────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM node:22-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev

# Copy compiled JS
COPY --from=builder /app/dist ./dist

# Copy static assets (views, SQL schema) that are read at runtime
COPY --from=builder /app/src/views ./dist/views
COPY --from=builder /app/src/db/schema.sql ./dist/db/schema.sql

EXPOSE 3000

CMD ["node", "dist/index.js"]
