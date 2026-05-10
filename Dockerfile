# ─────────────────────────────────────────────────────────────────────────────
# German Cybersecurity MCP — multi-stage Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
# Build:  docker build -t german-cybersecurity-mcp .
# Run:    docker run --rm -p 3000:3000 german-cybersecurity-mcp
#
# The image bakes /app/data/bsi.db at build time. Override path with BSI_DB_PATH.
# ─────────────────────────────────────────────────────────────────────────────

# --- Stage 1: Build TypeScript and native bindings ---
FROM node:20-alpine AS builder

# python3, make, g++ required for better-sqlite3 native build
RUN apk add --no-cache python3 make g++ libc6-compat

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci && npm rebuild better-sqlite3

COPY tsconfig.json ./
COPY src/ src/
COPY scripts/ scripts/
RUN npm run build

# --- Stage 2: Production ---
FROM node:20-alpine AS production

# libstdc++ required at runtime for better-sqlite3 native binding on alpine
RUN apk add --no-cache libstdc++ libc6-compat

WORKDIR /app
ENV NODE_ENV=production
ENV BSI_DB_PATH=/app/data/bsi.db

# Copy node_modules with the rebuilt better-sqlite3 binding from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY package.json ./

# Bake DB. CI workflow provisions data/database.db from GitHub Release;
# repo path is data/bsi.db when building locally.
COPY data/database.db data/bsi.db

# Non-root user for security
RUN addgroup -S -g 1001 mcp && \
    adduser -S -u 1001 -G mcp mcp && \
    chown -R mcp:mcp /app
USER mcp

# Health check: verify HTTP server responds
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

CMD ["node", "dist/src/http-server.js"]
