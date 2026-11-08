# syntax=docker/dockerfile:1
# Multi-stage build of the VEIL server + web app.
# Reproducibility: exact dependency versions come from package-lock.json (npm ci).
# For bit-for-bit reproducible images, pin the base image by digest
# (docker buildx imagetools inspect node:22.23.2-bookworm-slim) and set SOURCE_DATE_EPOCH.

FROM node:22.23.2-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json .npmrc ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/shared/package.json packages/shared/
COPY packages/client/package.json packages/client/
COPY apps/server/package.json apps/server/
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build -w @veil/server && npm run build -w @veil/web

FROM node:22.23.2-bookworm-slim AS runtime
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787 \
    VEIL_DATA_DIR=/data \
    VEIL_WEB_DIST=/app/web
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/shared/package.json packages/shared/
COPY packages/client/package.json packages/client/
COPY apps/server/package.json apps/server/
COPY apps/web/package.json apps/web/
# Only the server's runtime externals (argon2 native binding, pg, pglite) are needed.
RUN npm ci --omit=dev --no-audit --no-fund --workspace @veil/server && npm cache clean --force
COPY --from=build /src/apps/server/dist/ /app/apps/server/dist/
COPY --from=build /src/apps/web/dist/ /app/web/
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:8787/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "apps/server/dist/main.js"]
