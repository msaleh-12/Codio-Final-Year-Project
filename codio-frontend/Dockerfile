### Builder

FROM node:20-slim AS builder
WORKDIR /app

# Reduce telemetry and increase memory for build
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_OPTIONS=--max-old-space-size=4096
ENV npm_config_fund=false
ENV npm_config_audit=false
ENV npm_config_loglevel=verbose

# Copy dependency manifests
COPY package.json package-lock.json* pnpm-lock.yaml* ./

# Install build dependencies and install node modules
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates python3 build-essential make g++ \
	&& rm -rf /var/lib/apt/lists/*

RUN npm install --no-package-lock --legacy-peer-deps

# Copy source and build
COPY . .
RUN npm run build

### Production image
FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Copy built assets and package manifest
COPY --from=builder /app/.next .next
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json

# Install production dependencies
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	&& npm install --omit=dev --legacy-peer-deps

EXPOSE 3000
CMD ["npm", "start"]
