FROM node:22-alpine AS base
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app

# Install dependencies
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/server/package.json packages/server/
COPY prisma/ prisma/
RUN pnpm install --frozen-lockfile || pnpm install

# Build
COPY packages/crypto/ packages/crypto/
COPY packages/server/ packages/server/
RUN pnpm --filter @clavum/crypto build
RUN pnpm --filter @clavum/server build

# Generate Prisma client
RUN pnpm --filter @clavum/server exec prisma generate

EXPOSE 3100
CMD ["node", "packages/server/dist/index.js"]
