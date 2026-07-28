FROM oven/bun:1.3.9-alpine@sha256:9028ee7a60a04777190f0c3129ce49c73384d3fc918f3e5c75f5af188e431981

WORKDIR /app

RUN apk upgrade --no-cache

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

COPY . .

RUN mkdir /runtime && chown bun:bun /runtime && chmod 0700 /runtime

USER bun

HEALTHCHECK --interval=2s --timeout=2s --start-period=30s --retries=15 \
  CMD ["bun", "run", "./scripts/container-fixture-runtime.ts", "health"]

ENTRYPOINT ["bun", "run", "./scripts/container-fixture-runtime.ts"]
CMD ["serve"]
