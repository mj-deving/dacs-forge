FROM oven/bun:1.3.9-slim

WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

COPY . .

RUN mkdir /runtime && chown bun:bun /runtime && chmod 0700 /runtime

USER bun

HEALTHCHECK --interval=2s --timeout=2s --start-period=30s --retries=15 \
  CMD ["bun", "run", "./scripts/container-fixture-runtime.ts", "health"]

ENTRYPOINT ["bun", "run", "./scripts/container-fixture-runtime.ts"]
CMD ["serve"]
