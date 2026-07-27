import type { DacsDatabase } from "../substrate/sqlite/database.ts";
import { terminalErrorResponse } from "./terminal-server.ts";

const MAX_ROUTE_ID_LENGTH = 128;
const MAX_EMPTY_STREAM_CHUNKS = 16;
const MAX_CONTENT_LENGTH_HEADER_LENGTH = 32;

export interface HttpRateLimit {
  readonly requests: number;
  readonly windowMs: number;
}

export interface HttpResourceLimit {
  readonly bodyBytes: number;
  readonly concurrency: number;
  readonly rate: HttpRateLimit;
}

export interface HttpResourceGuardOptions {
  readonly database: DacsDatabase;
  readonly global: HttpResourceLimit;
  readonly routes: Readonly<Record<string, HttpResourceLimit>>;
  readonly now?: () => number;
  readonly onViolation?: (event: Readonly<{
    readonly route: string;
    readonly kind: "body" | "busy" | "rate";
  }>) => void;
}

export type GuardedHttpHandler = (
  request: Request,
  body: Uint8Array,
) => Response | Promise<Response>;

interface RateRequest {
  readonly scope: string;
  readonly limit: HttpRateLimit;
}

interface RateRow {
  readonly requestCount: bigint;
}

/** One shared guard instance is the concurrency and durable-rate authority for its server. */
export class HttpResourceGuards {
  readonly #consumeRate: (nowMs: number, requests: readonly RateRequest[]) => boolean;
  readonly #global: HttpResourceLimit;
  readonly #now: () => number;
  readonly #onViolation?: HttpResourceGuardOptions["onViolation"];
  readonly #routes: ReadonlyMap<string, HttpResourceLimit>;
  #globalActive = 0;
  readonly #routeActive = new Map<string, number>();

  constructor(
    private readonly database: DacsDatabase,
    options: Omit<HttpResourceGuardOptions, "database">,
  ) {
    this.#global = normalizeLimit("global", options.global);
    const routes = new Map<string, HttpResourceLimit>();
    for (const [route, limit] of Object.entries(options.routes)) {
      validateRouteId(route);
      routes.set(route, normalizeLimit(route, limit));
    }
    if (routes.size === 0) throw new TypeError("At least one guarded HTTP route is required");
    this.#routes = routes;
    this.#now = options.now ?? Date.now;
    this.#onViolation = options.onViolation;
    const consume = database.transaction((nowMs: number, requests: readonly RateRequest[]) =>
      this.#consumeRateTransaction(nowMs, requests));
    this.#consumeRate = (nowMs, requests) => consume.immediate(nowMs, requests) as boolean;
  }

  async run(route: string, request: Request, handler: GuardedHttpHandler): Promise<Response> {
    const limit = this.#routes.get(route);
    if (limit === undefined) throw new TypeError(`HTTP route ${route} has no resource policy`);

    const declaredLength = parseContentLength(request.headers.get("content-length"));
    if (declaredLength === null || (declaredLength !== undefined
      && (declaredLength > limit.bodyBytes || declaredLength > this.#global.bodyBytes))) {
      void request.body?.cancel().catch(() => undefined);
      this.#notify(route, "body");
      return terminalErrorResponse(413, "payload-too-large");
    }

    if (!this.#acquire(route, limit)) {
      void request.body?.cancel().catch(() => undefined);
      this.#notify(route, "busy");
      return terminalErrorResponse(503, "busy");
    }
    try {
      const nowMs = safeNow(this.#now);
      if (!this.#consumeRate(nowMs, [
        { scope: "global", limit: this.#global.rate },
        { scope: `route:${route}`, limit: limit.rate },
      ])) {
        void request.body?.cancel().catch(() => undefined);
        this.#notify(route, "rate");
        return terminalErrorResponse(429, "rate-limited");
      }
      const body = await collectBoundedRequestBody(
        request,
        Math.min(this.#global.bodyBytes, limit.bodyBytes),
      );
      if (body === null) {
        this.#notify(route, "body");
        return terminalErrorResponse(413, "payload-too-large");
      }
      if (declaredLength !== undefined && body.byteLength !== declaredLength) {
        this.#notify(route, "body");
        return terminalErrorResponse(400, "schema-violation");
      }
      return await handler(request, body);
    } finally {
      this.#release(route);
    }
  }

  #acquire(route: string, limit: HttpResourceLimit): boolean {
    const routeActive = this.#routeActive.get(route) ?? 0;
    if (this.#globalActive >= this.#global.concurrency
      || routeActive >= limit.concurrency) return false;
    this.#globalActive += 1;
    this.#routeActive.set(route, routeActive + 1);
    return true;
  }

  #release(route: string): void {
    this.#globalActive -= 1;
    const routeActive = (this.#routeActive.get(route) ?? 1) - 1;
    if (routeActive === 0) this.#routeActive.delete(route);
    else this.#routeActive.set(route, routeActive);
  }

  #consumeRateTransaction(nowMs: number, requests: readonly RateRequest[]): boolean {
    const windows = requests.map(({ scope, limit }) => ({
      scope,
      limit,
      windowStartMs: Math.floor(nowMs / limit.windowMs) * limit.windowMs,
    }));
    for (const window of windows) {
      const row = this.database.query<RateRow, {
        scope: string; windowMs: number; windowStartMs: number;
      }>(`
        SELECT request_count AS requestCount FROM http_rate_buckets
        WHERE scope = $scope AND window_ms = $windowMs AND window_start_ms = $windowStartMs
      `).get({
        scope: window.scope,
        windowMs: window.limit.windowMs,
        windowStartMs: window.windowStartMs,
      });
      if ((row?.requestCount ?? 0n) >= BigInt(window.limit.requests)) return false;
    }
    this.database.query<never, { nowMs: number }>(`
      /* atomic-write: http-rate.cleanup */
      DELETE FROM http_rate_buckets
      WHERE window_start_ms + window_ms <= $nowMs
    `).run({ nowMs });
    for (const window of windows) {
      this.database.query<never, {
        scope: string; windowMs: number; windowStartMs: number;
      }>(`
        /* atomic-write: http-rate.consume */
        INSERT INTO http_rate_buckets (scope, window_ms, window_start_ms, request_count)
        VALUES ($scope, $windowMs, $windowStartMs, 1)
        ON CONFLICT(scope, window_ms, window_start_ms)
        DO UPDATE SET request_count = request_count + 1
      `).run({
        scope: window.scope,
        windowMs: window.limit.windowMs,
        windowStartMs: window.windowStartMs,
      });
    }
    return true;
  }

  #notify(route: string, kind: "body" | "busy" | "rate"): void {
    try {
      this.#onViolation?.(Object.freeze({ route, kind }));
    } catch {
      // Diagnostics never decide request admission.
    }
  }
}

export interface BoundedArtifactResponseOptions {
  readonly source: ReadableStream<Uint8Array>;
  readonly declaredLength: number;
  readonly verifiedStoredLength: number;
  readonly maxBytes: number;
  readonly contentType?: string;
  readonly onMismatch?: (reason: string) => void;
}

/**
 * Start an immutable stream only after its persisted length is known and within policy. Runtime
 * byte counting then prevents a buggy source from emitting beyond that verified declaration.
 */
export function boundedArtifactResponse(options: BoundedArtifactResponseOptions): Response {
  const { declaredLength, verifiedStoredLength, maxBytes } = options;
  if (!validLength(declaredLength) || !validLength(verifiedStoredLength)
    || !validLength(maxBytes) || maxBytes === 0
    || declaredLength !== verifiedStoredLength || declaredLength > maxBytes) {
    void options.source.cancel().catch(() => undefined);
    safeMismatch(options.onMismatch, "artifact length is unverified or outside the route limit");
    return terminalErrorResponse(500, "schema-violation");
  }
  const reader = options.source.getReader();
  let emitted = 0;
  let emptyChunks = 0;
  let finished = false;
  const body = new ReadableStream<Uint8Array>({
    async pull(controller): Promise<void> {
      if (finished) return;
      for (;;) {
        let next: Awaited<ReturnType<typeof reader.read>>;
        try {
          next = await reader.read();
        } catch (error) {
          finished = true;
          safeMismatch(options.onMismatch, "artifact source failed before its declared length");
          controller.error(error);
          return;
        }
        if (next.done) {
          finished = true;
          reader.releaseLock();
          if (emitted !== declaredLength) {
            safeMismatch(options.onMismatch, "artifact source ended before its declared length");
            controller.error(new Error("Artifact stream length mismatch"));
          } else {
            controller.close();
          }
          return;
        }
        const value = next.value;
        if (!(value instanceof Uint8Array)) {
          finished = true;
          void reader.cancel().catch(() => undefined);
          safeMismatch(options.onMismatch, "artifact source emitted a non-byte chunk");
          controller.error(new Error("Artifact stream length mismatch"));
          return;
        }
        const remaining = Math.min(declaredLength, maxBytes) - emitted;
        const observedLength = value.byteLength;
        if (observedLength === 0) {
          emptyChunks += 1;
          if (emptyChunks <= MAX_EMPTY_STREAM_CHUNKS) continue;
          finished = true;
          void reader.cancel().catch(() => undefined);
          safeMismatch(options.onMismatch, "artifact source emitted too many empty chunks");
          controller.error(new Error("Artifact stream made no progress"));
          return;
        }
        if (observedLength > remaining) {
          finished = true;
          void reader.cancel().catch(() => undefined);
          safeMismatch(options.onMismatch, "artifact source exceeded its declared length");
          controller.error(new Error("Artifact stream length mismatch"));
          return;
        }
        // Allocate only the already-admitted length, and retain no source-owned view. The explicit
        // intrinsic subview avoids iterable hooks and fixes the copied length over resizable data.
        const snapshot = snapshotByteChunk(value, observedLength);
        emitted += snapshot.byteLength;
        controller.enqueue(snapshot);
        return;
      }
    },
    cancel(reason): Promise<void> {
      finished = true;
      return reader.cancel(reason).catch(() => undefined);
    },
  });
  return new Response(body, {
    status: 200,
    headers: {
      "cache-control": "no-store",
      "content-length": String(declaredLength),
      "content-type": options.contentType ?? "application/octet-stream",
      "x-content-type-options": "nosniff",
    },
  });
}

async function collectBoundedRequestBody(
  request: Request,
  maxBytes: number,
): Promise<Uint8Array | null> {
  if (request.body === null) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let emptyChunks = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        void reader.cancel().catch(() => undefined);
        return null;
      }
      const observedLength = value.byteLength;
      if (observedLength === 0) {
        emptyChunks += 1;
        if (emptyChunks <= MAX_EMPTY_STREAM_CHUNKS) continue;
        void reader.cancel().catch(() => undefined);
        return null;
      }
      if (observedLength > maxBytes - total) {
        void reader.cancel().catch(() => undefined);
        return null;
      }
      const snapshot = snapshotByteChunk(value, observedLength);
      total += snapshot.byteLength;
      chunks.push(snapshot);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // The over-limit cancel path may already detach the reader.
    }
  }
  return Buffer.concat(chunks, total);
}

function snapshotByteChunk(value: Uint8Array, length: number): Uint8Array {
  const snapshot = new Uint8Array(length);
  snapshot.set(Uint8Array.prototype.subarray.call(value, 0, length));
  return snapshot;
}

function normalizeLimit(name: string, value: HttpResourceLimit): HttpResourceLimit {
  if (value === undefined || !validLength(value.bodyBytes)
    || !Number.isSafeInteger(value.concurrency) || value.concurrency < 1
    || !Number.isSafeInteger(value.rate?.requests) || value.rate.requests < 1
    || !Number.isSafeInteger(value.rate?.windowMs) || value.rate.windowMs < 1) {
    throw new TypeError(`HTTP resource policy ${name} is invalid`);
  }
  return Object.freeze({
    bodyBytes: value.bodyBytes,
    concurrency: value.concurrency,
    rate: Object.freeze({ requests: value.rate.requests, windowMs: value.rate.windowMs }),
  });
}

function parseContentLength(value: string | null): number | undefined | null {
  if (value === null) return undefined;
  if (value.length > MAX_CONTENT_LENGTH_HEADER_LENGTH) return null;
  if (!/^(?:0|[1-9]\d*)$/.test(value)) return null;
  const length = Number(value);
  return validLength(length) ? length : null;
}

function validLength(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function validateRouteId(value: string): void {
  if (!/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/.test(value) || value.length > MAX_ROUTE_ID_LENGTH) {
    throw new TypeError(`HTTP route id ${value} is invalid`);
  }
}

function safeNow(now: () => number): number {
  const value = now();
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("Clock returned an invalid time");
  return value;
}

function safeMismatch(observer: ((reason: string) => void) | undefined, reason: string): void {
  try {
    observer?.(reason);
  } catch {
    // Diagnostics never decide stream containment.
  }
}
