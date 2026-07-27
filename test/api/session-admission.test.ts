import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  HttpResourceGuards,
  boundedArtifactResponse,
  type HttpResourceLimit,
} from "../../src/http/resource-guards.ts";
import { validateTerminalBody } from "../../src/http/terminal-server.ts";
import { openDatabase } from "../../src/substrate/sqlite/database.ts";

const directories: string[] = [];
const LIMIT: HttpResourceLimit = Object.freeze({
  bodyBytes: 16,
  concurrency: 1,
  rate: Object.freeze({ requests: 2, windowMs: 1_000 }),
});

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("HTTP admission resource guards", () => {
  test("migrates an existing schema v21 database to durable rate buckets", async () => {
    const { database, path } = await testDatabase();
    database.run("DROP TABLE http_rate_buckets");
    database.run("PRAGMA user_version = 21");
    database.close();

    const migrated = openDatabase(path);
    expect(migrated.query<{ user_version: bigint }, []>(
      "PRAGMA user_version",
    ).get()?.user_version).toBe(22n);
    expect(migrated.query<{ count: bigint }, []>(`
      SELECT count(*) AS count FROM sqlite_schema
      WHERE type = 'table' AND name = 'http_rate_buckets'
    `).get()?.count).toBe(1n);
    migrated.close();
  });

  test("rejects declared and streamed body overflow before protected work", async () => {
    const { database } = await testDatabase();
    let now = 1_000;
    const guards = new HttpResourceGuards(database, {
      global: LIMIT,
      routes: { protected: LIMIT },
      now: () => now,
    });
    let invocations = 0;
    const protectedWork = (): Response => {
      invocations += 1;
      return okResponse();
    };

    const declared = await guards.run("protected", new Request("http://127.0.0.1/protected", {
      method: "POST",
      headers: { "content-length": "17" },
      body: "x",
    }), protectedWork);
    expect(declared.status).toBe(413);
    expect(invocations).toBe(0);

    let preflightCancellations = 0;
    const rejectedBody = new ReadableStream<Uint8Array>({
      cancel() {
        preflightCancellations += 1;
      },
    });
    const malformedHeader = await guards.run("protected", new Request(
      "http://127.0.0.1/protected",
      {
        method: "POST",
        headers: { "content-length": "9".repeat(33) },
        body: rejectedBody,
      },
    ), protectedWork);
    expect(malformedHeader.status).toBe(413);
    expect(preflightCancellations).toBe(1);
    expect(invocations).toBe(0);

    const streamed = await guards.run("protected", new Request("http://127.0.0.1/protected", {
      method: "POST",
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(10));
          controller.enqueue(new Uint8Array(7));
          controller.close();
        },
      }),
    }), protectedWork);
    expect(streamed.status).toBe(413);
    expect(invocations).toBe(0);

    const nonProgressing = await guards.run("protected", new Request(
      "http://127.0.0.1/protected",
      { method: "POST", body: byteStream(Array.from({ length: 17 }, () => new Uint8Array())) },
    ), protectedWork);
    expect(nonProgressing.status).toBe(413);
    expect(invocations).toBe(0);

    now = 2_000;
    const invalidChunks = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(undefined as unknown as Uint8Array);
      },
    });
    const invalid = await guards.run("protected", new Request(
      "http://127.0.0.1/protected",
      { method: "POST", body: invalidChunks },
    ), protectedWork);
    expect(invalid.status).toBe(413);
    expect(invocations).toBe(0);
    database.close();
  });

  test("rejects declared versus actual request length mismatch before protected work", async () => {
    const { database } = await testDatabase();
    const guards = new HttpResourceGuards(database, {
      global: LIMIT,
      routes: { protected: LIMIT },
      now: () => 1_000,
    });
    let invocations = 0;
    const response = await guards.run("protected", new Request(
      "http://127.0.0.1/protected",
      { method: "POST", headers: { "content-length": "2" }, body: "x" },
    ), () => {
      invocations += 1;
      return okResponse();
    });
    expect(response.status).toBe(400);
    expect(invocations).toBe(0);
    database.close();
  });

  test("snapshots admitted request chunks before their backing buffer can grow", async () => {
    const { database } = await testDatabase();
    const guards = new HttpResourceGuards(database, {
      global: LIMIT,
      routes: { protected: LIMIT },
      now: () => 1_000,
    });
    const buffer = new ArrayBuffer(1, { maxByteLength: 4 });
    const view = new Uint8Array(buffer);
    view[0] = 9;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(view);
        setTimeout(() => {
          buffer.resize(4);
          controller.close();
        }, 0);
      },
    });
    const response = await guards.run("protected", new Request(
      "http://127.0.0.1/protected",
      { method: "POST", body },
    ), (_request, admitted) => new Response(JSON.stringify([...admitted])));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual([9]);
    database.close();
  });

  test("enforces global concurrency and durable route rate before the handler", async () => {
    const { database, path } = await testDatabase();
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const guards = new HttpResourceGuards(database, {
      global: LIMIT,
      routes: { protected: LIMIT },
      now: () => 2_000,
    });
    const first = guards.run("protected", post("a"), async () => {
      await blocked;
      return okResponse();
    });
    await Promise.resolve();
    let busyCancellations = 0;
    const concurrent = await guards.run("protected", requestWithCancellation(
      () => { busyCancellations += 1; },
    ), () => okResponse());
    expect(concurrent.status).toBe(503);
    expect(busyCancellations).toBe(1);
    expect(await errorCode(concurrent)).toBe("busy");
    release();
    expect((await first).status).toBe(418);

    expect((await guards.run("protected", post("c"), () => okResponse())).status).toBe(418);
    let rateCancellations = 0;
    expect((await guards.run("protected", requestWithCancellation(
      () => { rateCancellations += 1; },
    ), () => okResponse())).status).toBe(429);
    expect(rateCancellations).toBe(1);
    database.close();

    const reopened = openDatabase(path);
    const afterRestart = new HttpResourceGuards(reopened, {
      global: LIMIT,
      routes: { protected: LIMIT },
      now: () => 2_000,
    });
    const rejected = await afterRestart.run("protected", post("e"), () => okResponse());
    expect(rejected.status).toBe(429);
    expect(await errorCode(rejected)).toBe("rate-limited");
    reopened.close();
  });

  test("streams only a verified allowed length and reports short or long sources", async () => {
    const exact = boundedArtifactResponse({
      source: byteStream([new Uint8Array([1, 2]), new Uint8Array([3])]),
      declaredLength: 3,
      verifiedStoredLength: 3,
      maxBytes: 3,
    });
    expect(exact.status).toBe(200);
    expect(exact.headers.get("content-length")).toBe("3");
    expect([...new Uint8Array(await exact.arrayBuffer())]).toEqual([1, 2, 3]);

    const preflightReasons: string[] = [];
    const refused = boundedArtifactResponse({
      source: byteStream([new Uint8Array([1])]),
      declaredLength: 2,
      verifiedStoredLength: 3,
      maxBytes: 3,
      onMismatch: (reason) => preflightReasons.push(reason),
    });
    expect(refused.status).toBe(500);
    expect(validateTerminalBody(await refused.text())).toMatchObject({ valid: true });
    expect(preflightReasons).toHaveLength(1);

    for (const chunks of [
      [new Uint8Array([1])],
      [new Uint8Array([1, 2, 3, 4])],
      Array.from({ length: 17 }, () => new Uint8Array()),
    ]) {
      const reasons: string[] = [];
      const response = boundedArtifactResponse({
        source: byteStream(chunks),
        declaredLength: 3,
        verifiedStoredLength: 3,
        maxBytes: 3,
        onMismatch: (reason) => reasons.push(reason),
      });
      await expect(response.arrayBuffer()).rejects.toThrow(/length mismatch|made no progress/i);
      expect(reasons).toHaveLength(1);
    }
  });

  test("snapshots length-tracking stream chunks before exposing them", async () => {
    const buffer = new ArrayBuffer(1, { maxByteLength: 4 });
    const view = new Uint8Array(buffer);
    view[0] = 7;
    const response = boundedArtifactResponse({
      source: byteStream([view]),
      declaredLength: 1,
      verifiedStoredLength: 1,
      maxBytes: 1,
    });
    const reader = response.body!.getReader();
    const first = await reader.read();
    buffer.resize(4);
    expect(first.done).toBe(false);
    expect(first.value).toEqual(new Uint8Array([7]));
    expect(first.value?.byteLength).toBe(1);
    expect((await reader.read()).done).toBe(true);

    class OversizedChunk extends Uint8Array {
      override *[Symbol.iterator](): ArrayIterator<number> {
        throw new Error("oversized chunk was copied");
      }
    }
    const oversized = boundedArtifactResponse({
      source: byteStream([new OversizedChunk(2)]),
      declaredLength: 1,
      verifiedStoredLength: 1,
      maxBytes: 1,
    });
    await expect(oversized.arrayBuffer()).rejects.toThrow(/length mismatch/i);
  });

  test("cancels an artifact source rejected by length preflight", async () => {
    let cancellations = 0;
    const source = new ReadableStream<Uint8Array>({
      cancel() {
        cancellations += 1;
      },
    });
    const response = boundedArtifactResponse({
      source,
      declaredLength: 2,
      verifiedStoredLength: 3,
      maxBytes: 3,
    });
    expect(response.status).toBe(500);
    await response.text();
    expect(cancellations).toBe(1);
  });
});

async function testDatabase(): Promise<{
  readonly database: ReturnType<typeof openDatabase>;
  readonly path: string;
}> {
  const directory = await mkdtemp(join(tmpdir(), "dacs-http-guards-"));
  directories.push(directory);
  const path = join(directory, "state.sqlite");
  return { database: openDatabase(path), path };
}

function post(body: string): Request {
  return new Request("http://127.0.0.1/protected", { method: "POST", body });
}

function requestWithCancellation(onCancel: () => void): Request {
  return new Request("http://127.0.0.1/protected", {
    method: "POST",
    body: new ReadableStream<Uint8Array>({ cancel: onCancel }),
  });
}

function okResponse(): Response {
  return new Response(JSON.stringify({
    schema: "dacs-http-error/v1",
    status: 418,
    code: "internal-error",
  }), { status: 418, headers: { "content-type": "application/json" } });
}

async function errorCode(response: Response): Promise<string> {
  return (await response.json() as { code: string }).code;
}

function byteStream(chunks: readonly Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
}
