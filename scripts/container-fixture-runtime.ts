#!/usr/bin/env bun

import { startReadinessServer } from "../src/http/readiness-server.ts";

const HEALTH_URL = "http://127.0.0.1:3000/healthz";
const PROOF_TESTS = Object.freeze([
  "test/runtime/service-runtime.test.ts",
  "test/e2e/full-handshake.test.ts",
]);

export interface ContainerFixtureReceipt {
  readonly schema: "dacs-container-fixture/v1";
  readonly evidenceMode: "fixture";
  readonly lifecycle: "verified";
  readonly tests: readonly string[];
  readonly effects: Readonly<{
    readonly analytics: 0;
    readonly liveAnchors: 0;
    readonly liveBroadcasts: 0;
    readonly liveRegistrations: 0;
    readonly liveTransfers: 0;
    readonly liveWrites: 0;
    readonly telemetry: 0;
  }>;
}

export function containerFixtureReceipt(): ContainerFixtureReceipt {
  return Object.freeze({
    schema: "dacs-container-fixture/v1",
    evidenceMode: "fixture",
    lifecycle: "verified",
    tests: PROOF_TESTS,
    effects: Object.freeze({
      analytics: 0,
      liveAnchors: 0,
      liveBroadcasts: 0,
      liveRegistrations: 0,
      liveTransfers: 0,
      liveWrites: 0,
      telemetry: 0,
    }),
  });
}

export function normalizeHealthDocument(value: unknown): Readonly<Record<string, string>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Container health response must be an object");
  }
  const document = value as Record<string, unknown>;
  const keys = Object.keys(document).sort();
  const expected = ["schema", "service", "status", "timestamp", "version"];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error("Container health response has an unexpected shape");
  }
  if (document["schema"] !== "dacs-health/v1"
    || document["service"] !== "dacs-forge"
    || document["status"] !== "ok"
    || document["version"] !== "0.0.0-private"
    || typeof document["timestamp"] !== "string"
    || !Number.isFinite(Date.parse(document["timestamp"]))) {
    throw new Error("Container health response does not satisfy the DACS health contract");
  }
  return Object.freeze({
    schema: document["schema"],
    service: document["service"],
    status: document["status"],
    version: document["version"],
  });
}

async function runFixtureProof(): Promise<void> {
  const process = Bun.spawn([
    "bun",
    "test",
    "--timeout",
    "10000",
    ...PROOF_TESTS,
  ], {
    cwd: "/app",
    env: {
      DACS_EVIDENCE_MODE: "fixture",
      HOME: "/runtime",
      PATH: Bun.env["PATH"] ?? "/usr/local/bin:/usr/bin:/bin",
      TMPDIR: "/runtime",
    },
    stderr: "inherit",
    stdout: "inherit",
  });
  const exitCode = await process.exited;
  if (exitCode !== 0) throw new Error(`Container fixture proof failed with exit ${exitCode}`);
  console.log(JSON.stringify(containerFixtureReceipt()));
}

async function health(): Promise<void> {
  const response = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(1_500) });
  if (!response.ok) throw new Error(`Container health returned HTTP ${response.status}`);
  console.log(JSON.stringify(normalizeHealthDocument(await response.json())));
}

async function serve(): Promise<void> {
  await runFixtureProof();
  const server = startReadinessServer({ hostname: "127.0.0.1", port: 3_000 });
  await new Promise<void>((resolve, reject) => {
    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      void server.stop().then(resolve, reject);
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}

export async function main(args: readonly string[]): Promise<number> {
  const command = args[0] ?? "serve";
  if (args.length !== 1 || !["health", "self-test", "serve"].includes(command)) {
    console.error("Usage: container-fixture-runtime.ts <health|self-test|serve>");
    return 2;
  }
  if (command === "health") await health();
  else if (command === "self-test") await runFixtureProof();
  else await serve();
  return 0;
}

if (import.meta.main) {
  try {
    process.exitCode = await main(Bun.argv.slice(2));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown container fixture failure";
    console.error(`dacs-container: ${message}`);
    process.exitCode = 1;
  }
}
