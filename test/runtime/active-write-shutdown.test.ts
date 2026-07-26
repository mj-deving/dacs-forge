import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../..");
const PRELOAD = join(ROOT, "test/workers/atomic-write-preload.ts");
const VERIFIER = join(ROOT, "test/workers/atomic-write-verifier.ts");
const roots: string[] = [];

type Phase = "before-statement" | "after-statement" | "post-commit";

interface BoundaryEvent {
  readonly kind: "atomic-write-boundary";
  readonly phase: Phase;
  readonly target: string;
}

interface Case {
  readonly driverPattern: string;
  readonly phase: Phase;
  readonly target: string;
}

const TARGETS = Object.freeze([
  ["service-run.claim", "passes only the frozen documented request"],
  ["service-run.complete", "passes only the frozen documented request"],
  ["service-run.release", "releases an ordinary failed handler claim"],
  ["artifact.put-blob", "passes only the frozen documented request"],
  ["artifact.put-kind", "passes only the frozen documented request"],
] as const);
const CASES: Case[] = TARGETS.flatMap(([target, driverPattern]) =>
  (["before-statement", "after-statement", "post-commit"] as const)
    .map((phase) => ({ driverPattern, phase, target })),
);

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("active fixture-write shutdown", () => {
  test.each(CASES)("SIGINT exits within five seconds and preserves $target/$phase", async ({
    driverPattern,
    phase,
    target,
  }) => {
    const root = await mkdtemp(join(tmpdir(), `dacs-sigint-${safeName(target)}-${phase}-`));
    roots.push(root);
    const child = Bun.spawn([
      process.execPath,
      "test",
      "--preload",
      PRELOAD,
      join(ROOT, "test/runtime/service-runtime.test.ts"),
      "-t",
      driverPattern,
      "--timeout",
      "60000",
    ], {
      cwd: ROOT,
      detached: true,
      env: {
        ...process.env,
        TMPDIR: root,
        DACS_ATOMIC_WRITE_PHASE: phase,
        DACS_ATOMIC_WRITE_TARGET: target,
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const stderr = streamText(child.stderr);
    let boundary: BoundaryEvent;
    try {
      boundary = await waitForBoundary(child.stdout, child.exited, target, phase);
    } catch (error) {
      cleanupProcessGroup(child.pid);
      await child.exited;
      throw new Error(`${message(error)}\nchild stderr:\n${await stderr}`);
    }

    expect(boundary).toMatchObject({
      kind: "atomic-write-boundary",
      target,
      phase,
    });
    const startedAt = performance.now();
    process.kill(-child.pid, "SIGINT");
    const exitCode = await within(child.exited, 5_000, () => cleanupProcessGroup(child.pid));
    const elapsedMs = performance.now() - startedAt;
    expect(exitCode).not.toBe(0);
    expect(elapsedMs).toBeLessThanOrEqual(5_000);
    expect(processGroupExists(child.pid)).toBe(false);
    expect(await stderr).not.toContain("timed out");

    const databases = (await filesBelow(root)).filter((path) => path.endsWith(".sqlite"));
    expect(databases).toHaveLength(1);
    const verified = await runVerifier(
      databases[0]!,
      target.startsWith("artifact.") ? "service-run.complete" : target,
    );
    expect(verified.exitCode, `${verified.stderr}\n${verified.stdout}`).toBe(0);
    expect(verified.stdout).toContain('"kind":"atomic-write-verification"');
  }, 10_000);
});

async function waitForBoundary(
  stream: ReadableStream<Uint8Array>,
  exited: Promise<number>,
  target: string,
  phase: Phase,
): Promise<BoundaryEvent> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  try {
    while (true) {
      const next = await Promise.race([
        reader.read(),
        exited.then((code) => ({ done: true as const, value: new Uint8Array(), code })),
      ]);
      if ("code" in next) throw new Error(`child exited ${next.code} before ${target}/${phase}`);
      buffered += decoder.decode(next.value, { stream: !next.done });
      const lines = buffered.split("\n");
      buffered = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith('{"kind":"atomic-write-boundary"')) continue;
        const event = JSON.parse(line) as BoundaryEvent;
        if (event.target !== target || event.phase !== phase) {
          throw new Error(`expected ${target}/${phase}, received ${event.target}/${event.phase}`);
        }
        return event;
      }
      if (next.done) throw new Error(`stdout closed before ${target}/${phase}: ${buffered}`);
    }
  } finally {
    reader.releaseLock();
  }
}

async function runVerifier(path: string, target: string): Promise<{
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
}> {
  const child = Bun.spawn([process.execPath, "run", VERIFIER, path, target], {
    cwd: ROOT,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    streamText(child.stdout),
    streamText(child.stderr),
  ]);
  return { exitCode, stdout, stderr };
}

async function streamText(stream: ReadableStream<Uint8Array>): Promise<string> {
  return new Response(stream).text();
}

async function filesBelow(root: string): Promise<string[]> {
  const entries = await readdir(root, { recursive: true, withFileTypes: true });
  return entries.filter((entry) => entry.isFile()).map((entry) => join(entry.parentPath, entry.name));
}

async function within<T>(promise: Promise<T>, timeoutMs: number, onTimeout: () => void): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          onTimeout();
          reject(new Error(`SIGINT process tree did not exit within ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function cleanupProcessGroup(pid: number): void {
  try {
    process.kill(-pid, "SIGKILL");
  } catch (error) {
    if (!isMissingProcess(error)) throw error;
  }
}

function processGroupExists(pid: number): boolean {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    if (isMissingProcess(error)) return false;
    throw error;
  }
}

function isMissingProcess(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ESRCH";
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function safeName(value: string): string {
  return value.replaceAll(/[^a-z0-9]+/gi, "-");
}
