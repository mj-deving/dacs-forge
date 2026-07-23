import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { dirname } from "node:path";
import { FixtureLifecycleInProgressError } from "../../src/lifecycle/fixture-orchestrator.ts";
import { FIXTURE_JOB_ID } from "../fixtures/reference-agreement.ts";
import {
  admitLifecycleSession,
  agreementFixture,
  lifecycleCommitmentStore,
  lifecycleDatabasePath,
  lifecycleOrchestrator,
  lifecycleSessionStore,
  openLifecycleDatabase,
} from "../lifecycle/fixtures.ts";

const directories: string[] = [];
const workers: RaceWorker[] = [];

afterEach(async () => {
  await Promise.all(workers.splice(0).map((worker) => worker.stop()));
  await Promise.all(directories.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("two-executor fixture settlement race", () => {
  test.each(["left-first", "right-first"] as const)(
    "%s barrier release produces one effect chain and one deterministic loser",
    async (order) => {
      for (let iteration = 0; iteration < 3; iteration += 1) {
        const path = await preparedRaceDatabase();
        const gate = new SharedArrayBuffer(8);
        const left = raceWorker(path, `left-${iteration}`, order === "left-first", gate);
        const right = raceWorker(path, `right-${iteration}`, order === "right-first", gate);
        await Promise.all([left.waitFor("ready"), right.waitFor("ready")]);
        const ordered = order === "left-first" ? [left, right] : [right, left];
        ordered[0]!.worker.postMessage({ kind: "go" });
        ordered[1]!.worker.postMessage({ kind: "go" });
        await Promise.all([left.waitFor("barrier-ready"), right.waitFor("barrier-ready")]);
        expect(await ordered[0]!.waitFor("effect-started")).toMatchObject({
          attempt: `${order === "left-first" ? "left" : "right"}-${iteration}`,
        });
        const loser = await ordered[1]!.waitFor("result");
        expect(loser).toMatchObject({
          attempt: `${order === "left-first" ? "right" : "left"}-${iteration}`,
          disposition: "in-progress",
          invocations: [],
        });
        ordered[0]!.worker.postMessage({ kind: "release-payment" });
        const winner = await ordered[0]!.waitFor("result");
        const results = [winner, loser];
        expect(results.map(({ disposition }) => disposition).sort()).toEqual(["in-progress", "settled"]);
        expect(results.flatMap(({ invocations }) => invocations).sort()).toEqual([
          "delivery", "payment", "settlement",
        ]);
        await Promise.all([left.stop(), right.stop()]);
        await verifyPersistedRace(path);
      }
    },
  );

  test("winner termination leaves one explicit recoverable boundary and no second effect", async () => {
    const path = await preparedRaceDatabase();
    const gate = new SharedArrayBuffer(8);
    const left = raceWorker(path, "left", true, gate);
    const right = raceWorker(path, "right", false, gate);
    await Promise.all([left.waitFor("ready"), right.waitFor("ready")]);
    left.worker.postMessage({ kind: "go" });
    right.worker.postMessage({ kind: "go" });
    await Promise.all([left.waitFor("barrier-ready"), right.waitFor("barrier-ready")]);
    const winner = await left.waitFor("effect-started");
    const loser = await right.waitFor("result");
    expect(winner).toEqual({ attempt: "left", kind: "effect-started", stage: "payment" });
    expect(loser).toMatchObject({ disposition: "in-progress", invocations: [] });
    await left.stop();
    await right.stop();

    const database = openLifecycleDatabase(path);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_race_effects",
    ).get()?.count).toBe(1n);
    const orchestrator = lifecycleOrchestrator(
      database,
      lifecycleSessionStore(database),
      lifecycleCommitmentStore(database),
      {
        payment: () => { throw new Error("payment replayed"); },
        settlement: () => { throw new Error("settlement replayed"); },
        delivery: () => { throw new Error("delivery replayed"); },
      },
    );
    expect(orchestrator.getRestartBoundary(FIXTURE_JOB_ID)?.id).toBe("payment.in-flight");
    const fixture = agreementFixture();
    await expect(orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    })).rejects.toBeInstanceOf(FixtureLifecycleInProgressError);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_race_effects",
    ).get()?.count).toBe(1n);
    database.close();
  });

  test("worker failures reject every active phase wait without a timeout", async () => {
    const beforeReady = raceWorker("unused", "before-ready", true, new SharedArrayBuffer(8), "before-ready");
    await expect(beforeReady.waitFor("ready")).rejects.toThrow("injected before-ready failure");
    await beforeReady.stop();

    const path = await preparedRaceDatabase();
    const beforeRun = raceWorker(path, "before-run", true, new SharedArrayBuffer(8), "before-run");
    await beforeRun.waitFor("ready");
    const phaseWaits = Promise.all([
      beforeRun.waitFor("barrier-ready"),
      beforeRun.waitFor("effect-started"),
    ]);
    beforeRun.worker.postMessage({ kind: "go" });
    await expect(phaseWaits).rejects.toThrow("injected before-run failure");
    await beforeRun.stop();
  });
});

interface RaceResult {
  readonly attempt: string;
  readonly disposition: "already-settled" | "in-progress" | "settled";
  readonly invocations: readonly string[];
  readonly result?: unknown;
}

type WorkerEvent =
  | { readonly attempt: string; readonly kind: "ready" | "barrier-ready" }
  | { readonly attempt: string; readonly kind: "effect-started"; readonly stage: string }
  | ({ readonly kind: "result" } & RaceResult);

type WorkerEventKind = WorkerEvent["kind"];
type WorkerEventOf<K extends WorkerEventKind> = Extract<WorkerEvent, { readonly kind: K }>;

interface RaceWorker {
  readonly stop: () => Promise<void>;
  readonly waitFor: <K extends WorkerEventKind>(kind: K) => Promise<WorkerEventOf<K>>;
  readonly worker: Worker;
}

function raceWorker(
  path: string,
  attempt: string,
  first: boolean,
  gate: SharedArrayBuffer,
  failAt?: "before-ready" | "before-run",
): RaceWorker {
  const worker = new Worker(new URL("../workers/concurrent-settlement-worker.ts", import.meta.url).href);
  const buffered = new Map<WorkerEventKind, WorkerEvent[]>();
  const pending = new Map<WorkerEventKind, Array<{
    readonly reject: (error: Error) => void;
    readonly resolve: (event: WorkerEvent) => void;
  }>>();
  let failure: Error | null = null;
  let stopping = false;
  let stopped = false;
  let closeResolve!: () => void;
  const closed = new Promise<void>((resolve) => { closeResolve = resolve; });
  const fail = (error: Error) => {
    if (failure !== null) return;
    failure = error;
    for (const waiters of pending.values()) for (const waiter of waiters) waiter.reject(error);
    pending.clear();
  };
  worker.onmessage = (event: MessageEvent<Record<string, unknown>>) => {
    if (event.data["kind"] === "error") {
      fail(new Error(`Worker ${attempt}: ${String(event.data["message"])}`));
      return;
    }
    const kind = event.data["kind"];
    if (kind !== "ready" && kind !== "barrier-ready" && kind !== "effect-started" && kind !== "result") {
      fail(new Error(`Worker ${attempt} emitted an unknown event`));
      return;
    }
    const message = event.data as unknown as WorkerEvent;
    const waiter = pending.get(kind)?.shift();
    if (waiter === undefined) buffered.set(kind, [...(buffered.get(kind) ?? []), message]);
    else waiter.resolve(message);
  };
  worker.onerror = (event) => fail(new Error(`Worker ${attempt}: ${event.message}`));
  worker.addEventListener("close", () => {
    stopped = true;
    closeResolve();
    if (!stopping) fail(new Error(`Worker ${attempt} closed before explicit termination`));
  });
  const harness: RaceWorker = {
    worker,
    waitFor: <K extends WorkerEventKind>(kind: K) => {
      const message = buffered.get(kind)?.shift();
      if (message !== undefined) return Promise.resolve(message as WorkerEventOf<K>);
      if (failure !== null) return Promise.reject(failure);
      return new Promise<WorkerEventOf<K>>((resolve, reject) => {
        const waiter = { reject, resolve: resolve as (event: WorkerEvent) => void };
        pending.set(kind, [...(pending.get(kind) ?? []), waiter]);
      });
    },
    stop: async () => {
      if (stopped) return;
      if (!stopping) {
        stopping = true;
        worker.terminate();
      }
      await closed;
      const index = workers.indexOf(harness);
      if (index !== -1) workers.splice(index, 1);
    },
  };
  workers.push(harness);
  worker.postMessage({ attempt, first, gate, kind: "initialize", path, ...(failAt === undefined ? {} : { failAt }) });
  return harness;
}

async function preparedRaceDatabase(): Promise<string> {
  const fixture = agreementFixture();
  const path = await lifecycleDatabasePath();
  directories.push(dirname(path));
  const database = openLifecycleDatabase(path);
  admitLifecycleSession(lifecycleSessionStore(database), fixture.agreementCanonicalJson);
  database.run(`
    CREATE TABLE fixture_race_effects (
      id INTEGER PRIMARY KEY,
      attempt TEXT NOT NULL,
      stage TEXT NOT NULL CHECK (stage IN ('payment', 'settlement', 'delivery'))
    ) STRICT
  `);
  database.close();
  return path;
}

async function verifyPersistedRace(path: string): Promise<void> {
  const database = openLifecycleDatabase(path);
  const effects = database.query<{ attempt: string; stage: string }, []>(`
    SELECT attempt, stage FROM fixture_race_effects ORDER BY id
  `).all();
  expect(effects.map(({ stage }) => stage)).toEqual(["payment", "settlement", "delivery"]);
  expect(new Set(effects.map(({ attempt }) => attempt)).size).toBe(1);
  expect(database.query<{
    commitmentCount: bigint; deliveryInvocations: bigint; paymentInvocations: bigint;
    settlementInvocations: bigint; state: string;
  }, []>(`
    SELECT state, payment_invocations AS paymentInvocations,
      settlement_invocations AS settlementInvocations,
      delivery_invocations AS deliveryInvocations,
      (SELECT count(*) FROM fixture_commitments) AS commitmentCount
    FROM fixture_lifecycle_runs
  `).get()).toEqual({
    commitmentCount: 1n,
    deliveryInvocations: 1n,
    paymentInvocations: 1n,
    settlementInvocations: 1n,
    state: "settle-completed",
  });
  const invocations: string[] = [];
  const replay = lifecycleOrchestrator(
    database,
    lifecycleSessionStore(database),
    lifecycleCommitmentStore(database),
    {
      payment: () => { invocations.push("payment"); return { ok: true, value: {} }; },
      settlement: () => { invocations.push("settlement"); return { ok: true, value: {} }; },
      delivery: () => { invocations.push("delivery"); return { ok: true, value: {} }; },
    },
  );
  const fixture = agreementFixture();
  expect(await replay.run({
    agreementCanonicalJson: fixture.agreementCanonicalJson,
    jobId: FIXTURE_JOB_ID,
    verification: fixture.verification,
  })).toMatchObject({ state: "settle-completed" });
  expect(invocations).toEqual([]);
  database.close();
}
