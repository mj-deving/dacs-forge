import { FixtureLifecycleInProgressError } from "../../src/lifecycle/fixture-orchestrator.ts";
import { FIXTURE_JOB_ID } from "../fixtures/reference-agreement.ts";
import {
  agreementFixture,
  lifecycleCommitmentStore,
  lifecycleOrchestrator,
  lifecycleSessionStore,
  openLifecycleDatabase,
} from "../lifecycle/fixtures.ts";

interface InitializeMessage {
  readonly attempt: string;
  readonly failAt?: "before-ready" | "before-run";
  readonly first: boolean;
  readonly gate: SharedArrayBuffer;
  readonly kind: "initialize";
  readonly path: string;
}

type WorkerMessage = InitializeMessage | { readonly kind: "go" | "release-payment" };

declare const self: Worker;

interface InitializedState {
  readonly attempt: string;
  readonly database: ReturnType<typeof openLifecycleDatabase>;
  readonly failBeforeRun: boolean;
  readonly first: boolean;
  readonly gate: Int32Array;
  readonly invocations: string[];
  readonly orchestrator: ReturnType<typeof lifecycleOrchestrator>;
  readonly releasePayment: () => void;
}

let initialized: InitializedState | null = null;

self.onmessage = (event: MessageEvent<WorkerMessage>) => {
  if (event.data.kind === "initialize") {
    if (event.data.failAt === "before-ready") throw new Error("injected before-ready failure");
    const database = openLifecycleDatabase(event.data.path);
    const gate = new Int32Array(event.data.gate);
    const attempt = event.data.attempt;
    const first = event.data.first;
    const invocations: string[] = [];
    let releasePayment: (() => void) | null = null;
    const record = (stage: "payment" | "settlement" | "delivery") => {
      database.query<never, { attempt: string; stage: string }>(`
        INSERT INTO fixture_race_effects (attempt, stage) VALUES ($attempt, $stage)
      `).run({ attempt, stage });
      invocations.push(stage);
    };
    const sessions = lifecycleSessionStore(database);
    initialized = {
      attempt,
      database,
      failBeforeRun: event.data.failAt === "before-run",
      first,
      gate,
      invocations,
      releasePayment: () => {
        const release = releasePayment;
        releasePayment = null;
        release?.();
      },
      orchestrator: lifecycleOrchestrator(database, sessions, lifecycleCommitmentStore(database), {
        payment: async () => {
          record("payment");
          if (first) {
            Atomics.store(gate, 1, 1);
            Atomics.notify(gate, 1);
          }
          await new Promise<void>((resolve) => {
            releasePayment = resolve;
            postMessage({ attempt, kind: "effect-started", stage: "payment" });
          });
          return { ok: true, value: { txId: "fixture-payment" } };
        },
        settlement: () => { record("settlement"); return { ok: true, value: { evidenceHash: "fixture-settlement" } }; },
        delivery: () => { record("delivery"); return { ok: true, value: { receiptHash: "fixture-delivery" } }; },
      }),
    };
    postMessage({ attempt, kind: "ready" });
    return;
  }
  if (initialized === null) throw new Error("Concurrent settlement worker was not initialized");
  if (event.data.kind === "release-payment") {
    initialized.releasePayment();
    return;
  }
  if (initialized.failBeforeRun) throw new Error("injected before-run failure");
  void run(initialized);
};

async function run(state: InitializedState): Promise<void> {
  Atomics.add(state.gate, 0, 1);
  Atomics.notify(state.gate, 0);
  postMessage({ attempt: state.attempt, kind: "barrier-ready" });
  while (Atomics.load(state.gate, 0) < 2) Atomics.wait(state.gate, 0, 1);
  if (!state.first) Atomics.wait(state.gate, 1, 0);
  const fixture = agreementFixture();
  try {
    const result = await state.orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    postMessage({
      attempt: state.attempt,
      disposition: state.invocations.length === 0 ? "already-settled" : "settled",
      invocations: state.invocations,
      kind: "result",
      result,
    });
  } catch (error) {
    if (error instanceof FixtureLifecycleInProgressError) {
      postMessage({
        attempt: state.attempt,
        disposition: "in-progress",
        invocations: state.invocations,
        kind: "result",
      });
    } else {
      postMessage({
        attempt: state.attempt,
        kind: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  } finally {
    state.database.close();
  }
}
