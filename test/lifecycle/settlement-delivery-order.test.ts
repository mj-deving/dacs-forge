import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname } from "node:path";
import {
  FixtureLifecycleInProgressError,
  type FixtureLifecycleContext,
  type FixtureLifecycleOrchestratorOptions,
  type FixturePhaseResult,
} from "../../src/lifecycle/fixture-orchestrator.ts";
import { FIXTURE_JOB_ID } from "../fixtures/reference-agreement.ts";
import {
  admitLifecycleSession,
  agreementFixture,
  lifecycleCommitmentStore,
  lifecycleDatabasePath,
  lifecycleOrchestrator,
  lifecycleSessionStore,
  LIFECYCLE_NOW,
  openLifecycleDatabase,
} from "./fixtures.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { createFixtureEd25519Signer } from "../../src/producer/fixture-ed25519.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
import { fixtureCommitmentRequestHash } from "../../src/substrate/sqlite/fixture-commitment.ts";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("payment to delivery ordering", () => {
  test("payment failure prevents settlement and delivery across restart", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    let database = openLifecycleDatabase(path);
    let sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, fixture.agreementCanonicalJson);
    let commitments = lifecycleCommitmentStore(database);
    const order: string[] = [];
    const failed = await lifecycleOrchestrator(database, sessions, commitments, {
      payment: () => { order.push("payment"); return { ok: false, errorClass: "counterparty", reason: "fixture payment refused" }; },
      settlement: () => { order.push("settlement"); return { ok: true, value: {} }; },
      delivery: () => { order.push("delivery"); return { ok: true, value: {} }; },
    }).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(failed).toMatchObject({
      state: "settle-failed",
      failureStage: "payment",
      errorClass: "counterparty",
      counts: { payment: 1, settlement: 0, delivery: 0 },
    });
    expect(order).toEqual(["payment"]);
    database.close();

    database = openLifecycleDatabase(path);
    sessions = lifecycleSessionStore(database);
    commitments = lifecycleCommitmentStore(database);
    const replayOrder: string[] = [];
    const replay = await lifecycleOrchestrator(database, sessions, commitments, {
      payment: () => { replayOrder.push("payment"); return { ok: true, value: {} }; },
      settlement: () => { replayOrder.push("settlement"); return { ok: true, value: {} }; },
      delivery: () => { replayOrder.push("delivery"); return { ok: true, value: {} }; },
    }).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(replay).toEqual(failed);
    expect(replayOrder).toEqual([]);
    database.close();
  });

  test("settlement evidence failure prevents delivery", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    const order: string[] = [];
    const result = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      {
        payment: () => { order.push("payment"); return { ok: true, value: { txId: "fixture-payment" } }; },
        settlement: ({ payment }) => {
          order.push(`settlement:${String(payment?.["txId"])}`);
          return { ok: false, errorClass: "permanent", reason: "fixture evidence rejected" };
        },
        delivery: () => { order.push("delivery"); return { ok: true, value: {} }; },
      },
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });

    expect(result).toMatchObject({
      state: "settle-failed",
      failureStage: "settlement",
      counts: { payment: 1, settlement: 1, delivery: 0 },
    });
    expect(order).toEqual(["payment", "settlement:fixture-payment"]);
    harness.database.close();
  });

  test("every preceding payment phase must succeed before delivery", async () => {
    const fixture = multiPaymentFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    const order: string[] = [];
    const result = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      {
        payment: ({ phaseIndex }) => {
          order.push(`payment:${phaseIndex}`);
          return phaseIndex === 2
            ? { ok: true, value: { txId: "first-payment" } }
            : { ok: false, errorClass: "counterparty", reason: "second payment refused" };
        },
        settlement: ({ phaseIndex }) => {
          order.push(`settlement:${phaseIndex}`);
          return { ok: true, value: { evidenceHash: `evidence-${phaseIndex}` } };
        },
        delivery: () => { order.push("delivery"); return { ok: true, value: {} }; },
      },
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });

    expect(result).toMatchObject({
      state: "settle-failed",
      failureStage: "payment",
      counts: { payment: 2, settlement: 1, delivery: 0 },
      payments: [{ phaseIndex: 2, value: { txId: "first-payment" } }],
      settlements: [{ phaseIndex: 2, value: { evidenceHash: "evidence-2" } }],
    });
    expect(order).toEqual(["payment:2", "settlement:2", "payment:3"]);
    harness.database.close();
  });

  test("substrate pause resumes only from an exact stale snapshot with isolation proof", async () => {
    const fixture = agreementFixture();
    const substrateHarness = await harnessFor(fixture.agreementCanonicalJson);
    const substrateOrder: string[] = [];
    let unavailable = true;
    let trustedNow = LIFECYCLE_NOW;
    const substrate = lifecycleOrchestrator(
      substrateHarness.database,
      substrateHarness.sessions,
      substrateHarness.commitments,
      {
        payment: () => {
          substrateOrder.push("payment");
          return unavailable
            ? { ok: false, errorClass: "substrate", reason: "fixture substrate unavailable" }
            : { ok: true, value: { txId: "fixture-payment" } };
        },
        settlement: () => { substrateOrder.push("settlement"); return { ok: true, value: { evidenceHash: "verified" } }; },
        delivery: () => { substrateOrder.push("delivery"); return { ok: true, value: { receiptHash: "delivered" } }; },
        now: () => trustedNow,
      },
    );
    const input = {
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    } as const;
    const paused = await substrate.run(input);
    expect(paused).toMatchObject({
      state: "substrate-failure-paused",
      errorClass: "substrate",
      failureStage: "payment",
      counts: { payment: 1, settlement: 0, delivery: 0 },
    });
    if (paused.state !== "substrate-failure-paused") throw new Error("Lifecycle did not pause");
    expect(Date.parse(paused.pauseExpiresAt) - Date.parse(paused.pausedAt)).toBe(3_600_000);
    expect(await substrate.run(input)).toEqual(paused);
    expect(substrateOrder).toEqual(["payment"]);
    const snapshot = substrate.getRecoverySnapshot(FIXTURE_JOB_ID);
    if (snapshot?.state !== "substrate-failure-paused") throw new Error("Pause snapshot missing");
    unavailable = false;
    trustedNow = new Date(Date.parse(snapshot.updatedAt) + 500).toISOString();
    const recovery = {
      executorIsolationConfirmed: true,
      expectedBoundaryId: snapshot.boundaryId,
      expectedUpdatedAt: snapshot.updatedAt,
      expectedVersion: snapshot.version,
      minimumAgeMs: 100,
      sideEffectReconciliationConfirmed: true,
    } as const;
    await expect(substrate.recover(input, {
      ...recovery,
      executorIsolationConfirmed: false,
    } as unknown as typeof recovery)).rejects.toThrow(/executor isolation/);
    await expect(substrate.recover(input, {
      ...recovery,
      expectedVersion: recovery.expectedVersion + 1,
    })).rejects.toThrow(/snapshot no longer matches/);
    const completed = await substrate.recover(input, recovery);
    expect(completed).toMatchObject({
      state: "settle-completed",
      counts: { payment: 1, settlement: 1, delivery: 1 },
    });
    expect(substrateOrder).toEqual(["payment", "payment", "settlement", "delivery"]);
    await expect(substrate.recover(input, recovery)).rejects.toThrow(/boundary|snapshot|recoverable/);
    substrateHarness.database.close();
  });

  test("rejects unbounded pause configuration and date overflow before handler invocation", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    expect(() => lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      {
        ...successfulHandlers([]),
        substratePauseMs: Number.MAX_SAFE_INTEGER,
      },
    )).toThrow(/between 1 and 3600000/);

    let invocations = 0;
    const orchestrator = lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      {
        payment: () => { invocations += 1; return { ok: true, value: {} }; },
        settlement: () => { invocations += 1; return { ok: true, value: {} }; },
        delivery: () => { invocations += 1; return { ok: true, value: {} }; },
        now: () => "+275760-09-13T00:00:00.000Z",
      },
    );
    await expect(orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    })).rejects.toThrow(/pause deadline is not representable/);
    expect(invocations).toBe(0);
    expect(harness.database.query<{
      deliveryInvocations: bigint;
      paymentInvocations: bigint;
      settlementInvocations: bigint;
      state: string;
    }, []>(`
      SELECT state, payment_invocations AS paymentInvocations,
        settlement_invocations AS settlementInvocations,
        delivery_invocations AS deliveryInvocations
      FROM fixture_lifecycle_runs
    `).get()).toEqual({
      state: "settle-pending",
      paymentInvocations: 0n,
      settlementInvocations: 0n,
      deliveryInvocations: 0n,
    });
    harness.database.close();
  });

  test("expired substrate pause becomes terminal without replaying a handler", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    let invocations = 0;
    let trustedNow = LIFECYCLE_NOW;
    const orchestrator = lifecycleOrchestrator(harness.database, harness.sessions, harness.commitments, {
      payment: () => { invocations += 1; return { ok: false, errorClass: "substrate", reason: "offline" }; },
      settlement: () => { invocations += 1; return { ok: true, value: {} }; },
      delivery: () => { invocations += 1; return { ok: true, value: {} }; },
      now: () => trustedNow,
      substratePauseMs: 1_000,
    });
    const paused = await orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    if (paused.state !== "substrate-failure-paused") throw new Error("Lifecycle did not pause");
    expect(() => (orchestrator.expirePaused as unknown as (jobId: string, forgedNow: string) => unknown)(
      FIXTURE_JOB_ID,
      new Date(Date.parse(paused.pauseExpiresAt) + 60_000).toISOString(),
    )).toThrow(/has not expired/);
    trustedNow = paused.pauseExpiresAt;
    const expired = orchestrator.expirePaused(FIXTURE_JOB_ID);
    expect(expired).toMatchObject({
      state: "failed-substrate",
      errorClass: "substrate",
      counts: { payment: 1, settlement: 0, delivery: 0 },
    });
    expect(invocations).toBe(1);
    expect(orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID)).toBeNull();
    harness.database.close();
  });

  test("trusted time atomically expires a pause before recovery or replay", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    let invocations = 0;
    let trustedNow = LIFECYCLE_NOW;
    const orchestrator = lifecycleOrchestrator(harness.database, harness.sessions, harness.commitments, {
      payment: () => { invocations += 1; return { ok: false, errorClass: "substrate", reason: "offline" }; },
      settlement: () => { invocations += 1; return { ok: true, value: {} }; },
      delivery: () => { invocations += 1; return { ok: true, value: {} }; },
      now: () => trustedNow,
      substratePauseMs: 1_000,
    });
    const input = {
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    } as const;
    const paused = await orchestrator.run(input);
    if (paused.state !== "substrate-failure-paused") throw new Error("Lifecycle did not pause");
    const snapshot = orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID);
    if (snapshot?.state !== "substrate-failure-paused") throw new Error("Pause snapshot missing");
    trustedNow = new Date(Date.parse(paused.pauseExpiresAt) + 60_000).toISOString();
    await expect(orchestrator.recover(input, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: "delivery.substrate-paused",
      expectedUpdatedAt: snapshot.updatedAt,
      expectedVersion: snapshot.version,
      minimumAgeMs: 100,
      sideEffectReconciliationConfirmed: true,
    })).rejects.toThrow(/boundary no longer matches/);
    expect(harness.database.query<{ state: string; version: bigint }, []>(`
      SELECT state, version FROM fixture_lifecycle_runs
    `).get()).toEqual({ state: "substrate-failure-paused", version: BigInt(snapshot.version) });
    const expired = await orchestrator.recover(input, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: snapshot.boundaryId,
      expectedUpdatedAt: snapshot.updatedAt,
      expectedVersion: snapshot.version,
      minimumAgeMs: 100,
      sideEffectReconciliationConfirmed: true,
      observedAt: new Date(Date.parse(paused.pauseExpiresAt) - 1).toISOString(),
    } as unknown as Parameters<typeof orchestrator.recover>[1]);
    expect(expired).toMatchObject({ state: "failed-substrate", endedAt: trustedNow });
    expect(await orchestrator.run(input)).toEqual(expired);
    expect(orchestrator.get(FIXTURE_JOB_ID)).toEqual(expired);
    expect(orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID)).toBeNull();
    expect(invocations).toBe(1);
    harness.database.close();
  });

  test("rejects settlement-atomicity on a non-cross-chain rail without manufacturing ST8", async () => {
    const fixture = agreementFixture();
    const atomicHarness = await harnessFor(fixture.agreementCanonicalJson);
    const atomicOrder: string[] = [];
    const orchestrator = lifecycleOrchestrator(
      atomicHarness.database,
      atomicHarness.sessions,
      atomicHarness.commitments,
      {
        payment: () => { atomicOrder.push("payment"); return { ok: true, value: { txId: "locked" } }; },
        settlement: () => {
          atomicOrder.push("settlement");
          return { ok: false, errorClass: "settlement-atomicity", reason: "resolving leg pending" };
        },
        delivery: () => { atomicOrder.push("delivery"); return { ok: true, value: {} }; },
      },
    );
    const unsupported = await orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(unsupported).toMatchObject({
      state: "settle-unsupported",
      errorClass: "settlement-atomicity",
      failureStage: "settlement",
      counts: { payment: 1, settlement: 1, delivery: 0 },
      reason: expect.stringContaining("Unsupported on the non-cross-chain fixture rail"),
    });
    expect(atomicOrder).toEqual(["payment", "settlement"]);
    expect(orchestrator.get(FIXTURE_JOB_ID)).toEqual(unsupported);
    expect(atomicHarness.database.query<{ state: string }, []>(
      "SELECT state FROM fixture_lifecycle_runs",
    ).get()?.state).toBe("settle-unsupported");
    atomicHarness.database.close();
  });

  test("rejects cross-chain payment phases before admission lookup or handler execution", async () => {
    const fixture = agreementFixture();
    const listing = JSON.parse(fixture.verification.listingCanonicalJson) as {
      pipeline: Array<Record<string, unknown>>;
    };
    listing.pipeline[2] = {
      kind: "pay-cross-chain-htlc",
      parameters: { rail: "xchain:fixture" },
    };
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const invocations: string[] = [];
    const orchestrator = lifecycleOrchestrator(
      database,
      sessions,
      lifecycleCommitmentStore(database),
      successfulHandlers(invocations),
    );

    await expect(orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: {
        ...fixture.verification,
        listingCanonicalJson: canonicalize(listing),
      },
    })).rejects.toThrow(/non-cross-chain fixture vertical does not support pay-cross-chain-htlc/);
    expect(invocations).toEqual([]);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_lifecycle_runs",
    ).get()?.count).toBe(0n);
    database.close();
  });

  test("persists accumulated phase-output overflow as a terminal failure", async () => {
    const fixture = multiPaymentFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    let harness = await harnessFor(fixture.agreementCanonicalJson, path);
    const invocations: string[] = [];
    const oversizedValue = { payload: "x".repeat(600_000) };
    const failed = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      {
        payment: ({ phaseIndex }) => {
          invocations.push(`payment:${phaseIndex}`);
          return { ok: true, value: oversizedValue };
        },
        settlement: ({ phaseIndex }) => {
          invocations.push(`settlement:${phaseIndex}`);
          return { ok: true, value: { evidenceHash: `evidence-${phaseIndex}` } };
        },
        delivery: () => { invocations.push("delivery"); return { ok: true, value: {} }; },
      },
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(failed).toMatchObject({
      state: "settle-failed",
      failureStage: "payment",
      errorClass: "permanent",
      counts: { payment: 2, settlement: 1, delivery: 0 },
      reason: expect.stringContaining("Accumulated phase evidence exceeds"),
    });
    expect(invocations).toEqual(["payment:2", "settlement:2", "payment:3"]);
    harness.database.close();

    harness = await harnessFor(fixture.agreementCanonicalJson, path, false);
    const replayInvocations: string[] = [];
    const replay = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      successfulHandlers(replayInvocations),
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(replay).toEqual(failed);
    expect(replayInvocations).toEqual([]);
    harness.database.close();
  });

  test("bounds agreement and Listing bytes before JSON parsing", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const orchestrator = lifecycleOrchestrator(
      database,
      sessions,
      lifecycleCommitmentStore(database),
      successfulHandlers([]),
    );
    const oversizedAgreement = `[${" ".repeat(1_048_576)}`;
    const oversizedListing = `[${" ".repeat(16_384)}`;

    await expect(orchestrator.run({
      agreementCanonicalJson: oversizedAgreement,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    })).rejects.toThrow(/Agreement exceeds implementation input limit/);
    await expect(orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: { ...fixture.verification, listingCanonicalJson: oversizedListing },
    })).rejects.toThrow(/Listing exceeds implementation input limit/);
    await expect(orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: { ...fixture.verification, maxArtifactBytes: 1_048_577 },
    })).rejects.toThrow(/between 1 and 1048576 bytes/);
    expect(() => fixtureCommitmentRequestHash(oversizedAgreement))
      .toThrow(/Agreement exceeds implementation input limit/);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_lifecycle_runs",
    ).get()?.count).toBe(0n);
    database.close();
  });

  test("persists an empty handler failure reason as an invalid terminal result", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    const result = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      {
        payment: () => ({ ok: false, errorClass: "permanent", reason: "   " }),
        settlement: () => ({ ok: true, value: {} }),
        delivery: () => ({ ok: true, value: {} }),
      },
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(result).toMatchObject({
      state: "settle-failed",
      failureStage: "payment",
      errorClass: "permanent",
      reason: "Handler returned an empty failure reason",
      counts: { payment: 1, settlement: 0, delivery: 0 },
    });
    harness.database.close();
  });

  test("fails closed when a settlement handler throws after payment", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    const order: string[] = [];
    let trustedNow = LIFECYCLE_NOW;
    const orchestrator = lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      {
        payment: () => {
          order.push("payment");
          return { ok: true, value: { txId: "fixture-payment" } };
        },
        settlement: () => {
          order.push("settlement");
          throw new Error("unexpected adapter exception");
        },
        delivery: () => {
          order.push("delivery");
          return { ok: true, value: {} };
        },
        now: () => trustedNow,
      },
    );
    const input = {
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    } as const;

    const failed = await orchestrator.run(input);
    expect(failed).toMatchObject({
      state: "settle-failed",
      failureStage: "settlement",
      errorClass: "transient",
      reason: "Handler threw: unexpected adapter exception",
      counts: { payment: 1, settlement: 1, delivery: 0 },
      payments: [{ value: { txId: "fixture-payment" } }],
    });
    expect(order).toEqual(["payment", "settlement"]);
    expect(orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID)).toBeNull();
    const terminalSnapshot = harness.database.query<{ updatedAt: string; version: number }, []>(
      "SELECT updated_at AS updatedAt, version FROM fixture_lifecycle_runs",
    ).get();
    if (terminalSnapshot === null) throw new Error("Terminal lifecycle row missing");
    trustedNow = new Date(Date.parse(terminalSnapshot.updatedAt) + 1).toISOString();
    await expect(orchestrator.recover(input, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: "settlement.failed",
      expectedUpdatedAt: terminalSnapshot.updatedAt,
      expectedVersion: Number(terminalSnapshot.version),
      minimumAgeMs: 1,
      sideEffectReconciliationConfirmed: true,
    })).rejects.toThrow(/not recoverable/);
    expect(await orchestrator.run(input)).toEqual(failed);
    expect(order).toEqual(["payment", "settlement"]);
    harness.database.close();
  });

  test("terminalizes a thrown value whose string coercion also throws", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    const result = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      {
        payment: () => {
          throw {
            [Symbol.toPrimitive](): never {
              throw new Error("coercion denied");
            },
          };
        },
        settlement: () => ({ ok: true, value: {} }),
        delivery: () => ({ ok: true, value: {} }),
      },
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });

    expect(result).toMatchObject({
      state: "settle-failed",
      failureStage: "payment",
      errorClass: "transient",
      reason: "Handler threw: unprintable thrown value",
      counts: { payment: 1, settlement: 0, delivery: 0 },
    });
    expect(lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      successfulHandlers([]),
    ).getRecoverySnapshot(FIXTURE_JOB_ID)).toBeNull();
    harness.database.close();
  });

  test("terminalizes thenable assimilation failures and replays no handler after restart", async () => {
    const fixture = agreementFixture();
    const cases: ReadonlyArray<{
      readonly expectedReason: string;
      readonly name: string;
      readonly value: () => FixturePhaseResult;
    }> = [
      {
        name: "throwing then getter",
        expectedReason: "Handler threw: then getter denied",
        value: () => Object.defineProperty({}, "then", {
          get: () => { throw new Error("then getter denied"); },
        }) as FixturePhaseResult,
      },
      {
        name: "rejecting thenable",
        expectedReason: "Handler threw: then rejected",
        value: () => ({
          then: (_resolve: unknown, reject: (reason: unknown) => void) => {
            reject(new Error("then rejected"));
          },
        }) as unknown as FixturePhaseResult,
      },
    ];

    for (const testCase of cases) {
      const path = await lifecycleDatabasePath();
      directories.push(dirname(path));
      let harness = await harnessFor(fixture.agreementCanonicalJson, path);
      let invocations = 0;
      const failed = await lifecycleOrchestrator(
        harness.database,
        harness.sessions,
        harness.commitments,
        {
          payment: () => {
            invocations += 1;
            return testCase.value();
          },
          settlement: () => {
            invocations += 1;
            return { ok: true, value: {} };
          },
          delivery: () => {
            invocations += 1;
            return { ok: true, value: {} };
          },
        },
      ).run({
        agreementCanonicalJson: fixture.agreementCanonicalJson,
        jobId: FIXTURE_JOB_ID,
        verification: fixture.verification,
      });
      expect(failed, testCase.name).toMatchObject({
        state: "settle-failed",
        failureStage: "payment",
        errorClass: "transient",
        reason: testCase.expectedReason,
        counts: { payment: 1, settlement: 0, delivery: 0 },
      });
      expect(invocations, testCase.name).toBe(1);
      expect(lifecycleOrchestrator(
        harness.database,
        harness.sessions,
        harness.commitments,
        successfulHandlers([]),
      ).getRecoverySnapshot(FIXTURE_JOB_ID), testCase.name).toBeNull();
      harness.database.close();

      harness = await harnessFor(fixture.agreementCanonicalJson, path, false);
      const replayInvocations: string[] = [];
      const replay = await lifecycleOrchestrator(
        harness.database,
        harness.sessions,
        harness.commitments,
        successfulHandlers(replayInvocations),
      ).run({
        agreementCanonicalJson: fixture.agreementCanonicalJson,
        jobId: FIXTURE_JOB_ID,
        verification: fixture.verification,
      });
      expect(replay, testCase.name).toEqual(failed);
      expect(replayInvocations, testCase.name).toEqual([]);
      harness.database.close();
    }
  });

  test("persists a malformed handler result as a permanent terminal failure", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    let invocations = 0;
    let trustedNow = LIFECYCLE_NOW;
    const orchestrator = lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      {
        payment: () => {
          invocations += 1;
          return null as unknown as { ok: true; value: Record<string, never> };
        },
        settlement: () => {
          invocations += 1;
          return { ok: true, value: {} };
        },
        delivery: () => {
          invocations += 1;
          return { ok: true, value: {} };
        },
        now: () => trustedNow,
      },
    );
    const input = {
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    } as const;

    const failed = await orchestrator.run(input);
    expect(failed).toMatchObject({
      state: "settle-failed",
      failureStage: "payment",
      errorClass: "permanent",
      reason: "Handler returned an invalid result",
      counts: { payment: 1, settlement: 0, delivery: 0 },
    });
    expect(invocations).toBe(1);
    expect(orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID)).toBeNull();
    const terminalSnapshot = harness.database.query<{ updatedAt: string; version: number }, []>(
      "SELECT updated_at AS updatedAt, version FROM fixture_lifecycle_runs",
    ).get();
    if (terminalSnapshot === null) throw new Error("Terminal lifecycle row missing");
    trustedNow = new Date(Date.parse(terminalSnapshot.updatedAt) + 1).toISOString();
    await expect(orchestrator.recover(input, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: "payment.failed",
      expectedUpdatedAt: terminalSnapshot.updatedAt,
      expectedVersion: Number(terminalSnapshot.version),
      minimumAgeMs: 1,
      sideEffectReconciliationConfirmed: true,
    })).rejects.toThrow(/not recoverable/);
    expect(await orchestrator.run(input)).toEqual(failed);
    expect(invocations).toBe(1);
    harness.database.close();
  });

  test("contains throwing result accessors and never spreads an untrusted result", async () => {
    const fixture = agreementFixture();
    const cases: ReadonlyArray<{
      readonly expectedReason: string;
      readonly name: string;
      readonly result: () => FixturePhaseResult;
    }> = [
      {
        name: "ok getter",
        expectedReason: "Handler result inspection threw: ok denied",
        result: () => new Proxy({}, {
          get: (target, property, receiver) => {
            if (property === "ok") throw new Error("ok denied");
            return Reflect.get(target, property, receiver) as unknown;
          },
        }) as FixturePhaseResult,
      },
      {
        name: "errorClass getter",
        expectedReason: "Handler result inspection threw: error class denied",
        result: () => ({
          ok: false,
          get errorClass(): never { throw new Error("error class denied"); },
          reason: "failure",
        }) as FixturePhaseResult,
      },
      {
        name: "reason getter",
        expectedReason: "Handler result inspection threw: reason denied",
        result: () => ({
          ok: false,
          errorClass: "permanent",
          get reason(): never { throw new Error("reason denied"); },
        }) as FixturePhaseResult,
      },
      {
        name: "ownKeys trap",
        expectedReason: "reported failure",
        result: () => new Proxy(
          { ok: false, errorClass: "permanent", reason: "reported failure" } as const,
          { ownKeys: () => { throw new Error("spread denied"); } },
        ),
      },
    ];

    for (const testCase of cases) {
      const harness = await harnessFor(fixture.agreementCanonicalJson);
      const result = await lifecycleOrchestrator(
        harness.database,
        harness.sessions,
        harness.commitments,
        {
          payment: testCase.result,
          settlement: () => ({ ok: true, value: {} }),
          delivery: () => ({ ok: true, value: {} }),
        },
      ).run({
        agreementCanonicalJson: fixture.agreementCanonicalJson,
        jobId: FIXTURE_JOB_ID,
        verification: fixture.verification,
      });

      expect(result, testCase.name).toMatchObject({
        state: "settle-failed",
        failureStage: "payment",
        errorClass: "permanent",
        reason: testCase.expectedReason,
        counts: { payment: 1, settlement: 0, delivery: 0 },
      });
      expect(lifecycleOrchestrator(
        harness.database,
        harness.sessions,
        harness.commitments,
        successfulHandlers([]),
      ).getRecoverySnapshot(FIXTURE_JOB_ID), testCase.name).toBeNull();
      harness.database.close();
    }
  });

  test("successful handlers execute once in order and replay persisted outputs", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    let harness = await harnessFor(fixture.agreementCanonicalJson, path);
    const order: string[] = [];
    const completed = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      successfulHandlers(order),
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(completed).toMatchObject({
      state: "settle-completed",
      counts: { payment: 1, settlement: 1, delivery: 1 },
      payments: [{ value: { txId: "fixture-payment" } }],
      settlements: [{ value: { evidenceHash: "fixture-evidence" } }],
      delivery: { value: { receiptHash: "fixture-delivery" } },
    });
    expect(order).toEqual(["payment", "settlement", "delivery"]);
    harness.database.close();

    harness = await harnessFor(fixture.agreementCanonicalJson, path, false);
    const replayOrder: string[] = [];
    const replay = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      successfulHandlers(replayOrder),
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(replay).toEqual(completed);
    expect(replayOrder).toEqual([]);
    harness.database.close();
  });

  test("historical commitment replay requires an explicit retained signer after key rotation", async () => {
    const secondJobId = "01J00000000000000000000001";
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    let harness = await harnessFor(fixture.agreementCanonicalJson, path);
    const completed = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      successfulHandlers([]),
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    if (completed.state !== "settle-completed") throw new Error("Historical lifecycle did not complete");

    const secondFixture = agreementFixture((input) => ({ ...input, jobId: secondJobId }));
    const secondDeployment = { entropyByte: 10, jobId: secondJobId } as const;
    const secondSessions = lifecycleSessionStore(harness.database, secondDeployment);
    admitLifecycleSession(secondSessions, secondFixture.agreementCanonicalJson, secondDeployment);
    const secondCompleted = await lifecycleOrchestrator(
      harness.database,
      secondSessions,
      harness.commitments,
      successfulHandlers([]),
    ).run({
      agreementCanonicalJson: secondFixture.agreementCanonicalJson,
      jobId: secondJobId,
      verification: secondFixture.verification,
    });
    if (secondCompleted.state !== "settle-completed") throw new Error("Second old-key lifecycle did not complete");
    expect(secondCompleted.commitment.commitmentHash).not.toBe(completed.commitment.commitmentHash);
    harness.database.close();

    harness = await harnessFor(fixture.agreementCanonicalJson, path, false);
    const rotatedSigner = createFixtureEd25519Signer(
      createHash("sha256").update("rotated-lifecycle-commitment-key").digest(),
      { deploymentMode: "fixture", authorityMode: "fixture" },
    );
    const untrusted = lifecycleCommitmentStore(harness.database, undefined, rotatedSigner);
    await expect(lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      untrusted,
      successfulHandlers([]),
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    })).rejects.toThrow(/orchestrator authority/);

    const trusted = lifecycleCommitmentStore(
      harness.database,
      undefined,
      rotatedSigner,
      [{ signer: fixtureSigner().signer, commitmentHash: completed.commitment.commitmentHash }],
    );
    const replayInvocations: string[] = [];
    const replay = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      trusted,
      successfulHandlers(replayInvocations),
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(replay).toEqual(completed);
    expect(replayInvocations).toEqual([]);
    const rotatedSecondSessions = lifecycleSessionStore(harness.database, secondDeployment);
    await expect(lifecycleOrchestrator(
      harness.database,
      rotatedSecondSessions,
      trusted,
      successfulHandlers([]),
    ).run({
      agreementCanonicalJson: secondFixture.agreementCanonicalJson,
      jobId: secondJobId,
      verification: secondFixture.verification,
    })).rejects.toThrow(/orchestrator authority/);
    harness.database.close();
  });

  test("concurrent duplicate start cannot invoke payment twice", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    let releasePayment: (() => void) | undefined;
    const paymentGate = new Promise<void>((resolve) => { releasePayment = resolve; });
    let paymentStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => { paymentStarted = resolve; });
    let paymentInvocations = 0;
    const orchestrator = lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      {
        payment: async () => {
          paymentInvocations += 1;
          paymentStarted?.();
          await paymentGate;
          return { ok: true, value: { txId: "fixture-payment" } };
        },
        settlement: () => ({ ok: true, value: { evidenceHash: "fixture-evidence" } }),
        delivery: () => ({ ok: true, value: { receiptHash: "fixture-delivery" } }),
      },
    );
    const first = orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    await started;
    await expect(orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    })).rejects.toBeInstanceOf(FixtureLifecycleInProgressError);
    releasePayment?.();
    expect((await first).state).toBe("settle-completed");
    expect(paymentInvocations).toBe(1);
    harness.database.close();
  });

  test("restart requires reconciliation proof before reissuing a recorded payment invocation", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    const session = harness.sessions.get(FIXTURE_JOB_ID);
    if (session === null) throw new Error("Fixture session missing");
    const committed = harness.commitments.commit({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      session,
      verification: fixture.verification,
    });
    if (committed.disposition !== "committed") throw new Error("Fixture commitment failed");
    harness.database.query<never, Record<string, string>>(`
      INSERT INTO fixture_lifecycle_runs (
        instance_id, audience, job_id, request_hash, agreement_artifact_hash,
        required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
        state, commitment_artifact_hash, payment_invocations, created_at, updated_at
      ) VALUES (
        $instanceId, $audience, $jobId, $requestHash, $agreementArtifactHash,
        $requiredPaymentPhasesJson, 3, 'deliver-attested-payload',
        'settle-pending', $commitmentArtifactHash, 1, $now, $now
      )
    `).run({
      instanceId: session.instanceId,
      audience: session.audience,
      jobId: session.jobId,
      requestHash: session.requestHash,
      agreementArtifactHash: committed.record.agreementArtifactHash,
      requiredPaymentPhasesJson: '[{"phaseIndex":2,"phaseKind":"pay-x402"}]',
      commitmentArtifactHash: committed.record.commitmentArtifactHash,
      now: committed.record.createdAt,
    });
    const invocations: string[] = [];
    let trustedNow = committed.record.createdAt;
    const restarted = lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      { ...successfulHandlers(invocations), now: () => trustedNow },
    );

    await expect(restarted.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    })).rejects.toThrow(/automatic side-effect replay is forbidden/);
    expect(invocations).toEqual([]);
    expect(harness.database.query<{ paymentInvocations: bigint }, []>(`
      SELECT payment_invocations AS paymentInvocations FROM fixture_lifecycle_runs
    `).get()?.paymentInvocations).toBe(1n);
    const snapshot = restarted.getRecoverySnapshot(FIXTURE_JOB_ID);
    if (snapshot?.state !== "settle-pending") throw new Error("Settlement recovery snapshot missing");
    trustedNow = new Date(Date.parse(snapshot.updatedAt) + 500).toISOString();
    const recovered = await restarted.recover({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    }, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: snapshot.boundaryId,
      expectedUpdatedAt: snapshot.updatedAt,
      expectedVersion: snapshot.version,
      minimumAgeMs: 100,
      sideEffectReconciliationConfirmed: true,
    });
    expect(recovered).toMatchObject({
      state: "settle-completed",
      counts: { payment: 1, settlement: 1, delivery: 1 },
    });
    expect(invocations).toEqual(["payment", "settlement", "delivery"]);
    harness.database.close();
  });

  test("recovers a clean settle-pending boundary before the first side effect", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    const session = harness.sessions.get(FIXTURE_JOB_ID);
    if (session === null) throw new Error("Fixture session missing");
    const committed = harness.commitments.commit({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      session,
      verification: fixture.verification,
    });
    if (committed.disposition !== "committed") throw new Error("Fixture commitment failed");
    harness.database.query<never, Record<string, string>>(`
      INSERT INTO fixture_lifecycle_runs (
        instance_id, audience, job_id, request_hash, agreement_artifact_hash,
        required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
        state, commitment_artifact_hash, created_at, updated_at
      ) VALUES (
        $instanceId, $audience, $jobId, $requestHash, $agreementArtifactHash,
        $requiredPaymentPhasesJson, 3, 'deliver-attested-payload',
        'settle-pending', $commitmentArtifactHash, $now, $now
      )
    `).run({
      instanceId: session.instanceId,
      audience: session.audience,
      jobId: session.jobId,
      requestHash: session.requestHash,
      agreementArtifactHash: committed.record.agreementArtifactHash,
      requiredPaymentPhasesJson: '[{"phaseIndex":2,"phaseKind":"pay-x402"}]',
      commitmentArtifactHash: committed.record.commitmentArtifactHash,
      now: committed.record.createdAt,
    });
    const invocations: string[] = [];
    let trustedNow = committed.record.createdAt;
    const restarted = lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      { ...successfulHandlers(invocations), now: () => trustedNow },
    );
    const snapshot = restarted.getRecoverySnapshot(FIXTURE_JOB_ID);
    if (snapshot?.state !== "settle-pending") throw new Error("Settlement recovery snapshot missing");
    trustedNow = new Date(Date.parse(snapshot.updatedAt) + 500).toISOString();
    const recovered = await restarted.recover({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    }, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: snapshot.boundaryId,
      expectedUpdatedAt: snapshot.updatedAt,
      expectedVersion: snapshot.version,
      minimumAgeMs: 100,
      sideEffectReconciliationConfirmed: true,
    });
    expect(recovered.state).toBe("settle-completed");
    expect(invocations).toEqual(["payment", "settlement", "delivery"]);
    harness.database.close();
  });

  test("persisted commitment-binding corruption blocks lifecycle replay", async () => {
    const fixture = agreementFixture();
    const harness = await harnessFor(fixture.agreementCanonicalJson);
    const completed = await lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      successfulHandlers([]),
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(completed.state).toBe("settle-completed");
    harness.database.run(`UPDATE fixture_commitments SET agreement_hash = '${"f".repeat(64)}'`);

    await expect(lifecycleOrchestrator(
      harness.database,
      harness.sessions,
      harness.commitments,
      successfulHandlers([]),
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    })).rejects.toThrow(/commitment|agreement/i);
    harness.database.close();
  });
});

async function harnessFor(
  agreementCanonicalJson: string,
  path?: string,
  admit = true,
) {
  const databasePath = path ?? await lifecycleDatabasePath();
  if (path === undefined) directories.push(dirname(databasePath));
  const database = openLifecycleDatabase(databasePath);
  const sessions = lifecycleSessionStore(database);
  if (admit) admitLifecycleSession(sessions, agreementCanonicalJson);
  const commitments = lifecycleCommitmentStore(database);
  return { commitments, database, sessions };
}

function successfulHandlers(
  order: string[],
): Pick<FixtureLifecycleOrchestratorOptions, "payment" | "settlement" | "delivery"> {
  return {
    payment: () => { order.push("payment"); return { ok: true as const, value: { txId: "fixture-payment" } }; },
    settlement: ({ payment }: FixtureLifecycleContext) => {
      expect(payment).toEqual({ txId: "fixture-payment" });
      order.push("settlement");
      return { ok: true as const, value: { evidenceHash: "fixture-evidence" } };
    },
    delivery: ({ settlements }: FixtureLifecycleContext) => {
      expect(settlements.at(-1)?.value).toEqual({ evidenceHash: "fixture-evidence" });
      order.push("delivery");
      return { ok: true as const, value: { receiptHash: "fixture-delivery" } };
    },
  };
}

function multiPaymentFixture() {
  return agreementFixture((input) => {
    const first = (input.terms["payoutBindings"] as Array<Record<string, unknown>>)[0]!;
    return {
      ...input,
      terms: {
        ...input.terms,
        payoutBindings: [
          { ...first, phaseIndex: 2 },
          { ...first, phaseIndex: 3 },
        ],
      },
    };
  }, {
    pipeline: [
      { kind: "negotiate-fixed-price" },
      { kind: "commit-payee-bound-agreement" },
      { kind: "pay-x402", parameters: { rail: "x402:default" } },
      { kind: "pay-x402", parameters: { rail: "x402:default" } },
      { kind: "deliver-attested-payload" },
    ],
  });
}
