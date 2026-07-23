import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { dirname } from "node:path";
import type { FixtureLifecycleRecoverySnapshot } from "../../src/lifecycle/fixture-orchestrator.ts";
import {
  FIXTURE_LIFECYCLE_RESTART_BOUNDARIES,
  fixtureLifecycleRestartBoundary,
  type FixtureLifecycleRestartObservation,
} from "../../src/lifecycle/restart-boundaries.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import { FixtureCommitmentStore } from "../../src/substrate/sqlite/fixture-commitment.ts";
import { FIXTURE_JOB_ID } from "../fixtures/reference-agreement.ts";
import {
  LIFECYCLE_NOW,
  admitLifecycleSession,
  agreementFixture,
  lifecycleCommitmentStore,
  lifecycleDatabasePath,
  lifecycleOrchestrator,
  lifecycleSessionStore,
  openLifecycleDatabase,
} from "../lifecycle/fixtures.ts";

const directories: string[] = [];
const ROW_TIME = "2026-07-14T23:59:00.000Z";
const RECOVERY_TIME = "2026-07-15T00:00:00.000Z";
const PAUSE_EXPIRES_AT = "2026-07-15T00:59:00.000Z";
const PAYMENT_JSON = canonicalize([{
  phaseIndex: 2,
  phaseKind: "pay-x402",
  value: { txId: "fixture-payment" },
}]);
const SETTLEMENT_JSON = canonicalize([{
  phaseIndex: 2,
  phaseKind: "pay-x402",
  value: { evidenceHash: "fixture-settlement" },
}]);

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

interface RecoveryCase {
  readonly id: string;
  readonly expectedInvocations: readonly string[];
  readonly row: SeedRow;
}

interface SeedRow {
  readonly deliveryInvocations?: number;
  readonly errorClass?: "substrate";
  readonly failureStage?: "payment" | "settlement" | "delivery";
  readonly paymentInvocations?: number;
  readonly paymentResultJson?: string;
  readonly settlementInvocations?: number;
  readonly settlementResultJson?: string;
  readonly state: "commit-pending" | "settle-pending" | "substrate-failure-paused";
  readonly withCommitment: boolean;
}

const RECOVERY_CASES: readonly RecoveryCase[] = [
  { id: "commit.before-anchor", row: { state: "commit-pending", withCommitment: false }, expectedInvocations: ["payment", "settlement", "delivery"] },
  { id: "payment.ready", row: { state: "settle-pending", withCommitment: true }, expectedInvocations: ["payment", "settlement", "delivery"] },
  { id: "payment.in-flight", row: { state: "settle-pending", withCommitment: true, paymentInvocations: 1 }, expectedInvocations: ["payment", "settlement", "delivery"] },
  { id: "settlement.ready", row: { state: "settle-pending", withCommitment: true, paymentInvocations: 1, paymentResultJson: PAYMENT_JSON }, expectedInvocations: ["settlement", "delivery"] },
  { id: "settlement.in-flight", row: { state: "settle-pending", withCommitment: true, paymentInvocations: 1, paymentResultJson: PAYMENT_JSON, settlementInvocations: 1 }, expectedInvocations: ["settlement", "delivery"] },
  { id: "delivery.ready", row: { state: "settle-pending", withCommitment: true, paymentInvocations: 1, paymentResultJson: PAYMENT_JSON, settlementInvocations: 1, settlementResultJson: SETTLEMENT_JSON }, expectedInvocations: ["delivery"] },
  { id: "delivery.in-flight", row: { state: "settle-pending", withCommitment: true, paymentInvocations: 1, paymentResultJson: PAYMENT_JSON, settlementInvocations: 1, settlementResultJson: SETTLEMENT_JSON, deliveryInvocations: 1 }, expectedInvocations: ["delivery"] },
  { id: "payment.substrate-paused", row: { state: "substrate-failure-paused", withCommitment: true, paymentInvocations: 1, failureStage: "payment", errorClass: "substrate" }, expectedInvocations: ["payment", "settlement", "delivery"] },
  { id: "settlement.substrate-paused", row: { state: "substrate-failure-paused", withCommitment: true, paymentInvocations: 1, paymentResultJson: PAYMENT_JSON, settlementInvocations: 1, failureStage: "settlement", errorClass: "substrate" }, expectedInvocations: ["settlement", "delivery"] },
  { id: "delivery.substrate-paused", row: { state: "substrate-failure-paused", withCommitment: true, paymentInvocations: 1, paymentResultJson: PAYMENT_JSON, settlementInvocations: 1, settlementResultJson: SETTLEMENT_JSON, deliveryInvocations: 1, failureStage: "delivery", errorClass: "substrate" }, expectedInvocations: ["delivery"] },
];

describe("fixture lifecycle restart matrix", () => {
  test("registry and classifier matrix cover every stable boundary exactly once", () => {
    const observations = classifierMatrix();
    const classifiedIds = observations.map((observation) =>
      fixtureLifecycleRestartBoundary(observation).id);
    expect(new Set(classifiedIds).size).toBe(classifiedIds.length);
    expect(classifiedIds.sort()).toEqual(
      FIXTURE_LIFECYCLE_RESTART_BOUNDARIES
        .filter(({ strategy }) => strategy !== "reject-impossible")
        .map(({ id }) => id)
        .sort(),
    );
    expect(() => fixtureLifecycleRestartBoundary({
      ...baseObservation(),
      commitmentPresent: true,
      state: "commit-completed",
    })).toThrow(/not restart-visible/);
    expect(FIXTURE_LIFECYCLE_RESTART_BOUNDARIES.filter(
      ({ strategy }) => strategy === "reject-impossible",
    ).map(({ id }) => id)).toEqual(["commit.atomic-transition"]);
  });

  test.each([...RECOVERY_CASES])("reopens and resumes $id without skipped or duplicate persisted phases", async ({
    id,
    expectedInvocations,
    row,
  }) => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    await seed(path, fixture.agreementCanonicalJson, fixture.verification, row);

    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const commitments = lifecycleCommitmentStore(database);
    const invocations: string[] = [];
    const orchestrator = lifecycleOrchestrator(database, sessions, commitments, {
      payment: () => { invocations.push("payment"); return { ok: true, value: { txId: "fixture-payment" } }; },
      settlement: () => { invocations.push("settlement"); return { ok: true, value: { evidenceHash: "fixture-settlement" } }; },
      delivery: () => { invocations.push("delivery"); return { ok: true, value: { receiptHash: "fixture-delivery" } }; },
      now: () => RECOVERY_TIME,
    });
    const snapshot = requiredSnapshot(orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID));
    expect(snapshot.boundaryId).toBe(id);
    expect(orchestrator.getRestartBoundary(FIXTURE_JOB_ID)?.id).toBe(id);

    const result = await orchestrator.recover({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    }, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: snapshot.boundaryId,
      expectedUpdatedAt: snapshot.updatedAt,
      expectedVersion: snapshot.version,
      minimumAgeMs: 1,
      sideEffectReconciliationConfirmed: true,
    });

    expect(result).toMatchObject({
      state: "settle-completed",
      counts: { payment: 1, settlement: 1, delivery: 1 },
    });
    expect(invocations).toEqual([...expectedInvocations]);
    expect(orchestrator.getRestartBoundary(FIXTURE_JOB_ID)?.id).toBe("settlement.completed");
    database.close();
  });

  test("adopts an actually persisted commitment after an interrupted local transition", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    let database = openLifecycleDatabase(path);
    let sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, fixture.agreementCanonicalJson);
    let commitments = lifecycleCommitmentStore(database);
    database.run(`
      CREATE TRIGGER fixture_crash_after_commitment
      BEFORE UPDATE OF state ON fixture_lifecycle_runs
      WHEN NEW.state = 'commit-completed'
      BEGIN
        SELECT RAISE(ABORT, 'simulated crash after commitment anchor');
      END
    `);
    const crashing = lifecycleOrchestrator(database, sessions, commitments, successfulHandlers([]));
    await expect(crashing.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    })).rejects.toThrow(/simulated crash after commitment anchor/);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_commitments",
    ).get()?.count).toBe(1n);
    expect(crashing.getRecoverySnapshot(FIXTURE_JOB_ID)?.boundaryId).toBe("commit.after-anchor");
    database.run("DROP TRIGGER fixture_crash_after_commitment");
    database.close();

    database = openLifecycleDatabase(path);
    sessions = lifecycleSessionStore(database);
    commitments = lifecycleCommitmentStore(database);
    const invocations: string[] = [];
    const restarted = lifecycleOrchestrator(database, sessions, commitments, {
      ...successfulHandlers(invocations),
      now: () => new Date(Date.parse(LIFECYCLE_NOW) + 1_000).toISOString(),
    });
    const snapshot = requiredSnapshot(restarted.getRecoverySnapshot(FIXTURE_JOB_ID));
    expect(snapshot.boundaryId).toBe("commit.after-anchor");
    let commitCalls = 0;
    const originalCommit = FixtureCommitmentStore.prototype.commit;
    FixtureCommitmentStore.prototype.commit = function (...args) {
      commitCalls += 1;
      return originalCommit.apply(this, args);
    };
    try {
      const result = await restarted.recover({
        agreementCanonicalJson: fixture.agreementCanonicalJson,
        jobId: FIXTURE_JOB_ID,
        verification: fixture.verification,
      }, {
        executorIsolationConfirmed: true,
        expectedBoundaryId: snapshot.boundaryId,
        expectedUpdatedAt: snapshot.updatedAt,
        expectedVersion: snapshot.version,
        minimumAgeMs: 1,
        sideEffectReconciliationConfirmed: true,
      });
      expect(result.state).toBe("settle-completed");
    } finally {
      FixtureCommitmentStore.prototype.commit = originalCommit;
    }
    expect(commitCalls).toBe(0);
    expect(invocations).toEqual(["payment", "settlement", "delivery"]);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_commitments",
    ).get()?.count).toBe(1n);
    database.close();
  });

  test("atomically rejects a commitment inserted after boundary observation", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    await seed(path, fixture.agreementCanonicalJson, fixture.verification, {
      state: "commit-pending",
      withCommitment: false,
    });
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const commitments = lifecycleCommitmentStore(database);
    const orchestrator = lifecycleOrchestrator(database, sessions, commitments, {
      ...successfulHandlers([]),
      now: () => RECOVERY_TIME,
    });
    const snapshot = requiredSnapshot(orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID));
    expect(snapshot.boundaryId).toBe("commit.before-anchor");
    const session = sessions.get(FIXTURE_JOB_ID);
    if (session === null) throw new Error("Fixture session missing");

    let injected = false;
    const originalGet = FixtureCommitmentStore.prototype.get;
    FixtureCommitmentStore.prototype.get = function (...args) {
      const existing = originalGet.apply(this, args);
      if (!injected && existing === null) {
        injected = true;
        const result = commitments.commit({
          agreementCanonicalJson: fixture.agreementCanonicalJson,
          session,
          verification: fixture.verification,
        });
        if (result.disposition !== "committed") throw new Error("Race commitment injection failed");
      }
      return existing;
    };
    try {
      await expect(orchestrator.recover({
        agreementCanonicalJson: fixture.agreementCanonicalJson,
        jobId: FIXTURE_JOB_ID,
        verification: fixture.verification,
      }, {
        executorIsolationConfirmed: true,
        expectedBoundaryId: snapshot.boundaryId,
        expectedUpdatedAt: snapshot.updatedAt,
        expectedVersion: snapshot.version,
        minimumAgeMs: 1,
        sideEffectReconciliationConfirmed: true,
      })).rejects.toThrow(/snapshot raced/);
    } finally {
      FixtureCommitmentStore.prototype.get = originalGet;
    }
    expect(injected).toBe(true);
    expect(orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID)?.boundaryId).toBe("commit.after-anchor");
    database.close();
  });

  test("rejects stale boundary identity and structurally ambiguous progress", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    await seed(path, fixture.agreementCanonicalJson, fixture.verification, {
      state: "settle-pending",
      withCommitment: true,
    });
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const commitments = lifecycleCommitmentStore(database);
    const orchestrator = lifecycleOrchestrator(database, sessions, commitments, {
      ...successfulHandlers([]),
      now: () => RECOVERY_TIME,
    });
    const snapshot = requiredSnapshot(orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID));
    await expect(orchestrator.recover({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    }, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: "delivery.ready",
      expectedUpdatedAt: snapshot.updatedAt,
      expectedVersion: snapshot.version,
      minimumAgeMs: 1,
      sideEffectReconciliationConfirmed: true,
    })).rejects.toThrow(/boundary no longer matches/);
    expect(() => fixtureLifecycleRestartBoundary({
      ...baseObservation(),
      commitmentPresent: true,
      state: "settle-pending",
      paymentInvocations: 1,
      settlementInvocations: 1,
    })).toThrow(/multiple in-flight effects/);
    expect(() => fixtureLifecycleRestartBoundary({
      ...baseObservation(),
      commitmentPresent: true,
      failureStage: "settlement",
      state: "substrate-failure-paused",
    })).toThrow(/Paused settlement progress is inconsistent/);
    expect(() => fixtureLifecycleRestartBoundary({
      ...baseObservation(),
      commitmentPresent: true,
      paymentInvocations: 2,
      paymentResults: 1,
      settlementInvocations: 1,
      settlementResults: 1,
      state: "settle-pending",
    })).toThrow(/Payment started before prior settlement completion/);
    expect(() => fixtureLifecycleRestartBoundary({
      ...baseObservation(),
      commitmentPresent: true,
      failureStage: "settlement",
      paymentInvocations: 2,
      paymentResults: 2,
      settlementInvocations: 2,
      settlementResults: 1,
      state: "substrate-failure-paused",
    })).toThrow(/Paused settlement progress is inconsistent/);
    expect(() => fixtureLifecycleRestartBoundary({
      ...baseObservation(),
      state: "settle-completed",
    })).toThrow(/Completed lifecycle progress is inconsistent/);
    expect(() => fixtureLifecycleRestartBoundary({
      ...baseObservation(),
      commitmentPresent: true,
      state: "settle-pending",
      terminalState: "aborted",
    })).toThrow(/terminal-state marker/);
    expect(() => fixtureLifecycleRestartBoundary({
      ...baseObservation(),
      commitmentPresent: true,
      failureStage: "delivery",
      state: "settle-pending",
    })).toThrow(/failure-stage marker/);
    database.close();
  });
});

async function seed(
  path: string,
  agreementCanonicalJson: string,
  verification: ReturnType<typeof agreementFixture>["verification"],
  row: SeedRow,
): Promise<void> {
  const database = openLifecycleDatabase(path);
  const sessions = lifecycleSessionStore(database);
  admitLifecycleSession(sessions, agreementCanonicalJson);
  const session = sessions.get(FIXTURE_JOB_ID);
  if (session === null) throw new Error("Fixture session missing");
  const commitments = lifecycleCommitmentStore(database);
  const commitment = row.withCommitment
    ? commitments.commit({ agreementCanonicalJson, session, verification }) : undefined;
  if (commitment !== undefined && commitment.disposition !== "committed") {
    throw new Error("Fixture commitment failed");
  }
  const paused = row.state === "substrate-failure-paused";
  database.query<never, Record<string, string | number | null>>(`
    INSERT INTO fixture_lifecycle_runs (
      instance_id, audience, job_id, request_hash, agreement_artifact_hash,
      required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
      state, commitment_artifact_hash,
      payment_invocations, settlement_invocations, delivery_invocations,
      payment_result_json, settlement_result_json,
      failure_stage, error_class, failure_reason, paused_at, pause_expires_at,
      created_at, updated_at
    ) VALUES (
      $instanceId, $audience, $jobId, $requestHash, $agreementArtifactHash,
      '[{"phaseIndex":2,"phaseKind":"pay-x402"}]', 3, 'deliver-attested-payload',
      $state, $commitmentArtifactHash,
      $paymentInvocations, $settlementInvocations, $deliveryInvocations,
      $paymentResultJson, $settlementResultJson,
      $failureStage, $errorClass, $failureReason, $pausedAt, $pauseExpiresAt,
      $createdAt, $updatedAt
    )
  `).run({
    instanceId: session.instanceId,
    audience: session.audience,
    jobId: session.jobId,
    requestHash: session.requestHash,
    agreementArtifactHash: commitment?.record.agreementArtifactHash ?? sha256Hex(agreementCanonicalJson),
    state: row.state,
    commitmentArtifactHash: row.state === "commit-pending"
      ? null : commitment?.record.commitmentArtifactHash ?? null,
    paymentInvocations: row.paymentInvocations ?? 0,
    settlementInvocations: row.settlementInvocations ?? 0,
    deliveryInvocations: row.deliveryInvocations ?? 0,
    paymentResultJson: row.paymentResultJson ?? null,
    settlementResultJson: row.settlementResultJson ?? null,
    failureStage: row.failureStage ?? null,
    errorClass: row.errorClass ?? null,
    failureReason: paused ? "fixture substrate unavailable" : null,
    pausedAt: paused ? ROW_TIME : null,
    pauseExpiresAt: paused ? PAUSE_EXPIRES_AT : null,
    createdAt: ROW_TIME,
    updatedAt: ROW_TIME,
  });
  database.close();
}

function successfulHandlers(invocations: string[]) {
  return {
    payment: () => { invocations.push("payment"); return { ok: true as const, value: { txId: "fixture-payment" } }; },
    settlement: () => { invocations.push("settlement"); return { ok: true as const, value: { evidenceHash: "fixture-settlement" } }; },
    delivery: () => { invocations.push("delivery"); return { ok: true as const, value: { receiptHash: "fixture-delivery" } }; },
    now: () => LIFECYCLE_NOW,
  };
}

function requiredSnapshot(snapshot: FixtureLifecycleRecoverySnapshot | null): FixtureLifecycleRecoverySnapshot {
  if (snapshot === null) throw new Error("Recovery snapshot missing");
  return snapshot;
}

function baseObservation(): FixtureLifecycleRestartObservation {
  return {
    commitmentPresent: false,
    deliveryInvocations: 0,
    deliveryResultPresent: false,
    failureStage: null,
    paymentInvocations: 0,
    paymentResults: 0,
    requiredPaymentCount: 1,
    settlementInvocations: 0,
    settlementResults: 0,
    state: "commit-pending",
    terminalState: null,
  };
}

function classifierMatrix(): FixtureLifecycleRestartObservation[] {
  const base = baseObservation();
  const pending = { ...base, commitmentPresent: true, state: "settle-pending" };
  const terminal = { ...base, commitmentPresent: true };
  const completed = {
    ...terminal,
    deliveryInvocations: 1,
    deliveryResultPresent: true,
    paymentInvocations: 1,
    paymentResults: 1,
    settlementInvocations: 1,
    settlementResults: 1,
  };
  return [
    base,
    { ...base, commitmentPresent: true },
    pending,
    { ...pending, paymentInvocations: 1 },
    { ...pending, paymentInvocations: 1, paymentResults: 1 },
    { ...pending, paymentInvocations: 1, paymentResults: 1, settlementInvocations: 1 },
    { ...pending, paymentInvocations: 1, paymentResults: 1, settlementInvocations: 1, settlementResults: 1 },
    { ...pending, paymentInvocations: 1, paymentResults: 1, settlementInvocations: 1, settlementResults: 1, deliveryInvocations: 1 },
    { ...pending, state: "substrate-failure-paused", failureStage: "payment", paymentInvocations: 1 },
    { ...pending, state: "substrate-failure-paused", failureStage: "settlement", paymentInvocations: 1, paymentResults: 1, settlementInvocations: 1 },
    { ...pending, state: "substrate-failure-paused", failureStage: "delivery", paymentInvocations: 1, paymentResults: 1, settlementInvocations: 1, settlementResults: 1, deliveryInvocations: 1 },
    { ...terminal, state: "commit-failed", failureStage: "commit" },
    ...terminalStageObservations(terminal, "settle-failed"),
    ...terminalStageObservations(terminal, "settle-unsupported"),
    ...terminalStageObservations(terminal, "failed-substrate"),
    { ...terminal, state: "aborted" },
    { ...completed, state: "settle-completed" },
    { ...completed, state: "finalised" },
    ...(["settle-failed", "settle-unsupported", "failed-substrate", "aborted"] as const).map(
      (terminalState) => terminalState === "aborted"
        ? ({ ...terminal, state: "finalised", terminalState })
        : terminalStageObservation(terminal, "finalised", "payment", terminalState),
    ),
  ];
}

function terminalStageObservations(
  base: FixtureLifecycleRestartObservation,
  state: "settle-failed" | "settle-unsupported" | "failed-substrate",
): FixtureLifecycleRestartObservation[] {
  return (["payment", "settlement", "delivery"] as const).map((failureStage) =>
    terminalStageObservation(base, state, failureStage));
}

function terminalStageObservation(
  base: FixtureLifecycleRestartObservation,
  state: "settle-failed" | "settle-unsupported" | "failed-substrate" | "finalised",
  failureStage: "payment" | "settlement" | "delivery",
  terminalState: FixtureLifecycleRestartObservation["terminalState"] = null,
): FixtureLifecycleRestartObservation {
  const progress = failureStage === "payment"
    ? { paymentInvocations: 1 }
    : failureStage === "settlement"
      ? { paymentInvocations: 1, paymentResults: 1, settlementInvocations: 1 }
      : {
          deliveryInvocations: 1,
          paymentInvocations: 1,
          paymentResults: 1,
          settlementInvocations: 1,
          settlementResults: 1,
        };
  return { ...base, ...progress, failureStage, state, terminalState };
}
