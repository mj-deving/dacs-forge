import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { createFixtureAttestedDeliveryHandler } from "../../src/lifecycle/fixture-attested-delivery-handler.ts";
import type { FixtureLifecycleContext } from "../../src/lifecycle/fixture-orchestrator.ts";
import { FixtureDeliveryStore } from "../../src/substrate/sqlite/fixture-delivery.ts";
import { FIXTURE_COMMITTED_AT } from "../fixtures/reference-agreement.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
import {
  DELIVERY_PAYLOAD_JSON,
  DELIVERY_PAYMENT_AMOUNT,
  DELIVERY_PAYLOAD_FORMAT,
} from "../delivery/fixtures.ts";
import {
  admitLifecycleSession,
  agreementFixture,
  lifecycleCommitmentStore,
  lifecycleDatabasePath,
  lifecycleOrchestrator,
  lifecycleSessionStore,
  openLifecycleDatabase,
} from "./fixtures.ts";

const paths: string[] = [];
const NOW = new Date(FIXTURE_COMMITTED_AT + 1_000).toISOString();

afterEach(async () => {
  await Promise.all(paths.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("lifecycle attested delivery adapter", () => {
  test("anchors and verifies attested delivery before lifecycle success, then replays after restart", async () => {
    const path = await lifecycleDatabasePath();
    paths.push(path.slice(0, path.lastIndexOf("/")));
    let database = openLifecycleDatabase(path);
    let sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    let commitment = lifecycleCommitmentStore(database);
    let deliveries = new FixtureDeliveryStore(database, { deploymentMode: "fixture", signer: fixtureSigner() });
    let deliveryCalls = 0;
    const delivery = createFixtureAttestedDeliveryHandler(deliveries, {
      now: () => NOW,
      observedAt: () => FIXTURE_COMMITTED_AT + 1_000,
      payloadFormat: DELIVERY_PAYLOAD_FORMAT,
      payloadJson: () => {
        deliveryCalls += 1;
        return DELIVERY_PAYLOAD_JSON;
      },
      paymentAmount: DELIVERY_PAYMENT_AMOUNT,
      sessionStore: sessions,
    });
    let orchestrator = lifecycleOrchestrator(database, sessions, commitment, {
      payment: () => ({ ok: true, value: { submitted: true } }),
      settlement: () => ({ ok: true, value: { settled: true } }),
      delivery,
    });
    const result = await orchestrator.run({
      agreementCanonicalJson: agreement.agreementCanonicalJson,
      jobId: agreement.input.jobId,
      verification: agreement.verification,
    });
    expect(result.state).toBe("settle-completed");
    expect(deliveryCalls).toBe(1);
    const session = sessions.get(agreement.input.jobId)!;
    const delivered = deliveries.get(session);
    expect(delivered).not.toBeNull();
    expect(result.state === "settle-completed" ? result.delivery.value["evidenceHash"] : undefined)
      .toBe(delivered?.evidenceHash);
    database.close();

    database = openLifecycleDatabase(path);
    sessions = lifecycleSessionStore(database);
    commitment = lifecycleCommitmentStore(database);
    deliveries = new FixtureDeliveryStore(database, { deploymentMode: "fixture", signer: fixtureSigner() });
    orchestrator = lifecycleOrchestrator(database, sessions, commitment, {
      payment: () => { throw new Error("payment replayed"); },
      settlement: () => { throw new Error("settlement replayed"); },
      delivery: () => { throw new Error("delivery replayed"); },
    });
    expect(orchestrator.get(agreement.input.jobId)?.state).toBe("settle-completed");
    expect(deliveries.get(sessions.get(agreement.input.jobId)!)?.evidenceHash).toBe(delivered?.evidenceHash);
    expect(deliveryCalls).toBe(1);
    database.close();
  });

  test("invalid cleartext fails delivery without a partial delivery anchor", async () => {
    const path = await lifecycleDatabasePath();
    paths.push(path.slice(0, path.lastIndexOf("/")));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const commitment = lifecycleCommitmentStore(database);
    const deliveries = new FixtureDeliveryStore(database, { deploymentMode: "fixture", signer: fixtureSigner() });
    const delivery = createFixtureAttestedDeliveryHandler(deliveries, {
      now: () => NOW,
      observedAt: () => FIXTURE_COMMITTED_AT + 1_000,
      payloadFormat: DELIVERY_PAYLOAD_FORMAT,
      payloadJson: "{invalid",
      paymentAmount: DELIVERY_PAYMENT_AMOUNT,
      sessionStore: sessions,
    });
    const orchestrator = lifecycleOrchestrator(database, sessions, commitment, {
      payment: () => ({ ok: true, value: { submitted: true } }),
      settlement: () => ({ ok: true, value: { settled: true } }),
      delivery,
    });
    const result = await orchestrator.run({
      agreementCanonicalJson: agreement.agreementCanonicalJson,
      jobId: agreement.input.jobId,
      verification: agreement.verification,
    });
    expect(result).toMatchObject({ state: "settle-failed", failureStage: "delivery" });
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_deliveries",
    ).get()!.count).toBe(0n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_anchors",
    ).get()!.count).toBe(0n);
    database.close();
  });

  test("SQLite delivery failure enters ST-7 pause and commits no partial anchors", async () => {
    const path = await lifecycleDatabasePath();
    paths.push(path.slice(0, path.lastIndexOf("/")));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const commitment = lifecycleCommitmentStore(database);
    const deliveries = new FixtureDeliveryStore(database, { deploymentMode: "fixture", signer: fixtureSigner() });
    database.run(`
      CREATE TRIGGER fixture_delivery_substrate_failure
      BEFORE INSERT ON fixture_deliveries
      BEGIN SELECT RAISE(ABORT, 'forced delivery substrate failure'); END;
    `);
    const delivery = createFixtureAttestedDeliveryHandler(deliveries, {
      now: () => NOW,
      observedAt: () => FIXTURE_COMMITTED_AT + 1_000,
      payloadFormat: DELIVERY_PAYLOAD_FORMAT,
      payloadJson: DELIVERY_PAYLOAD_JSON,
      paymentAmount: DELIVERY_PAYMENT_AMOUNT,
      sessionStore: sessions,
    });
    const orchestrator = lifecycleOrchestrator(database, sessions, commitment, {
      payment: () => ({ ok: true, value: { submitted: true } }),
      settlement: () => ({ ok: true, value: { settled: true } }),
      delivery,
    });
    const result = await orchestrator.run({
      agreementCanonicalJson: agreement.agreementCanonicalJson,
      jobId: agreement.input.jobId,
      verification: agreement.verification,
    });
    expect(result).toMatchObject({
      state: "substrate-failure-paused",
      failureStage: "delivery",
      errorClass: "substrate",
    });
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_deliveries",
    ).get()!.count).toBe(0n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_anchors",
    ).get()!.count).toBe(0n);
    database.close();
  });

  test("post-commit indeterminate evidence read enters ST-7 with the delivery intact", async () => {
    const path = await lifecycleDatabasePath();
    paths.push(path.slice(0, path.lastIndexOf("/")));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const commitment = lifecycleCommitmentStore(database);
    const deliveries = new FixtureDeliveryStore(database, { deploymentMode: "fixture", signer: fixtureSigner() });
    Object.defineProperty(deliveries, "readEvidenceAnchor", {
      value: () => ({ status: "indeterminate", reason: "forced post-commit read outage" }),
    });
    const delivery = createFixtureAttestedDeliveryHandler(deliveries, {
      now: () => NOW,
      observedAt: () => FIXTURE_COMMITTED_AT + 1_000,
      payloadFormat: DELIVERY_PAYLOAD_FORMAT,
      payloadJson: DELIVERY_PAYLOAD_JSON,
      paymentAmount: DELIVERY_PAYMENT_AMOUNT,
      sessionStore: sessions,
    });
    const orchestrator = lifecycleOrchestrator(database, sessions, commitment, {
      payment: () => ({ ok: true, value: { submitted: true } }),
      settlement: () => ({ ok: true, value: { settled: true } }),
      delivery,
    });
    const result = await orchestrator.run({
      agreementCanonicalJson: agreement.agreementCanonicalJson,
      jobId: agreement.input.jobId,
      verification: agreement.verification,
    });
    expect(result).toMatchObject({
      state: "substrate-failure-paused",
      failureStage: "delivery",
      errorClass: "substrate",
    });
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_deliveries",
    ).get()!.count).toBe(1n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_anchors",
    ).get()!.count).toBe(4n);
    database.close();
  });

  test("contains session-store read failures as substrate results", async () => {
    const fixture = await openLifecycleDatabaseForHandler();
    const delivery = createFixtureAttestedDeliveryHandler(fixture.deliveries, {
      now: () => NOW,
      observedAt: () => FIXTURE_COMMITTED_AT + 1_000,
      payloadFormat: DELIVERY_PAYLOAD_FORMAT,
      payloadJson: DELIVERY_PAYLOAD_JSON,
      paymentAmount: DELIVERY_PAYMENT_AMOUNT,
      sessionStore: { get: () => { throw new Error("forced session read failure"); } },
    });
    const result = await delivery({
      agreementHash: "a".repeat(64),
      commitment: {} as FixtureLifecycleContext["commitment"],
      evidenceMode: "fixture",
      jobId: agreementFixture().input.jobId,
      payments: [],
      phaseIndex: 3,
      phaseKind: "deliver-attested-payload",
      settlements: [],
    });
    expect(result).toEqual({
      ok: false,
      errorClass: "substrate",
      reason: "Fixture attested delivery session read failed",
    });
    fixture.database.close();
  });
});

async function openLifecycleDatabaseForHandler() {
  const path = await lifecycleDatabasePath();
  paths.push(path.slice(0, path.lastIndexOf("/")));
  const database = openLifecycleDatabase(path);
  return {
    database,
    deliveries: new FixtureDeliveryStore(database, {
      deploymentMode: "fixture",
      signer: fixtureSigner(),
    }),
  };
}
