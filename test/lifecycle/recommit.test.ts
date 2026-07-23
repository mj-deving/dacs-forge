import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { dirname } from "node:path";
import { FIXTURE_JOB_ID } from "../fixtures/reference-agreement.ts";
import {
  admitLifecycleSession,
  agreementFixture,
  lifecycleCommitmentStore,
  lifecycleDatabasePath,
  lifecycleOrchestrator,
  lifecycleSessionStore,
  openLifecycleDatabase,
} from "./fixtures.ts";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("immutable agreement commitment", () => {
  test("identical re-commitment transitions to commit-failed with no downstream invocation", async () => {
    const fixture = agreementFixture();
    const harness = await precommittedHarness(fixture.agreementCanonicalJson, fixture.verification);
    const result = await harness.orchestrator.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });

    expect(result).toMatchObject({
      state: "commit-failed",
      failureStage: "commit",
      errorClass: "permanent",
      counts: { payment: 0, settlement: 0, delivery: 0 },
      reason: expect.stringContaining("recommit"),
    });
    expect(harness.invocations).toEqual([]);
    expect(harness.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_commitments",
    ).get()?.count).toBe(1n);
    harness.database.close();
  });

  test("different re-commitment is rejected before payment and preserves the first anchor", async () => {
    const first = agreementFixture();
    const second = agreementFixture((input) => ({
      ...input,
      generatedAt: input.generatedAt - 1,
      fixtureRevision: "different-signed-agreement",
    }));
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const firstSessions = lifecycleSessionStore(database);
    admitLifecycleSession(firstSessions, first.agreementCanonicalJson);
    const firstCommitments = lifecycleCommitmentStore(database);
    const firstSession = firstSessions.get(FIXTURE_JOB_ID);
    if (firstSession === null) throw new Error("First fixture session missing");
    expect(firstCommitments.commit({
      agreementCanonicalJson: first.agreementCanonicalJson,
      session: firstSession,
      verification: first.verification,
    }).disposition).toBe("committed");
    const original = firstCommitments.get(
      "reference-lifecycle-instance",
      "https://lifecycle.service.example",
      FIXTURE_JOB_ID,
    );
    expect(() => firstCommitments.commit({
      agreementCanonicalJson: second.agreementCanonicalJson,
      session: firstSession,
      verification: second.verification,
    })).toThrow(/does not match the persisted admitted request binding/);
    expect(firstCommitments.get(
      "reference-lifecycle-instance",
      "https://lifecycle.service.example",
      FIXTURE_JOB_ID,
    )?.commitmentHash).toBe(original?.commitmentHash);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_commitments",
    ).get()?.count).toBe(1n);
    database.close();
  });
});

async function precommittedHarness(
  agreementCanonicalJson: string,
  verification: ReturnType<typeof agreementFixture>["verification"],
) {
  const path = await lifecycleDatabasePath();
  directories.push(dirname(path));
  const database = openLifecycleDatabase(path);
  const sessions = lifecycleSessionStore(database);
  admitLifecycleSession(sessions, agreementCanonicalJson);
  const commitments = lifecycleCommitmentStore(database);
  const session = sessions.get(FIXTURE_JOB_ID);
  if (session === null) throw new Error("Fixture session missing");
  expect(commitments.commit({ agreementCanonicalJson, session, verification }).disposition)
    .toBe("committed");
  const invocations: string[] = [];
  const orchestrator = lifecycleOrchestrator(database, sessions, commitments, {
    payment: () => { invocations.push("payment"); return { ok: true, value: {} }; },
    settlement: () => { invocations.push("settlement"); return { ok: true, value: {} }; },
    delivery: () => { invocations.push("delivery"); return { ok: true, value: {} }; },
  });
  return { database, commitments, invocations, orchestrator };
}
