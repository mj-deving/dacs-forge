import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import { ArtifactStore } from "../../src/substrate/sqlite/artifact-store.ts";
import { fixtureLifecycleRequestHash } from "../../src/lifecycle/fixture-orchestrator.ts";
import { FixtureBilateralVetOrchestrator } from "../../src/lifecycle/fixture-vet-orchestrator.ts";
import { signBuyerVetRequirement } from "../../src/producer/buyer-vet-requirement.ts";
import { legacyFixtureCommitmentRequestHash } from "../../src/substrate/sqlite/fixture-commitment.ts";
import { FixtureVetStore } from "../../src/substrate/sqlite/fixture-vet.ts";
import {
  FIXTURE_COMMITTED_AT,
  FIXTURE_JOB_ID,
  buyerFixtureSigner,
  fixtureBuyerIdentity,
  fixtureListingSellerIdentity,
  fixtureSignedPaidListing,
} from "../fixtures/reference-agreement.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
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

describe("commitment failure stop boundary", () => {
  test("refuses a revoked Listing from the independent commitment authority", async () => {
    const fixture = agreementFixture();
    const result = await runFailure(fixture.agreementCanonicalJson, {
      ...fixture.verification,
      listingAuthority: {
        ...fixture.verification.listingAuthority,
        revocationCheck: () => "revoked",
      },
    }, FIXTURE_COMMITTED_AT);

    expect(result.lifecycle).toMatchObject({
      state: "commit-failed",
      failureStage: "commit",
      counts: { payment: 0, settlement: 0, delivery: 0 },
      reason: expect.stringContaining("Listing authority is invalid: revocation"),
    });
    expect(result.commitmentCount).toBe(0n);
    expect(result.invocations).toEqual([]);
  });

  test("pre-anchor signature rejection persists commit-failed and invokes nothing downstream", async () => {
    const fixture = agreementFixture();
    const poisoned = JSON.parse(fixture.agreementCanonicalJson) as {
      signatures: Array<{ value: string }>;
    };
    poisoned.signatures[0]!.value = "A".repeat(86);
    const result = await runFailure(canonicalize(poisoned), fixture.verification, FIXTURE_COMMITTED_AT);

    expect(result.lifecycle).toMatchObject({
      state: "commit-failed",
      failureStage: "commit",
      counts: { payment: 0, settlement: 0, delivery: 0 },
      reason: expect.stringContaining("pre-anchor"),
    });
    expect(result.commitmentCount).toBe(0n);
    expect(result.invocations).toEqual([]);
  });

  test("post-anchor expiry rejection retains the immutable anchor but invokes nothing downstream", async () => {
    const fixture = postAnchorExpiredFixture();
    const result = await runFailure(
      fixture.agreementCanonicalJson,
      fixture.verification,
      FIXTURE_COMMITTED_AT + 500_000,
    );

    expect(result.lifecycle).toMatchObject({
      state: "commit-failed",
      failureStage: "commit",
      counts: { payment: 0, settlement: 0, delivery: 0 },
      reason: expect.stringContaining("post-anchor"),
      commitment: { logicalAddress: `dacs3:commit:${FIXTURE_JOB_ID}` },
    });
    expect(result.commitmentCount).toBe(1n);
    expect(result.invocations).toEqual([]);
  });

  test("terminal commit failure replays after restart without invoking handlers", async () => {
    const fixture = postAnchorExpiredFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    let database = openLifecycleDatabase(path);
    let sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, fixture.agreementCanonicalJson);
    let commitments = lifecycleCommitmentStore(database, FIXTURE_COMMITTED_AT + 500_000);
    const firstInvocations: string[] = [];
    const first = lifecycleOrchestrator(database, sessions, commitments, handlers(firstInvocations));
    const failed = await first.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(first.getRestartBoundary(FIXTURE_JOB_ID)?.id).toBe("commit.failed");
    database.close();

    database = openLifecycleDatabase(path);
    sessions = lifecycleSessionStore(database);
    commitments = lifecycleCommitmentStore(database, FIXTURE_COMMITTED_AT + 500_000);
    const replayInvocations: string[] = [];
    const restarted = lifecycleOrchestrator(
      database,
      sessions,
      commitments,
      handlers(replayInvocations),
    );
    expect(restarted.getRestartBoundary(FIXTURE_JOB_ID)?.id).toBe("commit.failed");
    const replay = await restarted.run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });

    expect(replay).toEqual(failed);
    expect(firstInvocations).toEqual([]);
    expect(replayInvocations).toEqual([]);
    database.close();
  });

  test("rejects an agreement not bound by admission before lifecycle persistence", async () => {
    const admittedFixture = agreementFixture();
    const substitutedFixture = agreementFixture((input) => ({
      ...input,
      generatedAt: input.generatedAt - 1,
      substitution: "different-valid-agreement",
    }));
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, admittedFixture.agreementCanonicalJson);
    const invocations: string[] = [];
    const orchestrator = lifecycleOrchestrator(
      database,
      sessions,
      lifecycleCommitmentStore(database),
      handlers(invocations),
    );

    await expect(orchestrator.run({
      agreementCanonicalJson: substitutedFixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: substitutedFixture.verification,
    })).rejects.toThrow(/admitted request hash/);
    expect(invocations).toEqual([]);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_lifecycle_runs",
    ).get()?.count).toBe(0n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_commitments",
    ).get()?.count).toBe(0n);
    database.close();
  });

  test("admits post-Vet reference maturity but blocks fabricated composites before effects", async () => {
    const admittedFixture = agreementFixture();
    const vettedFixture = agreementFixture((input) => ({
      ...input,
      parties: input.parties.map((party) => ({
        ...party,
        vetRecordRef: {
          anchor: { kind: "storage-program", locator: `dacs2:composite:${input.jobId}:${party.role}` },
          contentHash: party.role === "buyer" ? "a".repeat(64) : "b".repeat(64),
        },
      })),
    }));
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, admittedFixture.agreementCanonicalJson);
    const session = sessions.get(FIXTURE_JOB_ID);
    if (session === null) throw new Error("Fixture session missing");
    const invocations: string[] = [];
    const orchestrator = lifecycleOrchestrator(
      database,
      sessions,
      lifecycleCommitmentStore(database),
      handlers(invocations),
    );

    expect(fixtureLifecycleRequestHash(vettedFixture.agreementCanonicalJson)).toBe(session.requestHash);
    const result = await orchestrator.run({
      agreementCanonicalJson: vettedFixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: vettedFixture.verification,
    });
    expect(result).toMatchObject({
      state: "commit-failed",
      errorClass: "permanent",
      failureStage: "commit",
    });
    expect(invocations).toEqual([]);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_commitments",
    ).get()!.count).toBe(0n);
    database.close();
  });

  test("rechecks committed Vet authority immediately before every lifecycle effect", async () => {
    const placeholder = agreementFixture();
    const listing = fixtureSignedPaidListing();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, placeholder.agreementCanonicalJson);
    const session = sessions.get(FIXTURE_JOB_ID)!;
    const generatedAt = FIXTURE_COMMITTED_AT - 500;
    const buyerRequirement = signBuyerVetRequirement({
      jobId: FIXTURE_JOB_ID,
      buyer: buyerFixtureSigner().signer,
      seller: fixtureSigner().signer,
      requirement: { required: [{ scheme: "key" }] },
      generatedAt,
    }, buyerFixtureSigner(), { deploymentMode: "fixture", requestMode: "fixture" });
    const vet = new FixtureBilateralVetOrchestrator(new FixtureVetStore(database, "fixture")).run({
      buyer: {
        session,
        evaluatedRole: "buyer",
        evaluatedBundleHash: fixtureBuyerIdentity().bundleHash,
        requirementAuthority: { kind: "seller-listing", canonicalJson: listing.canonicalJson },
        evaluatedSigner: buyerFixtureSigner(),
        verifierSigner: fixtureSigner(),
        generatedAt,
        createdAt: new Date(generatedAt).toISOString(),
      },
      seller: {
        session,
        evaluatedRole: "seller",
        evaluatedBundleHash: fixtureListingSellerIdentity(listing).bundleHash,
        requirementAuthority: { kind: "buyer-signed", canonicalJson: buyerRequirement.canonicalJson },
        evaluatedSigner: fixtureSigner(),
        verifierSigner: buyerFixtureSigner(),
        generatedAt,
        createdAt: new Date(generatedAt).toISOString(),
      },
    });
    if (vet.state !== "passed") throw new Error(JSON.stringify(vet));
    const fixture = agreementFixture((input) => ({
      ...input,
      parties: input.parties.map((party) => ({
        ...party,
        vetRecordRef: party.role === "buyer"
          ? vet.buyer.compositeReference : vet.seller.compositeReference,
      })),
    }));
    const commitmentStore = lifecycleCommitmentStore(database);
    const commit = commitmentStore.commit.bind(commitmentStore);
    Object.defineProperty(commitmentStore, "commit", {
      value: (input: Parameters<typeof commitmentStore.commit>[0]) => {
        const result = commit(input);
        if (result.disposition === "committed") {
          database.query<never, { jobId: string }>(`
            UPDATE fixture_vet_records SET recipe_availability = 'failed'
            WHERE job_id = $jobId AND evaluated_role = 'buyer'
          `).run({ jobId: FIXTURE_JOB_ID });
        }
        return result;
      },
    });
    const invocations: string[] = [];
    const result = await lifecycleOrchestrator(
      database,
      sessions,
      commitmentStore,
      handlers(invocations),
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });
    expect(result).toMatchObject({
      state: "commit-failed",
      failureStage: "commit",
      errorClass: "permanent",
    });
    expect(invocations).toEqual([]);
    database.close();
  });

  test("preserves a genuine legacy-v1 admitted Agreement hash across schema migration", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    let database = openLifecycleDatabase(path);
    let sessions = lifecycleSessionStore(database);
    admitLifecycleSession(
      sessions,
      fixture.agreementCanonicalJson,
      {},
      legacyFixtureCommitmentRequestHash(fixture.agreementCanonicalJson),
    );
    database.run("PRAGMA user_version = 16");
    database.close();

    database = openLifecycleDatabase(path);
    sessions = lifecycleSessionStore(database);
    const session = sessions.get(FIXTURE_JOB_ID)!;
    expect(lifecycleCommitmentStore(database).commit({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      session,
      verification: fixture.verification,
    }).disposition).toBe("committed");
    expect(database.query<{ user_version: bigint }, []>(
      "PRAGMA user_version",
    ).get()!.user_version).toBe(19n);
    database.close();
  });

  test("direct commitment-store use cannot bypass the persisted admission binding", async () => {
    const admitted = agreementFixture();
    const substituted = agreementFixture((input) => ({
      ...input,
      generatedAt: input.generatedAt - 1,
      substitution: "direct-store-bypass",
    }));
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, admitted.agreementCanonicalJson);
    const session = sessions.get(FIXTURE_JOB_ID);
    if (session === null) throw new Error("Fixture session missing");
    const commitments = lifecycleCommitmentStore(database);

    expect(() => commitments.commit({
      agreementCanonicalJson: substituted.agreementCanonicalJson,
      session,
      verification: substituted.verification,
    })).toThrow(/persisted admitted request binding/);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_commitments",
    ).get()?.count).toBe(0n);
    database.close();
  });

  test("readback re-verifies persisted agreement signatures, not only the unsigned hash", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, fixture.agreementCanonicalJson);
    const session = sessions.get(FIXTURE_JOB_ID);
    if (session === null) throw new Error("Fixture session missing");
    const commitments = lifecycleCommitmentStore(database);
    expect(commitments.commit({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      session,
      verification: fixture.verification,
    }).disposition).toBe("committed");
    const poisoned = JSON.parse(fixture.agreementCanonicalJson) as {
      signatures: Array<{ value: string }>;
    };
    poisoned.signatures[0]!.value = "A".repeat(86);
    const poisonedArtifact = new ArtifactStore(database).put(
      "dacs-3-payee-bound-agreement",
      poisoned,
      "2026-07-15T00:00:01.000Z",
    );
    database.query<never, { hash: string }>(
      "UPDATE fixture_commitments SET agreement_artifact_hash = $hash",
    ).run({ hash: poisonedArtifact.contentHash });

    expect(() => commitments.get(session.instanceId, session.audience, session.jobId))
      .toThrow(/agreement commitment binding is corrupt/);
    database.close();
  });

  test("recovers a stale commit claim before any anchor was created", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, fixture.agreementCanonicalJson);
    const session = sessions.get(FIXTURE_JOB_ID);
    if (session === null) throw new Error("Fixture session missing");
    database.query<never, Record<string, string | number>>(`
      INSERT INTO fixture_lifecycle_runs (
        instance_id, audience, job_id, request_hash, agreement_artifact_hash,
        required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
        state, created_at, updated_at
      ) VALUES (
        $instanceId, $audience, $jobId, $requestHash, $agreementArtifactHash,
        '[{"phaseIndex":2,"phaseKind":"pay-x402"}]', 3, 'deliver-attested-payload',
        'commit-pending', $now, $now
      )
    `).run({
      instanceId: session.instanceId,
      audience: session.audience,
      jobId: session.jobId,
      requestHash: session.requestHash,
      agreementArtifactHash: sha256Hex(fixture.agreementCanonicalJson),
      now: "2026-07-14T23:55:00.000Z",
    });
    const commitments = lifecycleCommitmentStore(database);
    const invocations: string[] = [];
    const orchestrator = lifecycleOrchestrator(database, sessions, commitments, {
      ...handlers(invocations),
      now: () => "2026-07-15T00:00:00.000Z",
    });
    const snapshot = orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID);
    if (snapshot?.state !== "commit-pending") throw new Error("Commit recovery snapshot missing");
    const completed = await orchestrator.recover({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    }, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: snapshot.boundaryId,
      expectedUpdatedAt: snapshot.updatedAt,
      expectedVersion: snapshot.version,
      minimumAgeMs: 60_000,
      sideEffectReconciliationConfirmed: true,
    });

    expect(completed.state).toBe("settle-completed");
    expect(invocations).toEqual(["payment", "settlement", "delivery"]);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_commitments",
    ).get()?.count).toBe(1n);
    database.close();
  });

  test("recovers a crash after anchor persistence by adopting only the exact verified commitment", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, fixture.agreementCanonicalJson);
    const session = sessions.get(FIXTURE_JOB_ID);
    if (session === null) throw new Error("Fixture session missing");
    const commitments = lifecycleCommitmentStore(database);
    database.query<never, Record<string, string | number>>(`
      INSERT INTO fixture_lifecycle_runs (
        instance_id, audience, job_id, request_hash, agreement_artifact_hash,
        required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
        state, created_at, updated_at
      ) VALUES (
        $instanceId, $audience, $jobId, $requestHash, $agreementArtifactHash,
        '[{"phaseIndex":2,"phaseKind":"pay-x402"}]', 3, 'deliver-attested-payload',
        'commit-pending', $now, $now
      )
    `).run({
      instanceId: session.instanceId,
      audience: session.audience,
      jobId: session.jobId,
      requestHash: session.requestHash,
      agreementArtifactHash: sha256Hex(fixture.agreementCanonicalJson),
      now: "2026-07-14T23:55:00.000Z",
    });
    expect(commitments.commit({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      session,
      verification: fixture.verification,
    }).disposition).toBe("committed");
    const invocations: string[] = [];
    const orchestrator = lifecycleOrchestrator(database, sessions, commitments, {
      ...handlers(invocations),
      now: () => "2026-07-15T00:00:00.000Z",
    });
    const input = {
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    } as const;
    await expect(orchestrator.run(input)).rejects.toThrow(/automatic side-effect replay is forbidden/);
    const snapshot = orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID);
    if (snapshot?.state !== "commit-pending") throw new Error("Commit recovery snapshot missing");
    const completed = await orchestrator.recover(input, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: snapshot.boundaryId,
      expectedUpdatedAt: snapshot.updatedAt,
      expectedVersion: snapshot.version,
      minimumAgeMs: 60_000,
      sideEffectReconciliationConfirmed: true,
    });

    expect(completed).toMatchObject({
      state: "settle-completed",
      counts: { payment: 1, settlement: 1, delivery: 1 },
    });
    expect(invocations).toEqual(["payment", "settlement", "delivery"]);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_commitments",
    ).get()?.count).toBe(1n);
    database.close();
  });

  test("crash adoption re-runs post-anchor validity before downstream execution", async () => {
    const fixture = postAnchorExpiredFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, fixture.agreementCanonicalJson);
    const session = sessions.get(FIXTURE_JOB_ID);
    if (session === null) throw new Error("Fixture session missing");
    const commitments = lifecycleCommitmentStore(database, FIXTURE_COMMITTED_AT + 500_000);
    database.query<never, Record<string, string | number>>(`
      INSERT INTO fixture_lifecycle_runs (
        instance_id, audience, job_id, request_hash, agreement_artifact_hash,
        required_payment_phases_json, delivery_phase_index, delivery_phase_kind,
        state, created_at, updated_at
      ) VALUES (
        $instanceId, $audience, $jobId, $requestHash, $agreementArtifactHash,
        '[{"phaseIndex":2,"phaseKind":"pay-x402"}]', 3, 'deliver-attested-payload',
        'commit-pending', $now, $now
      )
    `).run({
      instanceId: session.instanceId,
      audience: session.audience,
      jobId: session.jobId,
      requestHash: session.requestHash,
      agreementArtifactHash: sha256Hex(fixture.agreementCanonicalJson),
      now: "2026-07-14T23:55:00.000Z",
    });
    const anchored = commitments.commit({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      session,
      verification: fixture.verification,
    });
    expect(anchored).toMatchObject({ disposition: "rejected", stage: "post-anchor" });
    const invocations: string[] = [];
    const orchestrator = lifecycleOrchestrator(database, sessions, commitments, {
      ...handlers(invocations),
      now: () => "2026-07-15T00:00:00.000Z",
    });
    const snapshot = orchestrator.getRecoverySnapshot(FIXTURE_JOB_ID);
    if (snapshot?.state !== "commit-pending") throw new Error("Commit recovery snapshot missing");
    const result = await orchestrator.recover({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    }, {
      executorIsolationConfirmed: true,
      expectedBoundaryId: snapshot.boundaryId,
      expectedUpdatedAt: snapshot.updatedAt,
      expectedVersion: snapshot.version,
      minimumAgeMs: 60_000,
      sideEffectReconciliationConfirmed: true,
    });

    expect(result).toMatchObject({
      state: "commit-failed",
      failureStage: "commit",
      reason: expect.stringContaining("post-anchor recovery"),
      counts: { payment: 0, settlement: 0, delivery: 0 },
    });
    expect(invocations).toEqual([]);
    database.close();
  });

  test("reuses an agreement artifact created before commitment without corrupting its timestamp", async () => {
    const fixture = agreementFixture();
    const path = await lifecycleDatabasePath();
    directories.push(dirname(path));
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, fixture.agreementCanonicalJson);
    const earlier = "2026-07-14T23:59:00.000Z";
    const preexisting = new ArtifactStore(database).put(
      "dacs-3-payee-bound-agreement",
      JSON.parse(fixture.agreementCanonicalJson),
      earlier,
    );
    const completed = await lifecycleOrchestrator(
      database,
      sessions,
      lifecycleCommitmentStore(database),
      handlers([]),
    ).run({
      agreementCanonicalJson: fixture.agreementCanonicalJson,
      jobId: FIXTURE_JOB_ID,
      verification: fixture.verification,
    });

    expect(completed).toMatchObject({
      state: "settle-completed",
      commitment: { agreementArtifactHash: preexisting.contentHash },
    });
    expect(new ArtifactStore(database).get(preexisting.contentHash)?.createdAt).toBe(earlier);
    database.close();
  });
});

async function runFailure(
  agreementCanonicalJson: string,
  verification: ReturnType<typeof agreementFixture>["verification"],
  anchorTimeMs: number,
) {
  const path = await lifecycleDatabasePath();
  directories.push(dirname(path));
  const database = openLifecycleDatabase(path);
  const sessions = lifecycleSessionStore(database);
  admitLifecycleSession(sessions, agreementCanonicalJson);
  const commitments = lifecycleCommitmentStore(database, anchorTimeMs);
  const invocations: string[] = [];
  const lifecycle = await lifecycleOrchestrator(
    database,
    sessions,
    commitments,
    handlers(invocations),
  ).run({ agreementCanonicalJson, jobId: FIXTURE_JOB_ID, verification });
  const commitmentCount = database.query<{ count: bigint }, []>(
    "SELECT count(*) AS count FROM fixture_commitments",
  ).get()!.count;
  database.close();
  return { commitmentCount, invocations, lifecycle };
}

function handlers(invocations: string[]) {
  return {
    payment: () => { invocations.push("payment"); return { ok: true as const, value: {} }; },
    settlement: () => { invocations.push("settlement"); return { ok: true as const, value: {} }; },
    delivery: () => { invocations.push("delivery"); return { ok: true as const, value: {} }; },
  };
}

function postAnchorExpiredFixture() {
  return agreementFixture(undefined, {
    validity: {
      notBefore: FIXTURE_COMMITTED_AT - 10_000,
      notAfter: FIXTURE_COMMITTED_AT + 100_000,
    },
  });
}
