import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { canonicalize, withoutFields } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import { ArtifactStore } from "../../src/substrate/sqlite/artifact-store.ts";
import {
  FIXTURE_KEY_DEFAULT_MAX_AGE_SEC,
  FixtureVetConflictError,
  FixtureVetIntegrityError,
  FixtureVetStore,
} from "../../src/substrate/sqlite/fixture-vet.ts";
import { signBuyerVetRequirement } from "../../src/producer/buyer-vet-requirement.ts";
import {
  FixtureBilateralVetOrchestrator,
  classifyFixtureVetPhaseFailure,
} from "../../src/lifecycle/fixture-vet-orchestrator.ts";
import {
  FIXTURE_COMMITTED_AT,
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
  lifecycleSessionStore,
  openLifecycleDatabase,
} from "./fixtures.ts";

const paths: string[] = [];
const GENERATED_AT = FIXTURE_COMMITTED_AT - 500;
const CREATED_AT = new Date(GENERATED_AT).toISOString();
const REQUIREMENT = Object.freeze({ required: Object.freeze([{ scheme: "key" }]) });

afterEach(async () => {
  await Promise.all(paths.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("fixture bilateral Vet store", () => {
  test("orchestrates reciprocal buyer and seller Vet before exposing exact composite refs", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    const orchestrator = new FixtureBilateralVetOrchestrator(new FixtureVetStore(database, "fixture"));
    const result = orchestrator.run({
      buyer: vetInput(session, "buyer"),
      seller: vetInput(session, "seller"),
    });
    expect(result.state).toBe("passed");
    if (result.state !== "passed") throw new Error(JSON.stringify(result));
    expect(result.vetRecordRefs).toEqual([
      result.buyer.compositeReference,
      result.seller.compositeReference,
    ]);
    expect(result.buyer.verifierParty).toBe(result.seller.evaluatedParty);
    expect(result.seller.verifierParty).toBe(result.buyer.evaluatedParty);
    database.close();
  });

  test("scopes every Vet lookup to the admitted deployment session", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    const store = new FixtureVetStore(database, "fixture");
    const buyer = store.run(vetInput(session, "buyer"));

    expect(store.get(session, "buyer")).toEqual(buyer);
    expect(store.get({ ...session, instanceId: "other-instance" }, "buyer")).toBeNull();
    expect(store.get({ ...session, audience: "https://other.example" }, "buyer")).toBeNull();
    database.close();
  });

  test("binds Vet generation and buyer requirements to the admitted pre-Agreement interval", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const placeholder = agreementFixture();
    admitLifecycleSession(sessions, placeholder.agreementCanonicalJson);
    const session = sessions.get(placeholder.input.jobId)!;
    const store = new FixtureVetStore(database, "fixture");
    const beforeAdmission = Date.parse(session.createdAt) - 1;
    expect(() => store.run({
      ...vetInput(session, "buyer"),
      generatedAt: beforeAdmission,
      createdAt: new Date(beforeAdmission).toISOString(),
    })).toThrow("Fixture Vet input is invalid or not fixture-authorized");
    expect(() => store.run({
      ...vetInput(session, "buyer"),
      session: { ...session, createdAt: new Date(beforeAdmission).toISOString() },
    })).toThrow("Fixture Vet session differs from persisted admission authority");

    const sellerInput = vetInput(session, "seller");
    const futureRequirement = signBuyerVetRequirement({
      jobId: session.jobId,
      buyer: buyerFixtureSigner().signer,
      seller: fixtureSigner().signer,
      requirement: REQUIREMENT,
      generatedAt: sellerInput.generatedAt + 1,
    }, buyerFixtureSigner(), { deploymentMode: "fixture", requestMode: "fixture" });
    expect(() => store.run({
      ...sellerInput,
      requirementAuthority: { kind: "buyer-signed", canonicalJson: futureRequirement.canonicalJson },
    })).toThrow("Buyer Vet requirement is outside the admitted Vet evaluation interval");

    const result = new FixtureBilateralVetOrchestrator(store).run({
      buyer: vetInput(session, "buyer"),
      seller: sellerInput,
    });
    if (result.state !== "passed") throw new Error(JSON.stringify(result));
    const agreement = agreementFixture((input) => ({
      ...input,
      parties: input.parties.map((party) => ({
        ...party,
        vetRecordRef: party.role === "buyer"
          ? result.buyer.compositeReference : result.seller.compositeReference,
      })),
    }));
    expect(() => store.assertAgreementAuthority(
      JSON.parse(agreement.agreementCanonicalJson) as Record<string, unknown>,
      session,
      GENERATED_AT - 1,
    )).toThrow("Agreement Vet evidence does not precede its DACS-3 authority time");
    database.close();
  });

  test("rejects passing buyer Vet evidence produced for a different signed Listing", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const placeholder = agreementFixture();
    admitLifecycleSession(sessions, placeholder.agreementCanonicalJson);
    const session = sessions.get(placeholder.input.jobId)!;
    const result = new FixtureBilateralVetOrchestrator(new FixtureVetStore(database, "fixture")).run({
      buyer: vetInput(session, "buyer"),
      seller: vetInput(session, "seller"),
    });
    if (result.state !== "passed") throw new Error(JSON.stringify(result));
    const agreement = agreementFixture((input) => ({
      ...input,
      parties: input.parties.map((party) => ({
        ...party,
        vetRecordRef: party.role === "buyer"
          ? result.buyer.compositeReference : result.seller.compositeReference,
      })),
    }), { listingVersion: 2 });

    expect(() => new FixtureVetStore(database, "fixture").assertAgreementAuthority(
      JSON.parse(agreement.agreementCanonicalJson) as Record<string, unknown>,
      session,
      FIXTURE_COMMITTED_AT,
    )).toThrow("Buyer Vet requirement source does not match the Agreement Listing");
    database.close();
  });

  test("commitment rejects otherwise valid Vet evidence later than its trusted pre-anchor clock", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const placeholder = agreementFixture();
    admitLifecycleSession(sessions, placeholder.agreementCanonicalJson);
    const session = sessions.get(placeholder.input.jobId)!;
    const generatedAt = FIXTURE_COMMITTED_AT + 1;
    const at = new Date(generatedAt).toISOString();
    const result = new FixtureBilateralVetOrchestrator(new FixtureVetStore(database, "fixture")).run({
      buyer: { ...vetInput(session, "buyer"), generatedAt, createdAt: at },
      seller: { ...vetInput(session, "seller"), generatedAt, createdAt: at },
    });
    if (result.state !== "passed") throw new Error(JSON.stringify(result));
    const agreement = agreementFixture((input) => ({
      ...input,
      parties: input.parties.map((party) => ({
        ...party,
        vetRecordRef: party.role === "buyer"
          ? result.buyer.compositeReference : result.seller.compositeReference,
      })),
    }));

    expect(lifecycleCommitmentStore(database).commit({
      agreementCanonicalJson: agreement.agreementCanonicalJson,
      session,
      verification: agreement.verification,
    })).toMatchObject({
      disposition: "rejected",
      stage: "pre-anchor",
      reason: "Agreement Vet evidence does not precede its DACS-3 authority time",
    });
    database.close();
  });

  for (const evaluatedRole of ["buyer", "seller"] as const) {
    test(`classifies malformed ${evaluatedRole} Vet requirement authority as counterparty`, async () => {
      const path = await preparedPath();
      const database = openLifecycleDatabase(path);
      const sessions = lifecycleSessionStore(database);
      const agreement = agreementFixture();
      admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
      const session = sessions.get(agreement.input.jobId)!;
      const buyer = vetInput(session, "buyer");
      const seller = vetInput(session, "seller");
      const malformed = evaluatedRole === "buyer"
        ? { ...buyer, requirementAuthority: { kind: "seller-listing" as const, canonicalJson: "{}" } }
        : { ...seller, requirementAuthority: { kind: "buyer-signed" as const, canonicalJson: "{}" } };
      const result = new FixtureBilateralVetOrchestrator(
        new FixtureVetStore(database, "fixture"),
      ).run({
        buyer: evaluatedRole === "buyer" ? malformed : buyer,
        seller: evaluatedRole === "seller" ? malformed : seller,
      });
      expect(result).toMatchObject({
        state: "failed",
        evaluatedRole,
        decision: "error",
        errorClass: "counterparty",
      });
      expect(result).not.toHaveProperty("record");
      expect(database.query<{ count: bigint }, []>(
        "SELECT count(*) AS count FROM fixture_vet_records",
      ).get()!.count).toBe(evaluatedRole === "buyer" ? 0n : 1n);
      database.close();
    });
  }

  test("rejects unsupported Agreement Vet references without treating them as legacy", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const agreement = agreementFixture((input) => ({
      ...input,
      parties: input.parties.map((party) => ({
        ...party,
        vetRecordRef: {
          anchor: { kind: "storage-program", locator: `dacs2:unsupported:${party.role}` },
          contentHash: party.role === "buyer" ? "a".repeat(64) : "b".repeat(64),
        },
      })),
    }));
    expect(() => new FixtureVetStore(database, "fixture").assertAgreementAuthority(
      JSON.parse(agreement.agreementCanonicalJson) as Record<string, unknown>,
      { instanceId: "test-instance", audience: "https://test.example", jobId: agreement.input.jobId },
      FIXTURE_COMMITTED_AT,
    )).toThrow("Agreement carries unsupported or mixed Vet references");
    database.close();
  });

  test("stops before seller Vet and applies VPC-4 after a terminal buyer error", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    const orchestrator = new FixtureBilateralVetOrchestrator(new FixtureVetStore(database, "fixture", {
      version: 4,
      keyAvailability: "failed",
      keyDefaultMaxAgeSec: FIXTURE_KEY_DEFAULT_MAX_AGE_SEC,
    }));
    const result = orchestrator.run({
      buyer: vetInput(session, "buyer"),
      seller: vetInput(session, "seller"),
    });
    expect(result).toMatchObject({
      state: "failed",
      evaluatedRole: "buyer",
      decision: "error",
      errorClass: "permanent",
    });
    expect(new FixtureVetStore(database, "fixture").get(session, "seller")).toBeNull();
    expect(classifyFixtureVetPhaseFailure("fail")).toBe("counterparty");
    expect(classifyFixtureVetPhaseFailure("indeterminate")).toBe("permanent");
    expect(classifyFixtureVetPhaseFailure("error", true)).toBe("counterparty");
    database.close();
  });

  test("atomically anchors both role-distinct composites and independently verifies them after restart", async () => {
    const path = await preparedPath();
    let database = openLifecycleDatabase(path);
    let sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    let store = new FixtureVetStore(database, "fixture");
    const buyer = store.run(vetInput(session, "buyer"));
    const seller = store.run(vetInput(session, "seller"));
    expect(buyer).toMatchObject({
      evaluatedRole: "buyer",
      evaluatedParty: buyerFixtureSigner().signer,
      verifierParty: fixtureSigner().signer,
      overallDecision: "pass",
      recipeAvailability: "live",
    });
    expect(seller).toMatchObject({
      evaluatedRole: "seller",
      evaluatedParty: fixtureSigner().signer,
      verifierParty: buyerFixtureSigner().signer,
      overallDecision: "pass",
      recipeAvailability: "live",
    });
    expect(buyer.compositeAddress).not.toBe(seller.compositeAddress);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_vet_records",
    ).get()!.count).toBe(2n);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_anchors",
    ).get()!.count).toBe(8n);
    const artifacts = new ArtifactStore(database);
    for (const record of [buyer, seller]) {
      const compositeContentHash = record.compositeReference["contentHash"];
      expect(typeof compositeContentHash).toBe("string");
      if (typeof compositeContentHash !== "string") throw new Error("Composite reference content hash is absent");
      const compositeAnchor = database.query<{
        contentHash: string; artifactContentHash: string | null;
      }, { locator: string }>(`
        SELECT content_hash AS contentHash, artifact_content_hash AS artifactContentHash
        FROM fixture_anchors WHERE logical_address = $locator
      `).get({ locator: record.compositeAddress });
      expect(compositeAnchor).toEqual({
        contentHash: compositeContentHash,
        artifactContentHash: record.compositeArtifactHash,
      });
      expect(compositeAnchor!.contentHash).not.toBe(compositeAnchor!.artifactContentHash);

      const verifyResultAnchor = database.query<{
        contentHash: string; artifactContentHash: string | null;
      }, { locator: string }>(`
        SELECT content_hash AS contentHash, artifact_content_hash AS artifactContentHash
        FROM fixture_anchors WHERE logical_address = $locator
      `).get({ locator: record.verifyResultAddress });
      const verifyResultJson = artifacts.get(record.verifyResultArtifactHash)!.canonicalJson;
      expect(verifyResultAnchor).toEqual({
        contentHash: sha256Hex(canonicalize(withoutFields(
          JSON.parse(verifyResultJson) as Record<string, unknown>,
          "signature",
        ))),
        artifactContentHash: record.verifyResultArtifactHash,
      });
      expect(verifyResultAnchor!.contentHash).not.toBe(verifyResultAnchor!.artifactContentHash);
    }
    database.close();

    database = openLifecycleDatabase(path);
    sessions = lifecycleSessionStore(database);
    store = new FixtureVetStore(database, "fixture");
    expect(store.get(session, "buyer")).toEqual(buyer);
    expect(store.get(session, "seller")).toEqual(seller);
    expect(sessions.get(session.jobId)).not.toBeNull();
    database.close();
  });

  test("replays exact authority and rejects immutable requirement drift", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    const store = new FixtureVetStore(database, "fixture");
    const input = vetInput(session, "buyer");
    const first = store.run(input);
    expect(store.run(input)).toEqual(first);
    expect(() => store.run({
      ...input,
      requirementAuthority: {
        kind: "seller-listing",
        canonicalJson: fixtureSignedPaidListing({
          buyerRequirement: {
            requirementVersion: "1",
            required: [{ scheme: "key", verificationRequired: false }],
            oneOf: [[{ scheme: "did", verificationRequired: false }]],
          },
        }).canonicalJson,
      },
    })).toThrow(FixtureVetConflictError);
    database.close();
  });

  for (const availability of ["mocked", "disabled", "failed"] as const) {
    test(`persists ${availability} recipe availability as error despite predicate pass`, async () => {
      const path = await preparedPath();
      const database = openLifecycleDatabase(path);
      const sessions = lifecycleSessionStore(database);
      const agreement = agreementFixture();
      admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
      const session = sessions.get(agreement.input.jobId)!;
      const store = new FixtureVetStore(database, "fixture", {
        version: { mocked: 2, disabled: 3, failed: 4 }[availability],
        keyAvailability: availability,
        keyDefaultMaxAgeSec: FIXTURE_KEY_DEFAULT_MAX_AGE_SEC,
      });
      const callerControlled = {
        ...vetInput(session, "buyer"),
        recipeAvailability: "live",
        recipeRegistryVersion: 999,
      };
      const record = store.run(callerControlled);
      expect(record.overallDecision).toBe("error");
      expect(store.get(session, "buyer")?.overallDecision).toBe("error");
      database.close();
    });
  }

  test("rejects an unsupported fixture recipe registry version before Vet", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    expect(() => new FixtureVetStore(database, "fixture", {
      version: 2,
      keyAvailability: "live",
      keyDefaultMaxAgeSec: FIXTURE_KEY_DEFAULT_MAX_AGE_SEC,
    })).toThrow("Fixture recipe registry authority is unsupported");
    database.close();
  });

  test("rolls back all artifacts and anchors when the authority row cannot commit", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    database.run(`
      CREATE TRIGGER fixture_vet_forced_failure
      BEFORE INSERT ON fixture_vet_records
      BEGIN SELECT RAISE(ABORT, 'forced Vet persistence failure'); END;
    `);
    const store = new FixtureVetStore(database, "fixture");
    expect(() => store.run(vetInput(session, "buyer"))).toThrow("forced Vet persistence failure");
    expect(database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM artifacts").get()!.count).toBe(0n);
    expect(database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM fixture_anchors").get()!.count).toBe(0n);
    expect(database.query<{ count: bigint }, []>("SELECT count(*) AS count FROM fixture_vet_records").get()!.count).toBe(0n);
    database.close();
  });

  test("rejects persisted decision corruption rather than trusting the row", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    const store = new FixtureVetStore(database, "fixture");
    store.run(vetInput(session, "buyer"));
    database.query<never, { jobId: string }>(`
      UPDATE fixture_vet_records SET overall_decision = 'fail'
      WHERE job_id = $jobId AND evaluated_role = 'buyer'
    `).run({ jobId: session.jobId });
    expect(() => store.get(session, "buyer")).toThrow(FixtureVetIntegrityError);
    database.close();
  });

  test("rejects row chronology drift against signed Vet artifacts", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    const store = new FixtureVetStore(database, "fixture");
    const record = store.run(vetInput(session, "buyer"));
    const driftedAt = record.generatedAt - 1;
    database.query<never, { jobId: string; generatedAt: number; createdAt: string }>(`
      UPDATE fixture_vet_records SET generated_at = $generatedAt, created_at = $createdAt
      WHERE job_id = $jobId AND evaluated_role = 'buyer'
    `).run({
      jobId: session.jobId,
      generatedAt: driftedAt,
      createdAt: new Date(driftedAt).toISOString(),
    });
    expect(() => store.get(session, "buyer")).toThrow("Persisted fixture key-possession evidence is invalid");
    database.close();
  });

  test("rejects persisted recipe authority that differs from deployment configuration", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    const store = new FixtureVetStore(database, "fixture");
    store.run(vetInput(session, "buyer"));
    database.query<never, { jobId: string }>(`
      UPDATE fixture_vet_records SET recipe_availability = 'failed'
      WHERE job_id = $jobId AND evaluated_role = 'buyer'
    `).run({ jobId: session.jobId });
    expect(() => store.get(session, "buyer")).toThrow(
      "Persisted Vet recipe authority differs from the configured registry",
    );
    database.close();
  });

  test("rejects persisted signed requirement-source binding corruption", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    const store = new FixtureVetStore(database, "fixture");
    store.run(vetInput(session, "seller"));
    database.query<never, { jobId: string; contentHash: string }>(`
      UPDATE fixture_vet_records SET requirement_source_content_hash = $contentHash
      WHERE job_id = $jobId AND evaluated_role = 'seller'
    `).run({ jobId: session.jobId, contentHash: "f".repeat(64) });
    expect(() => store.get(session, "seller")).toThrow(FixtureVetIntegrityError);
    database.close();
  });

  test("migrates populated v16 state additively before accepting Vet evidence", async () => {
    const path = await preparedPath();
    let database = openLifecycleDatabase(path);
    let sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    database.run("DROP TABLE fixture_vet_records");
    database.run("PRAGMA user_version = 16");
    database.close();

    database = openLifecycleDatabase(path);
    sessions = lifecycleSessionStore(database);
    expect(database.query<{ user_version: bigint }, []>("PRAGMA user_version").get()!.user_version).toBe(26n);
    expect(sessions.get(session.jobId)).toEqual(session);
    const store = new FixtureVetStore(database, "fixture");
    expect(store.run(vetInput(session, "buyer")).overallDecision).toBe("pass");
    database.close();
  });

  test("recreates an exact empty Vet table before advancing schema v18", async () => {
    const path = await preparedPath();
    let database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    database.run("DROP TABLE fixture_vet_records");
    database.run("PRAGMA user_version = 18");
    database.close();

    database = openLifecycleDatabase(path);
    expect(database.query<{ user_version: bigint }, []>("PRAGMA user_version").get()!.user_version).toBe(26n);
    expect(new FixtureVetStore(database, "fixture").run(vetInput(session, "buyer")).overallDecision).toBe("pass");
    database.close();
  });

  test("refuses populated v17 Vet state whose requirement-source provenance cannot be recovered", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    new FixtureVetStore(database, "fixture").run(vetInput(session, "buyer"));
    database.run("PRAGMA user_version = 17");
    database.close();

    expect(() => openLifecycleDatabase(path)).toThrow(
      "Cannot migrate populated schema v17 Vet state: signed requirement-source provenance is unavailable",
    );
  });

  test("refuses populated v18 Vet evidence whose chronology provenance was not enforced", async () => {
    const path = await preparedPath();
    let database = openLifecycleDatabase(path);
    let sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    const original = new FixtureVetStore(database, "fixture").run(vetInput(session, "buyer"));
    database.run("PRAGMA user_version = 18");
    database.close();

    expect(() => openLifecycleDatabase(path)).toThrow(
      "Cannot migrate populated schema v18 Vet state: signed chronology provenance was not enforced",
    );
    expect(original.overallDecision).toBe("pass");
  });

  test("refuses a populated Vet table whose schema version was downgraded below v17", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const session = sessions.get(agreement.input.jobId)!;
    new FixtureVetStore(database, "fixture").run(vetInput(session, "buyer"));
    database.run("PRAGMA user_version = 16");
    database.close();

    expect(() => openLifecycleDatabase(path)).toThrow(
      "Cannot migrate populated pre-v17 Vet state: schema provenance is inconsistent",
    );
  });

  test("serializes two barrier-released writers to one exact Vet record", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const sessions = lifecycleSessionStore(database);
    const agreement = agreementFixture();
    admitLifecycleSession(sessions, agreement.agreementCanonicalJson);
    const workers = [vetWorker(path), vetWorker(path)];
    await Promise.all(workers.map((entry) => entry.ready));
    for (const entry of workers) entry.worker.postMessage({ kind: "start" });
    const [left, right] = await Promise.all(workers.map((entry) => entry.result));
    expect(left).toEqual(right);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_vet_records",
    ).get()!.count).toBe(1n);
    for (const entry of workers) entry.worker.terminate();
    database.close();
  });

  test("reuses one authenticated seller Listing source across distinct Vet jobs", async () => {
    const path = await preparedPath();
    const database = openLifecycleDatabase(path);
    const firstAgreement = agreementFixture();
    const firstSessions = lifecycleSessionStore(database);
    admitLifecycleSession(firstSessions, firstAgreement.agreementCanonicalJson);
    const first = firstSessions.get(firstAgreement.input.jobId)!;
    const secondJobId = "01J00000000000000000000001";
    const secondSessions = lifecycleSessionStore(database, { jobId: secondJobId, entropyByte: 10 });
    admitLifecycleSession(secondSessions, firstAgreement.agreementCanonicalJson, {
      jobId: secondJobId, entropyByte: 10,
    });
    const second = secondSessions.get(secondJobId)!;
    const store = new FixtureVetStore(database, "fixture");
    const firstRecord = store.run(vetInput(first, "buyer"));
    const secondRecord = store.run(vetInput(second, "buyer"));
    expect(firstRecord.requirementSourceAddress).toBe(secondRecord.requirementSourceAddress);
    expect(firstRecord.jobId).not.toBe(secondRecord.jobId);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_vet_records",
    ).get()!.count).toBe(2n);
    database.close();
  });
});

async function preparedPath(): Promise<string> {
  const path = await lifecycleDatabasePath();
  paths.push(path.slice(0, path.lastIndexOf("/")));
  return path;
}

function vetInput(
  session: NonNullable<ReturnType<ReturnType<typeof lifecycleSessionStore>["get"]>>,
  evaluatedRole: "buyer" | "seller",
) {
  const listing = fixtureSignedPaidListing();
  const buyerIdentity = fixtureBuyerIdentity();
  const sellerIdentity = fixtureListingSellerIdentity(listing);
  const buyer = evaluatedRole === "buyer";
  const buyerRequirement = signBuyerVetRequirement({
    jobId: session.jobId,
    buyer: buyerFixtureSigner().signer,
    seller: fixtureSigner().signer,
    requirement: REQUIREMENT,
    generatedAt: GENERATED_AT,
  }, buyerFixtureSigner(), { deploymentMode: "fixture", requestMode: "fixture" });
  return {
    session,
    evaluatedRole,
    evaluatedBundleHash: buyer ? buyerIdentity.bundleHash : sellerIdentity.bundleHash,
    requirementAuthority: buyer
      ? { kind: "seller-listing" as const, canonicalJson: listing.canonicalJson }
      : { kind: "buyer-signed" as const, canonicalJson: buyerRequirement.canonicalJson },
    evaluatedSigner: buyer ? buyerFixtureSigner() : fixtureSigner(),
    verifierSigner: buyer ? fixtureSigner() : buyerFixtureSigner(),
    generatedAt: GENERATED_AT,
    createdAt: CREATED_AT,
  };
}

function vetWorker(path: string) {
  const worker = new Worker(new URL("../workers/fixture-vet-worker.ts", import.meta.url).href);
  let readyResolve!: () => void;
  let resultResolve!: (value: unknown) => void;
  let resultReject!: (error: Error) => void;
  const ready = new Promise<void>((resolve) => { readyResolve = resolve; });
  const result = new Promise<unknown>((resolve, reject) => {
    resultResolve = resolve;
    resultReject = reject;
  });
  worker.onmessage = (event: MessageEvent<Record<string, unknown>>) => {
    if (event.data["kind"] === "ready") readyResolve();
    else if (event.data["kind"] === "result") resultResolve(event.data["record"]);
    else if (event.data["kind"] === "error") resultReject(new Error(String(event.data["message"])));
  };
  worker.onerror = (event) => resultReject(new Error(event.message));
  worker.postMessage({ kind: "initialize", path });
  return { ready, result, worker };
}
