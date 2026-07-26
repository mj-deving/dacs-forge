import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { signSettlementEvidence } from "../../src/producer/settlement-evidence.ts";
import { signCommitmentRecord } from "../../src/producer/commitment.ts";
import { canonicalize, withoutFields } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import { encodeComponentSignatureValue, importLegacyComponentSignatureValue } from "../../src/protocol/component-signature-codec.ts";
import { ArtifactStore } from "../../src/substrate/sqlite/artifact-store.ts";
import { sessionBindingHash, type SessionRecord } from "../../src/substrate/sqlite/session-store.ts";
import {
  FixtureBundleStore,
  type FixtureBundleFinalisation,
  type FixtureBundleFinaliseInput,
} from "../../src/substrate/sqlite/fixture-bundle.ts";
import { FixtureDeliveryStore } from "../../src/substrate/sqlite/fixture-delivery.ts";
import {
  FixtureAnchorStore,
  FixtureFailureEvidenceStore,
  FixtureSettlementLedger,
} from "../../src/substrate/sqlite/fixture-settlement.ts";
import { createFixtureAttestedDeliveryHandler } from "../../src/lifecycle/fixture-attested-delivery-handler.ts";
import {
  FIXTURE_COMMITTED_AT,
  buyerFixtureSigner,
  fixtureBuyerIdentity,
  fixtureListingSellerIdentity,
} from "../fixtures/reference-agreement.ts";
import { FIXTURE_SIGNING_CONTEXT, fixtureSigner } from "../fixtures/reference-listing.ts";
import { orchestratorFixtureIdentity, orchestratorFixtureSigner } from "../fixtures/reference-bundle.ts";
import {
  DELIVERY_PAYLOAD_FORMAT,
  DELIVERY_PAYLOAD_JSON,
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

const roots: string[] = [];
const FINALISED_AT = FIXTURE_COMMITTED_AT + 2_000;
const CREATED_AT = new Date(FINALISED_AT).toISOString();
const NO_SPEND_PAYMENT_AMOUNT = Object.freeze({ amount: "1", currency: "DEM", unit: "job" });
const NO_SPEND_RAIL_ID = "demos-native:DEM";
const NO_SPEND_PAYEE_ADDRESS = `0x${"2".repeat(64)}`;

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("atomic DACS-5 lifecycle finalisation", () => {
  test("persists three role-local copies, independently verifies after restart, and replays exactly", async () => {
    const fixture = noSpendAgreement();
    const path = await lifecycleDatabasePath();
    roots.push(path.slice(0, path.lastIndexOf("/")));
    let database = openLifecycleDatabase(path);
    let sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, fixture.canonicalJson);
    let commitments = lifecycleCommitmentStore(database);
    const orchestratorSigner = orchestratorFixtureSigner();
    const deliveries = new FixtureDeliveryStore(database, { deploymentMode: "fixture", signer: fixtureSigner() });
    const session = sessions.get(fixture.input.jobId)!;
    const delivery = createFixtureAttestedDeliveryHandler(deliveries, {
      now: () => CREATED_AT,
      observedAt: () => FINALISED_AT,
      payloadFormat: DELIVERY_PAYLOAD_FORMAT,
      payloadJson: DELIVERY_PAYLOAD_JSON,
      paymentAmount: NO_SPEND_PAYMENT_AMOUNT,
      sessionStore: sessions,
    });
    let lifecycleNow = new Date(FIXTURE_COMMITTED_AT).toISOString();
    const settlement = fixtureSettlementHandlers(database, orchestratorSigner, session);
    let lifecycle = lifecycleOrchestrator(database, sessions, commitments, {
      ...settlement,
      delivery: async (...args: Parameters<typeof delivery>) => {
        const result = await delivery(...args);
        lifecycleNow = CREATED_AT;
        return result;
      },
      now: () => lifecycleNow,
    });
    const settled = await lifecycle.run({
      agreementCanonicalJson: fixture.canonicalJson,
      jobId: fixture.input.jobId,
      verification: fixture.verification,
    });
    if (settled.state !== "settle-completed") throw new Error(JSON.stringify(settled));
    expect(settled.state).toBe("settle-completed");
    expect(lifecycle.getRestartBoundary(fixture.input.jobId)?.id).toBe("settlement.completed");
    const commitment = commitments.get(session.instanceId, session.audience, session.jobId)!;
    const settlementRef = settled.settlements[0]!.value["attestationRef"] as Record<string, unknown>;
    const attestationRef = settled.delivery.value["attestationRef"] as Record<string, unknown>;
    const bundle = {
      bundleVersion: "1" as const,
      jobId: fixture.input.jobId,
      outcome: "completed" as const,
      listingRef: fixture.input.listingRef,
      agreementRef: {
        anchor: { kind: "storage-program" as const, locator: commitment.logicalAddress },
        contentHash: commitment.agreementHash,
      },
      parties: [
        ...bundleAgreementParties(fixture.input),
        {
          role: "orchestrator" as const,
          bundleHash: orchestratorFixtureIdentity().bundleHash,
          primaryClaim: orchestratorSigner.signer,
        },
      ],
      phaseSummary: [
        {
          index: 1, kind: "commit-payee-bound-agreement", outcome: "ok" as const,
        },
        {
          index: settled.settlements[0]!.phaseIndex, kind: settled.settlements[0]!.phaseKind,
          outcome: "ok" as const, attestationRef: settlementRef,
        },
        {
          index: settled.delivery.phaseIndex, kind: settled.delivery.phaseKind,
          outcome: "ok" as const, attestationRef,
        },
      ],
      vetRecords: [],
      settlementEvidence: [settlementRef, attestationRef],
      recipeRegistryVersion: 1,
      railRegistryVersion: 1,
      finalisedAt: FINALISED_AT,
    };
    let bundles = new FixtureBundleStore(database, { commitments, deploymentMode: "fixture" });
    const input = {
      anchorRoles: ["buyer", "seller", "orchestrator"] as const,
      bundle,
      createdAt: CREATED_AT,
      partySigners: [
        { role: "buyer" as const, signer: buyerFixtureSigner() },
        { role: "seller" as const, signer: fixtureSigner() },
        { role: "orchestrator" as const, signer: orchestratorSigner },
      ],
      partyIdentityCanonicalJsons: [
        fixtureBuyerIdentity().canonicalJson,
        fixtureListingSellerIdentity().canonicalJson,
        orchestratorFixtureIdentity().canonicalJson,
      ],
      session,
    };
    const finalised = bundles.finalise(input);
    expect(finalised.copies).toHaveLength(3);
    expect(new Set(finalised.copies.map((copy) => copy.bundleHash)).size).toBe(1);
    for (const copy of finalised.copies) {
      expect(JSON.parse(copy.canonicalJson)).toMatchObject({
        faultBundleVersion: "1",
        faultedParty: "none",
        outcome: "completed",
      });
      expect(JSON.parse(copy.canonicalJson).bundleVersion).toBeUndefined();
    }
    expect(bundles.verifySession(fixture.input.jobId)).toMatchObject({
      disposition: "unified", reputationEligibility: "eligible",
    });
    expect(lifecycle.get(fixture.input.jobId)).toMatchObject({ state: "finalised", endedAt: CREATED_AT });
    expect(lifecycle.getRestartBoundary(fixture.input.jobId)?.id).toBe("bundle.finalised-completed");
    database.close();

    database = openLifecycleDatabase(path);
    sessions = lifecycleSessionStore(database);
    commitments = lifecycleCommitmentStore(database);
    lifecycle = lifecycleOrchestrator(database, sessions, commitments, {
      payment: () => { throw new Error("payment replayed"); },
      settlement: () => { throw new Error("settlement replayed"); },
      delivery: () => { throw new Error("delivery replayed"); },
    });
    bundles = new FixtureBundleStore(database, { commitments, deploymentMode: "fixture" });
    expect(lifecycle.get(fixture.input.jobId)).toMatchObject({ state: "finalised", endedAt: CREATED_AT });
    expect(lifecycle.getRestartBoundary(fixture.input.jobId)?.id).toBe("bundle.finalised-completed");
    expect(bundles.verifySession(fixture.input.jobId)).toMatchObject({ disposition: "unified" });
    expect(bundles.finalise({ ...input, session: sessions.get(fixture.input.jobId)! })).toEqual(finalised);
    database.close();
  });

  test("rolls back artifacts, anchors, copies, and lifecycle state on a mid-write substrate failure", async () => {
    const prepared = await settledFixture();
    prepared.database.run(`
      CREATE TRIGGER reject_fixture_bundle BEFORE INSERT ON fixture_bundles
      BEGIN SELECT RAISE(ABORT, 'forced bundle write failure'); END;
    `);
    expect(() => prepared.store.finalise(prepared.input)).toThrow("forced bundle write failure");
    expect(prepared.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_bundles",
    ).get()!.count).toBe(0n);
    expect(prepared.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_anchors WHERE artifact_kind = 'dacs-5-bundle'",
    ).get()!.count).toBe(0n);
    expect(prepared.database.query<{ state: string }, []>(
      "SELECT state FROM fixture_lifecycle_runs",
    ).get()!.state).toBe("settle-completed");
    prepared.database.close();
  });

  test("rejects post-write artifact corruption and excludes reputation", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    const buyer = prepared.store.get(prepared.input.session.jobId, "buyer")!;
    prepared.database.query<never, { hash: string }>(
      "UPDATE artifacts SET canonical_json = '{}' WHERE content_hash = $hash",
    ).run({ hash: buyer.artifactContentHash });
    expect(prepared.store.read(prepared.input.session.jobId, "buyer")).toMatchObject({ status: "rejected" });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects a hash-valid local evidence artifact with the wrong semantic shape", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    const ref = prepared.input.bundle.settlementEvidence[0]!;
    const locator = (ref["anchor"] as Record<string, unknown>)["locator"] as string;
    const malformed = new ArtifactStore(prepared.database).put("dacs-4-evidence", "not-an-object", CREATED_AT);
    prepared.database.query<never, { hash: string; locator: string }>(`
      UPDATE fixture_anchors
      SET content_hash = $hash, artifact_content_hash = $hash
      WHERE logical_address = $locator
    `).run({ hash: malformed.contentHash, locator });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects false terminal outcomes and incomplete role-local copy sets", async () => {
    const prepared = await settledFixture();
    expect(() => prepared.store.finalise({
      ...prepared.input,
      bundle: { ...prepared.input.bundle, outcome: "failed-counterparty" },
    })).toThrow("requires bundle outcome completed");
    expect(() => prepared.store.finalise({
      ...prepared.input,
      anchorRoles: ["buyer"],
    })).toThrow("one role-local anchor");
    expect(prepared.database.query<{ state: string }, []>(
      "SELECT state FROM fixture_lifecycle_runs",
    ).get()!.state).toBe("settle-completed");
    prepared.database.close();
  });

  test("rejects missing expected bundle anchors and evidence", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    const buyer = prepared.store.get(prepared.input.session.jobId, "buyer")!;
    prepared.database.query<never, { address: string }>(
      "DELETE FROM fixture_anchors WHERE logical_address = $address",
    ).run({ address: buyer.logicalAddress });
    expect(prepared.store.read(prepared.input.session.jobId, "buyer")).toMatchObject({ status: "rejected" });
    const seller = prepared.store.get(prepared.input.session.jobId, "seller")!;
    const evidenceAddress = ((prepared.input.bundle.settlementEvidence[0]!["anchor"] as Record<string, unknown>)["locator"] as string);
    prepared.database.query<never, { address: string }>(
      "DELETE FROM fixture_anchors WHERE logical_address = $address",
    ).run({ address: evidenceAddress });
    expect(prepared.store.read(prepared.input.session.jobId, "seller")).toMatchObject({ status: "rejected" });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    expect(seller.bundleHash).toBe(buyer.bundleHash);
    prepared.database.close();
  });

  test("binds result wrappers to the pinned phase plan before signing", async () => {
    const prepared = await settledFixture();
    const row = prepared.database.query<{ settlementJson: string }, []>(
      "SELECT settlement_result_json AS settlementJson FROM fixture_lifecycle_runs",
    ).get()!;
    const settlements = JSON.parse(row.settlementJson) as Record<string, unknown>[];
    settlements[0] = { ...settlements[0], phaseIndex: 99 };
    prepared.database.query<never, { value: string }>(
      "UPDATE fixture_lifecycle_runs SET settlement_result_json = $value",
    ).run({ value: canonicalize(settlements) });
    expect(() => prepared.store.finalise(prepared.input)).toThrow("pinned payment plan");
    prepared.database.close();
  });

  test("requires the executed commitment phase in the signed bundle plan", async () => {
    const prepared = await settledFixture();
    expect(() => prepared.store.finalise({
      ...prepared.input,
      bundle: {
        ...prepared.input.bundle,
        phaseSummary: prepared.input.bundle.phaseSummary.filter((phase) => !phase.kind.startsWith("commit-")),
      },
    })).toThrow(/exactly cover|phase plan/i);
    prepared.database.close();
  });

  test("rejects finalisation before session, commitment, or phase observation authority", async () => {
    const prepared = await settledFixture();
    const finalisedAt = FIXTURE_COMMITTED_AT - 1;
    expect(() => prepared.store.finalise({
      ...prepared.input,
      bundle: { ...prepared.input.bundle, finalisedAt },
      createdAt: new Date(finalisedAt).toISOString(),
    })).toThrow("predates persisted lifecycle authority");
    prepared.database.close();
  });

  test("rejects phase observations that predate commitment authority", async () => {
    const prepared = await settledFixture(FIXTURE_COMMITTED_AT - 1);
    expect(() => prepared.store.finalise(prepared.input))
      .toThrow("phase observations are not chronologically ordered");
    prepared.database.close();
  });

  test("rejects an already-ended settle-completed lifecycle before signing", async () => {
    const prepared = await settledFixture();
    prepared.database.run("PRAGMA ignore_check_constraints = ON");
    prepared.database.query<never, { endedAt: string }>(
      "UPDATE fixture_lifecycle_runs SET ended_at = $endedAt",
    ).run({ endedAt: CREATED_AT });
    prepared.database.run("PRAGMA ignore_check_constraints = OFF");
    expect(() => prepared.store.finalise(prepared.input)).toThrow("contains terminal metadata");
    prepared.database.close();
  });

  test("enforces session, lifecycle, observation, and update timestamp ordering", async () => {
    const earlyLifecycle = await settledFixture();
    earlyLifecycle.database.query<never, { createdAt: string }>(
      "UPDATE fixture_lifecycle_runs SET created_at = $createdAt",
    ).run({ createdAt: "1970-01-01T00:00:00.000Z" });
    expect(() => earlyLifecycle.store.finalise(earlyLifecycle.input))
      .toThrow("lifecycle predates persisted session authority");
    earlyLifecycle.database.close();

    const staleUpdate = await settledFixture();
    staleUpdate.database.query<never, { updatedAt: string }>(
      "UPDATE fixture_lifecycle_runs SET updated_at = $updatedAt",
    ).run({ updatedAt: new Date(FIXTURE_COMMITTED_AT).toISOString() });
    expect(() => staleUpdate.store.finalise(staleUpdate.input))
      .toThrow("lifecycle update predates phase observations");
    staleUpdate.database.close();
  });

  test("rejects reordered persisted execution phases", async () => {
    const prepared = await settledFixture();
    const row = prepared.database.query<{ deliveryJson: string; settlementJson: string }, []>(`
      SELECT delivery_result_json AS deliveryJson, settlement_result_json AS settlementJson
      FROM fixture_lifecycle_runs
    `).get()!;
    const settlements = JSON.parse(row.settlementJson) as Record<string, unknown>[];
    const delivery = JSON.parse(row.deliveryJson) as Record<string, unknown>;
    settlements[0] = { ...settlements[0], phaseIndex: 3 };
    delivery["phaseIndex"] = 2;
    prepared.database.query<never, { delivery: string; payments: string; settlements: string }>(`
      UPDATE fixture_lifecycle_runs
      SET required_payment_phases_json = $payments,
        settlement_result_json = $settlements,
        delivery_phase_index = 2,
        delivery_result_json = $delivery
    `).run({
      payments: canonicalize([{ phaseIndex: 3, phaseKind: "pay-dem" }]),
      settlements: canonicalize(settlements),
      delivery: canonicalize(delivery),
    });
    expect(() => prepared.store.finalise(prepared.input)).toThrow("pinned payment plan");
    prepared.database.close();
  });

  test("fails reputation closed when the declared orchestrator copy disappears", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    prepared.database.query<never, []>(
      "DELETE FROM fixture_bundles WHERE anchored_by_role = 'orchestrator'",
    ).run();
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects persisted finalisation metadata not bound to the signed copy", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    prepared.database.query<never, { role: string; createdAt: string }>(
      "UPDATE fixture_bundles SET created_at = $createdAt WHERE anchored_by_role = $role",
    ).run({ role: "buyer", createdAt: new Date(FINALISED_AT + 1_000).toISOString() });
    expect(() => prepared.store.get(prepared.input.session.jobId, "buyer"))
      .toThrow("finalisation metadata");
    prepared.database.close();
  });

  test("rejects deterministic lifecycle conflicts before resolver uncertainty", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    const row = prepared.database.query<{ settlementJson: string }, []>(
      "SELECT settlement_result_json AS settlementJson FROM fixture_lifecycle_runs",
    ).get()!;
    const settlements = JSON.parse(row.settlementJson) as Record<string, unknown>[];
    settlements[0] = { ...settlements[0], phaseIndex: 99 };
    prepared.database.query<never, { value: string }>(
      "UPDATE fixture_lifecycle_runs SET settlement_result_json = $value",
    ).run({ value: canonicalize(settlements) });
    prepared.database.run("ALTER TABLE fixture_settlements RENAME TO unavailable_fixture_settlements");
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects non-canonical and extended persisted lifecycle evidence wrappers", async () => {
    for (const mutation of ["non-canonical", "extended"] as const) {
      const prepared = await settledFixture();
      const row = prepared.database.query<{ value: string }, []>(
        "SELECT settlement_result_json AS value FROM fixture_lifecycle_runs",
      ).get()!;
      const value = mutation === "non-canonical"
        ? ` ${row.value}`
        : canonicalize((JSON.parse(row.value) as Record<string, unknown>[]).map((entry, index) =>
          index === 0 ? { ...entry, unexpected: true } : entry));
      prepared.database.query<never, { value: string }>(
        "UPDATE fixture_lifecycle_runs SET settlement_result_json = $value",
      ).run({ value });
      expect(() => prepared.store.finalise(prepared.input)).toThrow(/invalid|non-canonical/);
      prepared.database.close();
    }
  });

  test("binds persisted commitment time to the signed Commitment authority", async () => {
    const prepared = await settledFixture();
    prepared.database.run("UPDATE fixture_commitments SET committed_at = committed_at + 1");
    expect(() => prepared.store.finalise(prepared.input))
      .toThrow("Persisted commitment authority is invalid");
    prepared.database.close();
  });

  test("includes durable evidence-anchor creation in finalisation chronology", async () => {
    const prepared = await settledFixture();
    const ref = prepared.input.bundle.settlementEvidence.at(-1)!;
    const locator = (ref["anchor"] as Record<string, unknown>)["locator"] as string;
    prepared.database.query<never, { createdAt: string; locator: string }>(
      "UPDATE fixture_anchors SET created_at = $createdAt WHERE logical_address = $locator",
    ).run({ createdAt: new Date(FINALISED_AT + 1_000).toISOString(), locator });
    expect(() => prepared.store.finalise(prepared.input))
      .toThrow("Bundle lifecycle update predates phase observations");
    prepared.database.close();
  });

  test("keeps settlement-store outages indeterminate", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    prepared.database.run("ALTER TABLE fixture_settlements RENAME TO unavailable_fixture_settlements");
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "indeterminate", reputationEligibility: "indeterminate",
    });
    prepared.database.close();
  });

  test("rejects missing local artifact bindings and malformed lifecycle JSON", async () => {
    for (const mutation of ["anchor", "json"] as const) {
      const prepared = await settledFixture();
      prepared.store.finalise(prepared.input);
      if (mutation === "anchor") {
        const ref = prepared.input.bundle.settlementEvidence[0]!;
        const locator = (ref["anchor"] as Record<string, unknown>)["locator"] as string;
        prepared.database.query<never, { locator: string }>(
          "UPDATE fixture_anchors SET artifact_content_hash = NULL WHERE logical_address = $locator",
        ).run({ locator });
      } else {
        prepared.database.run("UPDATE fixture_lifecycle_runs SET required_payment_phases_json = '['");
      }
      expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
        disposition: "rejected", reputationEligibility: "excluded",
      });
      prepared.database.close();
    }
  });

  test("independently rejects replaced signatures at unchanged semantic references", async () => {
    for (const refIndex of [0, 1] as const) {
      const prepared = await settledFixture();
      prepared.store.finalise(prepared.input);
      const ref = prepared.input.bundle.settlementEvidence[refIndex]!;
      const locator = (ref["anchor"] as Record<string, unknown>)["locator"] as string;
      const anchor = prepared.database.query<{ artifactHash: string }, { locator: string }>(
        "SELECT artifact_content_hash AS artifactHash FROM fixture_anchors WHERE logical_address = $locator",
      ).get({ locator })!;
      const artifacts = new ArtifactStore(prepared.database);
      const original = artifacts.get(anchor.artifactHash)!;
      const mutated = JSON.parse(original.canonicalJson) as Record<string, unknown>;
      const signature = mutated["signature"] as Record<string, unknown>;
      if (refIndex === 0) {
        const signer = buyerFixtureSigner();
        const evidenceHash = sha256Hex(canonicalize(withoutFields(mutated, "signature")));
        signature["signer"] = signer.signer;
        signature["value"] = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
          signer.sign(Buffer.from(`dacs-evidence:v1:${evidenceHash}`), FIXTURE_SIGNING_CONTEXT),
          "standard-base64-padded",
          64,
        ));
      } else {
        signature["value"] = `${signature["value"] as string}A`;
      }
      const replacement = artifacts.put(original.kinds[0]!, mutated, CREATED_AT);
      prepared.database.query<never, { locator: string; artifactHash: string }>(
        "UPDATE fixture_anchors SET artifact_content_hash = $artifactHash WHERE logical_address = $locator",
      ).run({ locator, artifactHash: replacement.contentHash });
      expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
        disposition: "rejected", reputationEligibility: "excluded",
      });
      prepared.database.close();
    }
  });

  test("binds DACS-2 delivery verification to the independently persisted lifecycle authority", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    const row = prepared.database.query<{ deliveryJson: string }, []>(
      "SELECT delivery_result_json AS deliveryJson FROM fixture_lifecycle_runs",
    ).get()!;
    const delivery = JSON.parse(row.deliveryJson) as Record<string, unknown>;
    delivery["authorityClaim"] = buyerFixtureSigner().signer;
    prepared.database.query<never, { deliveryJson: string }>(
      "UPDATE fixture_lifecycle_runs SET delivery_result_json = $deliveryJson",
    ).run({ deliveryJson: canonicalize(delivery) });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects a delivery row whose assertion address contradicts the verified DACS-2 chain", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    prepared.database.query<never, []>(
      "UPDATE fixture_deliveries SET assertion_address = 'dacs2:delivery-assertion:substituted:3'",
    ).run();
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects an existing referenced artifact with a contradictory persisted kind", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    const ref = prepared.input.bundle.settlementEvidence[0]!;
    const locator = (ref["anchor"] as Record<string, unknown>)["locator"] as string;
    const row = prepared.database.query<{ artifactHash: string }, { locator: string }>(
      "SELECT artifact_content_hash AS artifactHash FROM fixture_anchors WHERE logical_address = $locator",
    ).get({ locator })!;
    prepared.database.query<never, { artifactHash: string }>(
      "DELETE FROM artifact_kinds WHERE content_hash = $artifactHash AND kind = 'dacs-4-evidence'",
    ).run({ artifactHash: row.artifactHash });
    prepared.database.query<never, { artifactHash: string; createdAt: string }>(
      "INSERT INTO artifact_kinds (content_hash, kind, created_at) VALUES ($artifactHash, 'mistyped-evidence', $createdAt)",
    ).run({ artifactHash: row.artifactHash, createdAt: CREATED_AT });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects an existing agreement artifact with a contradictory persisted kind", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    const { agreementHash } = prepared.database.query<{ agreementHash: string }, { jobId: string }>(
      "SELECT agreement_artifact_hash AS agreementHash FROM fixture_commitments WHERE job_id = $jobId",
    ).get({ jobId: prepared.input.session.jobId })!;
    prepared.database.query<never, { agreementHash: string }>(
      "DELETE FROM artifact_kinds WHERE content_hash = $agreementHash AND kind IN ('dacs-3-agreement', 'dacs-3-payee-bound-agreement')",
    ).run({ agreementHash });
    prepared.database.query<never, { agreementHash: string; createdAt: string }>(
      "INSERT INTO artifact_kinds (content_hash, kind, created_at) VALUES ($agreementHash, 'mistyped-agreement', $createdAt)",
    ).run({ agreementHash, createdAt: CREATED_AT });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects replay when the requested and persisted role-copy sets differ", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    expect(() => prepared.store.finalise({
      ...prepared.input,
      anchorRoles: ["buyer", "seller"],
    })).toThrow("role set differs");
    prepared.database.close();
  });

  test("rejects missing finalised rows instead of treating them as qualified absence", async () => {
    const prepared = await settledFixture();
    const finalised = prepared.store.finalise(prepared.input);
    const seller = finalised.copies.find((copy) => copy.anchoredByRole === "seller")!;
    prepared.database.query<never, { address: string }>(
      "DELETE FROM fixture_anchors WHERE logical_address = $address",
    ).run({ address: seller.logicalAddress });
    prepared.database.query<never, []>(
      "DELETE FROM fixture_bundles WHERE anchored_by_role = 'seller'",
    ).run();
    expect(prepared.store.read(prepared.input.session.jobId, "seller")).toMatchObject({ status: "rejected" });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("reconstructs exact lifecycle references on every restart read", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    const row = prepared.database.query<{ deliveryJson: string }, []>(
      "SELECT delivery_result_json AS deliveryJson FROM fixture_lifecycle_runs",
    ).get()!;
    const delivery = JSON.parse(row.deliveryJson) as Record<string, unknown>;
    const value = delivery["value"] as Record<string, unknown>;
    const ref = value["attestationRef"] as Record<string, unknown>;
    value["attestationRef"] = { ...ref, contentHash: "0".repeat(64) };
    prepared.database.query<never, { value: string }>(
      "UPDATE fixture_lifecycle_runs SET delivery_result_json = $value",
    ).run({ value: canonicalize(delivery) });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("requires the persisted agreement commitment anchor on restart", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    prepared.database.query<never, []>("DELETE FROM fixture_commitments").run();
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects a fully consistent commitment replacement by another valid signer before finalisation", async () => {
    const prepared = await settledFixture();
    const row = prepared.database.query<{
      canonicalJson: string; logicalAddress: string;
    }, []>(`
      SELECT c.logical_address AS logicalAddress, a.canonical_json AS canonicalJson
      FROM fixture_commitments AS c
      JOIN artifacts AS a ON a.content_hash = c.commitment_artifact_hash
    `).get()!;
    const unsigned = JSON.parse(row.canonicalJson) as Record<string, unknown>;
    delete unsigned["signature"];
    const committedAt = FIXTURE_COMMITTED_AT + 1_000;
    const replacement = signCommitmentRecord(
      { ...unsigned, committedAt } as Parameters<typeof signCommitmentRecord>[0],
      buyerFixtureSigner(),
      FIXTURE_SIGNING_CONTEXT,
    );
    const artifact = new ArtifactStore(prepared.database).put(
      "dacs-3-commitment",
      replacement.commitment,
      CREATED_AT,
    );
    const anchorTxHash = sha256Hex(canonicalize({
      fixtureAnchorVersion: "1",
      logicalAddress: row.logicalAddress,
      commitmentHash: replacement.commitmentHash,
      committedAt,
    }));
    prepared.database.query<never, {
      anchorTxHash: string; artifactHash: string; committedAt: number;
      commitmentHash: string; orchestratorClaim: string;
    }>(`
      UPDATE fixture_commitments SET
        commitment_artifact_hash = $artifactHash,
        commitment_hash = $commitmentHash,
        orchestrator_claim = $orchestratorClaim,
        committed_at = $committedAt,
        anchor_tx_hash = $anchorTxHash
    `).run({
      anchorTxHash,
      artifactHash: artifact.contentHash,
      committedAt,
      commitmentHash: replacement.commitmentHash,
      orchestratorClaim: buyerFixtureSigner().signer,
    });
    prepared.database.query<never, { artifactHash: string }>(
      "UPDATE fixture_lifecycle_runs SET commitment_artifact_hash = $artifactHash",
    ).run({ artifactHash: artifact.contentHash });
    expect(() => prepared.store.finalise(prepared.input))
      .toThrow("Persisted commitment orchestrator authority is corrupt");
    prepared.database.close();
  });

  test("accepts omitted signer hints through independently persisted phase authority", async () => {
    const prepared = await settledFixture();
    const row = prepared.database.query<{ settlementJson: string }, []>(
      "SELECT settlement_result_json AS settlementJson FROM fixture_lifecycle_runs",
    ).get()!;
    const settlements = JSON.parse(row.settlementJson) as Record<string, unknown>[];
    const value = settlements[0]!["value"] as Record<string, unknown>;
    const ref = { ...(value["attestationRef"] as Record<string, unknown>) };
    delete ref["signer"];
    value["attestationRef"] = ref;
    prepared.database.query<never, { settlementJson: string }>(
      "UPDATE fixture_lifecycle_runs SET settlement_result_json = $settlementJson",
    ).run({ settlementJson: canonicalize(settlements) });
    const bundle = {
      ...prepared.input.bundle,
      phaseSummary: prepared.input.bundle.phaseSummary.map((phase) => phase.index === 2
        ? { ...phase, attestationRef: ref } : phase),
      settlementEvidence: [ref, prepared.input.bundle.settlementEvidence[1]!],
    };
    prepared.store.finalise({ ...prepared.input, bundle });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "unified", reputationEligibility: "eligible",
    });
    prepared.database.close();
  });

  test("persists and restart-verifies bundles with omitted per-phase evidence pointers", async () => {
    const prepared = await settledFixture();
    const bundle = {
      ...prepared.input.bundle,
      phaseSummary: prepared.input.bundle.phaseSummary.map(({ attestationRef: _ref, ...phase }) => phase),
    };
    prepared.store.finalise({ ...prepared.input, bundle });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "unified", reputationEligibility: "eligible",
    });
    prepared.database.close();
  });

  test("fails reputation closed when persisted settlement economics are corrupted", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    prepared.database.query<never, { amount: string }>(
      "UPDATE fixture_settlements SET payment_amount_json = $amount",
    ).run({ amount: canonicalize({ amount: "2", currency: "DEM", unit: "job" }) });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("fails restart verification when lifecycle terminal time drifts", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    prepared.database.query<never, { endedAt: string }>(
      "UPDATE fixture_lifecycle_runs SET ended_at = $endedAt",
    ).run({ endedAt: new Date(FINALISED_AT + 1_000).toISOString() });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects bundles when persisted Listing or IdentityBundle authority disappears", async () => {
    const listing = await settledFixture();
    listing.store.finalise(listing.input);
    listing.database.run("DELETE FROM fixture_listing_authorities");
    expect(listing.store.verifySession(listing.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    listing.database.close();

    const identity = await settledFixture();
    identity.store.finalise(identity.input);
    identity.database.run("DELETE FROM fixture_identity_authorities");
    expect(identity.store.verifySession(identity.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    identity.database.close();
  });

  test("rechecks Listing validity against its per-commitment authority timestamp", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    prepared.database.query<never, { verifiedAt: number }>(`
      UPDATE fixture_listing_verification_authorities SET verified_at = $verifiedAt
    `).run({ verifiedAt: FIXTURE_COMMITTED_AT + 86_400_001 });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("replays Listing verification only from persisted revocation and rail authority", async () => {
    const revoked = await settledFixture();
    revoked.store.finalise(revoked.input);
    revoked.database.run(`
      UPDATE fixture_listing_verification_authorities SET revocation_status = 'revoked'
    `);
    expect(revoked.store.verifySession(revoked.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    revoked.database.close();

    const rail = await settledFixture();
    rail.store.finalise(rail.input);
    const persisted = rail.database.query<{ value: string }, []>(`
      SELECT rail_resolutions_json AS value FROM fixture_listing_verification_authorities
    `).get()!.value;
    const resolutions = JSON.parse(persisted) as Array<{ result: { phaseHandler: string; status: string } }>;
    resolutions[0]!.result.phaseHandler = "pay-x402";
    rail.database.query<never, { value: string }>(`
      UPDATE fixture_listing_verification_authorities SET rail_resolutions_json = $value
    `).run({ value: canonicalize(resolutions) });
    expect(rail.store.verifySession(rail.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    rail.database.close();

    const unavailable = await settledFixture();
    unavailable.store.finalise(unavailable.input);
    unavailable.database.run("DROP TABLE fixture_listing_verification_authorities");
    expect(unavailable.store.verifySession(unavailable.input.session.jobId)).toMatchObject({
      disposition: "indeterminate", reputationEligibility: "indeterminate",
    });
    unavailable.database.close();
  });

  test("rejects malformed persisted rail authority", async () => {
    const prepared = await settledFixture();
    prepared.store.finalise(prepared.input);
    const persisted = prepared.database.query<{ value: string }, []>(`
      SELECT rail_resolutions_json AS value FROM fixture_listing_verification_authorities
    `).get()!.value;
    const resolutions = JSON.parse(persisted) as Array<Record<string, unknown>>;
    resolutions[0] = { ...resolutions[0], result: null };
    prepared.database.query<never, { value: string }>(`
      UPDATE fixture_listing_verification_authorities SET rail_resolutions_json = $value
    `).run({ value: canonicalize(resolutions) });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    prepared.database.close();
  });

  test("rejects corrupted per-job Listing, registry, and IdentityBundle authority", async () => {
    const listing = await settledFixture();
    listing.store.finalise(listing.input);
    listing.database.query<never, { hash: string }>(`
      UPDATE fixture_listing_verification_authorities SET listing_content_hash = $hash
    `).run({ hash: "f".repeat(64) });
    expect(listing.store.verifySession(listing.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    listing.database.close();

    const registries = await settledFixture();
    registries.store.finalise(registries.input);
    registries.database.run(`
      UPDATE fixture_listing_verification_authorities SET rail_registry_version = 2
    `);
    expect(registries.store.verifySession(registries.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    registries.database.close();

    const identity = await settledFixture();
    identity.store.finalise(identity.input);
    identity.database.run(`
      UPDATE artifacts SET canonical_json = '{}'
      WHERE content_hash IN (SELECT artifact_content_hash FROM fixture_identity_authorities)
    `);
    expect(identity.store.verifySession(identity.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    identity.database.close();
  });

  test("rejects corrupted anchor content and lifecycle anchor-kind bindings", async () => {
    const deliveryAnchor = await settledFixture();
    deliveryAnchor.store.finalise(deliveryAnchor.input);
    deliveryAnchor.database.query<never, { hash: string }>(`
      UPDATE fixture_anchors SET content_hash = $hash
      WHERE logical_address IN (SELECT assertion_address FROM fixture_deliveries)
    `).run({ hash: "f".repeat(64) });
    expect(deliveryAnchor.store.verifySession(deliveryAnchor.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    deliveryAnchor.database.close();

    const lifecycleAnchor = await settledFixture();
    lifecycleAnchor.store.finalise(lifecycleAnchor.input);
    const row = lifecycleAnchor.database.query<{ value: string }, []>(`
      SELECT settlement_result_json AS value FROM fixture_lifecycle_runs
    `).get()!;
    const settlements = JSON.parse(row.value) as Array<{
      value: { attestationRef: { anchor: { kind: string } } };
    }>;
    settlements[0]!.value.attestationRef.anchor.kind = "https";
    lifecycleAnchor.database.query<never, { value: string }>(`
      UPDATE fixture_lifecycle_runs SET settlement_result_json = $value
    `).run({ value: canonicalize(settlements) });
    expect(lifecycleAnchor.store.verifySession(lifecycleAnchor.input.session.jobId)).toMatchObject({
      disposition: "rejected", reputationEligibility: "excluded",
    });
    lifecycleAnchor.database.close();
  });

  test("refuses populated pre-v13 commitment state without durable authority provenance", async () => {
    for (const version of [0, 12]) {
      const prepared = await settledFixture();
      prepared.database.run(`PRAGMA user_version = ${version}`);
      prepared.database.close();
      expect(() => openLifecycleDatabase(prepared.path)).toThrow(/persisted orchestrator authority is unavailable/);
    }
  });

  test("refuses populated v13 state without signed Listing and IdentityBundle authority provenance", async () => {
    const prepared = await settledFixture();
    prepared.database.run("DROP TABLE fixture_listing_authorities");
    prepared.database.run("DROP TABLE fixture_identity_authorities");
    prepared.database.run("PRAGMA user_version = 13");
    prepared.database.close();
    expect(() => openLifecycleDatabase(prepared.path)).toThrow(/schema v13.*authority provenance is unavailable/);
  });

  test("refuses populated v14 state without per-commitment Listing verification authority", async () => {
    const prepared = await settledFixture();
    prepared.database.run("DROP TABLE fixture_listing_verification_authorities");
    prepared.database.run("PRAGMA user_version = 14");
    prepared.database.close();
    expect(() => openLifecycleDatabase(prepared.path)).toThrow(/schema v14.*Listing verification authority is unavailable/);
  });

  test("migrates a populated v15 completed bundle without changing its verified result", async () => {
    const prepared = await settledFixture();
    const finalised = prepared.store.finalise(prepared.input);
    prepared.database.run("PRAGMA user_version = 15");
    prepared.database.close();

    const database = openLifecycleDatabase(prepared.path);
    const store = new FixtureBundleStore(database, {
      commitments: lifecycleCommitmentStore(database), deploymentMode: "fixture",
    });
    expect(database.query<{ user_version: bigint }, []>("PRAGMA user_version").get()!.user_version).toBe(20n);
    expect(store.verifySession(prepared.input.session.jobId)).toMatchObject({ disposition: "unified" });
    expect(store.finalise({
      ...prepared.input,
      session: lifecycleSessionStore(database).get(prepared.input.session.jobId)!,
    })).toEqual(finalised);
    database.close();
  });

  test.each([
    ["permanent", "failed-perm"],
    ["transient", "failed-perm"],
    ["counterparty", "failed-counterparty"],
    ["settlement-atomicity", "failed-counterparty"],
  ] as const)("persists and restart-verifies %s settlement failure as %s", async (errorClass, outcome) => {
    const prepared = await failedTerminalFixture(errorClass);
    const finalised = prepared.store.finalise(prepared.input);
    expect(finalised.copies).toHaveLength(3);
    const artifacts = finalised.copies.map((copy) => JSON.parse(copy.canonicalJson));
    expect(artifacts[0]).toMatchObject({ faultBundleVersion: "1", outcome });
    expect(artifacts.every((artifact) => artifact.bundleVersion === undefined)).toBe(true);
    expect(new Set(artifacts.map((artifact) => artifact.faultedParty)).size).toBe(1);
    const seller = artifacts.find((artifact) => artifact.anchoredByRole === "seller")!;
    expect(seller.outcome).toBe(outcome === "failed-perm" ? "failed-counterparty" : "failed-perm");
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "unified",
      reputationEligibility: "eligible",
    });
    prepared.database.close();

    const database = openLifecycleDatabase(prepared.path);
    const restarted = new FixtureBundleStore(database, {
      commitments: lifecycleCommitmentStore(database), deploymentMode: "fixture",
    });
    expect(restarted.verifySession(prepared.input.session.jobId)).toMatchObject({ disposition: "unified" });
    expect(restarted.finalise({
      ...prepared.input,
      session: lifecycleSessionStore(database).get(prepared.input.session.jobId)!,
    })).toEqual(finalised);
    database.close();
  });

  test("persists x402 failure authority without imposing the Demos address format", async () => {
    const prepared = await failedTerminalFixture("permanent", "settlement", "pay-x402");
    const finalised = prepared.store.finalise(prepared.input);
    expect(JSON.parse(finalised.copies[0]!.canonicalJson)).toMatchObject({
      outcome: "failed-perm",
      phaseSummary: [
        { outcome: "ok" },
        { kind: "pay-x402", outcome: "fail" },
      ],
    });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({ disposition: "unified" });
    prepared.database.close();

    const database = openLifecycleDatabase(prepared.path);
    const restarted = new FixtureBundleStore(database, {
      commitments: lifecycleCommitmentStore(database), deploymentMode: "fixture",
    });
    expect(restarted.verifySession(prepared.input.session.jobId)).toMatchObject({ disposition: "unified" });
    expect(restarted.finalise({
      ...prepared.input,
      session: lifecycleSessionStore(database).get(prepared.input.session.jobId)!,
    })).toEqual(finalised);
    database.close();
  });

  test.each(["payment", "delivery"] as const)(
    "derives a permanent %s failure from the exact executed phase prefix",
    async (failureStage) => {
      const prepared = await failedTerminalFixture("permanent", failureStage);
      const finalised = prepared.store.finalise(prepared.input);
      const artifact = JSON.parse(finalised.copies[0]!.canonicalJson) as {
        outcome: string; phaseSummary: Array<{ kind: string; outcome: string }>;
      };
      expect(artifact.outcome).toBe("failed-perm");
      expect(artifact.phaseSummary.at(-1)).toMatchObject({
        kind: failureStage === "payment" ? "pay-dem" : "deliver-attested-payload",
        outcome: "fail",
      });
      expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({ disposition: "unified" });
      prepared.database.close();
    },
  );

  test("persists expired substrate failure as reputation-neutral failed-substrate", async () => {
    const prepared = await failedTerminalFixture("substrate");
    const finalised = prepared.store.finalise(prepared.input);
    expect(JSON.parse(finalised.copies[0]!.canonicalJson)).toMatchObject({ outcome: "failed-substrate" });
    expect(prepared.store.verifySession(prepared.input.session.jobId)).toMatchObject({
      disposition: "unified",
      reputationEligibility: "eligible",
    });
    prepared.database.close();
  });

  test.each([
    ["permanent", "payment", "payment.failed", "bundle.finalised-settle-failed"],
    ["permanent", "settlement", "settlement.failed", "bundle.finalised-settle-failed"],
    ["permanent", "delivery", "delivery.failed", "bundle.finalised-settle-failed"],
    ["settlement-atomicity", "payment", "payment.unsupported", "bundle.finalised-settle-unsupported"],
    ["settlement-atomicity", "settlement", "settlement.unsupported", "bundle.finalised-settle-unsupported"],
    ["settlement-atomicity", "delivery", "delivery.unsupported", "bundle.finalised-settle-unsupported"],
    ["substrate", "payment", "payment.failed-substrate", "bundle.finalised-failed-substrate"],
    ["substrate", "settlement", "settlement.failed-substrate", "bundle.finalised-failed-substrate"],
    ["substrate", "delivery", "delivery.failed-substrate", "bundle.finalised-failed-substrate"],
  ] as const)(
    "classifies actual %s %s terminal rows before and after finalisation restart",
    async (errorClass, failureStage, terminalBoundary, finalisedBoundary) => {
      const prepared = await failedTerminalFixture(errorClass, failureStage);
      expect(prepared.lifecycle.getRestartBoundary(prepared.input.session.jobId)?.id).toBe(terminalBoundary);
      prepared.database.close();

      let database = openLifecycleDatabase(prepared.path);
      let sessions = lifecycleSessionStore(database);
      let commitments = lifecycleCommitmentStore(database);
      let lifecycle = lifecycleOrchestrator(database, sessions, commitments, {
        payment: () => { throw new Error("terminal payment replayed"); },
        settlement: () => { throw new Error("terminal settlement replayed"); },
        delivery: () => { throw new Error("terminal delivery replayed"); },
      });
      expect(lifecycle.getRestartBoundary(prepared.input.session.jobId)?.id).toBe(terminalBoundary);
      const store = new FixtureBundleStore(database, { commitments, deploymentMode: "fixture" });
      store.finalise({
        ...prepared.input,
        session: sessions.get(prepared.input.session.jobId)!,
      });
      expect(lifecycle.getRestartBoundary(prepared.input.session.jobId)?.id).toBe(finalisedBoundary);
      database.close();

      database = openLifecycleDatabase(prepared.path);
      sessions = lifecycleSessionStore(database);
      commitments = lifecycleCommitmentStore(database);
      lifecycle = lifecycleOrchestrator(database, sessions, commitments, {
        payment: () => { throw new Error("finalised payment replayed"); },
        settlement: () => { throw new Error("finalised settlement replayed"); },
        delivery: () => { throw new Error("finalised delivery replayed"); },
      });
      expect(lifecycle.getRestartBoundary(prepared.input.session.jobId)?.id).toBe(finalisedBoundary);
      database.close();
    },
  );

  test("rolls back every failed-terminal bundle write and rejects outcome or evidence mutation", async () => {
    const prepared = await failedTerminalFixture("counterparty");
    expect(() => prepared.store.finalise({
      ...prepared.input,
      bundle: { ...prepared.input.bundle, outcome: "failed-perm" },
    })).toThrow("requires bundle outcome failed-counterparty");
    const terminal = prepared.input.bundle.phaseSummary.at(-1)!;
    expect(() => prepared.store.finalise({
      ...prepared.input,
      bundle: {
        ...prepared.input.bundle,
        phaseSummary: [
          prepared.input.bundle.phaseSummary[0]!,
          { ...terminal, errorClass: "permanent" },
        ],
      },
    })).toThrow(/exactly cover|outcome/i);
    prepared.database.run(`
      CREATE TRIGGER reject_failed_bundle BEFORE INSERT ON fixture_bundles
      BEGIN SELECT RAISE(ABORT, 'forced failed bundle write failure'); END;
    `);
    expect(() => prepared.store.finalise(prepared.input)).toThrow("forced failed bundle write failure");
    expect(prepared.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_bundles",
    ).get()!.count).toBe(0n);
    expect(prepared.database.query<{ state: string }, []>(
      "SELECT state FROM fixture_lifecycle_runs",
    ).get()!.state).toBe("settle-failed");
    prepared.database.close();
  });

  test("serializes two barrier-released failed-terminal finalisers to one idempotent result", async () => {
    const prepared = await failedTerminalFixture("permanent");
    const workerInput = {
      anchorRoles: prepared.input.anchorRoles,
      bundle: prepared.input.bundle,
      createdAt: prepared.input.createdAt,
      partyIdentityCanonicalJsons: prepared.input.partyIdentityCanonicalJsons,
    };
    prepared.database.close();
    const workers = [createFinaliseWorker(prepared.path, workerInput), createFinaliseWorker(prepared.path, workerInput)];
    await Promise.all(workers.map((entry) => entry.ready));
    workers.forEach((entry) => entry.worker.postMessage({ kind: "go" }));
    const [left, right] = await Promise.all(workers.map((entry) => entry.result));
    workers.forEach((entry) => entry.worker.terminate());
    expect(left!).toEqual(right!);
    expect(left!.copies).toHaveLength(3);

    const database = openLifecycleDatabase(prepared.path);
    expect(database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_bundles",
    ).get()!.count).toBe(3n);
    expect(new FixtureBundleStore(database, {
      commitments: lifecycleCommitmentStore(database), deploymentMode: "fixture",
    })
      .verifySession(prepared.input.session.jobId)).toMatchObject({ disposition: "unified" });
    database.close();
  });

  test("fails restart verification closed on terminal-state and failure-authority mutation", async () => {
    const terminalMutation = await failedTerminalFixture("counterparty");
    terminalMutation.store.finalise(terminalMutation.input);
    terminalMutation.database.run("PRAGMA ignore_check_constraints = ON");
    terminalMutation.database.run("UPDATE fixture_lifecycle_runs SET error_class = 'permanent'");
    terminalMutation.database.run("PRAGMA ignore_check_constraints = OFF");
    expect(terminalMutation.store.verifySession(terminalMutation.input.session.jobId)).toMatchObject({
      disposition: "rejected",
      reputationEligibility: "excluded",
    });
    terminalMutation.database.close();

    const evidenceMutation = await failedTerminalFixture("counterparty");
    evidenceMutation.store.finalise(evidenceMutation.input);
    evidenceMutation.database.run("UPDATE fixture_failure_evidence SET expectation_json = '{}'");
    expect(evidenceMutation.store.verifySession(evidenceMutation.input.session.jobId)).toMatchObject({
      disposition: "rejected",
      reputationEligibility: "excluded",
    });
    evidenceMutation.database.close();
  });

  test("atomically seals an authenticated unilateral abort from the signer perspective", async () => {
    const prepared = await pendingAbortFixture();
    expect(() => prepared.lifecycle.abort({
      actorRole: "seller",
      actorSigner: buyerFixtureSigner(),
      jobId: prepared.fixture.input.jobId,
      reason: "forged seller abort",
    })).toThrow("does not control the claimed agreement role");
    const aborted = prepared.lifecycle.abort({
      actorRole: "seller",
      actorSigner: fixtureSigner(),
      jobId: prepared.fixture.input.jobId,
      reason: "seller declined before payment result",
    });
    expect(aborted).toMatchObject({ state: "aborted", abortActorRole: "seller" });
    expect(prepared.lifecycle.getRestartBoundary(prepared.fixture.input.jobId)?.id).toBe("session.aborted");
    prepared.releasePayment();
    await expect(prepared.running).rejects.toThrow(/Unable to persist successful payment result/);
    const finalised = prepared.store.finalise(prepared.input("seller", "aborted-by-self"));
    expect(finalised.copies).toHaveLength(1);
    expect(prepared.lifecycle.getRestartBoundary(prepared.fixture.input.jobId)?.id)
      .toBe("bundle.finalised-aborted");
    expect(prepared.store.verifySession(prepared.fixture.input.jobId, "seller")).toMatchObject({
      disposition: "one-sided",
    });
    expect(() => prepared.store.finalise(prepared.input("buyer", "aborted-by-self")))
      .toThrow(/replay role set|outcome/i);
    prepared.database.run("PRAGMA ignore_check_constraints = ON");
    prepared.database.run("UPDATE fixture_lifecycle_runs SET abort_actor_role = 'buyer'");
    prepared.database.run("PRAGMA ignore_check_constraints = OFF");
    expect(prepared.store.verifySession(prepared.fixture.input.jobId, "seller")).toMatchObject({
      disposition: "rejected",
      reputationEligibility: "excluded",
    });
    prepared.database.run("PRAGMA ignore_check_constraints = ON");
    prepared.database.run("UPDATE fixture_lifecycle_runs SET abort_actor_role = 'seller'");
    prepared.database.run("PRAGMA ignore_check_constraints = OFF");
    prepared.database.close();

    const database = openLifecycleDatabase(prepared.path);
    const restarted = new FixtureBundleStore(database, {
      commitments: lifecycleCommitmentStore(database), deploymentMode: "fixture",
    });
    expect(restarted.verifySession(prepared.fixture.input.jobId, "seller")).toMatchObject({
      disposition: "one-sided",
    });
    database.close();
  });
});

function createFinaliseWorker(
  path: string,
  input: Omit<FixtureBundleFinaliseInput, "partySigners" | "session">,
) {
  const worker = new Worker(new URL("../workers/finalise-negative-bundle-worker.ts", import.meta.url).href);
  let readyResolve!: () => void;
  let resultResolve!: (value: FixtureBundleFinalisation) => void;
  let resultReject!: (error: Error) => void;
  const ready = new Promise<void>((resolve) => { readyResolve = resolve; });
  const result = new Promise<FixtureBundleFinalisation>((resolve, reject) => {
    resultResolve = resolve;
    resultReject = reject;
  });
  worker.onmessage = (event: MessageEvent<Record<string, unknown>>) => {
    if (event.data["kind"] === "ready") readyResolve();
    else if (event.data["kind"] === "result") resultResolve(event.data["result"] as FixtureBundleFinalisation);
    else if (event.data["kind"] === "error") resultReject(new Error(String(event.data["message"])));
  };
  worker.onerror = (event) => resultReject(new Error(event.message));
  worker.postMessage({ kind: "initialize", path, input });
  return { ready, result, worker };
}

async function failedTerminalFixture(
  errorClass: "permanent" | "transient" | "counterparty" | "substrate" | "settlement-atomicity",
  failureStage: "payment" | "settlement" | "delivery" = "settlement",
  paymentKind: "pay-dem" | "pay-x402" = "pay-dem",
) {
  const fixture = paymentKind === "pay-dem" ? noSpendAgreement() : (() => {
    const x402 = agreementFixture();
    return {
      input: x402.input,
      canonicalJson: x402.agreementCanonicalJson,
      verification: x402.verification,
    };
  })();
  const path = await lifecycleDatabasePath();
  roots.push(path.slice(0, path.lastIndexOf("/")));
  const database = openLifecycleDatabase(path);
  const sessions = lifecycleSessionStore(database);
  admitLifecycleSession(sessions, fixture.canonicalJson);
  const session = sessions.get(fixture.input.jobId)!;
  const commitments = lifecycleCommitmentStore(database);
  const orchestratorSigner = orchestratorFixtureSigner();
  const reason = `fixture ${errorClass} ${failureStage} failure`;
  let lifecycleNow = new Date(FIXTURE_COMMITTED_AT).toISOString();
  const failureCreatedAt = new Date(FIXTURE_COMMITTED_AT + (failureStage === "delivery" ? 3_000 : 1_000)).toISOString();
  const successful = fixtureSettlementHandlers(database, orchestratorSigner, session);
  const fail = (context: { agreementHash: string; jobId: string; phaseIndex: number; phaseKind: string }) => {
    const paymentPhase = context.phaseKind.startsWith("pay-");
    const payeeAddress = context.phaseKind === "pay-dem"
      ? NO_SPEND_PAYEE_ADDRESS : "fixture:x402:payee";
    const unsigned = {
      evidenceVersion: "1" as const,
      jobId: context.jobId,
      phase: context.phaseKind as "pay-dem" | "pay-x402" | "deliver-attested-payload",
      outcome: "failure" as const,
      reason,
      observedAt: Date.parse(failureCreatedAt) - 500,
    };
    const evidenceHash = sha256Hex(canonicalize(unsigned));
    const failures = new FixtureFailureEvidenceStore(database, "fixture");
    const paymentOptions = !paymentPhase
      ? { expectedEvidenceLogicalAddress: `dacs4:delivery-evidence:${context.jobId}:${context.phaseIndex}` }
      : context.phaseKind === "pay-dem" ? {
        expectedFinality: { model: "bft-final" as const },
        expectedPayeeAddress: payeeAddress,
        expectedPaymentAmount: NO_SPEND_PAYMENT_AMOUNT,
        railId: NO_SPEND_RAIL_ID,
        pinnedRail: {
        assetCanonicalJson: '{"decimals":9,"kind":"native-dem","symbol":"DEM"}',
        assetCurrency: "DEM",
        networkKind: "demos" as const,
        phaseHandler: "pay-dem" as const,
        railId: NO_SPEND_RAIL_ID,
        },
      } : {
        expectedFinality: { model: "provider-receipt" as const },
        expectedPayeeAddress: payeeAddress,
        expectedPaymentAmount: { amount: "1", currency: "USDC", unit: "job" } as const,
        railId: "x402:default",
        pinnedRail: {
          assetCanonicalJson: '{"isoCurrency":"USDC","kind":"fiat-via-ap2","provider":"fixture-provider"}',
          assetCurrency: "USDC",
          networkKind: "x402-resource" as const,
          phaseHandler: "pay-x402" as const,
          railId: "x402:default",
        },
      };
    const signed = failures.persistSigned(unsigned, orchestratorSigner, {
      agreementHash: context.agreementHash,
      deploymentMode: "fixture",
      evidenceMode: "fixture",
      expectedJobId: context.jobId,
      expectedPayee: fixtureSigner().signer,
      expectedPayer: buyerFixtureSigner().signer,
      expectedPhase: unsigned.phase,
      expectedSessionBindingHash: sessionBindingHash(session),
      phaseIndex: context.phaseIndex,
      requestMode: "fixture",
      ...paymentOptions,
    }, {
      agreementHash: context.agreementHash,
      canonicalTxRefsJson: "[]",
      evidenceHash,
      evidenceMode: "fixture",
      jobId: context.jobId,
      orchestrator: orchestratorSigner.signer,
      payee: fixtureSigner().signer,
      ...(paymentPhase ? { payeeAddress } : {}),
      payer: buyerFixtureSigner().signer,
      phase: unsigned.phase,
      phaseIndex: context.phaseIndex,
      reason,
      sessionBindingHash: sessionBindingHash(session),
    }, failureCreatedAt);
    lifecycleNow = failureCreatedAt;
    return {
      ok: false as const,
      errorClass,
      reason,
      authorityClaim: orchestratorSigner.signer,
      value: {
        attestationRef: {
          anchor: { kind: "storage-program", locator: signed.logicalAddress },
          contentHash: signed.evidenceHash,
          signer: orchestratorSigner.signer,
        },
      },
    };
  };
  const lifecycle = lifecycleOrchestrator(database, sessions, commitments, {
    payment: failureStage === "payment" ? fail
      : () => ({ ok: true as const, value: { submitted: true, evidenceMode: "fixture" } }),
    settlement: failureStage === "settlement" ? fail : (...args) => {
      const result = successful.settlement(...args);
      lifecycleNow = CREATED_AT;
      return result;
    },
    delivery: failureStage === "delivery" ? fail
      : () => { throw new Error("delivery must not run after failure"); },
    now: () => lifecycleNow,
    substratePauseMs: 1_000,
  });
  let terminal = await lifecycle.run({
    agreementCanonicalJson: fixture.canonicalJson,
    jobId: fixture.input.jobId,
    verification: fixture.verification,
  });
  if (terminal.state === "substrate-failure-paused") {
    lifecycleNow = terminal.pauseExpiresAt;
    terminal = lifecycle.expirePaused(fixture.input.jobId);
  }
  if (terminal.state !== "settle-failed" && terminal.state !== "settle-unsupported"
    && terminal.state !== "failed-substrate") throw new Error(JSON.stringify(terminal));
  if (terminal.terminalEvidence === undefined) throw new Error(`missing terminal evidence: ${JSON.stringify(terminal)}`);
  const endedAt = terminal.endedAt;
  const commitment = commitments.get(session.instanceId, session.audience, session.jobId)!;
  const terminalRef = terminal.terminalEvidence?.value["attestationRef"] as Record<string, unknown>;
  const successfulRefs = terminal.settlements.map((entry) => entry.value["attestationRef"] as Record<string, unknown>);
  const outcome = errorClass === "permanent" || errorClass === "transient" ? "failed-perm" as const
    : errorClass === "substrate" ? "failed-substrate" as const : "failed-counterparty" as const;
  const bundle = {
    bundleVersion: "1" as const,
    jobId: fixture.input.jobId,
    outcome,
    listingRef: fixture.input.listingRef,
    agreementRef: {
      anchor: { kind: "storage-program" as const, locator: commitment.logicalAddress },
      contentHash: commitment.agreementHash,
    },
    parties: [
      ...bundleAgreementParties(fixture.input),
      {
        role: "orchestrator" as const,
        bundleHash: orchestratorFixtureIdentity().bundleHash,
        primaryClaim: orchestratorSigner.signer,
      },
    ],
    phaseSummary: [
      { index: 1, kind: "commit-payee-bound-agreement", outcome: "ok" as const },
      ...terminal.settlements.map((entry) => ({
        index: entry.phaseIndex,
        kind: entry.phaseKind,
        outcome: "ok" as const,
        attestationRef: entry.value["attestationRef"] as Record<string, unknown>,
      })),
      {
        index: terminal.terminalEvidence.phaseIndex,
        kind: terminal.terminalEvidence.phaseKind,
        outcome: "fail" as const,
        errorClass,
        attestationRef: terminalRef,
      },
    ],
    vetRecords: [],
    settlementEvidence: [...successfulRefs, terminalRef],
    recipeRegistryVersion: 1,
    railRegistryVersion: 1,
    finalisedAt: Date.parse(endedAt),
  };
  return {
    database,
    lifecycle,
    path,
    store: new FixtureBundleStore(database, { commitments, deploymentMode: "fixture" }),
    input: {
      anchorRoles: ["buyer", "seller", "orchestrator"] as const,
      bundle,
      createdAt: endedAt,
      faultedParty: outcome === "failed-counterparty" ? "seller" as const
        : outcome === "failed-perm" ? "buyer" as const : "none" as const,
      partySigners: [
        { role: "buyer" as const, signer: buyerFixtureSigner() },
        { role: "seller" as const, signer: fixtureSigner() },
        { role: "orchestrator" as const, signer: orchestratorSigner },
      ],
      partyIdentityCanonicalJsons: [
        fixtureBuyerIdentity().canonicalJson,
        fixtureListingSellerIdentity().canonicalJson,
        orchestratorFixtureIdentity().canonicalJson,
      ],
      session,
    },
  };
}

async function pendingAbortFixture() {
  const fixture = noSpendAgreement();
  const path = await lifecycleDatabasePath();
  roots.push(path.slice(0, path.lastIndexOf("/")));
  const database = openLifecycleDatabase(path);
  const sessions = lifecycleSessionStore(database);
  admitLifecycleSession(sessions, fixture.canonicalJson);
  const commitments = lifecycleCommitmentStore(database);
  let releasePayment!: () => void;
  let started!: () => void;
  const startedPromise = new Promise<void>((resolve) => { started = resolve; });
  const paymentGate = new Promise<void>((resolve) => { releasePayment = resolve; });
  let lifecycleNow = new Date(FIXTURE_COMMITTED_AT).toISOString();
  const lifecycle = lifecycleOrchestrator(database, sessions, commitments, {
    payment: async () => {
      started();
      await paymentGate;
      return { ok: true as const, value: { submitted: true } };
    },
    settlement: () => { throw new Error("settlement must not run after abort"); },
    delivery: () => { throw new Error("delivery must not run after abort"); },
    now: () => lifecycleNow,
  });
  const running = lifecycle.run({
    agreementCanonicalJson: fixture.canonicalJson,
    jobId: fixture.input.jobId,
    verification: fixture.verification,
  });
  await startedPromise;
  lifecycleNow = new Date(FIXTURE_COMMITTED_AT + 1_000).toISOString();
  const session = sessions.get(fixture.input.jobId)!;
  const commitment = commitments.get(session.instanceId, session.audience, session.jobId)!;
  const input = (role: "buyer" | "seller", outcome: "aborted-by-self" | "aborted-by-other") => ({
    anchorRoles: [role] as const,
    bundle: {
      bundleVersion: "1" as const,
      jobId: fixture.input.jobId,
      outcome,
      listingRef: fixture.input.listingRef,
      agreementRef: {
        anchor: { kind: "storage-program" as const, locator: commitment.logicalAddress },
        contentHash: commitment.agreementHash,
      },
      parties: bundleAgreementParties(fixture.input),
      phaseSummary: [{ index: 1, kind: "commit-payee-bound-agreement", outcome: "ok" as const }],
      vetRecords: [],
      settlementEvidence: [],
      recipeRegistryVersion: 1,
      railRegistryVersion: 1,
      finalisedAt: FIXTURE_COMMITTED_AT + 1_000,
    },
    createdAt: new Date(FIXTURE_COMMITTED_AT + 1_000).toISOString(),
    partySigners: [{ role, signer: role === "buyer" ? buyerFixtureSigner() : fixtureSigner() }],
    partyIdentityCanonicalJsons: [
      fixtureBuyerIdentity().canonicalJson,
      fixtureListingSellerIdentity().canonicalJson,
    ],
    session,
  });
  return {
    database,
    fixture,
    input,
    lifecycle,
    path,
    releasePayment,
    running,
    store: new FixtureBundleStore(database, { commitments, deploymentMode: "fixture" }),
  };
}

async function settledFixture(deliveryObservedAt = FINALISED_AT) {
  const fixture = noSpendAgreement();
  const path = await lifecycleDatabasePath();
  roots.push(path.slice(0, path.lastIndexOf("/")));
  const database = openLifecycleDatabase(path);
  const sessions = lifecycleSessionStore(database);
  admitLifecycleSession(sessions, fixture.canonicalJson);
  const commitments = lifecycleCommitmentStore(database);
  const orchestrator = orchestratorFixtureSigner();
  const deliveries = new FixtureDeliveryStore(database, { deploymentMode: "fixture", signer: fixtureSigner() });
  const delivery = createFixtureAttestedDeliveryHandler(deliveries, {
    now: () => CREATED_AT, observedAt: () => deliveryObservedAt,
    payloadFormat: DELIVERY_PAYLOAD_FORMAT, payloadJson: DELIVERY_PAYLOAD_JSON,
    paymentAmount: NO_SPEND_PAYMENT_AMOUNT, sessionStore: sessions,
  });
  let lifecycleNow = new Date(FIXTURE_COMMITTED_AT).toISOString();
  const lifecycle = lifecycleOrchestrator(database, sessions, commitments, {
    ...fixtureSettlementHandlers(database, orchestrator, sessions.get(fixture.input.jobId)!),
    delivery: async (...args: Parameters<typeof delivery>) => {
      const result = await delivery(...args);
      lifecycleNow = CREATED_AT;
      return result;
    },
    now: () => lifecycleNow,
  });
  const settled = await lifecycle.run({
    agreementCanonicalJson: fixture.canonicalJson, jobId: fixture.input.jobId,
    verification: fixture.verification,
  });
  if (settled.state !== "settle-completed") throw new Error(JSON.stringify(settled));
  const session = sessions.get(fixture.input.jobId)!;
  const commitment = commitments.get(session.instanceId, session.audience, session.jobId)!;
  const settlementRef = settled.settlements[0]!.value["attestationRef"] as Record<string, unknown>;
  const attestationRef = settled.delivery.value["attestationRef"] as Record<string, unknown>;
  const bundle = {
    bundleVersion: "1" as const, jobId: fixture.input.jobId, outcome: "completed" as const,
    listingRef: fixture.input.listingRef,
    agreementRef: { anchor: { kind: "storage-program" as const, locator: commitment.logicalAddress }, contentHash: commitment.agreementHash },
    parties: [
      ...bundleAgreementParties(fixture.input),
      {
        role: "orchestrator" as const,
        bundleHash: orchestratorFixtureIdentity().bundleHash,
        primaryClaim: orchestrator.signer,
      },
    ],
    phaseSummary: [
      { index: 1, kind: "commit-payee-bound-agreement", outcome: "ok" as const },
      { index: settled.settlements[0]!.phaseIndex, kind: settled.settlements[0]!.phaseKind, outcome: "ok" as const, attestationRef: settlementRef },
      { index: settled.delivery.phaseIndex, kind: settled.delivery.phaseKind, outcome: "ok" as const, attestationRef },
    ],
    vetRecords: [], settlementEvidence: [settlementRef, attestationRef], recipeRegistryVersion: 1,
    railRegistryVersion: 1, finalisedAt: FINALISED_AT,
  };
  return {
    database,
    path,
    store: new FixtureBundleStore(database, { commitments, deploymentMode: "fixture" }),
    input: {
      anchorRoles: ["buyer", "seller", "orchestrator"] as const, bundle, createdAt: CREATED_AT,
      partySigners: [
        { role: "buyer" as const, signer: buyerFixtureSigner() },
        { role: "seller" as const, signer: fixtureSigner() },
        { role: "orchestrator" as const, signer: orchestrator },
      ],
      partyIdentityCanonicalJsons: [
        fixtureBuyerIdentity().canonicalJson,
        fixtureListingSellerIdentity().canonicalJson,
        orchestratorFixtureIdentity().canonicalJson,
      ],
      session,
    },
  };
}

function noSpendAgreement() {
  const fixture = agreementFixture(undefined, {
    pipeline: [
      { kind: "negotiate-fixed-price" },
      { kind: "commit-payee-bound-agreement" },
      { kind: "pay-dem", parameters: { rail: NO_SPEND_RAIL_ID } },
      { kind: "deliver-attested-payload" },
    ],
    acceptedRails: [{ railId: NO_SPEND_RAIL_ID, railVersion: 1 }],
    pricing: { kind: "fixed", price: NO_SPEND_PAYMENT_AMOUNT },
  });
  return { input: fixture.input, canonicalJson: fixture.agreementCanonicalJson, verification: fixture.verification };
}

function bundleAgreementParties(input: ReturnType<typeof agreementFixture>["input"]) {
  return input.parties
    .filter((party) => party.role === "buyer" || party.role === "seller")
    .map(({ role, bundleHash, primaryClaim }) => ({
      role: role as "buyer" | "seller", bundleHash, primaryClaim,
    }));
}

function fixtureSettlementHandlers(
  database: ReturnType<typeof openLifecycleDatabase>,
  orchestrator: ReturnType<typeof orchestratorFixtureSigner>,
  session: SessionRecord,
) {
  return {
    payment: () => ({ ok: true as const, value: { submitted: true, evidenceMode: "fixture" } }),
    settlement: (context: { agreementHash: string; jobId: string; phaseIndex: number; phaseKind: string }) => {
      const ledger = new FixtureSettlementLedger(database, "fixture");
      const transaction = ledger.record({
        agreementHash: context.agreementHash,
        blockNumber: 42,
        createdAt: CREATED_AT,
        finalityObservedAt: FINALISED_AT - 1,
        jobId: context.jobId,
        orchestrator: orchestrator.signer,
        payee: fixtureSigner().signer,
        payeeAddress: NO_SPEND_PAYEE_ADDRESS,
        payer: buyerFixtureSigner().signer,
        paymentAmount: NO_SPEND_PAYMENT_AMOUNT,
        phaseIndex: context.phaseIndex,
        sessionBindingHash: sessionBindingHash(session),
      });
      const signed = signSettlementEvidence({
        evidenceVersion: "1",
        jobId: context.jobId,
        phase: "pay-dem",
        outcome: "success",
        paymentTxRefs: [{ kind: "demos", txHash: `0x${transaction.txHash}`, blockNumber: 42 }],
        paymentAmount: NO_SPEND_PAYMENT_AMOUNT,
        settlementFinality: { model: "bft-final", finalityObservedAt: FINALISED_AT - 1 },
        observedAt: FINALISED_AT - 1,
      }, orchestrator, {
        agreementHash: context.agreementHash,
        deploymentMode: "fixture",
        evidenceMode: "fixture",
        expectedFinality: { model: "bft-final" },
        expectedJobId: context.jobId,
        expectedPayee: fixtureSigner().signer,
        expectedPayeeAddress: NO_SPEND_PAYEE_ADDRESS,
        expectedPayer: buyerFixtureSigner().signer,
        expectedPaymentAmount: NO_SPEND_PAYMENT_AMOUNT,
        expectedSessionBindingHash: sessionBindingHash(session),
        phaseIndex: context.phaseIndex,
        railId: NO_SPEND_RAIL_ID,
        requestMode: "fixture",
        paymentTransactionCheck: (txRef, expected) => ledger.verifyTransaction(txRef, expected),
        pinnedRail: {
          assetCanonicalJson: '{"decimals":9,"kind":"native-dem","symbol":"DEM"}',
          assetCurrency: "DEM",
          networkKind: "demos",
          phaseHandler: "pay-dem",
          railId: NO_SPEND_RAIL_ID,
        },
      });
      new FixtureAnchorStore(database, "fixture").put(
        signed.logicalAddress,
        "dacs-4-evidence",
        signed.evidenceHash,
        signed.canonicalJson,
        CREATED_AT,
      );
      return {
        ok: true as const,
        authorityClaim: orchestrator.signer,
        value: {
          attestationRef: {
            anchor: { kind: "storage-program", locator: signed.logicalAddress },
            contentHash: signed.evidenceHash,
            signer: orchestrator.signer,
          },
          evidenceHash: signed.evidenceHash,
          evidenceMode: "fixture",
        },
      };
    },
  };
}
