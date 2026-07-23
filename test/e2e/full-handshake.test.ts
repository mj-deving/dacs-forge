import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { dirname } from "node:path";
import { FixtureBilateralVetOrchestrator } from "../../src/lifecycle/fixture-vet-orchestrator.ts";
import { createFixtureAttestedDeliveryHandler } from "../../src/lifecycle/fixture-attested-delivery-handler.ts";
import { signBuyerVetRequirement } from "../../src/producer/buyer-vet-requirement.ts";
import { signSettlementEvidence } from "../../src/producer/settlement-evidence.ts";
import { FixtureBundleStore } from "../../src/substrate/sqlite/fixture-bundle.ts";
import { FixtureDeliveryStore } from "../../src/substrate/sqlite/fixture-delivery.ts";
import { FixtureAnchorStore, FixtureSettlementLedger } from "../../src/substrate/sqlite/fixture-settlement.ts";
import { sessionBindingHash } from "../../src/substrate/sqlite/session-store.ts";
import { FixtureVetStore } from "../../src/substrate/sqlite/fixture-vet.ts";
import {
  FIXTURE_COMMITTED_AT,
  buyerFixtureSigner,
  fixtureBuyerIdentity,
  fixtureListingSellerIdentity,
  fixtureSignedPaidListing,
} from "../fixtures/reference-agreement.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
import { orchestratorFixtureIdentity, orchestratorFixtureSigner } from "../fixtures/reference-bundle.ts";
import { DELIVERY_PAYLOAD_FORMAT, DELIVERY_PAYLOAD_JSON } from "../delivery/fixtures.ts";
import {
  admitLifecycleSession,
  agreementFixture,
  lifecycleCommitmentStore,
  lifecycleDatabasePath,
  lifecycleOrchestrator,
  lifecycleSessionStore,
  openLifecycleDatabase,
} from "../lifecycle/fixtures.ts";

const roots: string[] = [];
const PAYMENT_AMOUNT = Object.freeze({ amount: "1", currency: "DEM", unit: "job" });
const RAIL_ID = "demos-native:DEM";
const PAYEE_ADDRESS = `0x${"2".repeat(64)}`;
const VET_AT = FIXTURE_COMMITTED_AT - 500;
const FINALISED_AT = FIXTURE_COMMITTED_AT + 2_000;
const CREATED_AT = new Date(FINALISED_AT).toISOString();
const LISTING_OVERRIDES = Object.freeze({
  pipeline: [
    { kind: "negotiate-fixed-price" as const },
    { kind: "commit-payee-bound-agreement" as const },
    { kind: "pay-dem" as const, parameters: { rail: RAIL_ID } },
    { kind: "deliver-attested-payload" as const },
  ],
  acceptedRails: [{ railId: RAIL_ID, railVersion: 1 }],
  pricing: { kind: "fixed" as const, price: PAYMENT_AMOUNT },
});

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("complete no-spend DACS fixture handshake", () => {
  test("dogfoods listing through bilateral Vet and restart-verified role-local bundles", async () => {
    const placeholder = agreementFixture(undefined, LISTING_OVERRIDES);
    const listing = fixtureSignedPaidListing(LISTING_OVERRIDES);
    const path = await lifecycleDatabasePath();
    roots.push(dirname(path));
    let database = openLifecycleDatabase(path);
    let sessions = lifecycleSessionStore(database);
    admitLifecycleSession(sessions, placeholder.agreementCanonicalJson);
    const session = sessions.get(placeholder.input.jobId)!;

    const buyerRequirement = signBuyerVetRequirement({
      jobId: session.jobId,
      buyer: buyerFixtureSigner().signer,
      seller: fixtureSigner().signer,
      requirement: { required: [{ scheme: "key" }] },
      generatedAt: VET_AT,
    }, buyerFixtureSigner(), { deploymentMode: "fixture", requestMode: "fixture" });
    const vet = new FixtureBilateralVetOrchestrator(new FixtureVetStore(database, "fixture")).run({
      buyer: {
        session,
        evaluatedRole: "buyer",
        evaluatedBundleHash: fixtureBuyerIdentity().bundleHash,
        requirementAuthority: { kind: "seller-listing", canonicalJson: listing.canonicalJson },
        evaluatedSigner: buyerFixtureSigner(),
        verifierSigner: fixtureSigner(),
        generatedAt: VET_AT,
        createdAt: new Date(VET_AT).toISOString(),
      },
      seller: {
        session,
        evaluatedRole: "seller",
        evaluatedBundleHash: fixtureListingSellerIdentity(listing).bundleHash,
        requirementAuthority: { kind: "buyer-signed", canonicalJson: buyerRequirement.canonicalJson },
        evaluatedSigner: fixtureSigner(),
        verifierSigner: buyerFixtureSigner(),
        generatedAt: VET_AT,
        createdAt: new Date(VET_AT).toISOString(),
      },
    });
    if (vet.state !== "passed") throw new Error(JSON.stringify(vet));

    const agreement = agreementFixture((input) => ({
      ...input,
      parties: input.parties.map((party) => ({
        ...party,
        vetRecordRef: party.role === "buyer"
          ? vet.buyer.compositeReference : vet.seller.compositeReference,
      })),
    }), LISTING_OVERRIDES);
    let commitments = lifecycleCommitmentStore(database);
    const orchestratorSigner = orchestratorFixtureSigner();
    const ledger = new FixtureSettlementLedger(database, "fixture");
    const deliveries = new FixtureDeliveryStore(database, { deploymentMode: "fixture", signer: fixtureSigner() });
    const delivery = createFixtureAttestedDeliveryHandler(deliveries, {
      now: () => CREATED_AT,
      observedAt: () => FINALISED_AT,
      payloadFormat: DELIVERY_PAYLOAD_FORMAT,
      payloadJson: DELIVERY_PAYLOAD_JSON,
      paymentAmount: PAYMENT_AMOUNT,
      sessionStore: sessions,
    });
    let lifecycleNow = new Date(FIXTURE_COMMITTED_AT).toISOString();
    const lifecycle = lifecycleOrchestrator(database, sessions, commitments, {
      payment: () => ({ ok: true, value: { submitted: true, evidenceMode: "fixture" } }),
      settlement: (context) => {
        const transaction = ledger.record({
          agreementHash: context.agreementHash,
          blockNumber: 42,
          createdAt: CREATED_AT,
          finalityObservedAt: FINALISED_AT - 1,
          jobId: context.jobId,
          orchestrator: orchestratorSigner.signer,
          payee: fixtureSigner().signer,
          payeeAddress: PAYEE_ADDRESS,
          payer: buyerFixtureSigner().signer,
          paymentAmount: PAYMENT_AMOUNT,
          phaseIndex: context.phaseIndex,
          sessionBindingHash: sessionBindingHash(session),
        });
        const signed = signSettlementEvidence({
          evidenceVersion: "1",
          jobId: context.jobId,
          phase: "pay-dem",
          outcome: "success",
          paymentTxRefs: [{ kind: "demos", txHash: `0x${transaction.txHash}`, blockNumber: 42 }],
          paymentAmount: PAYMENT_AMOUNT,
          settlementFinality: { model: "bft-final", finalityObservedAt: FINALISED_AT - 1 },
          observedAt: FINALISED_AT - 1,
        }, orchestratorSigner, {
          agreementHash: context.agreementHash,
          deploymentMode: "fixture",
          evidenceMode: "fixture",
          expectedFinality: { model: "bft-final" },
          expectedJobId: context.jobId,
          expectedPayee: fixtureSigner().signer,
          expectedPayeeAddress: PAYEE_ADDRESS,
          expectedPayer: buyerFixtureSigner().signer,
          expectedPaymentAmount: PAYMENT_AMOUNT,
          expectedSessionBindingHash: sessionBindingHash(session),
          phaseIndex: context.phaseIndex,
          railId: RAIL_ID,
          requestMode: "fixture",
          paymentTransactionCheck: (txRef, expected) => ledger.verifyTransaction(txRef, expected),
          pinnedRail: {
            assetCanonicalJson: '{"decimals":9,"kind":"native-dem","symbol":"DEM"}',
            assetCurrency: "DEM",
            networkKind: "demos",
            phaseHandler: "pay-dem",
            railId: RAIL_ID,
          },
        });
        new FixtureAnchorStore(database, "fixture").put(
          signed.logicalAddress, "dacs-4-evidence", signed.evidenceHash, signed.canonicalJson, CREATED_AT,
        );
        return {
          ok: true as const,
          authorityClaim: orchestratorSigner.signer,
          value: {
            attestationRef: {
              anchor: { kind: "storage-program", locator: signed.logicalAddress },
              contentHash: signed.evidenceHash,
              signer: orchestratorSigner.signer,
            },
          },
        };
      },
      delivery: async (...args: Parameters<typeof delivery>) => {
        const result = await delivery(...args);
        lifecycleNow = CREATED_AT;
        return result;
      },
      now: () => lifecycleNow,
    });
    const settled = await lifecycle.run({
      agreementCanonicalJson: agreement.agreementCanonicalJson,
      jobId: agreement.input.jobId,
      verification: agreement.verification,
    });
    if (settled.state !== "settle-completed") throw new Error(JSON.stringify(settled));
    const commitment = commitments.get(session.instanceId, session.audience, session.jobId)!;
    const settlementRef = settled.settlements[0]!.value["attestationRef"] as Record<string, unknown>;
    const deliveryRef = settled.delivery.value["attestationRef"] as Record<string, unknown>;
    const parties = agreement.input.parties.map(({ role, bundleHash, primaryClaim }) => ({
      role: role as "buyer" | "seller", bundleHash, primaryClaim,
    }));
    const bundle = {
      bundleVersion: "1" as const,
      jobId: agreement.input.jobId,
      outcome: "completed" as const,
      listingRef: agreement.input.listingRef,
      agreementRef: {
        anchor: { kind: "storage-program" as const, locator: commitment.logicalAddress },
        contentHash: commitment.agreementHash,
      },
      parties: [...parties, {
        role: "orchestrator" as const,
        bundleHash: orchestratorFixtureIdentity().bundleHash,
        primaryClaim: orchestratorSigner.signer,
      }],
      phaseSummary: [
        { index: 1, kind: "commit-payee-bound-agreement", outcome: "ok" as const },
        { index: settled.settlements[0]!.phaseIndex, kind: settled.settlements[0]!.phaseKind, outcome: "ok" as const, attestationRef: settlementRef },
        { index: settled.delivery.phaseIndex, kind: settled.delivery.phaseKind, outcome: "ok" as const, attestationRef: deliveryRef },
      ],
      vetRecords: vet.vetRecordRefs,
      settlementEvidence: [settlementRef, deliveryRef],
      recipeRegistryVersion: 1,
      railRegistryVersion: 1,
      finalisedAt: FINALISED_AT,
    };
    const bundleInput = {
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
        fixtureListingSellerIdentity(listing).canonicalJson,
        orchestratorFixtureIdentity().canonicalJson,
      ],
      session,
    };
    let bundles = new FixtureBundleStore(database, { commitments, deploymentMode: "fixture" });
    expect(() => bundles.finalise({
      ...bundleInput,
      bundle: { ...bundle, vetRecords: [] },
    })).toThrow("Bundle Vet records do not exactly match two passing persisted composites");
    expect(() => bundles.finalise({
      ...bundleInput,
      bundle: { ...bundle, vetRecords: [vet.buyer.compositeReference] },
    })).toThrow("Bundle Vet records do not exactly match two passing persisted composites");
    expect(() => bundles.finalise({
      ...bundleInput,
      bundle: { ...bundle, vetRecords: [...vet.vetRecordRefs].reverse() },
    })).toThrow("Bundle Vet records do not exactly match two passing persisted composites");
    expect(() => bundles.finalise({
      ...bundleInput,
      bundle: { ...bundle, recipeRegistryVersion: 2 },
    })).toThrow("Bundle Vet records do not exactly match two passing persisted composites");
    expect(bundles.finalise(bundleInput).copies).toHaveLength(3);
    expect(bundles.verifySession(session.jobId)).toMatchObject({
      disposition: "unified",
      reputationEligibility: "eligible",
    });
    database.close();

    database = openLifecycleDatabase(path);
    sessions = lifecycleSessionStore(database);
    commitments = lifecycleCommitmentStore(database);
    bundles = new FixtureBundleStore(database, { commitments, deploymentMode: "fixture" });
    expect(new FixtureVetStore(database, "fixture").get(session, "buyer")?.overallDecision).toBe("pass");
    expect(new FixtureVetStore(database, "fixture").get(session, "seller")?.overallDecision).toBe("pass");
    expect(new FixtureDeliveryStore(database, {
      deploymentMode: "fixture",
      signer: fixtureSigner(),
    }).get(session)).not.toBeNull();
    expect(bundles.verifySession(session.jobId)).toMatchObject({
      disposition: "unified",
      reputationEligibility: "eligible",
    });
    expect(sessions.get(session.jobId)).not.toBeNull();
    database.query<never, { jobId: string }>(`
      UPDATE fixture_vet_records SET overall_decision = 'error'
      WHERE job_id = $jobId AND evaluated_role = 'buyer'
    `).run({ jobId: session.jobId });
    expect(bundles.verifySession(session.jobId)).toMatchObject({
      disposition: "rejected",
      reputationEligibility: "excluded",
    });
    database.close();
  });
});
