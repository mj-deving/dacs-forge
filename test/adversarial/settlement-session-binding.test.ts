import { afterEach, describe, expect, test } from "bun:test";
import { rm } from "node:fs/promises";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { signSettlementEvidence } from "../../src/producer/settlement-evidence.ts";
import {
  verifyCanonicalSettlementEvidenceJson,
  type SettlementDeliveryExpectation,
} from "../../src/consumer/settlement-evidence-verifier.ts";
import {
  FixtureSettlementConflictError,
  FixtureSettlementLedger,
} from "../../src/substrate/sqlite/fixture-settlement.ts";
import { sessionBindingHash } from "../../src/substrate/sqlite/session-store.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";
import {
  DELIVERY_AGREEMENT_HASH,
  DELIVERY_CREATED_AT,
  deliveryInput,
  openDeliveryFixture,
} from "../delivery/fixtures.ts";

const paths: string[] = [];
const PAYMENT_PHASE_INDEX = 2;
const PAYMENT_AMOUNT = Object.freeze({ amount: "1", currency: "DEM" });
const PAYEE_ADDRESS = `0x${"2".repeat(64)}`;
const PAYER = `key:${"1".repeat(64)}`;
const RAIL_ID = "demos-native:DEM";
const ASSET_JSON = canonicalize({ decimals: 9, kind: "native-dem", symbol: "DEM" });

afterEach(async () => {
  await Promise.all(paths.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

describe("settlement and delivery session binding", () => {
  test("derives settlement binding from the persisted admitted session", async () => {
    const fixture = await openDeliveryFixture();
    paths.push(fixture.path.slice(0, fixture.path.lastIndexOf("/")));
    const ledger = new FixtureSettlementLedger(fixture.database, "fixture");
    const base = {
      agreementHash: DELIVERY_AGREEMENT_HASH,
      blockNumber: 42,
      createdAt: DELIVERY_CREATED_AT,
      finalityObservedAt: Date.parse(DELIVERY_CREATED_AT),
      jobId: fixture.session.jobId,
      orchestrator: fixtureSigner().signer,
      payee: fixtureSigner().signer,
      payeeAddress: PAYEE_ADDRESS,
      payer: PAYER,
      paymentAmount: PAYMENT_AMOUNT,
      phaseIndex: PAYMENT_PHASE_INDEX,
      sessionBindingHash: sessionBindingHash(fixture.session),
    } as const;
    expect(() => ledger.record({ ...base, sessionBindingHash: "f".repeat(64) }))
      .toThrow(FixtureSettlementConflictError);
    expect(() => ledger.record({
      ...base,
      jobId: "01J8ME0SXKQ4T9V2RC5HJ6WX7E",
      sessionBindingHash: "e".repeat(64),
    })).toThrow(FixtureSettlementConflictError);
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_settlements",
    ).get()!.count).toBe(0n);
    expect(ledger.record(base).sessionBindingHash).toBe(sessionBindingHash(fixture.session));
    fixture.database.close();
  });

  test("rejects payment transaction substitution across job, phase, agreement, and session", async () => {
    const fixture = await openDeliveryFixture();
    paths.push(fixture.path.slice(0, fixture.path.lastIndexOf("/")));
    const ledger = new FixtureSettlementLedger(fixture.database, "fixture");
    const bindingHash = sessionBindingHash(fixture.session);
    const transaction = ledger.record({
      agreementHash: DELIVERY_AGREEMENT_HASH,
      blockNumber: 42,
      createdAt: DELIVERY_CREATED_AT,
      finalityObservedAt: Date.parse(DELIVERY_CREATED_AT),
      jobId: fixture.session.jobId,
      orchestrator: fixtureSigner().signer,
      payee: fixtureSigner().signer,
      payeeAddress: PAYEE_ADDRESS,
      payer: PAYER,
      paymentAmount: PAYMENT_AMOUNT,
      phaseIndex: PAYMENT_PHASE_INDEX,
      sessionBindingHash: bindingHash,
    });
    const signed = signSettlementEvidence({
      evidenceVersion: "1",
      jobId: fixture.session.jobId,
      phase: "pay-dem",
      outcome: "success",
      paymentTxRefs: [{ kind: "demos", txHash: transaction.txHash, blockNumber: 42 }],
      paymentAmount: PAYMENT_AMOUNT,
      settlementFinality: { model: "bft-final", finalityObservedAt: transaction.finalityObservedAt },
      observedAt: transaction.finalityObservedAt,
    }, fixtureSigner(), signingOptions(ledger, fixture.session.jobId, DELIVERY_AGREEMENT_HASH, bindingHash));
    const base = verificationOptions(ledger, fixture.session.jobId, DELIVERY_AGREEMENT_HASH, bindingHash);
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, base))
      .toMatchObject({ disposition: "provisionally-verified" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      expectedJobId: "01J8ME0SXKQ4T9V2RC5HJ6WX7E",
    })).toMatchObject({ disposition: "rejected", stage: "job-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      phaseIndex: PAYMENT_PHASE_INDEX + 1,
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      agreementHash: "e".repeat(64),
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      expectedSessionBindingHash: "f".repeat(64),
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    fixture.database.close();
  });

  test("rejects delivery anchor substitution across every pinned binding", async () => {
    const fixture = await openDeliveryFixture();
    paths.push(fixture.path.slice(0, fixture.path.lastIndexOf("/")));
    const record = fixture.store.deliver(deliveryInput(fixture.session));
    const paymentAmount = JSON.parse(record.paymentAmountCanonicalJson) as Record<string, unknown>;
    const base = {
      agreementHash: record.agreementHash,
      anchorContext: { mode: "post-anchor" as const, read: (address: string) => fixture.store.readEvidenceAnchor(address) },
      deliveryArtifactCheck: (address: string, expected: SettlementDeliveryExpectation) =>
        fixture.store.verifyDeliveryArtifact(address, expected),
      evidenceMode: "fixture" as const,
      expectedEvidenceLogicalAddress: record.evidenceAddress,
      expectedJobId: record.jobId,
      expectedOrchestrator: record.orchestrator,
      expectedPaymentAmount: paymentAmount,
      expectedPhase: "deliver-attested-payload",
      expectedSessionBindingHash: record.sessionBindingHash,
      phaseIndex: record.phaseIndex,
    };
    expect(verifyCanonicalSettlementEvidenceJson(record.evidenceCanonicalJson, base))
      .toMatchObject({ disposition: "verified" });
    expect(verifyCanonicalSettlementEvidenceJson(record.evidenceCanonicalJson, {
      ...base,
      expectedJobId: "01J8ME0SXKQ4T9V2RC5HJ6WX7E",
    })).toMatchObject({ disposition: "rejected", stage: "job-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(record.evidenceCanonicalJson, {
      ...base,
      phaseIndex: record.phaseIndex + 1,
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(record.evidenceCanonicalJson, {
      ...base,
      agreementHash: "e".repeat(64),
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(record.evidenceCanonicalJson, {
      ...base,
      expectedSessionBindingHash: "f".repeat(64),
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(record.evidenceCanonicalJson, {
      ...base,
      expectedEvidenceLogicalAddress: `${record.evidenceAddress}:substituted`,
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    fixture.database.close();
  });

  test("refuses a caller-fabricated clone of a persisted admitted session", async () => {
    const fixture = await openDeliveryFixture();
    paths.push(fixture.path.slice(0, fixture.path.lastIndexOf("/")));
    const forged = Object.freeze({
      ...fixture.session,
      requestHash: "f".repeat(64),
    });
    expect(() => fixture.store.deliver(deliveryInput(forged)))
      .toThrow(/does not match persisted admission/);
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_deliveries",
    ).get()!.count).toBe(0n);
    expect(fixture.database.query<{ count: bigint }, []>(
      "SELECT count(*) AS count FROM fixture_anchors",
    ).get()!.count).toBe(0n);
    fixture.database.close();
  });
});

function signingOptions(
  ledger: FixtureSettlementLedger,
  jobId: string,
  agreementHash: string,
  bindingHash: string,
) {
  return {
    agreementHash,
    deploymentMode: "fixture" as const,
    evidenceMode: "fixture" as const,
    expectedFinality: { model: "bft-final" },
    expectedJobId: jobId,
    expectedPayee: fixtureSigner().signer,
    expectedPayeeAddress: PAYEE_ADDRESS,
    expectedPayer: PAYER,
    expectedPaymentAmount: PAYMENT_AMOUNT,
    expectedSessionBindingHash: bindingHash,
    phaseIndex: PAYMENT_PHASE_INDEX,
    railId: RAIL_ID,
    requestMode: "fixture" as const,
    paymentTransactionCheck: (txRef: Readonly<Record<string, unknown>>, expected: Parameters<FixtureSettlementLedger["verifyTransaction"]>[1]) =>
      ledger.verifyTransaction(txRef, expected),
    pinnedRail: {
      assetCanonicalJson: ASSET_JSON,
      assetCurrency: "DEM",
      networkKind: "demos" as const,
      phaseHandler: "pay-dem",
      railId: RAIL_ID,
    },
  };
}

function verificationOptions(
  ledger: FixtureSettlementLedger,
  jobId: string,
  agreementHash: string,
  bindingHash: string,
) {
  return {
    ...signingOptions(ledger, jobId, agreementHash, bindingHash),
    anchorContext: { mode: "pre-anchor" as const },
    expectedOrchestrator: fixtureSigner().signer,
    expectedPhase: "pay-dem",
  };
}
