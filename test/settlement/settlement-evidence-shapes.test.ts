import { describe, expect, test } from "bun:test";
import {
  verifyCanonicalSettlementEvidenceJson,
  type SettlementEvidenceVerificationOptions,
} from "../../src/consumer/settlement-evidence-verifier.ts";
import { canonicalize } from "../../src/protocol/canonical-json.ts";
import { sha256Hex } from "../../src/protocol/hash.ts";
import {
  signSettlementEvidence,
  type SettlementEvidenceSigningOptions,
  type UnsignedSettlementEvidence,
} from "../../src/producer/settlement-evidence.ts";
import { fixtureSigner } from "../fixtures/reference-listing.ts";

const JOB_ID = "01J8ME0SXKQ4T9V2RC5HJ6WX7D";
const AGREEMENT_HASH = "a".repeat(64);
const CONTENT_HASH = "b".repeat(64);
const SESSION_BINDING_HASH = "c".repeat(64);
const PAYER = `key:${"1".repeat(64)}`;
const PAYEE = fixtureSigner().signer;
const PAYEE_ADDRESS = "0x00000000000000000000000000000000000000aa";
const DEMOS_PAYEE_ADDRESS = `0x${"2".repeat(64)}`;
const DELIVERY_AMOUNT = Object.freeze({ amount: "1", currency: "DEM" });
const DELIVERY_EVIDENCE_ADDRESS = `fixture:dacs4-evidence:${JOB_ID}:2`;

describe("SettlementEvidence phase-specific conformance", () => {
  test("requires authoritative delivery resolution before verifying storage evidence", () => {
    const input: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "deliver-storage-program",
      outcome: "success",
      paymentAmount: DELIVERY_AMOUNT,
      deliverableContentHash: CONTENT_HASH,
      deliverableAnchor: { kind: "storage-program", locator: "stor-fixture-delivery" },
      observedAt: 1_780_014_402_000,
    };
    const signed = signSettlementEvidence(input, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedPaymentAmount: DELIVERY_AMOUNT,
      deliveryArtifactCheck: (address, expected) => {
        expect(address).toBe(`dacs4:deliverable:${JOB_ID}`);
        expect(expected.phaseIndex).toBe(2);
        expect(expected.evidenceLogicalAddress).toBe(DELIVERY_EVIDENCE_ADDRESS);
        return { status: "verified", ...expected };
      },
      expectedPhase: "deliver-storage-program",
    });
    const base = {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" as const },
      evidenceMode: "fixture" as const,
      expectedEvidenceLogicalAddress: DELIVERY_EVIDENCE_ADDRESS,
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPaymentAmount: DELIVERY_AMOUNT,
      expectedPhase: input.phase,
      expectedSessionBindingHash: SESSION_BINDING_HASH,
      phaseIndex: 3,
    };

    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, base)).toEqual({
      disposition: "indeterminate",
      stage: "transaction-binding",
      reason: "Delivery artifact verifier is unavailable",
      evidenceHash: signed.evidenceHash,
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      agreementHash: "not-a-hash",
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "amount-binding",
      reason: "Configured expected agreement hash is malformed",
    });
    expect(() => signSettlementEvidence({
      ...input,
      paymentAmount: undefined,
    } as unknown as UnsignedSettlementEvidence, fixtureSigner(), {
      ...baseSigningOptions(),
      deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
      expectedPaymentAmount: DELIVERY_AMOUNT,
      expectedPhase: "deliver-storage-program",
    })).toThrow(/requires paymentAmount/);
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      expectedPaymentAmount: { amount: "2", currency: "DEM" },
    })).toMatchObject({
      disposition: "rejected",
      stage: "amount-binding",
      reason: "SettlementEvidence payment amount differs from the agreement price",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      phaseIndex: -1,
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "phase-binding",
      reason: "Settlement verification requires a valid phaseIndex",
    });
    const { expectedEvidenceLogicalAddress: _evidenceAddress, ...withoutEvidenceAddress } = base;
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, withoutEvidenceAddress)).toMatchObject({
      disposition: "refused-unsupported",
      stage: "anchor-binding",
      reason: "Delivery verification requires an explicit evidence anchor address",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      expectedEvidenceLogicalAddress: `dacs4:deliverable:${JOB_ID}`,
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "anchor-binding",
      reason: "Delivery evidence anchor must be distinct from the delivered artifact address",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      anchorContext: {
        mode: "post-anchor",
        read: (address) => {
          expect(address).toBe(DELIVERY_EVIDENCE_ADDRESS);
          return {
            status: "resolved",
            artifactContentHash: sha256Hex(signed.canonicalJson),
            artifactKind: "dacs-4-evidence",
            evidenceHash: signed.evidenceHash,
            evidenceMode: "fixture",
          };
        },
      },
      deliveryArtifactCheck: (address, expected) => {
        expect(address).toBe(`dacs4:deliverable:${JOB_ID}`);
        return { status: "verified", ...expected };
      },
    })).toMatchObject({ disposition: "verified", logicalAddress: DELIVERY_EVIDENCE_ADDRESS });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      deliveryArtifactCheck: (_address, expected) => ({
        status: "verified",
        ...expected,
        deliverableContentHash: "c".repeat(64),
      }),
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      deliveryArtifactCheck: () => {
        throw new Error("fixture storage unavailable");
      },
    })).toMatchObject({
      disposition: "indeterminate",
      stage: "transaction-binding",
      reason: "Delivery artifact verifier failed: fixture storage unavailable",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      deliveryArtifactCheck: () => null as unknown as ReturnType<NonNullable<
        SettlementEvidenceVerificationOptions["deliveryArtifactCheck"]
      >>,
    })).toMatchObject({
      disposition: "indeterminate",
      reason: "Delivery artifact verifier returned a malformed result",
    });
    expect(() => signSettlementEvidence(input, fixtureSigner(), {
      ...baseSigningOptions(),
      deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
      expectedJobId: "01J8ME0SXKQ4T9V2RC5HJ6WX7E",
      expectedPhase: "deliver-storage-program",
    })).toThrow(/jobId does not match the session/);
    expect(() => signSettlementEvidence(input, fixtureSigner(), {
      ...baseSigningOptions(),
      deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
      expectedPhase: "deliver-entitlement",
    })).toThrow(/phase does not match the pipeline invocation/);
    expect(() => signSettlementEvidence({
      ...input,
      deliverableAnchor: { kind: "https", locator: "https://example.test/payload" },
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
      expectedPhase: "deliver-storage-program",
    })).toThrow(/storage-program anchor/);
  });

  test("accepts entitlement evidence without storage payload fields only after record resolution", () => {
    const input: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "deliver-entitlement",
      outcome: "success",
      paymentAmount: DELIVERY_AMOUNT,
      observedAt: 1_780_014_402_000,
    };
    const signed = signSettlementEvidence(input, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedPaymentAmount: DELIVERY_AMOUNT,
      entitlementRenewalSeq: 7,
      deliveryArtifactCheck: (address, expected) => {
        expect(address).toBe(`dacs4:entitlement:${JOB_ID}:7`);
        expect(expected.renewalSeq).toBe(7);
        return { status: "verified", ...expected };
      },
      expectedPhase: "deliver-entitlement",
    });
    expect(signed.logicalAddress).toBe(DELIVERY_EVIDENCE_ADDRESS);
    expect(Object.hasOwn(signed.evidence, "deliverableContentHash")).toBe(false);
  });

  test("derives the resolved address for a superseding cross-chain success record", () => {
    const amount = { amount: "5", currency: "USDC" };
    const settlementIds: Array<string | undefined> = [];
    const input: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-cross-chain-htlc",
      outcome: "success",
      paymentTxRefs: [
        {
          kind: "htlc-lock",
          chainId: 1,
          contractAddress: "0x0000000000000000000000000000000000000001",
          lockTxHash: `0x${"a".repeat(64)}`,
        },
        {
          kind: "htlc-reveal",
          chainId: 8453,
          contractAddress: "0x0000000000000000000000000000000000000002",
          revealTxHash: `0x${"b".repeat(64)}`,
        },
        {
          kind: "htlc-claim",
          chainId: 1,
          contractAddress: "0x0000000000000000000000000000000000000001",
          claimTxHash: `0x${"c".repeat(64)}`,
        },
      ],
      paymentAmount: amount,
      settlementFinality: { model: "htlc-reveal", finalityObservedAt: 1_780_014_402_000 },
      supersedesEvidenceRef: {
        anchor: {
          kind: "storage-program",
          locator: `dacs4:payment:${JOB_ID}:cross-chain-htlc%3AUSDC:2`,
        },
        contentHash: "d".repeat(64),
      },
      observedAt: 1_780_014_402_000,
    };
    const signed = signSettlementEvidence(input, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedPaymentAmount: amount,
      expectedFinality: { model: "htlc-reveal" },
      expectedPayee: PAYEE,
      expectedPayeeAddress: PAYEE_ADDRESS,
      expectedPayer: PAYER,
      htlcAtomicityCheck: (_refs, expected) => ({ status: "verified", ...expected }),
      railId: "cross-chain-htlc:USDC",
      paymentTransactionCheck: (_txRef, expected) => {
        settlementIds.push(expected.settlementTxId);
        return { status: "verified", ...expected };
      },
      pinnedRail: {
        assetCanonicalJson: pinnedAsset("pay-cross-chain-htlc", "USDC"),
        assetCurrency: "USDC",
        networkKind: "cross-chain",
        phaseHandler: "pay-cross-chain-htlc",
        railId: "cross-chain-htlc:USDC",
      },
      supersededEvidenceCheck: (_ref, expected) => ({
        status: "verified",
        artifactKind: "dacs-4-evidence",
        outcome: "failure",
        ...expected,
      }),
    });
    expect(signed.logicalAddress).toBe(
      `dacs4:payment:${JOB_ID}:cross-chain-htlc%3AUSDC:2:resolved`,
    );
    expect(settlementIds).toEqual([undefined, undefined, undefined]);
    const verificationBase: SettlementEvidenceVerificationOptions = {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" },
      evidenceMode: "fixture",
      expectedEvidenceLogicalAddress: DELIVERY_EVIDENCE_ADDRESS,
      expectedFinality: { model: "htlc-reveal" },
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPayee: PAYEE,
      expectedPayeeAddress: PAYEE_ADDRESS,
      expectedPayer: PAYER,
      expectedPaymentAmount: amount,
      expectedPhase: input.phase,
      expectedSessionBindingHash: SESSION_BINDING_HASH,
      phaseIndex: 2,
      railId: "cross-chain-htlc:USDC",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: {
        assetCanonicalJson: pinnedAsset("pay-cross-chain-htlc", "USDC"),
        assetCurrency: "USDC",
        networkKind: "cross-chain",
        phaseHandler: "pay-cross-chain-htlc",
        railId: "cross-chain-htlc:USDC",
      },
    };
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, verificationBase))
      .toMatchObject({
        disposition: "indeterminate",
        reason: "Grouped HTLC atomicity verifier is unavailable",
      });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      htlcAtomicityCheck: (_refs, expected) => ({ status: "verified", ...expected }),
    })).toMatchObject({
      disposition: "indeterminate",
      reason: "Superseded settlement evidence resolver is unavailable",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      htlcAtomicityCheck: (_refs, expected) => ({
        status: "verified",
        ...expected,
        canonicalTxRefsJson: "[]",
      }),
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      htlcAtomicityCheck: (_refs, expected) => ({ status: "verified", ...expected }),
      anchorContext: {
        mode: "post-anchor",
        read: () => ({
          status: "resolved",
          artifactContentHash: sha256Hex(signed.canonicalJson),
          artifactKind: "dacs-4-evidence",
          evidenceHash: signed.evidenceHash,
          evidenceMode: "fixture",
        }),
      },
      settlementConsumptionCheck: (_ids, expected) => ({ status: "verified", ...expected }),
      supersededEvidenceCheck: (_ref, expected) => ({
        status: "verified",
        artifactKind: "dacs-4-evidence",
        outcome: "failure",
        ...expected,
      }),
    })).toMatchObject({
      disposition: "refused-unsupported",
      reason: "DACS-4 SB-1 does not define canonical settlement-tx-ids for cross-chain references",
    });
  });

  test("validates every known optional field even on failure evidence", () => {
    const base: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "failure",
      reason: "fixture failure",
      observedAt: 1_780_014_402_000,
    };
    const malformed = [
      { ...base, paymentAmount: { amount: "1.0", currency: "DEM" } },
      { ...base, paymentFee: { amount: "-1", currency: "DEM" } },
      { ...base, paymentTxRefs: [null] },
      { ...base, deliverableContentHash: "bad" },
      { ...base, deliverableAnchor: { kind: "storage-program", locator: "" } },
      {
        ...base,
        attestationRef: {
          anchor: { kind: "storage-program", locator: "fixture" },
          contentHash: "bad",
        },
      },
      { ...base, settlementFinality: { model: "bft-final", finalityObservedAt: 1 } },
    ];
    for (const evidence of malformed) {
      expect(() => signSettlementEvidence(
        evidence as UnsignedSettlementEvidence,
        fixtureSigner(),
        { ...baseSigningOptions(), railId: "demos-native:DEM" },
      )).toThrow(/shape/);
    }
  });

  test("rejects delivery fields on payment evidence but preserves inert payment fields on delivery", () => {
    expect(() => signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "failure",
      reason: "fixture failure",
      deliverableContentHash: CONTENT_HASH,
      deliverableAnchor: { kind: "storage-program", locator: "fixture-delivery" },
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      railId: "demos-native:DEM",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toThrow(/shape/);

    const delivery = signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "deliver-entitlement",
      outcome: "success",
      paymentAmount: { amount: "1", currency: "DEM" },
      paymentFee: { amount: "0", currency: "DEM" },
      paymentTxRefs: [{ kind: "demos", txHash: `0x${"a".repeat(64)}`, blockNumber: 1 }],
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
      expectedPaymentAmount: DELIVERY_AMOUNT,
      expectedPhase: "deliver-entitlement",
    });
    expect(delivery.evidence.paymentFee).toEqual({ amount: "0", currency: "DEM" });
    expect(delivery.evidence.paymentTxRefs).toHaveLength(1);
    const storageDelivery = signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "deliver-storage-program",
      outcome: "success",
      paymentAmount: DELIVERY_AMOUNT,
      deliverableContentHash: CONTENT_HASH,
      deliverableAnchor: { kind: "storage-program", locator: "stor-fixture-delivery" },
      paymentTxRefs: [{
        kind: "storage-program",
        address: "stor-fixture-delivery",
        writeTxHash: `0x${"c".repeat(64)}`,
      }],
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
      expectedPaymentAmount: DELIVERY_AMOUNT,
      expectedPhase: "deliver-storage-program",
    });
    expect(storageDelivery.evidence.paymentTxRefs).toHaveLength(1);
    const { signature: _signature, ...unsignedStorageDelivery } = storageDelivery.evidence;
    expect(() => signSettlementEvidence({
      ...unsignedStorageDelivery,
      paymentTxRefs: [{ kind: "storage-program", address: "stor-fixture-delivery", writeTxHash: "" }],
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
      expectedPaymentAmount: DELIVERY_AMOUNT,
      expectedPhase: "deliver-storage-program",
    })).toThrow(/storage-program transaction reference/);
    expect(() => signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "deliver-entitlement",
      outcome: "success",
      paymentAmount: DELIVERY_AMOUNT,
      paymentTxRefs: [{ anything: "goes" }],
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
      expectedPaymentAmount: DELIVERY_AMOUNT,
      expectedPhase: "deliver-entitlement",
    })).toThrow(/transaction reference/);
    expect(verifyCanonicalSettlementEvidenceJson(delivery.canonicalJson, {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" },
      deliveryArtifactCheck: (_address, expected) => {
        const { paymentFeeCanonicalJson: _fee, ...withoutFee } = expected;
        return { status: "verified", ...withoutFee };
      },
      entitlementRenewalSeq: 0,
      evidenceMode: "fixture",
      expectedEvidenceLogicalAddress: DELIVERY_EVIDENCE_ADDRESS,
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPaymentAmount: DELIVERY_AMOUNT,
      expectedPhase: "deliver-entitlement",
      expectedSessionBindingHash: SESSION_BINDING_HASH,
      phaseIndex: 2,
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });

    const failedDelivery = signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "deliver-storage-program",
      outcome: "failure",
      reason: "fixture failure",
      paymentFee: { amount: "0", currency: "DEM" },
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedPhase: "deliver-storage-program",
    });
    expect(failedDelivery.evidence.paymentFee).toEqual({ amount: "0", currency: "DEM" });
    expect(verifyCanonicalSettlementEvidenceJson(failedDelivery.canonicalJson, {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" },
      evidenceMode: "fixture",
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPhase: "deliver-storage-program",
      phaseIndex: 1.5,
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "phase-binding",
      reason: "Settlement verification requires a valid phaseIndex",
    });
  });

  test("binds monetary fields carried by failure evidence", () => {
    const base: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "failure",
      reason: "terminal failure after fee observation",
      paymentAmount: { amount: "6", currency: "DEM" },
      paymentFee: { amount: "0", currency: "DEM" },
      observedAt: 1,
    };
    const options: SettlementEvidenceSigningOptions = {
      ...baseSigningOptions(),
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPaymentAmount: { amount: "5", currency: "DEM" },
      railId: "demos-native:DEM",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    };
    expect(() => signSettlementEvidence(base, fixtureSigner(), options))
      .toThrow(/differs from the agreement price/);
    expect(() => signSettlementEvidence({
      ...base,
      paymentAmount: { amount: "5", currency: "DEM" },
    }, fixtureSigner(), {
      ...options,
      failureStateCheck: (expected) => {
        const { paymentFeeCanonicalJson: _fee, ...withoutFee } = expected;
        return { status: "verified", ...withoutFee };
      },
    })).toThrow(/does not match the exact pipeline state/);
  });

  test("requires authoritative transaction evidence for a claimed payment fee", () => {
    const amount = { amount: "5", currency: "DEM" };
    const fee = { amount: "0", currency: "DEM" };
    const input: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "success",
      paymentTxRefs: [{ kind: "demos", txHash: `0x${"a".repeat(64)}`, blockNumber: 1 }],
      paymentAmount: amount,
      paymentFee: fee,
      settlementFinality: { model: "bft-final", finalityObservedAt: 1 },
      observedAt: 1,
    };
    const options: SettlementEvidenceSigningOptions = {
      ...baseSigningOptions(),
      expectedFinality: { model: "bft-final" },
      expectedPayee: PAYEE,
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPayer: PAYER,
      expectedPaymentAmount: amount,
      railId: "demos-native:DEM",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    };
    const signed = signSettlementEvidence(input, fixtureSigner(), options);
    const verificationBase = {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" as const },
      evidenceMode: "fixture" as const,
      expectedFinality: { model: "bft-final" },
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPayee: PAYEE,
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPayer: PAYER,
      expectedPaymentAmount: amount,
      expectedSessionBindingHash: SESSION_BINDING_HASH,
      expectedPhase: "pay-dem",
      phaseIndex: 2,
      railId: "demos-native:DEM",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    };
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
    })).toMatchObject({
      disposition: "provisionally-verified",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      paymentTransactionCheck: (_txRef, expected) => ({
        status: "verified",
        ...expected,
        assetCanonicalJson: canonicalize({
          kind: "native-dem",
          symbol: "DEM",
          decimals: 8,
        }),
      }),
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      paymentTransactionCheck: (_txRef, expected) => {
        const { paymentFeeCanonicalJson: _unverifiedFee, ...withoutFee } = expected;
        return { status: "verified", ...withoutFee };
      },
    })).toMatchObject({ disposition: "rejected", stage: "transaction-binding" });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      paymentTransactionCheck: () => ({ status: "indeterminate", reason: "fee lookup unavailable" }),
    })).toMatchObject({
      disposition: "indeterminate",
      stage: "transaction-binding",
      reason: "fee lookup unavailable",
    });
  });

  test("rejects transaction kinds and finality models that do not match the payment phase", () => {
    const amount = { amount: "5", currency: "USDC" };
    const invalid = [
      {
        phase: "pay-evm-erc20" as const,
        paymentTxRefs: [{ kind: "demos", txHash: `0x${"a".repeat(64)}`, blockNumber: 1 }],
        settlementFinality: { model: "block-depth" as const, finalityBlocks: 1, finalityObservedAt: 1 },
        railId: "evm-erc20:8453:USDC",
      },
      {
        phase: "pay-solana-spl" as const,
        paymentTxRefs: [{ kind: "evm", chainId: 8453, txHash: `0x${"a".repeat(64)}` }],
        settlementFinality: { model: "commitment-level" as const, finalityCommitmentLevel: "confirmed" as const, finalityObservedAt: 1 },
        railId: "solana-spl:mainnet:USDC",
      },
      {
        phase: "pay-ap2" as const,
        paymentTxRefs: [{ kind: "ap2", mandateId: "m", providerRef: "p", protocolVersion: "1" }],
        settlementFinality: { model: "bft-final" as const, finalityObservedAt: 1 },
        railId: "ap2:visa-direct",
      },
      {
        phase: "pay-cross-chain-htlc" as const,
        paymentTxRefs: [{
          kind: "htlc-claim",
          chainId: 1,
          contractAddress: "0x1",
          claimTxHash: `0x${"a".repeat(64)}`,
        }],
        settlementFinality: { model: "htlc-reveal" as const, finalityObservedAt: 1 },
        railId: "cross-chain-htlc:USDC",
      },
      {
        phase: "pay-x402" as const,
        paymentTxRefs: [{
          kind: "x402",
          httpResource: "https://example.test/resource",
          paymentReceiptHash: "a".repeat(64),
          settlementTxHash: `0x${"b".repeat(64)}`,
          chainId: 8453,
          protocolVersion: "2",
        }],
        settlementFinality: { model: "block-depth" as const, finalityBlocks: 1, finalityObservedAt: 1 },
        railId: "x402:default",
      },
    ];
    for (const testCase of invalid) {
      expect(() => signSettlementEvidence({
        evidenceVersion: "1",
        jobId: JOB_ID,
        phase: testCase.phase,
        outcome: "success",
        paymentTxRefs: testCase.paymentTxRefs,
        paymentAmount: amount,
        settlementFinality: testCase.settlementFinality,
        observedAt: 1,
      }, fixtureSigner(), {
        ...baseSigningOptions(),
        expectedPaymentAmount: amount,
        expectedFinality: {
          model: testCase.settlementFinality.model,
          ...(Object.hasOwn(testCase.settlementFinality, "finalityBlocks")
            ? { finalityBlocks: testCase.settlementFinality.finalityBlocks } : {}),
          ...(Object.hasOwn(testCase.settlementFinality, "finalityCommitmentLevel")
            ? { finalityCommitmentLevel: testCase.settlementFinality.finalityCommitmentLevel } : {}),
        },
        expectedPayee: PAYEE,
        expectedPayeeAddress: PAYEE_ADDRESS,
        expectedPayer: PAYER,
        railId: testCase.railId,
        paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
        pinnedRail: pinnedRail(testCase.phase, testCase.railId, "USDC"),
      })).toThrow(/shape/);
    }
  });

  test("binds an EVM settlement to the exact asset contract", () => {
    const amount = { amount: "5", currency: "USDC" };
    const input: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-evm-erc20",
      outcome: "success",
      paymentTxRefs: [{
        kind: "evm",
        chainId: 8453,
        txHash: `0x${"a".repeat(64)}`,
        logIndex: 0,
      }],
      paymentAmount: amount,
      settlementFinality: { model: "block-depth", finalityBlocks: 1, finalityObservedAt: 1 },
      observedAt: 1,
    };
    const options: SettlementEvidenceSigningOptions = {
      ...baseSigningOptions(),
      expectedFinality: { model: "block-depth", finalityBlocks: 1 },
      expectedPaymentAmount: amount,
      expectedPayee: PAYEE,
      expectedPayeeAddress: PAYEE_ADDRESS,
      expectedPayer: PAYER,
      railId: "evm-erc20:8453:USDC",
      paymentTransactionCheck: (_txRef, expected) => ({
        status: "verified",
        ...expected,
        assetCanonicalJson: canonicalize({
          kind: "erc20",
          chainId: 8453,
          contract: "0x0000000000000000000000000000000000000002",
          symbol: "USDC",
          decimals: 6,
        }),
      }),
      pinnedRail: pinnedRail("pay-evm-erc20", "evm-erc20:8453:USDC", "USDC"),
    };
    expect(() => signSettlementEvidence(input, fixtureSigner(), options))
      .toThrow(/agreement, asset, amount/);
  });

  test("refuses pinned-rail verifier configuration errors without blaming the evidence", () => {
    const amount = { amount: "5", currency: "DEM" };
    const input: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "success",
      paymentTxRefs: [{ kind: "demos", txHash: `0x${"a".repeat(64)}`, blockNumber: 1 }],
      paymentAmount: amount,
      settlementFinality: { model: "bft-final", finalityObservedAt: 1 },
      observedAt: 1,
    };
    const signed = signSettlementEvidence(input, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedFinality: { model: "bft-final" },
      expectedPaymentAmount: amount,
      expectedPayee: PAYEE,
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPayer: PAYER,
      railId: "demos-native:DEM",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    });
    const verificationBase: SettlementEvidenceVerificationOptions = {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" },
      evidenceMode: "fixture",
      expectedFinality: { model: "bft-final" },
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPayee: PAYEE,
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPayer: PAYER,
      expectedPaymentAmount: amount,
      expectedPhase: "pay-dem",
      expectedSessionBindingHash: SESSION_BINDING_HASH,
      phaseIndex: 2,
      railId: "demos-native:DEM",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
    };
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, verificationBase)).toMatchObject({
      disposition: "refused-unsupported",
      stage: "phase-binding",
      reason: "Payment verification requires a verified pinned rail",
    });
    const { expectedPaymentAmount: _expectedAmount, ...withoutExpectedAmount } = verificationBase;
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...withoutExpectedAmount,
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toMatchObject({
      disposition: "refused-unsupported",
      reason: "Successful settlement verification requires the agreement price",
    });
    const { expectedPayer: _expectedPayer, ...withoutExpectedPayer } = verificationBase;
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...withoutExpectedPayer,
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "transaction-binding",
      reason: "Settlement verification requires an agreement-bound payer ClaimReference",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      pinnedRail: {
        ...pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
        assetCanonicalJson: "not-json",
      },
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "phase-binding",
      reason: "Pinned rail asset is not valid canonical JSON",
    });
    const { expectedFinality: _expectedFinality, ...withoutExpectedFinality } = verificationBase;
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...withoutExpectedFinality,
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "transaction-binding",
      reason: "Successful payment verification requires pinned rail finality",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      expectedFinality: { model: "block-depth" },
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "transaction-binding",
      reason: "Configured block-depth finality pin is malformed",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      expectedFinality: null as unknown as NonNullable<SettlementEvidenceVerificationOptions["expectedFinality"]>,
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toMatchObject({
      disposition: "refused-unsupported",
      reason: "Successful payment verification requires pinned rail finality",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      pinnedRail: null as unknown as NonNullable<SettlementEvidenceVerificationOptions["pinnedRail"]>,
    })).toMatchObject({
      disposition: "refused-unsupported",
      reason: "Payment verification requires a verified pinned rail",
    });
    const malformedRailId = "bad rail id";
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      railId: malformedRailId,
      pinnedRail: {
        ...pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
        railId: malformedRailId,
      },
    })).toMatchObject({
      disposition: "refused-unsupported",
      reason: "Payment verification requires a valid pinned railId",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      phaseIndex: -1,
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toMatchObject({
      disposition: "refused-unsupported",
      reason: "Settlement verification requires a valid phaseIndex",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      expectedPayer: "not-a-claim-reference",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "transaction-binding",
      reason: expect.stringContaining("Configured payer ClaimReference is invalid"),
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      expectedPayeeAddress: PAYEE_ADDRESS,
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "transaction-binding",
      reason: "Configured Demos payee address is non-canonical",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...verificationBase,
      expectedPaymentAmount: {
        amount: "5",
        currency: "DEM",
        unsupported: 1n,
      },
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "amount-binding",
      reason: expect.stringContaining("Configured agreement price is not canonicalizable"),
    });

    const evmAmount = { amount: "5", currency: "USDC" };
    const evmInput: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-evm-erc20",
      outcome: "success",
      paymentTxRefs: [{
        kind: "evm",
        chainId: 8453,
        txHash: `0x${"b".repeat(64)}`,
        logIndex: 0,
      }],
      paymentAmount: evmAmount,
      settlementFinality: { model: "block-depth", finalityBlocks: 1, finalityObservedAt: 1 },
      observedAt: 1,
    };
    const evmRail = pinnedRail("pay-evm-erc20", "evm-erc20:8453:USDC", "USDC");
    const { chainId: _chainId, ...evmRailWithoutChainId } = evmRail;
    const evmSigned = signSettlementEvidence(evmInput, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedFinality: { model: "block-depth", finalityBlocks: 1 },
      expectedPaymentAmount: evmAmount,
      expectedPayee: PAYEE,
      expectedPayeeAddress: PAYEE_ADDRESS,
      expectedPayer: PAYER,
      railId: evmRail.railId,
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: evmRail,
    });
    expect(verifyCanonicalSettlementEvidenceJson(evmSigned.canonicalJson, {
      ...verificationBase,
      expectedFinality: { model: "block-depth", finalityBlocks: 1 },
      expectedPaymentAmount: evmAmount,
      expectedPhase: "pay-evm-erc20",
      railId: evmRail.railId,
      pinnedRail: evmRailWithoutChainId,
    })).toMatchObject({
      disposition: "refused-unsupported",
      stage: "phase-binding",
      reason: "Pinned EVM rail requires a positive chainId",
    });
  });

  test("applies RD-5 to asset and network kinds without inventing chain-id equality", () => {
    const amount = { amount: "5", currency: "USDC" };
    const input: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-evm-erc20",
      outcome: "success",
      paymentTxRefs: [{
        kind: "evm",
        chainId: 8453,
        txHash: `0x${"a".repeat(64)}`,
        logIndex: 0,
      }],
      paymentAmount: amount,
      settlementFinality: { model: "block-depth", finalityBlocks: 1, finalityObservedAt: 1 },
      observedAt: 1,
    };
    const assetCanonicalJson = canonicalize({
      kind: "erc20",
      chainId: 1,
      contract: "0x0000000000000000000000000000000000000001",
      symbol: "USDC",
      decimals: 6,
    });
    const signed = signSettlementEvidence(input, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedFinality: { model: "block-depth", finalityBlocks: 1 },
      expectedPaymentAmount: amount,
      railId: "evm-erc20:8453:USDC",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: {
        assetCanonicalJson,
        assetCurrency: "USDC",
        chainId: 8453,
        networkKind: "evm",
        phaseHandler: "pay-evm-erc20",
        railId: "evm-erc20:8453:USDC",
      },
    });
    expect(signed.evidence.paymentTxRefs?.[0]?.["chainId"]).toBe(8453);
  });

  test("fails closed on an undefined native Solana HTLC leg encoding", () => {
    const amount = { amount: "5", currency: "USDC" };
    expect(() => signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-cross-chain-htlc",
      outcome: "success",
      paymentTxRefs: [
        {
          kind: "htlc-lock",
          chainId: 8453,
          contractAddress: "0x0000000000000000000000000000000000000001",
          lockTxHash: `0x${"a".repeat(64)}`,
        },
        {
          kind: "htlc-reveal",
          cluster: "devnet",
          programAddress: "fixture-program",
          signature: "1".repeat(88),
        },
        {
          kind: "htlc-claim",
          chainId: 8453,
          contractAddress: "0x0000000000000000000000000000000000000001",
          claimTxHash: `0x${"b".repeat(64)}`,
        },
      ],
      paymentAmount: amount,
      settlementFinality: { model: "htlc-reveal", finalityObservedAt: 1 },
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedFinality: { model: "htlc-reveal" },
      expectedPaymentAmount: amount,
      expectedPayee: PAYEE,
      expectedPayeeAddress: PAYEE_ADDRESS,
      expectedPayer: PAYER,
      htlcAtomicityCheck: (_refs, expected) => ({ status: "verified", ...expected }),
      railId: "cross-chain-htlc:USDC",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: pinnedRail("pay-cross-chain-htlc", "cross-chain-htlc:USDC", "USDC"),
    })).toThrow(/shape/);
  });

  test("requires AP2 receipt attestation and a supported x402 receipt version", () => {
    const amount = { amount: "5", currency: "USD" };
    const paymentBase = {
      evidenceVersion: "1" as const,
      jobId: JOB_ID,
      outcome: "success" as const,
      paymentAmount: amount,
      observedAt: 1,
    };
    expect(() => signSettlementEvidence({
      ...paymentBase,
      phase: "pay-ap2",
      paymentTxRefs: [{ kind: "ap2", mandateId: "m", providerRef: "p", protocolVersion: "1" }],
      settlementFinality: { model: "provider-receipt", finalityObservedAt: 1 },
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedFinality: { model: "provider-receipt" },
      expectedPaymentAmount: amount,
      expectedPayee: PAYEE,
      expectedPayeeAddress: PAYEE_ADDRESS,
      expectedPayer: PAYER,
      railId: "ap2:visa-direct",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: pinnedRail("pay-ap2", "ap2:visa-direct", "USD"),
    })).toThrow(/attested provider receipt/);

    expect(() => signSettlementEvidence({
      ...paymentBase,
      phase: "pay-x402",
      paymentTxRefs: [{
        kind: "x402",
        httpResource: "https://example.test/resource",
        paymentReceiptHash: "a".repeat(64),
        protocolVersion: "01",
      }],
      settlementFinality: { model: "provider-receipt", finalityObservedAt: 1 },
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedFinality: { model: "provider-receipt" },
      expectedPaymentAmount: amount,
      expectedPayee: PAYEE,
      expectedPayeeAddress: PAYEE_ADDRESS,
      expectedPayer: PAYER,
      railId: "x402:default",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: pinnedRail("pay-x402", "x402:default", "USD"),
    })).toThrow(/unsupported protocol version/);

    expect(() => signSettlementEvidence({
      ...paymentBase,
      phase: "pay-x402",
      paymentTxRefs: [{
        kind: "x402",
        httpResource: "https://example.test/resource",
        paymentReceiptHash: "a".repeat(64),
        protocolVersion: "2",
      }],
      settlementFinality: { model: "provider-receipt", finalityObservedAt: 1 },
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedFinality: { model: "provider-receipt" },
      expectedPaymentAmount: amount,
      expectedPayee: PAYEE,
      expectedPayeeAddress: PAYEE_ADDRESS,
      expectedPayer: PAYER,
      railId: "x402:default",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: { ...pinnedRail("pay-x402", "x402:default", "USD"), chainId: 8453 },
    })).toThrow(/chainId differs/);

    for (const extension of ["first", "second"]) {
      const signed = signSettlementEvidence({
        ...paymentBase,
        phase: "pay-x402",
        paymentTxRefs: [{
          kind: "x402",
          httpResource: "https://example.test/resource",
          paymentReceiptHash: "a".repeat(64),
          protocolVersion: "2",
          futureExtension: extension,
        }],
        settlementFinality: { model: "provider-receipt", finalityObservedAt: 1 },
      }, fixtureSigner(), {
        ...baseSigningOptions(),
        expectedFinality: { model: "provider-receipt" },
        expectedPaymentAmount: amount,
        expectedPayee: PAYEE,
        expectedPayeeAddress: PAYEE_ADDRESS,
        expectedPayer: PAYER,
        railId: "x402:default",
        paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
        pinnedRail: pinnedRail("pay-x402", "x402:default", "USD"),
      });
      expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
        agreementHash: AGREEMENT_HASH,
        anchorContext: {
          mode: "post-anchor",
          read: () => ({
            status: "resolved",
            artifactContentHash: sha256Hex(signed.canonicalJson),
            artifactKind: "dacs-4-evidence",
            evidenceHash: signed.evidenceHash,
            evidenceMode: "fixture",
          }),
        },
        evidenceMode: "fixture",
        expectedFinality: { model: "provider-receipt" },
        expectedJobId: JOB_ID,
        expectedOrchestrator: fixtureSigner().signer,
        expectedPayee: PAYEE,
        expectedPayeeAddress: PAYEE_ADDRESS,
        expectedPayer: PAYER,
        expectedPaymentAmount: amount,
        expectedPhase: "pay-x402",
        expectedSessionBindingHash: SESSION_BINDING_HASH,
        phaseIndex: 2,
        railId: "x402:default",
        paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
        pinnedRail: pinnedRail("pay-x402", "x402:default", "USD"),
        settlementConsumptionCheck: (_ids, expected) => ({ status: "verified", ...expected }),
      })).toMatchObject({
        disposition: "refused-unsupported",
        reason: expect.stringContaining("x402 without a chain transaction"),
      });
    }
  });

  test("keeps AP2 provisional while SB-1 leaves its post-anchor consumption identifier undefined", () => {
    const amount = { amount: "5", currency: "USD" };
    const providerRef = "shared-provider-local-reference";
    const receiptAttestation = {
      anchor: { kind: "https", locator: "https://provider.test/receipts/shared" },
      contentHash: "d".repeat(64),
    };
    for (const [railId, provider] of [
      ["ap2:provider-one", "provider-one"],
      ["ap2:provider-two", "provider-two"],
    ] as const) {
      const rail = {
        assetCanonicalJson: canonicalize({
          kind: "fiat-via-ap2",
          isoCurrency: "USD",
          provider,
        }),
        assetCurrency: "USD",
        networkKind: "ap2-provider" as const,
        phaseHandler: "pay-ap2",
        railId,
      };
      const signed = signSettlementEvidence({
        evidenceVersion: "1",
        jobId: JOB_ID,
        phase: "pay-ap2",
        outcome: "success",
        paymentTxRefs: [{
          kind: "ap2",
          mandateId: "fixture-mandate",
          providerRef,
          protocolVersion: "1",
          receiptAttestation,
        }],
        paymentAmount: amount,
        settlementFinality: { model: "provider-receipt", finalityObservedAt: 1 },
        observedAt: 1,
      }, fixtureSigner(), {
        ...baseSigningOptions(),
        expectedFinality: { model: "provider-receipt" },
        expectedPaymentAmount: amount,
        expectedPayee: PAYEE,
        expectedPayeeAddress: PAYEE_ADDRESS,
        expectedPayer: PAYER,
        railId,
        paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
        pinnedRail: rail,
      });
      expect(signed.evidence.paymentTxRefs?.[0]?.["providerRef"]).toBe(providerRef);
      expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
        agreementHash: AGREEMENT_HASH,
        anchorContext: {
          mode: "post-anchor",
          read: () => ({
            status: "resolved",
            artifactContentHash: sha256Hex(signed.canonicalJson),
            artifactKind: "dacs-4-evidence",
            evidenceHash: signed.evidenceHash,
            evidenceMode: "fixture",
          }),
        },
        evidenceMode: "fixture",
        expectedFinality: { model: "provider-receipt" },
        expectedJobId: JOB_ID,
        expectedOrchestrator: fixtureSigner().signer,
        expectedPayee: PAYEE,
        expectedPayeeAddress: PAYEE_ADDRESS,
        expectedPayer: PAYER,
        expectedPaymentAmount: amount,
        expectedPhase: "pay-ap2",
        expectedSessionBindingHash: SESSION_BINDING_HASH,
        phaseIndex: 2,
        railId,
        paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
        pinnedRail: rail,
        settlementConsumptionCheck: (_ids, expected) => ({ status: "verified", ...expected }),
      })).toMatchObject({
        disposition: "refused-unsupported",
        reason: expect.stringContaining("pay-ap2"),
      });
    }
  });

  test("requires authoritative proof for asymmetric settlement failures", () => {
    const input: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-cross-chain-htlc",
      outcome: "failure",
      reason: "dest-revealed-source-unclaimed",
      paymentTxRefs: [{
        kind: "htlc-reveal",
        chainId: 8453,
        contractAddress: "0x0000000000000000000000000000000000000002",
        revealTxHash: `0x${"b".repeat(64)}`,
      }],
      observedAt: 1,
    };
    const options: SettlementEvidenceSigningOptions = {
      ...baseSigningOptions(),
      expectedAsymmetricFailure: "htlc",
      expectedPayee: PAYEE,
      expectedPayeeAddress: PAYEE_ADDRESS,
      expectedPayer: PAYER,
      railId: "cross-chain-htlc:USDC",
      pinnedRail: pinnedRail("pay-cross-chain-htlc", "cross-chain-htlc:USDC", "USDC"),
    };
    expect(() => signSettlementEvidence(input, fixtureSigner(), options))
      .toThrow(/verifier is unavailable/);
    const { expectedPayeeAddress: _expectedPayeeAddress, ...withoutPayeeAddress } = options;
    expect(() => signSettlementEvidence(input, fixtureSigner(), {
      ...withoutPayeeAddress,
      asymmetricSettlementCheck: (_refs, expected) => ({ status: "verified", ...expected }),
    })).toThrow(/payee address/);
    expect(() => signSettlementEvidence(input, fixtureSigner(), {
      ...options,
      asymmetricSettlementCheck: (_refs, expected) => ({
        status: "verified",
        ...expected,
        payeeAddress: "0x00000000000000000000000000000000000000bb",
      }),
    })).toThrow(/does not match the expected state/);
    const signed = signSettlementEvidence(input, fixtureSigner(), {
      ...options,
      asymmetricSettlementCheck: (_refs, expected) => ({ status: "verified", ...expected }),
    });
    expect(signed.evidence.outcome).toBe("failure");
    for (const resolvingKind of ["htlc-claim", "htlc-refund"] as const) {
      expect(() => signSettlementEvidence({
        ...input,
        paymentTxRefs: [
          ...(input.paymentTxRefs ?? []),
          {
            kind: resolvingKind,
            chainId: 1,
            contractAddress: "0x0000000000000000000000000000000000000001",
            [resolvingKind === "htlc-claim" ? "claimTxHash" : "refundTxHash"]: `0x${"c".repeat(64)}`,
          },
        ],
      }, fixtureSigner(), {
        ...options,
        asymmetricSettlementCheck: (_refs, expected) => ({ status: "verified", ...expected }),
      })).toThrow(/cannot include a claim or refund transaction/);
    }
    const tankInterim: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-cross-chain-liquidity-tank",
      outcome: "failure",
      reason: "tank-locked-unreleased",
      paymentTxRefs: [{
        kind: "liquidity-tank",
        bridgeId: "fixture-tank",
        sourceChainId: 1,
        destChainId: 8453,
        lockTxHash: `0x${"a".repeat(64)}`,
        releaseTxHash: `0x${"b".repeat(64)}`,
        recoveryDeadline: 1_780_014_500_000,
      }],
      observedAt: 1,
    };
    const tankOptions: SettlementEvidenceSigningOptions = {
      ...baseSigningOptions(),
      asymmetricSettlementCheck: (_refs, expected) => ({ status: "verified", ...expected }),
      expectedAsymmetricFailure: "liquidity-tank",
      railId: "cross-chain-liquidity-tank:USDC",
      pinnedRail: pinnedRail(
        "pay-cross-chain-liquidity-tank",
        "cross-chain-liquidity-tank:USDC",
        "USDC",
      ),
    };
    expect(() => signSettlementEvidence(tankInterim, fixtureSigner(), tankOptions))
      .toThrow(/cannot include a release transaction/);
    const [tankRef] = tankInterim.paymentTxRefs ?? [];
    const { releaseTxHash: _releaseTxHash, ...unreleasedTankRef } = tankRef ?? {};
    expect(() => signSettlementEvidence({
      ...tankInterim,
      paymentTxRefs: [unreleasedTankRef],
      observedAt: 1_780_014_500_000,
    }, fixtureSigner(), tankOptions)).toThrow(/observed before its recovery deadline/);
    expect(() => signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "success",
      paymentTxRefs: [{ kind: "demos", txHash: `0x${"a".repeat(64)}`, blockNumber: 1 }],
      paymentAmount: { amount: "5", currency: "DEM" },
      settlementFinality: { model: "bft-final", finalityObservedAt: 1 },
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedAsymmetricFailure: "htlc",
      expectedFinality: { model: "bft-final" },
      expectedPaymentAmount: { amount: "5", currency: "DEM" },
      expectedPayee: PAYEE,
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPayer: PAYER,
      railId: "demos-native:DEM",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toThrow(/Expected asymmetric settlement failure/);
  });

  test("bounds unauthenticated Solana references before base58 decoding", () => {
    const canonicalJson = canonicalize({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-solana-spl",
      outcome: "failure",
      reason: "fixture failure",
      paymentTxRefs: [{
        kind: "solana",
        cluster: "mainnet",
        signature: "1".repeat(100_000),
        instructionIndex: 0,
      }],
      observedAt: 1,
      signature: { algorithm: "ed25519", signer: fixtureSigner().signer, value: "AA" },
    });
    expect(verifyCanonicalSettlementEvidenceJson(canonicalJson, {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" },
      evidenceMode: "fixture",
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPhase: "pay-solana-spl",
      phaseIndex: 2,
      railId: "solana-spl:mainnet:USDC",
    })).toMatchObject({ disposition: "rejected", stage: "shape" });
  });

  test("returns a structured rejection for unsupported signer schemes", () => {
    const input: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "deliver-entitlement",
      outcome: "success",
      paymentAmount: DELIVERY_AMOUNT,
      observedAt: 1,
    };
    const signed = signSettlementEvidence(input, fixtureSigner(), {
      ...baseSigningOptions(),
      deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
      expectedPaymentAmount: DELIVERY_AMOUNT,
      expectedPhase: "deliver-entitlement",
    });
    const mutated = JSON.parse(signed.canonicalJson) as { signature: { signer: string } };
    mutated.signature.signer = "foo:bar";
    expect(verifyCanonicalSettlementEvidenceJson(canonicalize(mutated), {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" },
      deliveryArtifactCheck: (_address, expected) => ({ status: "verified", ...expected }),
      evidenceMode: "fixture",
      entitlementRenewalSeq: 0,
      expectedEvidenceLogicalAddress: DELIVERY_EVIDENCE_ADDRESS,
      expectedJobId: JOB_ID,
      expectedOrchestrator: "foo:bar",
      expectedPaymentAmount: DELIVERY_AMOUNT,
      expectedPhase: "deliver-entitlement",
      expectedSessionBindingHash: SESSION_BINDING_HASH,
      phaseIndex: 2,
    })).toMatchObject({ disposition: "rejected", stage: "orchestrator-binding" });
  });

  test("fixture authority cannot emit live-mode evidence", () => {
    expect(() => signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "failure",
      reason: "fixture refusal",
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      evidenceMode: "live",
      railId: "demos-native:DEM",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toThrow(/only fixture evidence/);
  });

  test("accepts pay-dem failure references without an inclusion block", () => {
    const signed = signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "failure",
      reason: "transaction reached terminal failed state",
      paymentTxRefs: [{ kind: "demos", txHash: `0x${"f".repeat(64)}` }],
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      railId: "demos-native:DEM",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    });
    expect(signed.evidence.outcome).toBe("failure");

    const base = {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" as const },
      evidenceMode: "fixture" as const,
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPayee: PAYEE,
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPayer: PAYER,
      expectedPhase: "pay-dem",
      phaseIndex: 2,
      railId: "demos-native:DEM",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    };
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, base)).toMatchObject({
      disposition: "indeterminate",
      reason: "Settlement failure-state verifier is unavailable",
    });
    expect(verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      ...base,
      phaseIndex: 3,
      failureStateCheck: (expected) => expected.phaseIndex === 2
        ? { status: "verified", ...expected }
        : { status: "rejected", reason: "failure belongs to phase index 2" },
    })).toMatchObject({
      disposition: "rejected",
      reason: "failure belongs to phase index 2",
    });
  });

  test("keeps signed transaction references and callback expectations immutable", () => {
    const amount = { amount: "5", currency: "DEM" };
    const input: UnsignedSettlementEvidence = {
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "success",
      paymentTxRefs: [{ kind: "demos", txHash: `0x${"a".repeat(64)}`, blockNumber: 1 }],
      paymentAmount: amount,
      settlementFinality: { model: "bft-final", finalityObservedAt: 1 },
      observedAt: 1,
    };
    const options: SettlementEvidenceSigningOptions = {
      ...baseSigningOptions(),
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedFinality: { model: "bft-final" },
      expectedPaymentAmount: amount,
      railId: "demos-native:DEM",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    };
    const signed = signSettlementEvidence(input, fixtureSigner(), options);
    const result = verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" },
      evidenceMode: "fixture",
      expectedFinality: { model: "bft-final" },
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPayee: PAYEE,
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPayer: PAYER,
      expectedPaymentAmount: amount,
      expectedPhase: "pay-dem",
      expectedSessionBindingHash: SESSION_BINDING_HASH,
      phaseIndex: 2,
      railId: "demos-native:DEM",
      paymentTransactionCheck: (txRef, expected) => {
        expect(Object.isFrozen(txRef)).toBe(true);
        expect(Reflect.set(txRef, "txHash", `0x${"b".repeat(64)}`)).toBe(false);
        expect(Object.isFrozen(expected)).toBe(true);
        expect(Reflect.set(expected, "phaseIndex", 3)).toBe(false);
        return { status: "verified", ...expected };
      },
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    });
    expect(result).toMatchObject({ disposition: "provisionally-verified" });
    expect(signed.canonicalJson).toContain(`0x${"a".repeat(64)}`);
  });

  test("returns indeterminate for a non-canonical authoritative callback result", () => {
    const signed = signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "failure",
      reason: "fixture terminal failure",
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      railId: "demos-native:DEM",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    });
    const result = verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      agreementHash: AGREEMENT_HASH,
      anchorContext: { mode: "pre-anchor" },
      evidenceMode: "fixture",
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPayee: PAYEE,
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPayer: PAYER,
      expectedPhase: "pay-dem",
      failureStateCheck: (expected) => ({
        status: "verified",
        ...expected,
        unsupported: 1n,
      } as unknown as ReturnType<NonNullable<SettlementEvidenceVerificationOptions["failureStateCheck"]>>),
      phaseIndex: 2,
      railId: "demos-native:DEM",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    });
    expect(result).toMatchObject({
      disposition: "indeterminate",
      stage: "transaction-binding",
      reason: "Settlement failure-state verifier returned a malformed result",
    });
  });

  test("accepts local-chain provenance from an authoritative resolved anchor", () => {
    const signed = signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "failure",
      reason: "fixture terminal failure",
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      railId: "demos-native:DEM",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    });
    const result = verifyCanonicalSettlementEvidenceJson(signed.canonicalJson, {
      agreementHash: AGREEMENT_HASH,
      anchorContext: {
        mode: "post-anchor",
        read: () => ({
          status: "resolved",
          artifactContentHash: sha256Hex(signed.canonicalJson),
          artifactKind: "dacs-4-evidence",
          evidenceHash: signed.evidenceHash,
          evidenceMode: "local-chain",
        }),
      },
      evidenceMode: "local-chain",
      expectedJobId: JOB_ID,
      expectedOrchestrator: fixtureSigner().signer,
      expectedPayee: PAYEE,
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPayer: PAYER,
      expectedPhase: "pay-dem",
      failureStateCheck: (expected) => ({ status: "verified", ...expected }),
      phaseIndex: 2,
      railId: "demos-native:DEM",
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    });
    expect(result).toMatchObject({ disposition: "verified", evidenceHash: signed.evidenceHash });
  });

  test("rejects settlement finality on failed delivery evidence", () => {
    expect(() => signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "deliver-storage-program",
      outcome: "failure",
      reason: "delivery failed",
      settlementFinality: { model: "bft-final", finalityObservedAt: 1 },
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedPhase: "deliver-storage-program",
    })).toThrow(/must omit settlementFinality/);
  });

  test("rejects successful payment evidence observed before finality", () => {
    const amount = { amount: "5", currency: "DEM" };
    expect(() => signSettlementEvidence({
      evidenceVersion: "1",
      jobId: JOB_ID,
      phase: "pay-dem",
      outcome: "success",
      paymentTxRefs: [{ kind: "demos", txHash: `0x${"a".repeat(64)}`, blockNumber: 1 }],
      paymentAmount: amount,
      settlementFinality: { model: "bft-final", finalityObservedAt: 2 },
      observedAt: 1,
    }, fixtureSigner(), {
      ...baseSigningOptions(),
      expectedFinality: { model: "bft-final" },
      expectedPaymentAmount: amount,
      expectedPayee: PAYEE,
      expectedPayeeAddress: DEMOS_PAYEE_ADDRESS,
      expectedPayer: PAYER,
      railId: "demos-native:DEM",
      paymentTransactionCheck: (_txRef, expected) => ({ status: "verified", ...expected }),
      pinnedRail: pinnedRail("pay-dem", "demos-native:DEM", "DEM"),
    })).toThrow(/cannot be observed before settlement finality/);
  });
});

function baseSigningOptions(): SettlementEvidenceSigningOptions {
  return {
    agreementHash: AGREEMENT_HASH,
    deploymentMode: "fixture",
    entitlementRenewalSeq: 0,
    evidenceMode: "fixture",
    expectedEvidenceLogicalAddress: DELIVERY_EVIDENCE_ADDRESS,
    expectedJobId: JOB_ID,
    expectedPayee: PAYEE,
    expectedPayeeAddress: PAYEE_ADDRESS,
    expectedPayer: PAYER,
    expectedSessionBindingHash: SESSION_BINDING_HASH,
    failureStateCheck: (expected) => ({ status: "verified", ...expected }),
    phaseIndex: 2,
    requestMode: "fixture",
  };
}

function pinnedRail(phaseHandler: string, railId: string, assetCurrency: string) {
  const networkKind = phaseHandler === "pay-dem" ? "demos"
    : phaseHandler === "pay-solana-spl" ? "solana"
      : phaseHandler === "pay-evm-erc20" ? "evm"
        : phaseHandler === "pay-ap2" ? "ap2-provider"
          : phaseHandler === "pay-x402" ? "x402-resource" : "cross-chain";
  return {
    assetCanonicalJson: pinnedAsset(phaseHandler, assetCurrency),
    assetCurrency,
    ...(networkKind === "evm" ? { chainId: 8453 } : {}),
    ...(networkKind === "solana" ? { cluster: "mainnet" as const } : {}),
    networkKind: networkKind as "evm" | "solana" | "demos" | "ap2-provider" | "x402-resource" | "cross-chain",
    phaseHandler,
    railId,
  };
}

function pinnedAsset(phaseHandler: string, assetCurrency: string): string {
  if (phaseHandler === "pay-dem") {
    return canonicalize({ kind: "native-dem", symbol: "DEM", decimals: 9 });
  }
  if (phaseHandler === "pay-evm-erc20") {
    return canonicalize({
      kind: "erc20",
      chainId: 8453,
      contract: "0x0000000000000000000000000000000000000001",
      symbol: assetCurrency,
      decimals: 6,
    });
  }
  if (phaseHandler === "pay-solana-spl") {
    return canonicalize({
      kind: "spl",
      cluster: "mainnet",
      mint: "fixture-mint",
      symbol: assetCurrency,
      decimals: 6,
    });
  }
  if (phaseHandler === "pay-ap2" || phaseHandler === "pay-x402") {
    return canonicalize({ kind: "fiat-via-ap2", isoCurrency: assetCurrency, provider: "fixture-provider" });
  }
  return canonicalize({
    kind: "stablecoin-cross-chain",
    canonicalSymbol: assetCurrency,
    routes: [{ sourceChainId: 1, destChainId: 8453 }],
  });
}
