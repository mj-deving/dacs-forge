import type { EvidenceMode } from "../core/evidence-mode.ts";
import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  preflightCanonicalUnsignedSettlementEvidenceJson,
  verifyCanonicalSettlementEvidenceJson,
  type SettlementEvidenceVerificationOptions,
} from "../consumer/settlement-evidence-verifier.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

export const SETTLEMENT_EVIDENCE_DOMAIN = "dacs-evidence:v1:";

export type PaymentPhaseType =
  | "pay-evm-erc20"
  | "pay-solana-spl"
  | "pay-cross-chain-htlc"
  | "pay-cross-chain-liquidity-tank"
  | "pay-ap2"
  | "pay-x402"
  | "pay-dem";

export type DeliveryPhaseType =
  | "deliver-storage-program"
  | "deliver-entitlement"
  | "deliver-attested-payload";

export interface SettlementPriceTerm extends Record<string, unknown> {
  readonly amount: string;
  readonly currency: string;
  readonly unit?: string;
}

export interface SettlementAttestationRef extends Record<string, unknown> {
  readonly anchor: Readonly<{
    readonly kind: "storage-program" | "ipfs" | "https";
    readonly locator: string;
  }>;
  readonly contentHash: string;
  readonly signer?: string;
}

export interface SettlementFinalityRecord extends Record<string, unknown> {
  readonly model:
    | "block-depth"
    | "commitment-level"
    | "provider-receipt"
    | "htlc-reveal"
    | "liquidity-tank"
    | "bft-final";
  readonly finalityBlocks?: number;
  readonly finalityCommitmentLevel?: "processed" | "confirmed" | "finalized";
  readonly finalityObservedAt: number;
}

export interface DemosTransactionRef extends Record<string, unknown> {
  readonly kind: "demos";
  readonly txHash: string;
  readonly blockNumber?: number;
}

export interface UnsignedSettlementEvidence extends Record<string, unknown> {
  readonly evidenceVersion: "1";
  readonly jobId: string;
  readonly phase: PaymentPhaseType | DeliveryPhaseType;
  readonly outcome: "success" | "failure";
  readonly reason?: string;
  readonly paymentTxRefs?: readonly Readonly<Record<string, unknown>>[];
  readonly paymentAmount?: SettlementPriceTerm;
  readonly paymentFee?: SettlementPriceTerm;
  readonly deliverableContentHash?: string;
  readonly deliverableAnchor?: Readonly<{ readonly kind: string; readonly locator: string }>;
  readonly attestationRef?: SettlementAttestationRef;
  readonly settlementFinality?: SettlementFinalityRecord;
  readonly amendmentRefs?: readonly SettlementAttestationRef[];
  readonly supersedesEvidenceRef?: SettlementAttestationRef;
  readonly observedAt: number;
}

export interface SettlementEvidence extends UnsignedSettlementEvidence {
  readonly signature: {
    readonly algorithm: "ed25519";
    readonly signer: string;
    readonly value: string;
  };
}

export interface SignedSettlementEvidence {
  readonly artifactContentHash: string;
  readonly evidence: SettlementEvidence;
  readonly evidenceHash: string;
  readonly canonicalJson: string;
  readonly logicalAddress: string;
}

export interface SettlementEvidenceSigningOptions extends FixtureSigningContext {
  readonly agreementHash: string;
  readonly amendmentSetCheck?: SettlementEvidenceVerificationOptions["amendmentSetCheck"];
  readonly asymmetricSettlementCheck?: SettlementEvidenceVerificationOptions["asymmetricSettlementCheck"];
  readonly evidenceMode: EvidenceMode;
  readonly entitlementRenewalSeq?: number;
  readonly deliveryArtifactCheck?: SettlementEvidenceVerificationOptions["deliveryArtifactCheck"];
  readonly expectedPaymentAmount?: SettlementPriceTerm;
  readonly expectedFinality?: SettlementEvidenceVerificationOptions["expectedFinality"];
  readonly expectedAsymmetricFailure?: SettlementEvidenceVerificationOptions["expectedAsymmetricFailure"];
  readonly expectedJobId: string;
  readonly expectedEvidenceLogicalAddress?: SettlementEvidenceVerificationOptions["expectedEvidenceLogicalAddress"];
  readonly expectedPhase?: PaymentPhaseType | DeliveryPhaseType;
  readonly expectedSessionBindingHash: string;
  readonly failureStateCheck?: SettlementEvidenceVerificationOptions["failureStateCheck"];
  readonly expectedPayee?: string;
  readonly expectedPayeeAddress?: string;
  readonly expectedPayer?: string;
  readonly htlcAtomicityCheck?: SettlementEvidenceVerificationOptions["htlcAtomicityCheck"];
  readonly phaseIndex: number;
  readonly railId?: string;
  readonly paymentTransactionCheck?: SettlementEvidenceVerificationOptions["paymentTransactionCheck"];
  readonly pinnedRail?: SettlementEvidenceVerificationOptions["pinnedRail"];
  readonly supersededEvidenceCheck?: SettlementEvidenceVerificationOptions["supersededEvidenceCheck"];
}

export function signSettlementEvidence(
  input: UnsignedSettlementEvidence,
  signer: ArtifactSigner,
  options: SettlementEvidenceSigningOptions,
): SignedSettlementEvidence {
  assertFixtureSigningAuthority(signer, options);
  if (options.evidenceMode !== "fixture") {
    throw new TypeError("Fixture signing authority may emit only fixture evidence");
  }
  if (Object.hasOwn(input, "signature")) {
    throw new TypeError("Unsigned SettlementEvidence must not contain a signature");
  }
  const normalized = JSON.parse(canonicalize(input)) as UnsignedSettlementEvidence;
  const unsignedCanonicalJson = canonicalize(normalized);
  const verificationOptions = settlementEvidenceVerificationOptions(signer.signer, options);
  assertProvisionalVerification(
    preflightCanonicalUnsignedSettlementEvidenceJson(unsignedCanonicalJson, verificationOptions, signer.signer),
    "unsigned authoritative preflight",
  );
  const evidenceHash = sha256Hex(canonicalize(withoutFields(normalized, "signature")));
  const rawSignature = importLegacyComponentSignatureValue(
    signer.sign(
      new TextEncoder().encode(`${SETTLEMENT_EVIDENCE_DOMAIN}${evidenceHash}`),
      options,
    ),
    "standard-base64-padded",
    64,
  );
  const evidence = deepFreezeJson({
    ...normalized,
    signature: {
      algorithm: signer.algorithm,
      signer: signer.signer,
      value: encodeComponentSignatureValue(rawSignature),
    },
  }) as SettlementEvidence;
  const canonicalJson = canonicalize(evidence);
  const verification = verifyCanonicalSettlementEvidenceJson(canonicalJson, verificationOptions);
  assertProvisionalVerification(verification, "signed conformance verification");
  return Object.freeze({
    artifactContentHash: sha256Hex(canonicalJson),
    evidence,
    evidenceHash,
    canonicalJson,
    logicalAddress: verification.logicalAddress,
  });
}

export function settlementEvidenceVerificationOptions(
  signer: string,
  options: SettlementEvidenceSigningOptions,
): SettlementEvidenceVerificationOptions {
  return {
    anchorContext: { mode: "pre-anchor" },
    agreementHash: options.agreementHash,
    ...(options.amendmentSetCheck === undefined
      ? {} : { amendmentSetCheck: options.amendmentSetCheck }),
    ...(options.asymmetricSettlementCheck === undefined
      ? {} : { asymmetricSettlementCheck: options.asymmetricSettlementCheck }),
    evidenceMode: options.evidenceMode,
    ...(options.entitlementRenewalSeq === undefined
      ? {} : { entitlementRenewalSeq: options.entitlementRenewalSeq }),
    expectedJobId: options.expectedJobId,
    ...(options.expectedEvidenceLogicalAddress === undefined
      ? {} : { expectedEvidenceLogicalAddress: options.expectedEvidenceLogicalAddress }),
    expectedOrchestrator: signer,
    expectedPhase: options.expectedPhase ?? options.pinnedRail?.phaseHandler ?? "",
    expectedSessionBindingHash: options.expectedSessionBindingHash,
    ...(options.htlcAtomicityCheck === undefined
      ? {} : { htlcAtomicityCheck: options.htlcAtomicityCheck }),
    ...(options.expectedFinality === undefined ? {} : { expectedFinality: options.expectedFinality }),
    ...(options.expectedAsymmetricFailure === undefined
      ? {} : { expectedAsymmetricFailure: options.expectedAsymmetricFailure }),
    ...(options.failureStateCheck === undefined ? {} : { failureStateCheck: options.failureStateCheck }),
    phaseIndex: options.phaseIndex,
    ...(options.expectedPaymentAmount === undefined
      ? {} : { expectedPaymentAmount: options.expectedPaymentAmount }),
    ...(options.expectedPayee === undefined ? {} : { expectedPayee: options.expectedPayee }),
    ...(options.expectedPayeeAddress === undefined
      ? {} : { expectedPayeeAddress: options.expectedPayeeAddress }),
    ...(options.expectedPayer === undefined ? {} : { expectedPayer: options.expectedPayer }),
    ...(options.paymentTransactionCheck === undefined
      ? {} : { paymentTransactionCheck: options.paymentTransactionCheck }),
    ...(options.pinnedRail === undefined ? {} : { pinnedRail: options.pinnedRail }),
    ...(options.deliveryArtifactCheck === undefined
      ? {} : { deliveryArtifactCheck: options.deliveryArtifactCheck }),
    ...(options.railId === undefined ? {} : { railId: options.railId }),
    ...(options.supersededEvidenceCheck === undefined
      ? {} : { supersededEvidenceCheck: options.supersededEvidenceCheck }),
  };
}

function assertProvisionalVerification(
  verification: ReturnType<typeof verifyCanonicalSettlementEvidenceJson>,
  boundary: string,
): asserts verification is ReturnType<typeof verifyCanonicalSettlementEvidenceJson> & {
  readonly disposition: "provisionally-verified";
  readonly logicalAddress: string;
} {
  if (verification.disposition !== "provisionally-verified") {
    if (!("stage" in verification)) {
      throw new TypeError("SettlementEvidence producer received an unexpected post-anchor verdict");
    }
    throw new TypeError(
      `SettlementEvidence failed ${boundary}: ${verification.stage}: ${verification.reason}`,
    );
  }
}
