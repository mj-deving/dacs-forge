import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { EVIDENCE_MODES, type EvidenceMode } from "../core/evidence-mode.ts";
import { decodeComponentSignatureValue } from "../protocol/component-signature-codec.ts";
import {
  isCanonicalNonNegativeDecimal,
  isCanonicalPositiveDecimal,
} from "../protocol/decimal.ts";
import { canonicalizeGenericClaimReference, sameClaimIdentity } from "../protocol/claim-reference.ts";
import { consumerCanonicalize } from "./canonical-json.ts";

const DOMAIN = "dacs-evidence:v1:";
const HASH = /^[0-9a-f]{64}$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const RAIL_ID = /^[a-z0-9]+(?:[.:_-][A-Za-z0-9]+)*$/;
const KEY_CLAIM = /^key:([0-9a-f]{64})$/;
const DEMOS_TX_HASH = /^(?:0x)?[0-9a-fA-F]{64}$/;
const EVM_TX_HASH = /^(?:0x)?[0-9a-fA-F]{64}$/;
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;
const UNSIGNED_DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ANCHOR_KINDS = new Set(["storage-program", "ipfs", "https"]);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_EVIDENCE_BYTES = 1_048_576;
const MAX_TX_REFS = 64;
const MAX_AMENDMENT_REFS = 256;
const MAX_SIGNATURE_CHARS = 16_384;

const PAYMENT_PHASES = new Set([
  "pay-evm-erc20",
  "pay-solana-spl",
  "pay-cross-chain-htlc",
  "pay-cross-chain-liquidity-tank",
  "pay-ap2",
  "pay-x402",
  "pay-dem",
]);
const DELIVERY_PHASES = new Set([
  "deliver-storage-program",
  "deliver-entitlement",
  "deliver-attested-payload",
]);

export type SettlementEvidenceVerificationStage =
  | "canonical-form"
  | "shape"
  | "job-binding"
  | "session-binding"
  | "phase-binding"
  | "amount-binding"
  | "signature"
  | "orchestrator-binding"
  | "anchor-binding"
  | "transaction-binding"
  | "evidence-mode";

export type SettlementEvidenceVerificationResult =
  | {
    readonly disposition: "verified" | "provisionally-verified";
    readonly evidenceHash: string;
    readonly logicalAddress: string;
    readonly orchestrator: string;
  }
  | {
    readonly disposition: "rejected" | "refused-unsupported" | "indeterminate";
    readonly stage: SettlementEvidenceVerificationStage;
    readonly reason: string;
    readonly evidenceHash?: string;
  };

export type SettlementAnchorRead =
  | {
    readonly status: "resolved";
    readonly artifactContentHash: string;
    readonly artifactKind: string;
    readonly evidenceHash: string;
    readonly evidenceMode: EvidenceMode;
  }
  | { readonly status: "absent" }
  | { readonly status: "indeterminate"; readonly reason: string };

export type SettlementAnchorContext =
  | { readonly mode: "pre-anchor" }
  | { readonly mode: "post-anchor"; readonly read: (logicalAddress: string) => SettlementAnchorRead };

export interface SettlementTransactionExpectation {
  readonly agreementHash: string;
  readonly assetCanonicalJson: string;
  readonly canonicalTxRefJson: string;
  readonly evidenceMode: EvidenceMode;
  readonly finalityModel: string;
  readonly finalityBlocks?: number;
  readonly finalityCommitmentLevel?: string;
  readonly finalityObservedAt: number;
  readonly jobId: string;
  readonly payee: string;
  readonly payeeAddress: string;
  readonly payer: string;
  readonly paymentAmountCanonicalJson: string;
  readonly paymentFeeCanonicalJson?: string;
  readonly phaseIndex: number;
  readonly protocolVersion?: string;
  readonly receiptCommitment?: string;
  readonly sessionBindingHash: string;
  readonly settlementTxId?: string;
}

export type SettlementTransactionCheckResult =
  | {
    readonly status: "verified";
    readonly agreementHash: string;
    readonly assetCanonicalJson: string;
    readonly canonicalTxRefJson: string;
    readonly evidenceMode: EvidenceMode;
    readonly finalityModel: string;
    readonly finalityBlocks?: number;
    readonly finalityCommitmentLevel?: string;
    readonly finalityObservedAt: number;
    readonly jobId: string;
    readonly payee: string;
    readonly payeeAddress: string;
    readonly payer: string;
    readonly paymentAmountCanonicalJson: string;
    readonly paymentFeeCanonicalJson?: string;
    readonly phaseIndex: number;
    readonly protocolVersion?: string;
    readonly receiptCommitment?: string;
    readonly sessionBindingHash: string;
    readonly settlementTxId?: string;
  }
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export interface HtlcAtomicityExpectation {
  readonly agreementHash: string;
  readonly canonicalTxRefsJson: string;
  readonly evidenceMode: EvidenceMode;
  readonly finalityObservedAt: number;
  readonly jobId: string;
  readonly payee: string;
  readonly payeeAddress: string;
  readonly payer: string;
  readonly paymentAmountCanonicalJson: string;
  readonly phaseIndex: number;
  readonly railId: string;
}

export type HtlcAtomicityCheckResult =
  | ({ readonly status: "verified" } & HtlcAtomicityExpectation)
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export interface SettlementConsumptionExpectation {
  readonly canonicalSettlementTxIdsJson: string;
  readonly evidenceHash: string;
  readonly evidenceMode: EvidenceMode;
  readonly jobId: string;
  readonly observedAt: number;
  readonly phaseIndex: number;
}

export type SettlementConsumptionCheckResult =
  | ({ readonly status: "verified" } & SettlementConsumptionExpectation)
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export interface SettlementFailureExpectation {
  readonly agreementHash: string;
  readonly canonicalTxRefsJson: string;
  readonly evidenceHash: string;
  readonly evidenceMode: EvidenceMode;
  readonly jobId: string;
  readonly orchestrator: string;
  readonly payee: string;
  readonly payeeAddress?: string;
  readonly payer: string;
  readonly phase: string;
  readonly phaseIndex: number;
  readonly paymentAmountCanonicalJson?: string;
  readonly paymentFeeCanonicalJson?: string;
  readonly reason: string;
  readonly sessionBindingHash: string;
}

export type SettlementFailureCheckResult =
  | ({ readonly status: "verified" } & SettlementFailureExpectation)
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export interface SettlementDeliveryExpectation {
  readonly agreementHash: string;
  readonly attestationRefCanonicalJson?: string;
  readonly deliverableAnchorCanonicalJson?: string;
  readonly deliverableContentHash?: string;
  readonly evidenceMode: EvidenceMode;
  readonly evidenceLogicalAddress: string;
  readonly jobId: string;
  readonly phase: string;
  readonly phaseIndex: number;
  readonly paymentAmountCanonicalJson?: string;
  readonly paymentFeeCanonicalJson?: string;
  readonly paymentTxRefsCanonicalJson?: string;
  readonly renewalSeq?: number;
  readonly sessionBindingHash: string;
}

export type SettlementDeliveryCheckResult =
  | {
    readonly status: "verified";
    readonly agreementHash: string;
    readonly attestationRefCanonicalJson?: string;
    readonly deliverableAnchorCanonicalJson?: string;
    readonly deliverableContentHash?: string;
    readonly evidenceMode: EvidenceMode;
    readonly evidenceLogicalAddress: string;
    readonly jobId: string;
    readonly phase: string;
    readonly phaseIndex: number;
    readonly paymentAmountCanonicalJson?: string;
    readonly paymentFeeCanonicalJson?: string;
    readonly paymentTxRefsCanonicalJson?: string;
    readonly renewalSeq?: number;
    readonly sessionBindingHash: string;
  }
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export interface AsymmetricSettlementExpectation {
  readonly agreementHash: string;
  readonly canonicalTxRefsJson: string;
  readonly evidenceMode: EvidenceMode;
  readonly jobId: string;
  readonly observedAt: number;
  readonly payee: string;
  readonly payeeAddress: string;
  readonly payer: string;
  readonly phase: "pay-cross-chain-htlc" | "pay-cross-chain-liquidity-tank";
  readonly phaseIndex: number;
  readonly reason: string;
  readonly recoveryDeadline?: number;
}

export type AsymmetricSettlementCheckResult =
  | ({ readonly status: "verified" } & AsymmetricSettlementExpectation)
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export interface SupersededEvidenceExpectation {
  readonly contentHash: string;
  readonly evidenceMode: EvidenceMode;
  readonly jobId: string;
  readonly logicalAddress: string;
  readonly phase: "pay-cross-chain-htlc" | "pay-cross-chain-liquidity-tank";
  readonly reason: "dest-revealed-source-unclaimed" | "tank-locked-unreleased";
}

export type SupersededEvidenceCheckResult =
  | ({ readonly status: "verified"; readonly artifactKind: "dacs-4-evidence"; readonly outcome: "failure" }
    & SupersededEvidenceExpectation)
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export interface AmendmentSetExpectation {
  readonly evidenceHash: string;
  readonly evidenceMode: EvidenceMode;
  readonly jobId: string;
  readonly paymentAmountCanonicalJson?: string;
  readonly refsCanonicalJson: string;
}

export type AmendmentSetCheckResult =
  | ({ readonly status: "verified" } & AmendmentSetExpectation)
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export interface SettlementEvidenceVerificationOptions {
  readonly agreementHash: string;
  readonly amendmentSetCheck?: (
    refs: readonly Readonly<Record<string, unknown>>[],
    expected: AmendmentSetExpectation,
  ) => AmendmentSetCheckResult;
  readonly asymmetricSettlementCheck?: (
    txRefs: readonly Readonly<Record<string, unknown>>[],
    expected: AsymmetricSettlementExpectation,
  ) => AsymmetricSettlementCheckResult;
  readonly anchorContext: SettlementAnchorContext;
  readonly evidenceMode: EvidenceMode;
  readonly expectedJobId: string;
  readonly expectedEvidenceLogicalAddress?: string;
  readonly expectedOrchestrator: string;
  readonly expectedPayee?: string;
  readonly expectedPayeeAddress?: string;
  readonly expectedPayer?: string;
  readonly expectedPaymentAmount?: Readonly<Record<string, unknown>>;
  readonly expectedFinality?: Readonly<{
    readonly model: string;
    readonly finalityBlocks?: number;
    readonly finalityCommitmentLevel?: string;
  }>;
  readonly expectedAsymmetricFailure?: "htlc" | "liquidity-tank";
  readonly expectedPhase: string;
  readonly expectedSessionBindingHash?: string;
  readonly htlcAtomicityCheck?: (
    txRefs: readonly Readonly<Record<string, unknown>>[],
    expected: HtlcAtomicityExpectation,
  ) => HtlcAtomicityCheckResult;
  readonly pinnedRail?: Readonly<{
    readonly assetCanonicalJson: string;
    readonly assetCurrency: string;
    readonly chainId?: number;
    readonly cluster?: "mainnet" | "devnet" | "testnet";
    readonly networkKind: "evm" | "solana" | "demos" | "ap2-provider" | "x402-resource" | "cross-chain";
    readonly phaseHandler: string;
    readonly railId: string;
  }>;
  readonly maxArtifactBytes?: number;
  readonly deliveryArtifactCheck?: (
    logicalAddress: string,
    expected: SettlementDeliveryExpectation,
  ) => SettlementDeliveryCheckResult;
  readonly entitlementRenewalSeq?: number;
  readonly paymentTransactionCheck?: (
    txRef: Readonly<Record<string, unknown>>,
    expected: SettlementTransactionExpectation,
  ) => SettlementTransactionCheckResult;
  readonly phaseIndex: number;
  readonly railId?: string;
  readonly settlementConsumptionCheck?: (
    settlementTxIds: readonly string[],
    expected: SettlementConsumptionExpectation,
  ) => SettlementConsumptionCheckResult;
  readonly failureStateCheck?: (
    expected: SettlementFailureExpectation,
  ) => SettlementFailureCheckResult;
  readonly supersededEvidenceCheck?: (
    ref: Readonly<Record<string, unknown>>,
    expected: SupersededEvidenceExpectation,
  ) => SupersededEvidenceCheckResult;
}

export type ReferencedSettlementEvidenceCryptographyResult =
  | {
    readonly disposition: "verified";
    readonly evidenceHash: string;
    readonly outcome: "success" | "failure";
    readonly signer: string;
  }
  | { readonly disposition: "rejected"; readonly stage: string; readonly reason: string };

export function verifyReferencedSettlementEvidenceCryptography(
  canonicalJson: string,
  expected: Readonly<{ expectedJobId: string; expectedOrchestrator: string; expectedPhase: string }>,
): ReferencedSettlementEvidenceCryptographyResult {
  try {
    if (typeof canonicalJson !== "string" || Buffer.byteLength(canonicalJson, "utf8") > MAX_EVIDENCE_BYTES) {
      return { disposition: "rejected", stage: "canonical-form", reason: "SettlementEvidence exceeds the input limit" };
    }
    const evidence = deepFreezeJson(parseCanonicalObject(canonicalJson));
    const shapeError = validateShape(evidence, true);
    if (shapeError !== null) return { disposition: "rejected", stage: "shape", reason: shapeError };
    if (evidence["jobId"] !== expected.expectedJobId) {
      return { disposition: "rejected", stage: "job-binding", reason: "SettlementEvidence jobId differs from persisted lifecycle authority" };
    }
    if (evidence["phase"] !== expected.expectedPhase) {
      return { disposition: "rejected", stage: "phase-binding", reason: "SettlementEvidence phase differs from persisted lifecycle authority" };
    }
    const signature = evidence["signature"] as Record<string, unknown>;
    const signer = signature["signer"] as string;
    const expectedSigner = canonicalizeGenericClaimReference(expected.expectedOrchestrator).canonicalReference;
    const canonicalSigner = canonicalizeGenericClaimReference(signer).canonicalReference;
    if (expectedSigner !== expected.expectedOrchestrator || canonicalSigner !== signer
      || !sameClaimIdentity(canonicalSigner, expectedSigner)) {
      return { disposition: "rejected", stage: "orchestrator-binding", reason: "SettlementEvidence signer is not the persisted phase authority" };
    }
    if (signature["algorithm"] !== "ed25519") {
      return { disposition: "rejected", stage: "signature", reason: "SettlementEvidence signature algorithm is unsupported" };
    }
    const keyMatch = KEY_CLAIM.exec(signer);
    if (keyMatch === null) {
      return { disposition: "rejected", stage: "signature", reason: "SettlementEvidence signer key is unavailable" };
    }
    const evidenceHash = sha256(consumerCanonicalize(omitField(evidence, "signature")));
    const signatureBytes = decodeComponentSignatureValue(signature["value"] as string, 64);
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(keyMatch[1]!, "hex")]),
      format: "der",
      type: "spki",
    });
    if (!verifyBytes(null, Buffer.from(`${DOMAIN}${evidenceHash}`, "utf8"), publicKey, signatureBytes)) {
      return { disposition: "rejected", stage: "signature", reason: "SettlementEvidence signature is invalid" };
    }
    return Object.freeze({
      disposition: "verified",
      evidenceHash,
      outcome: evidence["outcome"] as "success" | "failure",
      signer,
    });
  } catch (error) {
    return { disposition: "rejected", stage: "parse", reason: message(error) };
  }
}

export function verifyCanonicalSettlementEvidenceJson(
  canonicalJson: string,
  options: SettlementEvidenceVerificationOptions,
): SettlementEvidenceVerificationResult {
  return verifySettlementEvidenceJson(canonicalJson, options, { mode: "signed" });
}

export function preflightCanonicalUnsignedSettlementEvidenceJson(
  canonicalJson: string,
  options: SettlementEvidenceVerificationOptions,
  signer: string,
): SettlementEvidenceVerificationResult {
  return verifySettlementEvidenceJson(canonicalJson, options, { mode: "unsigned-preflight", signer });
}

function verifySettlementEvidenceJson(
  canonicalJson: string,
  options: SettlementEvidenceVerificationOptions,
  signatureMode: { readonly mode: "signed" } | { readonly mode: "unsigned-preflight"; readonly signer: string },
): SettlementEvidenceVerificationResult {
  if (object(options as unknown) === null) {
    return unsupported("canonical-form", "SettlementEvidence verifier configuration is missing");
  }
  const anchorContext = object(options.anchorContext as unknown);
  if (anchorContext === null
    || (anchorContext["mode"] !== "pre-anchor" && anchorContext["mode"] !== "post-anchor")
    || (anchorContext["mode"] === "post-anchor" && typeof anchorContext["read"] !== "function")) {
    return unsupported("anchor-binding", "SettlementEvidence anchor context is malformed");
  }
  const maxBytes = options.maxArtifactBytes ?? MAX_EVIDENCE_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    return unsupported("canonical-form", "Configured SettlementEvidence byte limit is invalid");
  }
  if (typeof canonicalJson !== "string" || Buffer.byteLength(canonicalJson, "utf8") > maxBytes) {
    return unsupported("canonical-form", `SettlementEvidence exceeds implementation input limit of ${maxBytes} bytes`);
  }
  let evidence: Record<string, unknown>;
  try {
    evidence = deepFreezeJson(parseCanonicalObject(canonicalJson));
  } catch (error) {
    return rejected("canonical-form", message(error));
  }
  const shapeError = validateShape(evidence, signatureMode.mode === "signed");
  if (shapeError !== null) return rejected("shape", shapeError);
  if (evidence["jobId"] !== options.expectedJobId) {
    return rejected("job-binding", "SettlementEvidence jobId does not match the session");
  }
  if (evidence["phase"] !== options.expectedPhase) {
    return rejected("phase-binding", "SettlementEvidence phase does not match the pipeline invocation");
  }
  if (evidence["outcome"] === "success"
    && (typeof options.expectedSessionBindingHash !== "string"
      || !HASH.test(options.expectedSessionBindingHash))) {
    return unsupported(
      "session-binding",
      "Successful settlement verification requires a valid pinned session binding hash",
    );
  }
  if (!nonNegativeSafeInteger(options.phaseIndex)) {
    return unsupported("phase-binding", "Settlement verification requires a valid phaseIndex");
  }
  if (!HASH.test(options.agreementHash)) {
    return unsupported("amount-binding", "Configured expected agreement hash is malformed");
  }
  const phase = evidence["phase"] as string;
  const isPayment = PAYMENT_PHASES.has(phase);
  if (options.expectedAsymmetricFailure !== undefined && evidence["outcome"] !== "failure") {
    return rejected(
      "transaction-binding",
      "Expected asymmetric settlement failure cannot be satisfied by success evidence",
    );
  }
  if (isPayment) {
    const railError = validatePinnedRail(evidence, options);
    if (railError?.kind === "configuration") {
      return unsupported("phase-binding", railError.reason);
    }
    if (railError?.kind === "evidence") {
      return rejected("phase-binding", railError.reason);
    }
  }
  const partyConfigurationError = validateConfiguredParties(evidence, options, isPayment);
  if (partyConfigurationError !== null) {
    return unsupported("transaction-binding", partyConfigurationError);
  }
  let expectedPaymentJson: string | undefined;
  let expectedPaymentFeeJson: string | undefined;
  if (evidence["outcome"] === "success") {
    if (options.expectedPaymentAmount === undefined) {
      return unsupported("amount-binding", "Successful settlement verification requires the agreement price");
    }
    const expectedAmountError = validatePriceTerm(options.expectedPaymentAmount, true);
    if (expectedAmountError !== null) {
      return unsupported("amount-binding", `Configured agreement price ${expectedAmountError}`);
    }
    try {
      expectedPaymentJson = consumerCanonicalize(options.expectedPaymentAmount);
    } catch (error) {
      return unsupported("amount-binding", `Configured agreement price is not canonicalizable: ${message(error)}`);
    }
    if (consumerCanonicalize(evidence["paymentAmount"]) !== expectedPaymentJson) {
      return rejected("amount-binding", "SettlementEvidence payment amount differs from the agreement price");
    }
  }
  if (isPayment && evidence["outcome"] === "success") {
    if (options.expectedPayer === undefined || options.expectedPayee === undefined
      || options.expectedPayeeAddress === undefined) {
      return unsupported(
        "transaction-binding",
        "Successful payment verification requires agreement-bound payer and payee claims",
      );
    }
    if (Object.hasOwn(evidence, "paymentFee")) {
      expectedPaymentFeeJson = consumerCanonicalize(evidence["paymentFee"]);
    }
  }
  const signedScope = signatureMode.mode === "signed" ? omitField(evidence, "signature") : evidence;
  const evidenceHash = sha256(consumerCanonicalize(signedScope));
  const artifactContentHash = sha256(canonicalJson);
  const signature = signatureMode.mode === "signed"
    ? evidence["signature"] as Record<string, unknown> : undefined;
  const signer = signatureMode.mode === "signed"
    ? signature!["signer"] as string : signatureMode.signer;
  let canonicalExpectedSigner: string;
  try {
    canonicalExpectedSigner = canonicalizeGenericClaimReference(options.expectedOrchestrator).canonicalReference;
    if (canonicalExpectedSigner !== options.expectedOrchestrator) {
      return unsupported("orchestrator-binding", "Configured phase orchestrator is non-canonical", evidenceHash);
    }
  } catch (error) {
    return unsupported(
      "orchestrator-binding",
      `Configured phase orchestrator is invalid: ${message(error)}`,
      evidenceHash,
    );
  }
  let canonicalSigner: string;
  try {
    canonicalSigner = canonicalizeGenericClaimReference(signer).canonicalReference;
    if (canonicalSigner !== signer || !sameClaimIdentity(canonicalSigner, canonicalExpectedSigner)) {
      return rejected(
        "orchestrator-binding",
        "SettlementEvidence signer is not the expected phase orchestrator",
        evidenceHash,
      );
    }
  } catch (error) {
    return rejected("orchestrator-binding", `SettlementEvidence signer is invalid: ${message(error)}`, evidenceHash);
  }
  if (signature !== undefined) {
    if (signature["algorithm"] !== "ed25519") {
      return unsupported("signature", "SettlementEvidence signature algorithm is unsupported", evidenceHash);
    }
    const keyMatch = KEY_CLAIM.exec(signer);
    if (keyMatch === null) {
      return unsupported("signature", "SettlementEvidence signer key resolution is unavailable", evidenceHash);
    }
    if ((signature["value"] as string).length > MAX_SIGNATURE_CHARS) {
      return unsupported("signature", "SettlementEvidence signature exceeds implementation input limit", evidenceHash);
    }
    try {
      const signatureBytes = decodeComponentSignatureValue(signature["value"] as string, 64);
      const publicKey = createPublicKey({
        key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(keyMatch[1]!, "hex")]),
        format: "der",
        type: "spki",
      });
      if (!verifyBytes(
        null,
        Buffer.from(`${DOMAIN}${evidenceHash}`, "utf8"),
        publicKey,
        signatureBytes,
      )) return rejected("signature", "SettlementEvidence signature is invalid", evidenceHash);
    } catch (error) {
      return rejected("signature", `SettlementEvidence signature cannot be verified: ${message(error)}`, evidenceHash);
    }
  }

  const logicalAddressResult = logicalAddress(evidence, options);
  if (typeof logicalAddressResult !== "string") return logicalAddressResult(evidenceHash);
  const logicalAddressValue = logicalAddressResult;
  if (isPayment && evidence["outcome"] === "success") {
    if (options.paymentTransactionCheck === undefined || expectedPaymentJson === undefined) {
      return indeterminate(
        "transaction-binding",
        "Payment transaction verifier is unavailable",
        evidenceHash,
      );
    }
    const finality = evidence["settlementFinality"] as Record<string, unknown>;
    const finalityPinError = validatePinnedFinality(finality, options.expectedFinality);
    if (finalityPinError?.kind === "configuration") {
      return unsupported("transaction-binding", finalityPinError.reason, evidenceHash);
    }
    if (finalityPinError?.kind === "evidence") {
      return rejected("transaction-binding", finalityPinError.reason, evidenceHash);
    }
    if (phase === "pay-cross-chain-htlc") {
      if (options.htlcAtomicityCheck === undefined) {
        return indeterminate(
          "transaction-binding",
          "Grouped HTLC atomicity verifier is unavailable",
          evidenceHash,
        );
      }
      const txRefs = evidence["paymentTxRefs"] as readonly Readonly<Record<string, unknown>>[];
      const expectedAtomicity = Object.freeze({
        agreementHash: options.agreementHash,
        canonicalTxRefsJson: consumerCanonicalize(txRefs),
        evidenceMode: options.evidenceMode,
        finalityObservedAt: finality["finalityObservedAt"] as number,
        jobId: options.expectedJobId,
        payee: options.expectedPayee!,
        payeeAddress: options.expectedPayeeAddress!,
        payer: options.expectedPayer!,
        paymentAmountCanonicalJson: expectedPaymentJson,
        phaseIndex: options.phaseIndex,
        railId: options.railId!,
      });
      let atomicity: HtlcAtomicityCheckResult;
      try {
        atomicity = options.htlcAtomicityCheck(txRefs, expectedAtomicity);
      } catch (error) {
        return indeterminate(
          "transaction-binding",
          `Grouped HTLC atomicity verifier failed: ${message(error)}`,
          evidenceHash,
        );
      }
      if (callbackStatus(atomicity) === null) {
        return indeterminate("transaction-binding", "Grouped HTLC atomicity verifier returned a malformed result", evidenceHash);
      }
      if (atomicity.status === "indeterminate") {
        return indeterminate("transaction-binding", atomicity.reason, evidenceHash);
      }
      if (atomicity.status === "rejected") {
        return rejected("transaction-binding", atomicity.reason, evidenceHash);
      }
      if (atomicity.agreementHash !== expectedAtomicity.agreementHash
        || atomicity.canonicalTxRefsJson !== expectedAtomicity.canonicalTxRefsJson
        || atomicity.evidenceMode !== expectedAtomicity.evidenceMode
        || atomicity.finalityObservedAt !== expectedAtomicity.finalityObservedAt
        || atomicity.jobId !== expectedAtomicity.jobId
        || atomicity.payee !== expectedAtomicity.payee
        || atomicity.payeeAddress !== expectedAtomicity.payeeAddress
        || atomicity.payer !== expectedAtomicity.payer
        || atomicity.paymentAmountCanonicalJson !== expectedAtomicity.paymentAmountCanonicalJson
        || atomicity.phaseIndex !== expectedAtomicity.phaseIndex
        || atomicity.railId !== expectedAtomicity.railId) {
        return rejected(
          "transaction-binding",
          "Grouped HTLC proof does not bind the complete route, parties, amount, finality, and session",
          evidenceHash,
        );
      }
    }
    for (const txRef of evidence["paymentTxRefs"] as Record<string, unknown>[]) {
      const settlementTxId = settlementTransactionId(txRef);
      let checked: SettlementTransactionCheckResult;
      try {
        checked = options.paymentTransactionCheck(txRef, Object.freeze({
          agreementHash: options.agreementHash,
          assetCanonicalJson: options.pinnedRail!.assetCanonicalJson,
          canonicalTxRefJson: consumerCanonicalize(txRef),
          evidenceMode: options.evidenceMode,
          ...(typeof finality["finalityBlocks"] === "number"
            ? { finalityBlocks: finality["finalityBlocks"] } : {}),
          ...(typeof finality["finalityCommitmentLevel"] === "string"
            ? { finalityCommitmentLevel: finality["finalityCommitmentLevel"] } : {}),
          finalityModel: finality["model"] as string,
          finalityObservedAt: finality["finalityObservedAt"] as number,
          jobId: options.expectedJobId,
          payee: options.expectedPayee!,
          payeeAddress: options.expectedPayeeAddress!,
          payer: options.expectedPayer!,
          paymentAmountCanonicalJson: expectedPaymentJson,
          ...(expectedPaymentFeeJson === undefined
            ? {} : { paymentFeeCanonicalJson: expectedPaymentFeeJson }),
          phaseIndex: options.phaseIndex,
          ...(typeof txRef["protocolVersion"] === "string"
            ? { protocolVersion: txRef["protocolVersion"] } : {}),
          ...(phase === "pay-x402"
            ? { receiptCommitment: txRef["paymentReceiptHash"] as string }
            : phase === "pay-ap2"
              ? { receiptCommitment: consumerCanonicalize(txRef["receiptAttestation"]) }
              : {}),
          sessionBindingHash: options.expectedSessionBindingHash!,
          ...(settlementTxId === null ? {} : { settlementTxId }),
        }));
      } catch (error) {
        return indeterminate(
          "transaction-binding",
          `Payment transaction verifier failed: ${message(error)}`,
          evidenceHash,
        );
      }
      if (callbackStatus(checked) === null) {
        return indeterminate("transaction-binding", "Payment transaction verifier returned a malformed result", evidenceHash);
      }
      if (checked.status === "indeterminate") {
        return indeterminate("transaction-binding", checked.reason, evidenceHash);
      }
      if (checked.status === "rejected") {
        return rejected("transaction-binding", checked.reason, evidenceHash);
      }
      if (
        checked.evidenceMode !== options.evidenceMode
        || checked.assetCanonicalJson !== options.pinnedRail!.assetCanonicalJson
        || checked.canonicalTxRefJson !== consumerCanonicalize(txRef)
        || checked.jobId !== options.expectedJobId
        || checked.payer !== options.expectedPayer
        || checked.payee !== options.expectedPayee
        || checked.payeeAddress !== options.expectedPayeeAddress
        || checked.phaseIndex !== options.phaseIndex
        || checked.agreementHash !== options.agreementHash
        || checked.paymentAmountCanonicalJson !== expectedPaymentJson
        || checked.paymentFeeCanonicalJson !== expectedPaymentFeeJson
        || checked.protocolVersion !== txRef["protocolVersion"]
        || checked.receiptCommitment !== (phase === "pay-x402"
          ? txRef["paymentReceiptHash"]
          : phase === "pay-ap2" ? consumerCanonicalize(txRef["receiptAttestation"]) : undefined)
        || checked.sessionBindingHash !== options.expectedSessionBindingHash
        || checked.finalityModel !== finality["model"]
        || checked.finalityBlocks !== finality["finalityBlocks"]
        || checked.finalityCommitmentLevel !== finality["finalityCommitmentLevel"]
        || checked.finalityObservedAt !== finality["finalityObservedAt"]
        || checked.settlementTxId !== (settlementTxId ?? undefined)
      ) {
        return rejected(
          checked.evidenceMode !== options.evidenceMode ? "evidence-mode" : "transaction-binding",
          "Settlement transaction proof does not match the expected session, agreement, asset, amount, finality, or mode",
          evidenceHash,
        );
      }
    }
  }
  if (isPayment && evidence["outcome"] === "failure") {
    if (Object.hasOwn(evidence, "paymentAmount")) {
      if (options.expectedPaymentAmount === undefined) {
        return unsupported(
          "amount-binding",
          "Failure paymentAmount requires the agreement price for comparison",
          evidenceHash,
        );
      }
      const expectedAmountError = validatePriceTerm(options.expectedPaymentAmount, true);
      if (expectedAmountError !== null) {
        return unsupported(
          "amount-binding",
          `Configured agreement price ${expectedAmountError}`,
          evidenceHash,
        );
      }
      let expectedFailureAmount: string;
      try {
        expectedFailureAmount = consumerCanonicalize(options.expectedPaymentAmount);
      } catch (error) {
        return unsupported(
          "amount-binding",
          `Configured agreement price is not canonicalizable: ${message(error)}`,
          evidenceHash,
        );
      }
      if (consumerCanonicalize(evidence["paymentAmount"]) !== expectedFailureAmount) {
        return rejected("amount-binding", "Failure paymentAmount differs from the agreement price", evidenceHash);
      }
    }
    const asymmetricKind = asymmetricFailureKind(evidence);
    if (options.expectedAsymmetricFailure !== undefined
      && options.expectedAsymmetricFailure !== asymmetricKind) {
      return rejected("transaction-binding", "Settlement failure does not match the expected asymmetric state", evidenceHash);
    }
    if (asymmetricKind !== null) {
      if (options.expectedPayer === undefined || options.expectedPayee === undefined
        || options.expectedPayeeAddress === undefined) {
        return unsupported(
          "transaction-binding",
          "Asymmetric settlement verification requires agreement-bound parties and payee address",
          evidenceHash,
        );
      }
      if (options.asymmetricSettlementCheck === undefined) {
        return indeterminate("transaction-binding", "Asymmetric settlement verifier is unavailable", evidenceHash);
      }
      const refs = evidence["paymentTxRefs"] as Record<string, unknown>[];
      const tankRef = asymmetricKind === "liquidity-tank" ? refs[0] : undefined;
      const expected: AsymmetricSettlementExpectation = Object.freeze({
        agreementHash: options.agreementHash,
        canonicalTxRefsJson: consumerCanonicalize(refs),
        evidenceMode: options.evidenceMode,
        jobId: options.expectedJobId,
        observedAt: evidence["observedAt"] as number,
        payee: options.expectedPayee,
        payeeAddress: options.expectedPayeeAddress,
        payer: options.expectedPayer,
        phase: evidence["phase"] as AsymmetricSettlementExpectation["phase"],
        phaseIndex: options.phaseIndex,
        reason: evidence["reason"] as string,
        ...(tankRef === undefined ? {} : { recoveryDeadline: tankRef["recoveryDeadline"] as number }),
      });
      let checked: AsymmetricSettlementCheckResult;
      try {
        checked = options.asymmetricSettlementCheck(refs, expected);
      } catch (error) {
        return indeterminate(
          "transaction-binding",
          `Asymmetric settlement verifier failed: ${message(error)}`,
          evidenceHash,
        );
      }
      if (callbackStatus(checked) === null) {
        return indeterminate("transaction-binding", "Asymmetric settlement verifier returned a malformed result", evidenceHash);
      }
      if (checked.status === "indeterminate") {
        return indeterminate("transaction-binding", checked.reason, evidenceHash);
      }
      if (checked.status === "rejected") return rejected("transaction-binding", checked.reason, evidenceHash);
      const callbackMatches = canonicalJsonEquals(checked, { status: "verified", ...expected });
      if (callbackMatches === null) {
        return indeterminate("transaction-binding", "Asymmetric settlement verifier returned a malformed result", evidenceHash);
      }
      if (!callbackMatches) {
        return rejected("transaction-binding", "Asymmetric settlement proof does not match the expected state", evidenceHash);
      }
    }
  }
  if (evidence["outcome"] === "failure") {
    if (options.expectedPayer === undefined || options.expectedPayee === undefined) {
      return unsupported(
        "transaction-binding",
        "Settlement failure verification requires agreement-bound payer and payee claims",
        evidenceHash,
      );
    }
    if (options.failureStateCheck === undefined) {
      return indeterminate("transaction-binding", "Settlement failure-state verifier is unavailable", evidenceHash);
    }
    const expected = Object.freeze({
      agreementHash: options.agreementHash,
      canonicalTxRefsJson: consumerCanonicalize(evidence["paymentTxRefs"] ?? []),
      evidenceHash,
      evidenceMode: options.evidenceMode,
      jobId: options.expectedJobId,
      orchestrator: canonicalExpectedSigner,
      payee: options.expectedPayee,
      ...(options.expectedPayeeAddress === undefined ? {} : { payeeAddress: options.expectedPayeeAddress }),
      payer: options.expectedPayer,
      phase,
      phaseIndex: options.phaseIndex,
      sessionBindingHash: options.expectedSessionBindingHash!,
      ...(Object.hasOwn(evidence, "paymentAmount")
        ? { paymentAmountCanonicalJson: consumerCanonicalize(evidence["paymentAmount"]) } : {}),
      ...(Object.hasOwn(evidence, "paymentFee")
        ? { paymentFeeCanonicalJson: consumerCanonicalize(evidence["paymentFee"]) } : {}),
      reason: evidence["reason"] as string,
    });
    let checked: SettlementFailureCheckResult;
    try {
      checked = options.failureStateCheck(expected);
    } catch (error) {
      return indeterminate(
        "transaction-binding",
        `Settlement failure-state verifier failed: ${message(error)}`,
        evidenceHash,
      );
    }
    if (callbackStatus(checked) === null) {
      return indeterminate("transaction-binding", "Settlement failure-state verifier returned a malformed result", evidenceHash);
    }
    if (checked.status === "indeterminate") {
      return indeterminate("transaction-binding", checked.reason, evidenceHash);
    }
    if (checked.status === "rejected") return rejected("transaction-binding", checked.reason, evidenceHash);
    const callbackMatches = canonicalJsonEquals(checked, { status: "verified", ...expected });
    if (callbackMatches === null) {
      return indeterminate("transaction-binding", "Settlement failure-state verifier returned a malformed result", evidenceHash);
    }
    if (!callbackMatches) {
      return rejected("transaction-binding", "Settlement failure proof does not match the exact pipeline state", evidenceHash);
    }
  }
  if (Object.hasOwn(evidence, "supersedesEvidenceRef")) {
    if (options.supersededEvidenceCheck === undefined) {
      return indeterminate("transaction-binding", "Superseded settlement evidence resolver is unavailable", evidenceHash);
    }
    const ref = evidence["supersedesEvidenceRef"] as Record<string, unknown>;
    const expected: SupersededEvidenceExpectation = Object.freeze({
      contentHash: ref["contentHash"] as string,
      evidenceMode: options.evidenceMode,
      jobId: options.expectedJobId,
      logicalAddress: logicalAddressValue.slice(0, -":resolved".length),
      phase: phase as SupersededEvidenceExpectation["phase"],
      reason: phase === "pay-cross-chain-htlc"
        ? "dest-revealed-source-unclaimed" : "tank-locked-unreleased",
    });
    let checked: SupersededEvidenceCheckResult;
    try {
      checked = options.supersededEvidenceCheck(ref, expected);
    } catch (error) {
      return indeterminate(
        "transaction-binding",
        `Superseded settlement evidence resolver failed: ${message(error)}`,
        evidenceHash,
      );
    }
    if (callbackStatus(checked) === null) {
      return indeterminate("transaction-binding", "Superseded settlement resolver returned a malformed result", evidenceHash);
    }
    if (checked.status === "indeterminate") {
      return indeterminate("transaction-binding", checked.reason, evidenceHash);
    }
    if (checked.status === "rejected") return rejected("transaction-binding", checked.reason, evidenceHash);
    const callbackMatches = canonicalJsonEquals(checked, {
      status: "verified",
      artifactKind: "dacs-4-evidence",
      outcome: "failure",
      ...expected,
    });
    if (callbackMatches === null) {
      return indeterminate("transaction-binding", "Superseded settlement resolver returned a malformed result", evidenceHash);
    }
    if (!callbackMatches) {
      return rejected("transaction-binding", "Superseded settlement evidence does not match the interim state", evidenceHash);
    }
  }
  if (Array.isArray(evidence["amendmentRefs"]) && evidence["amendmentRefs"].length > 0) {
    if (options.amendmentSetCheck === undefined) {
      return indeterminate("transaction-binding", "Settlement amendment resolver is unavailable", evidenceHash);
    }
    const refs = evidence["amendmentRefs"] as Record<string, unknown>[];
    const expected: AmendmentSetExpectation = Object.freeze({
      evidenceHash,
      evidenceMode: options.evidenceMode,
      jobId: options.expectedJobId,
      ...(Object.hasOwn(evidence, "paymentAmount")
        ? { paymentAmountCanonicalJson: consumerCanonicalize(evidence["paymentAmount"]) } : {}),
      refsCanonicalJson: consumerCanonicalize(refs),
    });
    let checked: AmendmentSetCheckResult;
    try {
      checked = options.amendmentSetCheck(refs, expected);
    } catch (error) {
      return indeterminate("transaction-binding", `Settlement amendment resolver failed: ${message(error)}`, evidenceHash);
    }
    if (callbackStatus(checked) === null) {
      return indeterminate("transaction-binding", "Settlement amendment resolver returned a malformed result", evidenceHash);
    }
    if (checked.status === "indeterminate") return indeterminate("transaction-binding", checked.reason, evidenceHash);
    if (checked.status === "rejected") return rejected("transaction-binding", checked.reason, evidenceHash);
    const callbackMatches = canonicalJsonEquals(checked, { status: "verified", ...expected });
    if (callbackMatches === null) {
      return indeterminate("transaction-binding", "Settlement amendment resolver returned a malformed result", evidenceHash);
    }
    if (!callbackMatches) {
      return rejected("transaction-binding", "Settlement amendments do not match the verified amendment set", evidenceHash);
    }
  }
  if (!isPayment && evidence["outcome"] === "success") {
    if (options.deliveryArtifactCheck === undefined) {
      return indeterminate("transaction-binding", "Delivery artifact verifier is unavailable", evidenceHash);
    }
    const expectedDelivery: SettlementDeliveryExpectation = Object.freeze({
      agreementHash: options.agreementHash,
      evidenceMode: options.evidenceMode,
      evidenceLogicalAddress: logicalAddressValue,
      jobId: options.expectedJobId,
      phase,
      phaseIndex: options.phaseIndex,
      sessionBindingHash: options.expectedSessionBindingHash!,
      ...(Object.hasOwn(evidence, "paymentAmount")
        ? { paymentAmountCanonicalJson: consumerCanonicalize(evidence["paymentAmount"]) } : {}),
      ...(Object.hasOwn(evidence, "paymentFee")
        ? { paymentFeeCanonicalJson: consumerCanonicalize(evidence["paymentFee"]) } : {}),
      ...(Object.hasOwn(evidence, "paymentTxRefs")
        ? { paymentTxRefsCanonicalJson: consumerCanonicalize(evidence["paymentTxRefs"]) } : {}),
      ...(phase === "deliver-entitlement"
        ? { renewalSeq: options.entitlementRenewalSeq } : {}),
      ...(typeof evidence["deliverableContentHash"] === "string"
        ? { deliverableContentHash: evidence["deliverableContentHash"] } : {}),
      ...(object(evidence["deliverableAnchor"]) === null
        ? {} : { deliverableAnchorCanonicalJson: consumerCanonicalize(evidence["deliverableAnchor"]) }),
      ...(object(evidence["attestationRef"]) === null
        ? {} : { attestationRefCanonicalJson: consumerCanonicalize(evidence["attestationRef"]) }),
    });
    let checked: SettlementDeliveryCheckResult;
    try {
      checked = options.deliveryArtifactCheck(
        deliveryArtifactAddress(evidence, options.entitlementRenewalSeq),
        expectedDelivery,
      );
    } catch (error) {
      return indeterminate(
        "transaction-binding",
        `Delivery artifact verifier failed: ${message(error)}`,
        evidenceHash,
      );
    }
    if (callbackStatus(checked) === null) {
      return indeterminate("transaction-binding", "Delivery artifact verifier returned a malformed result", evidenceHash);
    }
    if (checked.status === "indeterminate") {
      return indeterminate("transaction-binding", checked.reason, evidenceHash);
    }
    if (checked.status === "rejected") {
      return rejected("transaction-binding", checked.reason, evidenceHash);
    }
    if (
      checked.agreementHash !== expectedDelivery.agreementHash
      || checked.evidenceMode !== expectedDelivery.evidenceMode
      || checked.evidenceLogicalAddress !== expectedDelivery.evidenceLogicalAddress
      || checked.jobId !== expectedDelivery.jobId
      || checked.phase !== expectedDelivery.phase
      || checked.phaseIndex !== expectedDelivery.phaseIndex
      || checked.paymentAmountCanonicalJson !== expectedDelivery.paymentAmountCanonicalJson
      || checked.paymentFeeCanonicalJson !== expectedDelivery.paymentFeeCanonicalJson
      || checked.paymentTxRefsCanonicalJson !== expectedDelivery.paymentTxRefsCanonicalJson
      || checked.renewalSeq !== expectedDelivery.renewalSeq
      || checked.sessionBindingHash !== expectedDelivery.sessionBindingHash
      || checked.deliverableContentHash !== expectedDelivery.deliverableContentHash
      || checked.deliverableAnchorCanonicalJson !== expectedDelivery.deliverableAnchorCanonicalJson
      || checked.attestationRefCanonicalJson !== expectedDelivery.attestationRefCanonicalJson
    ) {
      return rejected(
        checked.evidenceMode !== options.evidenceMode ? "evidence-mode" : "transaction-binding",
        "Resolved delivery artifact does not match the session, agreement, content, attestation, or mode",
        evidenceHash,
      );
    }
  }

  if (options.anchorContext.mode === "pre-anchor") {
    return Object.freeze({
      disposition: "provisionally-verified",
      evidenceHash,
      logicalAddress: logicalAddressValue,
      orchestrator: signer,
    });
  }
  let anchorRead: SettlementAnchorRead;
  try {
    anchorRead = options.anchorContext.read(logicalAddressValue);
  } catch (error) {
    return indeterminate("anchor-binding", `Settlement evidence anchor read failed: ${message(error)}`, evidenceHash);
  }
  if (anchorReadStatus(anchorRead) === null) {
    return indeterminate("anchor-binding", "Settlement evidence anchor reader returned a malformed result", evidenceHash);
  }
  if (anchorRead.status === "indeterminate") {
    return indeterminate("anchor-binding", anchorRead.reason, evidenceHash);
  }
  if (anchorRead.status === "absent") {
    return rejected("anchor-binding", "Settlement evidence is authoritatively absent", evidenceHash);
  }
  if (anchorRead.evidenceHash !== evidenceHash) {
    return rejected("anchor-binding", "Anchored SettlementEvidence hash does not match", evidenceHash);
  }
  if (anchorRead.artifactContentHash !== artifactContentHash) {
    return rejected(
      "anchor-binding",
      "Anchored SettlementEvidence artifact hash does not match the exact signed artifact",
      evidenceHash,
    );
  }
  if (anchorRead.artifactKind !== "dacs-4-evidence") {
    return rejected("anchor-binding", "Settlement evidence anchor has the wrong artifact kind", evidenceHash);
  }
  if (anchorRead.evidenceMode !== options.evidenceMode) {
    return rejected("evidence-mode", "Settlement evidence anchor provenance mode does not match", evidenceHash);
  }
  const consumption = checkSettlementConsumption(evidence, options, evidenceHash);
  if (consumption !== null) return consumption;
  return Object.freeze({
    disposition: "verified",
    evidenceHash,
    logicalAddress: logicalAddressValue,
    orchestrator: signer,
  });
}

function checkSettlementConsumption(
  evidence: Record<string, unknown>,
  options: SettlementEvidenceVerificationOptions,
  evidenceHash: string,
): SettlementEvidenceVerificationResult | null {
  if (!PAYMENT_PHASES.has(evidence["phase"] as string) || evidence["outcome"] !== "success") {
    return null;
  }
  if (options.settlementConsumptionCheck === undefined) {
    return indeterminate(
      "transaction-binding",
      "Settlement transaction consumption verifier is unavailable",
      evidenceHash,
    );
  }
  const settlementTxIds: string[] = [];
  for (const ref of evidence["paymentTxRefs"] as Record<string, unknown>[]) {
    const id = settlementTransactionId(ref);
    if (id === null) {
      return unsupported("transaction-binding", unsupportedSettlementTransactionIdReason(ref), evidenceHash);
    }
    settlementTxIds.push(id);
  }
  if (new Set(settlementTxIds).size !== settlementTxIds.length) {
    return rejected("transaction-binding", "SettlementEvidence repeats a settlement transaction identifier", evidenceHash);
  }
  const expected: SettlementConsumptionExpectation = Object.freeze({
    canonicalSettlementTxIdsJson: consumerCanonicalize(settlementTxIds),
    evidenceHash,
    evidenceMode: options.evidenceMode,
    jobId: options.expectedJobId,
    observedAt: evidence["observedAt"] as number,
    phaseIndex: options.phaseIndex,
  });
  let checked: SettlementConsumptionCheckResult;
  try {
    checked = options.settlementConsumptionCheck(Object.freeze(settlementTxIds), expected);
  } catch (error) {
    return indeterminate(
      "transaction-binding",
      `Settlement transaction consumption verifier failed: ${message(error)}`,
      evidenceHash,
    );
  }
  if (callbackStatus(checked) === null) {
    return indeterminate(
      "transaction-binding",
      "Settlement transaction consumption verifier returned a malformed result",
      evidenceHash,
    );
  }
  if (checked.status === "indeterminate") {
    return indeterminate("transaction-binding", checked.reason, evidenceHash);
  }
  if (checked.status === "rejected") {
    return rejected("transaction-binding", checked.reason, evidenceHash);
  }
  const callbackMatches = canonicalJsonEquals(checked, { status: "verified", ...expected });
  if (callbackMatches === null) {
    return indeterminate(
      "transaction-binding",
      "Settlement transaction consumption verifier returned a malformed result",
      evidenceHash,
    );
  }
  if (!callbackMatches) {
    return rejected(
      "transaction-binding",
      "Settlement transaction consumption proof does not match the evidence ordering and session binding",
      evidenceHash,
    );
  }
  return null;
}

function validateShape(evidence: Record<string, unknown>, requireSignature: boolean): string | null {
  for (const field of [
    "evidenceVersion",
    "jobId",
    "phase",
    "outcome",
    "observedAt",
    ...(requireSignature ? ["signature" as const] : []),
  ] as const) {
    if (!Object.hasOwn(evidence, field)) return `SettlementEvidence is missing ${field}`;
  }
  if (evidence["evidenceVersion"] !== "1") return "SettlementEvidence version is unsupported";
  if (typeof evidence["jobId"] !== "string" || !ULID.test(evidence["jobId"])) {
    return "SettlementEvidence jobId must be a canonical ULID";
  }
  if (typeof evidence["phase"] !== "string"
    || (!PAYMENT_PHASES.has(evidence["phase"]) && !DELIVERY_PHASES.has(evidence["phase"]))) {
    return "SettlementEvidence phase is unsupported";
  }
  if (evidence["outcome"] !== "success" && evidence["outcome"] !== "failure") {
    return "SettlementEvidence outcome is invalid";
  }
  if (!nonNegativeSafeInteger(evidence["observedAt"])) return "SettlementEvidence observedAt is invalid";
  if (evidence["outcome"] === "failure") {
    if (typeof evidence["reason"] !== "string" || evidence["reason"].length === 0) {
      return "Failure SettlementEvidence requires a non-empty reason";
    }
    if (Object.hasOwn(evidence, "settlementFinality")) {
      return "Failure SettlementEvidence must omit settlementFinality";
    }
  } else if (Object.hasOwn(evidence, "reason")) {
    return "Successful SettlementEvidence must omit reason";
  }
  const isPayment = PAYMENT_PHASES.has(evidence["phase"] as string);
  if (isPayment && hasAny(evidence, ["deliverableContentHash", "deliverableAnchor", "attestationRef"])) {
    return "Payment SettlementEvidence must omit delivery fields";
  }
  if (!isPayment && Object.hasOwn(evidence, "settlementFinality")) {
    return "Delivery SettlementEvidence must omit settlementFinality";
  }
  if (Object.hasOwn(evidence, "paymentTxRefs")
    && (!Array.isArray(evidence["paymentTxRefs"])
      || evidence["paymentTxRefs"].length === 0
      || evidence["paymentTxRefs"].length > MAX_TX_REFS
      || !evidence["paymentTxRefs"].every((entry) => object(entry) !== null))) {
    return "SettlementEvidence paymentTxRefs are malformed or exceed the implementation limit";
  }
  if (Object.hasOwn(evidence, "paymentAmount")) {
    const amountError = validatePriceTerm(evidence["paymentAmount"], true);
    if (amountError !== null) return `SettlementEvidence paymentAmount ${amountError}`;
  }
  if (Object.hasOwn(evidence, "deliverableContentHash")
    && (typeof evidence["deliverableContentHash"] !== "string"
      || !HASH.test(evidence["deliverableContentHash"]))) {
    return "SettlementEvidence deliverableContentHash is malformed";
  }
  if (Object.hasOwn(evidence, "deliverableAnchor")
    && validateDeliverableAnchor(evidence["deliverableAnchor"]) !== null) {
    return "SettlementEvidence deliverableAnchor is malformed";
  }
  if (Object.hasOwn(evidence, "attestationRef")
    && validateAttestationRef(evidence["attestationRef"]) !== null) {
    return "SettlementEvidence attestationRef is malformed";
  }
  if (evidence["outcome"] === "success" && !Object.hasOwn(evidence, "paymentAmount")) {
    return "Successful SettlementEvidence requires paymentAmount";
  }
  if (evidence["outcome"] === "success" && isPayment) {
    if (!Array.isArray(evidence["paymentTxRefs"])) {
      return "Successful payment evidence requires bounded paymentTxRefs";
    }
    if (!Object.hasOwn(evidence, "paymentAmount")) {
      return "Successful payment evidence requires paymentAmount";
    }
    const finalityError = validateFinality(evidence["settlementFinality"], evidence["phase"] as string);
    if (finalityError !== null) return finalityError;
    const finality = evidence["settlementFinality"] as Record<string, unknown>;
    if ((evidence["observedAt"] as number) < (finality["finalityObservedAt"] as number)) {
      return "Successful payment evidence cannot be observed before settlement finality";
    }
    const phaseError = validatePaymentPhaseSemantics(evidence, true);
    if (phaseError !== null) return phaseError;
  } else if (isPayment && Array.isArray(evidence["paymentTxRefs"])) {
    const phaseError = validatePaymentPhaseSemantics(evidence, false);
    if (phaseError !== null) return phaseError;
  } else if (!isPayment && Array.isArray(evidence["paymentTxRefs"])) {
    const invalidRef = evidence["paymentTxRefs"].find((entry) => validateChainTxRef(entry) !== null);
    if (invalidRef !== undefined) return validateChainTxRef(invalidRef);
  }
  if (asymmetricFailureKind(evidence) !== null && !Array.isArray(evidence["paymentTxRefs"])) {
    return "Asymmetric settlement failure requires transaction proof";
  }
  if (evidence["outcome"] === "success" && !isPayment) {
    if (evidence["phase"] === "deliver-entitlement") {
      if (hasAny(evidence, ["deliverableContentHash", "deliverableAnchor", "attestationRef"])) {
        return "deliver-entitlement evidence resolves its EntitlementRecord and must omit payload fields";
      }
    } else {
      if (!Object.hasOwn(evidence, "deliverableContentHash")
        || !Object.hasOwn(evidence, "deliverableAnchor")) {
        return "Successful payload delivery evidence requires content hash and anchor";
      }
      if ((evidence["deliverableAnchor"] as Record<string, unknown>)["kind"] !== "storage-program") {
        return "Successful storage delivery requires a storage-program anchor";
      }
      if (evidence["phase"] === "deliver-attested-payload"
        && !Object.hasOwn(evidence, "attestationRef")) {
        return "deliver-attested-payload evidence requires a valid attestationRef";
      }
    }
  }
  if (Object.hasOwn(evidence, "paymentFee")) {
    const feeError = validatePriceTerm(evidence["paymentFee"], false);
    if (feeError !== null) return `SettlementEvidence paymentFee ${feeError}`;
  }
  if (Object.hasOwn(evidence, "amendmentRefs")) {
    if (!Array.isArray(evidence["amendmentRefs"])
      || evidence["amendmentRefs"].length > MAX_AMENDMENT_REFS
      || !evidence["amendmentRefs"].every((entry) => validateAttestationRef(entry) === null)) {
      return "SettlementEvidence amendmentRefs are malformed or exceed the implementation limit";
    }
  }
  if (Object.hasOwn(evidence, "supersedesEvidenceRef")
    && validateAttestationRef(evidence["supersedesEvidenceRef"]) !== null) {
    return "SettlementEvidence supersedesEvidenceRef is malformed";
  }
  if (Object.hasOwn(evidence, "supersedesEvidenceRef")
    && (evidence["outcome"] !== "success"
      || (evidence["phase"] !== "pay-cross-chain-htlc"
        && evidence["phase"] !== "pay-cross-chain-liquidity-tank"))) {
    return "supersedesEvidenceRef is valid only on resolved cross-chain success evidence";
  }
  if (requireSignature) {
    const signature = object(evidence["signature"]);
    if (signature === null || !exactKeys(signature, ["algorithm", "signer", "value"])
      || typeof signature["algorithm"] !== "string"
      || typeof signature["signer"] !== "string"
      || typeof signature["value"] !== "string") {
      return "SettlementEvidence signature shape is invalid";
    }
  }
  return null;
}

function validatePriceTerm(value: unknown, positive: boolean): string | null {
  const price = object(value);
  if (price === null) return "must be an object";
  if (typeof price["amount"] !== "string"
    || !(positive ? isCanonicalPositiveDecimal(price["amount"]) : isCanonicalNonNegativeDecimal(price["amount"]))) {
    return positive ? "must have a positive canonical amount" : "must have a non-negative canonical amount";
  }
  if (typeof price["currency"] !== "string" || price["currency"].length === 0) {
    return "must have a currency";
  }
  if (Object.hasOwn(price, "unit") && (typeof price["unit"] !== "string" || price["unit"].length === 0)) {
    return "unit must be non-empty when present";
  }
  return null;
}

function validateFinality(value: unknown, phase: string): string | null {
  const finality = object(value);
  if (finality === null || typeof finality["model"] !== "string"
    || !nonNegativeSafeInteger(finality["finalityObservedAt"])) {
    return "Successful payment evidence requires valid settlementFinality";
  }
  const model = finality["model"];
  if (!["block-depth", "commitment-level", "provider-receipt", "htlc-reveal", "liquidity-tank", "bft-final"].includes(model)) {
    return "SettlementEvidence finality model is unsupported";
  }
  if (model === "block-depth"
    && (!Number.isSafeInteger(finality["finalityBlocks"]) || (finality["finalityBlocks"] as number) < 1)) {
    return "block-depth finality requires positive finalityBlocks";
  }
  if (model === "commitment-level"
    && !["processed", "confirmed", "finalized"].includes(finality["finalityCommitmentLevel"] as string)) {
    return "commitment-level finality requires a supported level";
  }
  if (model !== "block-depth" && Object.hasOwn(finality, "finalityBlocks")) {
    return `${model} finality must omit finalityBlocks`;
  }
  if (model !== "commitment-level" && Object.hasOwn(finality, "finalityCommitmentLevel")) {
    return `${model} finality must omit finalityCommitmentLevel`;
  }
  if (phase === "pay-dem" && (model !== "bft-final"
    || Object.hasOwn(finality, "finalityBlocks")
    || Object.hasOwn(finality, "finalityCommitmentLevel"))) {
    return "pay-dem success requires exact bft-final semantics";
  }
  return null;
}

function validatePinnedFinality(
  actual: Record<string, unknown>,
  expected: SettlementEvidenceVerificationOptions["expectedFinality"],
): { readonly kind: "configuration" | "evidence"; readonly reason: string } | null {
  const configuration = (reason: string) => ({ kind: "configuration" as const, reason });
  const evidenceMismatch = (reason: string) => ({ kind: "evidence" as const, reason });
  const expectedObject = object(expected as unknown);
  if (expectedObject === null) {
    return configuration("Successful payment verification requires pinned rail finality");
  }
  const pin = expectedObject as NonNullable<SettlementEvidenceVerificationOptions["expectedFinality"]>;
  if (!["block-depth", "commitment-level", "provider-receipt", "htlc-reveal", "liquidity-tank", "bft-final"]
    .includes(pin.model)) {
    return configuration("Configured pinned finality model is unsupported");
  }
  if (pin.model === "block-depth"
    && (!positiveSafeInteger(pin.finalityBlocks)
      || pin.finalityCommitmentLevel !== undefined)) {
    return configuration("Configured block-depth finality pin is malformed");
  }
  if (pin.model === "commitment-level"
    && (!["processed", "confirmed", "finalized"].includes(pin.finalityCommitmentLevel ?? "")
      || pin.finalityBlocks !== undefined)) {
    return configuration("Configured commitment-level finality pin is malformed");
  }
  if (pin.model !== "block-depth" && pin.model !== "commitment-level"
    && (pin.finalityBlocks !== undefined || pin.finalityCommitmentLevel !== undefined)) {
    return configuration("Configured finality pin carries fields outside its model");
  }
  if (actual["model"] !== pin.model) {
    return evidenceMismatch("Settlement finality model differs from the pinned rail");
  }
  if (actual["finalityBlocks"] !== pin.finalityBlocks) {
    return evidenceMismatch("Settlement finality block depth differs from the pinned rail");
  }
  if (actual["finalityCommitmentLevel"] !== pin.finalityCommitmentLevel) {
    return evidenceMismatch("Settlement commitment level differs from the pinned rail");
  }
  return null;
}

function validatePinnedRail(
  evidence: Record<string, unknown>,
  options: SettlementEvidenceVerificationOptions,
): { readonly kind: "configuration" | "evidence"; readonly reason: string } | null {
  const configuration = (reason: string) => ({ kind: "configuration" as const, reason });
  const evidenceMismatch = (reason: string) => ({ kind: "evidence" as const, reason });
  const railObject = object(options.pinnedRail as unknown);
  if (railObject === null) return configuration("Payment verification requires a verified pinned rail");
  const rail = railObject as NonNullable<SettlementEvidenceVerificationOptions["pinnedRail"]>;
  if (rail.railId !== options.railId || rail.phaseHandler !== evidence["phase"]) {
    return configuration("Configured phase or railId differs from the pinned rail");
  }
  const assetResult = validatePinnedAsset(rail.assetCanonicalJson, evidence["phase"] as string);
  if (typeof assetResult === "string") return configuration(assetResult);
  if (assetCurrency(assetResult) !== rail.assetCurrency) {
    return configuration("Pinned rail assetCurrency differs from its canonical asset");
  }
  const expectedNetwork = {
    "pay-evm-erc20": "evm",
    "pay-solana-spl": "solana",
    "pay-cross-chain-htlc": "cross-chain",
    "pay-cross-chain-liquidity-tank": "cross-chain",
    "pay-ap2": "ap2-provider",
    "pay-x402": "x402-resource",
    "pay-dem": "demos",
  }[evidence["phase"] as string];
  if (rail.networkKind !== expectedNetwork) {
    return configuration("Settlement phase is incompatible with the pinned rail network kind");
  }
  const amount = object(evidence["paymentAmount"]);
  if (evidence["outcome"] === "success" && amount?.["currency"] !== rail.assetCurrency) {
    return evidenceMismatch("Settlement currency differs from the pinned rail asset");
  }
  const refs = Array.isArray(evidence["paymentTxRefs"])
    ? evidence["paymentTxRefs"] as Record<string, unknown>[] : [];
  if (rail.networkKind === "demos" && evidence["phase"] !== "pay-dem") {
    return configuration("Pinned Demos rail phase mismatch");
  }
  if (rail.networkKind === "evm" && !positiveSafeInteger(rail.chainId)) {
    return configuration("Pinned EVM rail requires a positive chainId");
  }
  if (rail.networkKind === "solana"
    && !["mainnet", "devnet", "testnet"].includes(rail.cluster ?? "")) {
    return configuration("Pinned Solana rail requires a supported cluster");
  }
  if (rail.networkKind === "x402-resource" && rail.chainId !== undefined
    && !positiveSafeInteger(rail.chainId)) {
    return configuration("Pinned x402 rail chainId is malformed");
  }
  if (rail.networkKind === "evm" && refs.some((ref) => ref["chainId"] !== rail.chainId)) {
    return evidenceMismatch("Settlement chainId differs from the pinned EVM rail");
  }
  if (rail.networkKind === "solana" && refs.some((ref) => ref["cluster"] !== rail.cluster)) {
    return evidenceMismatch("Settlement cluster differs from the pinned Solana rail");
  }
  if (rail.networkKind === "x402-resource" && rail.chainId !== undefined
    && refs.some((ref) => ref["chainId"] !== rail.chainId)) {
    return evidenceMismatch("x402 settlement chainId differs from the pinned rail");
  }
  return null;
}

function validateConfiguredParties(
  evidence: Record<string, unknown>,
  options: SettlementEvidenceVerificationOptions,
  isPayment: boolean,
): string | null {
  if (!isPayment && evidence["outcome"] !== "failure") return null;
  for (const [role, reference] of [["payer", options.expectedPayer], ["payee", options.expectedPayee]] as const) {
    if (typeof reference !== "string" || reference.length === 0) {
      return `Settlement verification requires an agreement-bound ${role} ClaimReference`;
    }
    try {
      if (canonicalizeGenericClaimReference(reference).canonicalReference !== reference) {
        return `Configured ${role} ClaimReference is non-canonical`;
      }
    } catch (error) {
      return `Configured ${role} ClaimReference is invalid: ${message(error)}`;
    }
  }
  const requiresAddress = isPayment
    && (evidence["outcome"] === "success" || asymmetricFailureKind(evidence) !== null);
  if (!requiresAddress && options.expectedPayeeAddress === undefined) return null;
  const address = options.expectedPayeeAddress;
  if (typeof address !== "string" || address.length === 0 || address.length > 512 || /\s/.test(address)) {
    return "Configured payee address is missing or malformed";
  }
  const rail = object(options.pinnedRail as unknown);
  if (rail?.["networkKind"] === "demos" && !/^0x[0-9a-f]{64}$/.test(address)) {
    return "Configured Demos payee address is non-canonical";
  }
  if (rail?.["networkKind"] === "evm" && !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    return "Configured EVM payee address is malformed";
  }
  if (rail?.["networkKind"] === "solana" && base58DecodedLength(address) !== 32) {
    return "Configured Solana payee address must decode to 32 bytes";
  }
  return null;
}

function validatePinnedAsset(canonicalJson: string, phase: string): Record<string, unknown> | string {
  if (typeof canonicalJson !== "string" || canonicalJson.length > 16_384) {
    return "Pinned rail canonical asset is missing or exceeds the input limit";
  }
  let asset: Record<string, unknown>;
  try {
    const parsed = JSON.parse(canonicalJson) as unknown;
    if (consumerCanonicalize(parsed) !== canonicalJson || object(parsed) === null) {
      return "Pinned rail asset is not a canonical JSON object";
    }
    asset = parsed as Record<string, unknown>;
  } catch {
    return "Pinned rail asset is not valid canonical JSON";
  }
  const shapeError = validateAssetShape(asset);
  if (shapeError !== null) return shapeError;
  const requiredKind = {
    "pay-evm-erc20": "erc20",
    "pay-solana-spl": "spl",
    "pay-cross-chain-htlc": "stablecoin-cross-chain",
    "pay-cross-chain-liquidity-tank": "stablecoin-cross-chain",
    "pay-ap2": "fiat-via-ap2",
    "pay-dem": "native-dem",
  }[phase];
  if (requiredKind !== undefined && asset["kind"] !== requiredKind) {
    return `Settlement phase ${phase} is incompatible with pinned asset kind`;
  }
  return asset;
}

function validateAssetShape(asset: Record<string, unknown>): string | null {
  const kind = asset["kind"];
  if (kind === "erc20") {
    return exactKeys(asset, ["kind", "chainId", "contract", "symbol", "decimals"])
      && positiveSafeInteger(asset["chainId"]) && nonEmpty(asset["contract"])
      && nonEmpty(asset["symbol"]) && nonNegativeSafeInteger(asset["decimals"])
      ? null : "Pinned ERC-20 asset is malformed";
  }
  if (kind === "spl") {
    return exactKeys(asset, ["kind", "cluster", "mint", "symbol", "decimals"])
      && ["mainnet", "devnet", "testnet"].includes(asset["cluster"] as string)
      && nonEmpty(asset["mint"]) && nonEmpty(asset["symbol"])
      && nonNegativeSafeInteger(asset["decimals"])
      ? null : "Pinned SPL asset is malformed";
  }
  if (kind === "native-evm") {
    return exactKeys(asset, ["kind", "chainId", "symbol", "decimals"])
      && positiveSafeInteger(asset["chainId"]) && nonEmpty(asset["symbol"])
      && nonNegativeSafeInteger(asset["decimals"])
      ? null : "Pinned native EVM asset is malformed";
  }
  if (kind === "native-solana") {
    return exactKeys(asset, ["kind", "cluster", "symbol", "decimals"])
      && ["mainnet", "devnet", "testnet"].includes(asset["cluster"] as string)
      && asset["symbol"] === "SOL" && asset["decimals"] === 9
      ? null : "Pinned native Solana asset is malformed";
  }
  if (kind === "native-dem") {
    return exactKeys(asset, ["kind", "symbol", "decimals"])
      && asset["symbol"] === "DEM" && asset["decimals"] === 9
      ? null : "Pinned native DEM asset is malformed";
  }
  if (kind === "fiat-via-ap2") {
    return exactKeys(asset, ["kind", "isoCurrency", "provider"])
      && nonEmpty(asset["isoCurrency"]) && nonEmpty(asset["provider"])
      ? null : "Pinned AP2 fiat asset is malformed";
  }
  if (kind === "stablecoin-cross-chain") {
    return exactKeys(asset, ["kind", "canonicalSymbol", "routes"])
      && nonEmpty(asset["canonicalSymbol"]) && Array.isArray(asset["routes"])
      && asset["routes"].length > 0 && asset["routes"].every(validCrossChainRoute)
      ? null : "Pinned cross-chain stablecoin asset is malformed";
  }
  return "Pinned rail asset kind is unsupported";
}

function validCrossChainRoute(value: unknown): boolean {
  const route = object(value);
  if (route === null || !exactKeys(route, [
    "sourceChainId",
    "destChainId",
    ...(Object.hasOwn(route, "htlcContracts") ? ["htlcContracts"] : []),
    ...(Object.hasOwn(route, "liquidityTankIds") ? ["liquidityTankIds"] : []),
  ])) return false;
  const validChainId = (candidate: unknown) => positiveSafeInteger(candidate) || nonEmpty(candidate);
  if (!validChainId(route["sourceChainId"]) || !validChainId(route["destChainId"])) return false;
  if (Object.hasOwn(route, "htlcContracts")) {
    const contracts = object(route["htlcContracts"]);
    if (contracts === null || !exactKeys(contracts, ["source", "dest"])
      || !nonEmpty(contracts["source"]) || !nonEmpty(contracts["dest"])) return false;
  }
  return !Object.hasOwn(route, "liquidityTankIds")
    || (Array.isArray(route["liquidityTankIds"]) && route["liquidityTankIds"].length > 0
      && route["liquidityTankIds"].every(nonEmpty));
}

function assetCurrency(asset: Record<string, unknown>): unknown {
  if (asset["kind"] === "fiat-via-ap2") return asset["isoCurrency"];
  if (asset["kind"] === "stablecoin-cross-chain") return asset["canonicalSymbol"];
  return asset["symbol"];
}

function validatePaymentPhaseSemantics(
  evidence: Record<string, unknown>,
  success: boolean,
): string | null {
  const phase = evidence["phase"] as string;
  const refs = evidence["paymentTxRefs"] as Record<string, unknown>[];
  const model = object(evidence["settlementFinality"] ?? null)?.["model"];
  const requireSuccess = (count: number, expectedModel: string): string | null => {
    if (!success) return null;
    if (refs.length !== count) return `${phase} success requires exactly ${count} transaction reference${count === 1 ? "" : "s"}`;
    return model === expectedModel ? null : `${phase} success requires ${expectedModel} finality`;
  };
  if (phase === "pay-evm-erc20") {
    const required = requireSuccess(1, "block-depth");
    if (required !== null) return required;
    return refs.every((ref) => validateEvmTxRef(ref) === null)
      ? null : "pay-evm-erc20 transaction reference is malformed";
  }
  if (phase === "pay-solana-spl") {
    const required = requireSuccess(1, "commitment-level");
    if (required !== null) return required;
    return refs.every((ref) => validateSolanaTxRef(ref) === null)
      ? null : "pay-solana-spl transaction reference is malformed";
  }
  if (phase === "pay-dem") {
    const required = requireSuccess(1, "bft-final");
    if (required !== null) return required;
    return refs.every((ref) => validateDemosTxRef(ref, success) === null)
      ? null : "pay-dem transaction reference is malformed";
  }
  if (phase === "pay-ap2") {
    const required = requireSuccess(1, "provider-receipt");
    if (required !== null) return required;
    for (const ref of refs) {
      const ap2Error = validateAp2TxRef(ref, success);
      if (ap2Error !== null) return ap2Error;
    }
    return null;
  }
  if (phase === "pay-x402") {
    const required = success && refs.length !== 1
      ? "pay-x402 success requires exactly one transaction reference" : null;
    if (required !== null) return required;
    for (const ref of refs) {
      const x402Error = validateX402TxRef(ref);
      if (x402Error !== null) return x402Error;
      const isChainVerifiable = Object.hasOwn(ref, "settlementTxHash");
      if (success && model !== (isChainVerifiable ? "block-depth" : "provider-receipt")) {
        return isChainVerifiable
          ? "Chain-verifiable pay-x402 success requires block-depth finality"
          : "Receipt-only pay-x402 success requires provider-receipt finality";
      }
    }
    return null;
  }
  if (phase === "pay-cross-chain-htlc") {
    if (success) {
      const required = requireSuccess(3, "htlc-reveal");
      if (required !== null) return required;
      const counts = new Map<string, number>();
      for (const ref of refs) {
        const htlcError = validateHtlcTxRef(ref);
        if (htlcError !== null) return htlcError;
        const kind = ref["kind"] as string;
        counts.set(kind, (counts.get(kind) ?? 0) + 1);
      }
      if (counts.get("htlc-lock") !== 1 || counts.get("htlc-reveal") !== 1
        || counts.get("htlc-claim") !== 1 || counts.size !== 3) {
        return "pay-cross-chain-htlc success requires one lock, reveal, and claim reference";
      }
      return null;
    }
    if (!refs.every((ref) => validateHtlcTxRef(ref) === null)) {
      return "pay-cross-chain-htlc transaction reference is malformed";
    }
    if (evidence["reason"] === "dest-revealed-source-unclaimed"
      && !refs.some((ref) => ref["kind"] === "htlc-reveal")) {
      return "Asymmetric HTLC failure requires a reveal transaction";
    }
    if (evidence["reason"] === "dest-revealed-source-unclaimed"
      && refs.some((ref) => ref["kind"] === "htlc-claim" || ref["kind"] === "htlc-refund")) {
      return "Asymmetric HTLC failure cannot include a claim or refund transaction";
    }
    return null;
  }
  if (phase === "pay-cross-chain-liquidity-tank") {
    const required = requireSuccess(1, "liquidity-tank");
    if (required !== null) return required;
    for (const ref of refs) {
      const tankError = validateLiquidityTankTxRef(ref, success);
      if (tankError !== null) return tankError;
    }
    if (!success && evidence["reason"] === "tank-locked-unreleased"
      && (refs.length !== 1 || !nonNegativeSafeInteger(refs[0]?.["recoveryDeadline"]))) {
      return "Asymmetric liquidity-tank failure requires one lock and recoveryDeadline";
    }
    if (!success && evidence["reason"] === "tank-locked-unreleased"
      && Object.hasOwn(refs[0] ?? {}, "releaseTxHash")) {
      return "Asymmetric liquidity-tank failure cannot include a release transaction";
    }
    if (!success && evidence["reason"] === "tank-locked-unreleased"
      && (evidence["observedAt"] as number) >= (refs[0]?.["recoveryDeadline"] as number)) {
      return "Asymmetric liquidity-tank failure must be observed before its recovery deadline";
    }
    return null;
  }
  return `SettlementEvidence payment phase ${phase} is unsupported`;
}

function validateChainTxRef(value: unknown): string | null {
  const ref = object(value);
  if (ref === null || typeof ref["kind"] !== "string") return "Settlement transaction reference is malformed";
  if (ref["kind"] === "evm") return validateEvmTxRef(ref);
  if (ref["kind"] === "solana") return validateSolanaTxRef(ref);
  if (ref["kind"] === "demos") return validateDemosTxRef(ref, false);
  if (ref["kind"] === "ap2") return validateAp2TxRef(ref, false);
  if (ref["kind"] === "x402") return validateX402TxRef(ref);
  if (ref["kind"] === "storage-program") {
    return nonEmpty(ref["address"]) && nonEmpty(ref["writeTxHash"])
      ? null : "invalid storage-program transaction reference";
  }
  if (["htlc-lock", "htlc-reveal", "htlc-claim", "htlc-refund"].includes(ref["kind"])) {
    return validateHtlcTxRef(ref);
  }
  if (ref["kind"] === "liquidity-tank") return validateLiquidityTankTxRef(ref, false);
  return "Settlement transaction reference kind is unsupported";
}

function validateEvmTxRef(ref: Record<string, unknown>): string | null {
  return ref["kind"] === "evm" && positiveSafeInteger(ref["chainId"])
    && typeof ref["txHash"] === "string" && EVM_TX_HASH.test(ref["txHash"])
    && nonNegativeSafeInteger(ref["logIndex"])
    ? null : "invalid EVM transaction reference";
}

function validateSolanaTxRef(ref: Record<string, unknown>): string | null {
  return ref["kind"] === "solana"
    && ["mainnet", "devnet", "testnet"].includes(ref["cluster"] as string)
    && typeof ref["signature"] === "string"
    && ref["signature"].length >= 64 && ref["signature"].length <= 88
    && base58DecodedLength(ref["signature"]) === 64
    && nonNegativeSafeInteger(ref["instructionIndex"])
    ? null : "invalid Solana transaction reference";
}

function validateDemosTxRef(txRef: Record<string, unknown>, success: boolean): string | null {
  if (txRef["kind"] !== "demos" || typeof txRef["txHash"] !== "string"
    || !DEMOS_TX_HASH.test(txRef["txHash"])) {
    return "pay-dem transaction reference is malformed";
  }
  if (success && !nonNegativeSafeInteger(txRef["blockNumber"])) {
    return "pay-dem success requires a non-negative blockNumber";
  }
  if (!success && Object.hasOwn(txRef, "blockNumber")
    && !nonNegativeSafeInteger(txRef["blockNumber"])) {
    return "pay-dem failure blockNumber is malformed";
  }
  return null;
}

function validateAp2TxRef(ref: Record<string, unknown>, success: boolean): string | null {
  if (ref["kind"] !== "ap2" || !nonEmpty(ref["mandateId"]) || !nonEmpty(ref["providerRef"])
    || !nonEmpty(ref["protocolVersion"]) || !UNSIGNED_DECIMAL.test(ref["protocolVersion"])) {
    return "invalid AP2 transaction reference";
  }
  if (Object.hasOwn(ref, "receiptAttestation")
    && validateAttestationRef(ref["receiptAttestation"]) !== null) {
    return "pay-ap2 receiptAttestation is malformed";
  }
  if (success && !Object.hasOwn(ref, "receiptAttestation")) {
    return "Successful pay-ap2 evidence requires an attested provider receipt";
  }
  return null;
}

function validateX402TxRef(ref: Record<string, unknown>): string | null {
  if (ref["kind"] !== "x402" || !nonEmpty(ref["httpResource"])
    || typeof ref["paymentReceiptHash"] !== "string" || !HASH.test(ref["paymentReceiptHash"])
    || typeof ref["protocolVersion"] !== "string"
    || (ref["protocolVersion"] !== "1" && ref["protocolVersion"] !== "2")) {
    return "pay-x402 transaction reference is malformed or uses an unsupported protocol version";
  }
  const hasHash = Object.hasOwn(ref, "settlementTxHash");
  const hasChain = Object.hasOwn(ref, "chainId");
  if (hasHash !== hasChain) return "pay-x402 settlementTxHash and chainId must appear together";
  if (hasHash && (typeof ref["settlementTxHash"] !== "string"
    || !EVM_TX_HASH.test(ref["settlementTxHash"]) || !positiveSafeInteger(ref["chainId"])
    || !nonNegativeSafeInteger(ref["logIndex"]))) {
    return "pay-x402 settlement transaction is malformed";
  }
  return null;
}

function validateHtlcTxRef(ref: Record<string, unknown>): string | null {
  // The current DACS-4 union pins this EVM-shaped form even though the registry names an
  // EVM-to-Solana rail. Native-leg alternatives stay fail-closed until upstream defines them.
  if (!positiveSafeInteger(ref["chainId"]) || !nonEmpty(ref["contractAddress"])) {
    return "pay-cross-chain-htlc transaction reference is malformed";
  }
  const hashField = {
    "htlc-lock": "lockTxHash",
    "htlc-reveal": "revealTxHash",
    "htlc-claim": "claimTxHash",
    "htlc-refund": "refundTxHash",
  }[ref["kind"] as string];
  return hashField !== undefined && typeof ref[hashField] === "string" && EVM_TX_HASH.test(ref[hashField])
    ? null : "pay-cross-chain-htlc transaction reference is malformed";
}

function validateLiquidityTankTxRef(ref: Record<string, unknown>, success: boolean): string | null {
  if (ref["kind"] !== "liquidity-tank" || !nonEmpty(ref["bridgeId"])
    || !positiveSafeInteger(ref["sourceChainId"]) || !positiveSafeInteger(ref["destChainId"])
    || typeof ref["lockTxHash"] !== "string" || !EVM_TX_HASH.test(ref["lockTxHash"])) {
    return "pay-cross-chain-liquidity-tank transaction reference is malformed";
  }
  if (success) {
    return typeof ref["releaseTxHash"] === "string" && EVM_TX_HASH.test(ref["releaseTxHash"])
      ? null : "Successful liquidity-tank evidence requires a release transaction";
  }
  if (Object.hasOwn(ref, "releaseTxHash")
    && (typeof ref["releaseTxHash"] !== "string" || !EVM_TX_HASH.test(ref["releaseTxHash"]))) {
    return "Liquidity-tank release transaction is malformed";
  }
  if (Object.hasOwn(ref, "recoveryDeadline") && !nonNegativeSafeInteger(ref["recoveryDeadline"])) {
    return "Liquidity-tank recovery deadline is malformed";
  }
  return null;
}

function settlementTransactionId(ref: Record<string, unknown>): string | null {
  const kind = ref["kind"];
  if (kind === "evm") {
    return `evm:${ref["chainId"]}:${normalizeHex(ref["txHash"] as string)}:${ref["logIndex"]}`;
  }
  if (kind === "x402" && typeof ref["settlementTxHash"] === "string") {
    return `evm:${ref["chainId"]}:${normalizeHex(ref["settlementTxHash"])}:${ref["logIndex"]}`;
  }
  if (kind === "x402" || kind === "ap2") return null;
  if (kind === "solana") {
    return `solana:${ref["cluster"]}:${ref["signature"]}:${ref["instructionIndex"]}`;
  }
  if (kind === "demos") return `demos:${normalizeHex(ref["txHash"] as string)}`;
  if (kind === "htlc-lock" || kind === "htlc-reveal" || kind === "htlc-claim"
    || kind === "htlc-refund" || kind === "liquidity-tank") return null;
  return `${String(kind)}:${sha256(consumerCanonicalize(ref))}`;
}

function unsupportedSettlementTransactionIdReason(ref: Record<string, unknown>): string {
  const kind = ref["kind"];
  if (kind === "ap2") return "DACS-4 SB-1 does not define a canonical settlement-tx-id for pay-ap2";
  if (kind === "x402") {
    return "DACS-4 SB-1 does not define a canonical settlement-tx-id for x402 without a chain transaction";
  }
  return "DACS-4 SB-1 does not define canonical settlement-tx-ids for cross-chain references";
}

function normalizeHex(value: string): string {
  return (value.startsWith("0x") ? value.slice(2) : value).toLowerCase();
}

function asymmetricFailureKind(
  evidence: Record<string, unknown>,
): "htlc" | "liquidity-tank" | null {
  if (evidence["outcome"] !== "failure") return null;
  if (evidence["phase"] === "pay-cross-chain-htlc"
    && evidence["reason"] === "dest-revealed-source-unclaimed") return "htlc";
  if (evidence["phase"] === "pay-cross-chain-liquidity-tank"
    && evidence["reason"] === "tank-locked-unreleased") return "liquidity-tank";
  return null;
}

function validateAttestationRef(value: unknown): string | null {
  const ref = object(value);
  const anchor = object(ref?.["anchor"]);
  if (ref === null || anchor === null || !ANCHOR_KINDS.has(anchor["kind"] as string)
    || !nonEmpty(anchor["locator"])
    || typeof ref["contentHash"] !== "string" || !HASH.test(ref["contentHash"])) {
    return "invalid attestation reference";
  }
  if (Object.hasOwn(ref, "signer")) {
    if (typeof ref["signer"] !== "string") return "invalid attestation reference signer";
    try {
      if (canonicalizeGenericClaimReference(ref["signer"]).canonicalReference !== ref["signer"]) {
        return "non-canonical attestation reference signer";
      }
    } catch {
      return "invalid attestation reference signer";
    }
  }
  return null;
}

function validateDeliverableAnchor(value: unknown): string | null {
  const anchor = object(value);
  return anchor !== null
    && typeof anchor["kind"] === "string" && anchor["kind"].length > 0
    && typeof anchor["locator"] === "string" && anchor["locator"].length > 0
    ? null : "invalid deliverable anchor";
}

function logicalAddress(
  evidence: Record<string, unknown>,
  options: SettlementEvidenceVerificationOptions,
): string | ((hash: string) => SettlementEvidenceVerificationResult) {
  if (PAYMENT_PHASES.has(evidence["phase"] as string)) {
    if (typeof options.railId !== "string" || !RAIL_ID.test(options.railId) || options.railId.length > 64) {
      return (hash) => unsupported("phase-binding", "Payment verification requires a valid pinned railId", hash);
    }
    const encodedRail = options.railId.replaceAll(":", "%3A");
    const resolved = Object.hasOwn(evidence, "supersedesEvidenceRef") ? ":resolved" : "";
    return `dacs4:payment:${options.expectedJobId}:${encodedRail}:${options.phaseIndex}${resolved}`;
  }
  if (evidence["phase"] === "deliver-entitlement"
    && !nonNegativeSafeInteger(options.entitlementRenewalSeq)) {
    return (hash) => unsupported(
      "phase-binding",
      "Entitlement verification requires a non-negative renewalSeq",
      hash,
    );
  }
  const artifactAddress = deliveryArtifactAddress(evidence, options.entitlementRenewalSeq);
  const evidenceAddress = options.expectedEvidenceLogicalAddress;
  if (typeof evidenceAddress !== "string" || evidenceAddress.length === 0
    || evidenceAddress.length > 512 || /\s/.test(evidenceAddress)) {
    return (hash) => unsupported(
      "anchor-binding",
      "Delivery verification requires an explicit evidence anchor address",
      hash,
    );
  }
  if (evidenceAddress === artifactAddress) {
    return (hash) => unsupported(
      "anchor-binding",
      "Delivery evidence anchor must be distinct from the delivered artifact address",
      hash,
    );
  }
  return evidenceAddress;
}

function deliveryArtifactAddress(
  evidence: Record<string, unknown>,
  renewalSeq: number | undefined,
): string {
  if (evidence["phase"] !== "deliver-entitlement") {
    return `dacs4:deliverable:${evidence["jobId"]}`;
  }
  if (!nonNegativeSafeInteger(renewalSeq)) {
    throw new TypeError("Entitlement verification requires a non-negative renewalSeq");
  }
  return `dacs4:entitlement:${evidence["jobId"]}:${renewalSeq}`;
}

function parseCanonicalObject(canonicalJson: string): Record<string, unknown> {
  const parsed = JSON.parse(canonicalJson) as unknown;
  if (consumerCanonicalize(parsed) !== canonicalJson) {
    throw new TypeError("SettlementEvidence JSON is not canonical");
  }
  const record = object(parsed);
  if (record === null) throw new TypeError("SettlementEvidence must be an object");
  return record;
}

function deepFreezeJson<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  if (Array.isArray(value)) {
    for (const member of value) deepFreezeJson(member);
  } else {
    for (const member of Object.values(value as Record<string, unknown>)) deepFreezeJson(member);
  }
  return Object.freeze(value);
}

function omitField(value: Record<string, unknown>, field: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => key !== field));
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function callbackStatus(value: unknown): "verified" | "rejected" | "indeterminate" | null {
  const result = object(value);
  if (result === null
    || !["verified", "rejected", "indeterminate"].includes(result["status"] as string)) return null;
  if ((result["status"] === "rejected" || result["status"] === "indeterminate")
    && !nonEmpty(result["reason"])) return null;
  return result["status"] as "verified" | "rejected" | "indeterminate";
}

function canonicalJsonEquals(left: unknown, right: unknown): boolean | null {
  try {
    return consumerCanonicalize(left) === consumerCanonicalize(right);
  } catch {
    return null;
  }
}

function anchorReadStatus(value: unknown): "resolved" | "absent" | "indeterminate" | null {
  const result = object(value);
  if (result === null || !["resolved", "absent", "indeterminate"].includes(result["status"] as string)) return null;
  if (result["status"] === "indeterminate") {
    return nonEmpty(result["reason"]) ? "indeterminate" : null;
  }
  if (result["status"] === "resolved"
    && (!nonEmpty(result["artifactContentHash"])
      || !nonEmpty(result["artifactKind"])
      || !nonEmpty(result["evidenceHash"])
      || !EVIDENCE_MODES.includes(result["evidenceMode"] as EvidenceMode))) return null;
  return result["status"] as "resolved" | "absent";
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function hasAny(value: Record<string, unknown>, fields: readonly string[]): boolean {
  return fields.some((field) => Object.hasOwn(value, field));
}

function nonNegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function positiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function base58DecodedLength(value: string): number {
  if (!BASE58.test(value)) return -1;
  let decoded = 0n;
  for (const character of value) {
    decoded = decoded * 58n + BigInt(
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".indexOf(character),
    );
  }
  let byteLength = 0;
  for (let remaining = decoded; remaining > 0n; remaining >>= 8n) byteLength += 1;
  let leadingZeroes = 0;
  while (value[leadingZeroes] === "1") leadingZeroes += 1;
  return leadingZeroes + byteLength;
}

function sha256(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}

function rejected(
  stage: SettlementEvidenceVerificationStage,
  reason: string,
  evidenceHash?: string,
): SettlementEvidenceVerificationResult {
  return Object.freeze({ disposition: "rejected", stage, reason, ...(evidenceHash === undefined ? {} : { evidenceHash }) });
}

function unsupported(
  stage: SettlementEvidenceVerificationStage,
  reason: string,
  evidenceHash?: string,
): SettlementEvidenceVerificationResult {
  return Object.freeze({ disposition: "refused-unsupported", stage, reason, ...(evidenceHash === undefined ? {} : { evidenceHash }) });
}

function indeterminate(
  stage: SettlementEvidenceVerificationStage,
  reason: string,
  evidenceHash?: string,
): SettlementEvidenceVerificationResult {
  return Object.freeze({ disposition: "indeterminate", stage, reason, ...(evidenceHash === undefined ? {} : { evidenceHash }) });
}
