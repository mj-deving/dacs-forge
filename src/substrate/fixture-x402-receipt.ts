import { canonicalize } from "../protocol/canonical-json.ts";
import { sha256Hex } from "../protocol/hash.ts";
import type {
  SettlementTransactionCheckResult,
  SettlementTransactionExpectation,
} from "../consumer/settlement-evidence-verifier.ts";

export interface FixtureX402ReceiptBinding {
  readonly agreementHash: string;
  readonly finalityObservedAt: number;
  readonly httpResource: string;
  readonly jobId: string;
  readonly payee: string;
  readonly payeeAddress: string;
  readonly payer: string;
  readonly paymentAmountCanonicalJson: string;
  readonly phaseIndex: number;
  readonly protocolVersion: string;
  readonly sessionBindingHash: string;
}

export function fixtureX402ReceiptHash(binding: FixtureX402ReceiptBinding): string {
  return sha256Hex(canonicalize({ fixtureX402ReceiptVersion: "1", ...binding }));
}

export function verifyFixtureX402Receipt(
  txRef: Readonly<Record<string, unknown>>,
  expected: SettlementTransactionExpectation,
): SettlementTransactionCheckResult {
  const httpResource = txRef["httpResource"];
  const protocolVersion = txRef["protocolVersion"];
  const paymentReceiptHash = txRef["paymentReceiptHash"];
  if (txRef["kind"] !== "x402" || typeof httpResource !== "string"
    || typeof protocolVersion !== "string" || typeof paymentReceiptHash !== "string") {
    return Object.freeze({ status: "rejected", reason: "Fixture x402 receipt shape is invalid" });
  }
  const hash = fixtureX402ReceiptHash({
    agreementHash: expected.agreementHash,
    finalityObservedAt: expected.finalityObservedAt,
    httpResource,
    jobId: expected.jobId,
    payee: expected.payee,
    payeeAddress: expected.payeeAddress,
    payer: expected.payer,
    paymentAmountCanonicalJson: expected.paymentAmountCanonicalJson,
    phaseIndex: expected.phaseIndex,
    protocolVersion,
    sessionBindingHash: expected.sessionBindingHash,
  });
  return hash === paymentReceiptHash
    ? Object.freeze({ status: "verified" as const, ...expected })
    : Object.freeze({ status: "rejected" as const, reason: "Fixture x402 receipt hash is not authoritative" });
}
