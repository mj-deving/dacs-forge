import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { decodeComponentSignatureValue } from "../protocol/component-signature-codec.ts";
import { VERIFY_RESULT_DOMAIN } from "../protocol/vet.ts";
import { canonicalizeGenericClaimReference } from "../protocol/claim-reference.ts";
import { consumerCanonicalize } from "./canonical-json.ts";

const ASSERTION_DOMAIN = "dacs-delivery-assertion:v1:";
const HASH = /^[0-9a-f]{64}$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const KEY_CLAIM = /^key:([0-9a-f]{64})$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_ARTIFACT_BYTES = 1_048_576;

export interface DeliveryAttestationExpectation {
  readonly agreementHash: string;
  readonly deliverableContentHash: string;
  readonly jobId: string;
  readonly payloadFormat: string;
  readonly phaseIndex: number;
  readonly sessionBindingHash: string;
  readonly signer: string;
}

export type DeliveryAttestationAnchorRead =
  | { readonly status: "resolved"; readonly artifactContentHash: string; readonly artifactKind: string }
  | { readonly status: "absent" }
  | { readonly status: "rejected"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string };

export type DeliveryAttestationAnchorContext =
  | { readonly mode: "pre-anchor" }
  | { readonly mode: "post-anchor"; readonly read: (address: string) => DeliveryAttestationAnchorRead };

export interface DeliveryAttestationVerificationOptions extends DeliveryAttestationExpectation {
  readonly anchorContext: DeliveryAttestationAnchorContext;
  readonly maxArtifactBytes?: number;
}

export type DeliveryAttestationVerificationResult =
  | {
    readonly disposition: "provisionally-verified" | "verified";
    readonly assertionAddress: string;
    readonly assertionArtifactHash: string;
    readonly verifyResultAddress: string;
    readonly verifyResultArtifactHash: string;
  }
  | {
    readonly disposition: "rejected" | "refused-unsupported" | "indeterminate";
    readonly stage: "canonical-form" | "shape" | "binding" | "signature" | "anchor-binding";
    readonly reason: string;
  };

type DeliveryAttestationVerificationStage =
  "canonical-form" | "shape" | "binding" | "signature" | "anchor-binding";
type DeliveryAttestationFailure = Extract<DeliveryAttestationVerificationResult, { readonly reason: string }>;
type ResolvedDeliveryAttestationAnchor = Extract<DeliveryAttestationAnchorRead, { readonly status: "resolved" }>;

export function deliveryAssertionLogicalAddress(jobId: string, phaseIndex: number): string {
  validateAddressBinding(jobId, phaseIndex);
  return `dacs2:delivery-assertion:${jobId}:${phaseIndex}`;
}

export function deliveryVerifyResultLogicalAddress(jobId: string, phaseIndex: number): string {
  validateAddressBinding(jobId, phaseIndex);
  return `dacs2:delivery-verify-result:${jobId}:${phaseIndex}`;
}

export function verifyDeliveryAttestation(
  assertionCanonicalJson: string,
  verifyResultCanonicalJson: string,
  options: DeliveryAttestationVerificationOptions,
): DeliveryAttestationVerificationResult {
  const configurationError = validateExpectation(options);
  if (configurationError !== null) return refused("binding", configurationError);
  const maxBytes = options.maxArtifactBytes ?? MAX_ARTIFACT_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    return refused("canonical-form", "Delivery attestation byte limit is invalid");
  }
  const assertion = parseCanonicalObject(assertionCanonicalJson, maxBytes);
  if ("error" in assertion) return rejected("canonical-form", assertion.error);
  const verifyResult = parseCanonicalObject(verifyResultCanonicalJson, maxBytes);
  if ("error" in verifyResult) return rejected("canonical-form", verifyResult.error);

  const assertionError = validateAssertion(assertion.value);
  if (assertionError !== null) return rejected("shape", assertionError);
  const verifyResultError = validateVerifyResult(verifyResult.value);
  if (verifyResultError !== null) return rejected("shape", verifyResultError);

  const expected = expectationObject(options);
  for (const [field, value] of Object.entries(expected)) {
    if (assertion.value[field] !== value) {
      return rejected("binding", `Delivery assertion ${field} does not match the pinned session`);
    }
  }
  const assertionSignature = assertion.value["signature"] as Record<string, unknown>;
  const assertionHash = hashUnsigned(assertion.value);
  const assertionSigner = verifySignature(assertionSignature, ASSERTION_DOMAIN, assertionHash, options.signer);
  if (assertionSigner !== null) return assertionSigner;

  const assertionAddress = deliveryAssertionLogicalAddress(options.jobId, options.phaseIndex);
  const verifyResultAddress = deliveryVerifyResultLogicalAddress(options.jobId, options.phaseIndex);
  const attestation = verifyResult.value["attestation"] as Record<string, unknown>;
  const attestationAnchor = attestation["anchor"] as Record<string, unknown>;
  if (verifyResult.value["scheme"] !== "key"
    || verifyResult.value["identifier"] !== options.signer.slice("key:".length)
    || verifyResult.value["recipeVersion"] !== 1
    || verifyResult.value["method"] !== "self-signed"
    || verifyResult.value["decision"] !== "pass"
    || attestationAnchor["kind"] !== "storage-program"
    || attestationAnchor["locator"] !== assertionAddress
    || attestation["contentHash"] !== assertion.artifactHash
    || attestation["signer"] !== options.signer) {
    return rejected("binding", "DACS-2 VerifyResult does not bind the exact delivery assertion");
  }
  const data = verifyResult.value["data"] as Record<string, unknown>;
  for (const [field, value] of Object.entries(expected)) {
    if (field === "signer") continue;
    if (data[field] !== value) {
      return rejected("binding", `DACS-2 VerifyResult data ${field} does not match the delivery`);
    }
  }
  if (verifyResult.value["fetchedAt"] !== assertion.value["observedAt"]
    || verifyResult.value["verifiedAt"] !== assertion.value["observedAt"]) {
    return rejected("binding", "DACS-2 VerifyResult timestamps do not match the delivery assertion");
  }
  const resultSignature = verifyResult.value["signature"] as Record<string, unknown>;
  const verifyResultHash = hashUnsigned(verifyResult.value);
  const resultSigner = verifySignature(resultSignature, VERIFY_RESULT_DOMAIN, verifyResultHash, options.signer);
  if (resultSigner !== null) return resultSigner;

  if (options.anchorContext.mode === "post-anchor") {
    const assertionAnchor = readAnchor(options.anchorContext, assertionAddress);
    if ("disposition" in assertionAnchor) return assertionAnchor;
    if (assertionAnchor.artifactKind !== "dacs-2-delivery-assertion"
      || assertionAnchor.artifactContentHash !== assertion.artifactHash) {
      return rejected("anchor-binding", "Anchored delivery assertion does not match its signed artifact");
    }
    const resultAnchor = readAnchor(options.anchorContext, verifyResultAddress);
    if ("disposition" in resultAnchor) return resultAnchor;
    if (resultAnchor.artifactKind !== "dacs-2-verify-result"
      || resultAnchor.artifactContentHash !== verifyResult.artifactHash) {
      return rejected("anchor-binding", "Anchored DACS-2 VerifyResult does not match its signed artifact");
    }
  }
  return Object.freeze({
    disposition: options.anchorContext.mode === "pre-anchor" ? "provisionally-verified" : "verified",
    assertionAddress,
    assertionArtifactHash: assertion.artifactHash,
    verifyResultAddress,
    verifyResultArtifactHash: verifyResult.artifactHash,
  });
}

function expectationObject(options: DeliveryAttestationExpectation): Record<string, unknown> {
  return {
    agreementHash: options.agreementHash,
    deliverableContentHash: options.deliverableContentHash,
    jobId: options.jobId,
    payloadFormat: options.payloadFormat,
    phaseIndex: options.phaseIndex,
    sessionBindingHash: options.sessionBindingHash,
  };
}

function validateExpectation(options: DeliveryAttestationExpectation): string | null {
  if (options === null || typeof options !== "object" || !ULID.test(options.jobId)
    || !HASH.test(options.agreementHash) || !HASH.test(options.deliverableContentHash)
    || !HASH.test(options.sessionBindingHash) || !Number.isSafeInteger(options.phaseIndex)
    || options.phaseIndex < 0 || typeof options.payloadFormat !== "string"
    || options.payloadFormat.length === 0 || KEY_CLAIM.exec(options.signer) === null) {
    return "Delivery attestation expectation is malformed";
  }
  try {
    if (canonicalizeGenericClaimReference(options.signer).canonicalReference !== options.signer) {
      return "Delivery attestation signer is non-canonical";
    }
  } catch {
    return "Delivery attestation signer is invalid";
  }
  return null;
}

function validateAssertion(value: Record<string, unknown>): string | null {
  if (value["assertionVersion"] !== "1" || !ULID.test(value["jobId"] as string)
    || !HASH.test(value["agreementHash"] as string)
    || !HASH.test(value["sessionBindingHash"] as string)
    || !HASH.test(value["deliverableContentHash"] as string)
    || !Number.isSafeInteger(value["phaseIndex"]) || (value["phaseIndex"] as number) < 0
    || typeof value["payloadFormat"] !== "string" || (value["payloadFormat"] as string).length === 0
    || !Number.isSafeInteger(value["observedAt"]) || (value["observedAt"] as number) < 0
    || !signatureShape(value["signature"])) return "Delivery assertion shape is invalid";
  return null;
}

function validateVerifyResult(value: Record<string, unknown>): string | null {
  const attestation = object(value["attestation"]);
  const anchor = object(attestation?.["anchor"]);
  if (value["resultVersion"] !== "1" || typeof value["scheme"] !== "string"
    || typeof value["identifier"] !== "string" || !Number.isSafeInteger(value["recipeVersion"])
    || typeof value["method"] !== "string" || typeof value["decision"] !== "string"
    || typeof value["reason"] !== "string" || (value["reason"] as string).length === 0
    || !Number.isSafeInteger(value["fetchedAt"]) || (value["fetchedAt"] as number) < 0
    || !Number.isSafeInteger(value["verifiedAt"]) || (value["verifiedAt"] as number) < 0
    || object(value["data"]) === null || attestation === null || anchor === null
    || typeof anchor["kind"] !== "string" || typeof anchor["locator"] !== "string"
    || !HASH.test(attestation["contentHash"] as string)
    || typeof attestation["signer"] !== "string" || !signatureShape(value["signature"])) {
    return "DACS-2 VerifyResult shape is invalid";
  }
  return null;
}

function signatureShape(value: unknown): boolean {
  const signature = object(value);
  return signature !== null && signature["algorithm"] === "ed25519"
    && typeof signature["signer"] === "string" && typeof signature["value"] === "string";
}

function verifySignature(
  signature: Record<string, unknown>,
  domain: string,
  hash: string,
  expectedSigner: string,
): DeliveryAttestationVerificationResult | null {
  if (signature["algorithm"] !== "ed25519" || signature["signer"] !== expectedSigner) {
    return rejected("signature", "Delivery attestation signer or algorithm does not match");
  }
  const key = KEY_CLAIM.exec(expectedSigner);
  if (key === null) return refused("signature", "Delivery attestation signer key is unavailable");
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(key[1]!, "hex")]),
      format: "der",
      type: "spki",
    });
    const signatureBytes = decodeComponentSignatureValue(signature["value"] as string, 64);
    return verifyBytes(null, Buffer.from(`${domain}${hash}`, "utf8"), publicKey, signatureBytes)
      ? null : rejected("signature", "Delivery attestation signature is invalid");
  } catch {
    return rejected("signature", "Delivery attestation signature cannot be verified");
  }
}

function hashUnsigned(value: Record<string, unknown>): string {
  const unsigned = { ...value };
  delete unsigned["signature"];
  return sha256(consumerCanonicalize(unsigned));
}

function parseCanonicalObject(
  canonicalJson: string,
  maxBytes: number,
): { readonly value: Record<string, unknown>; readonly artifactHash: string } | { readonly error: string } {
  if (typeof canonicalJson !== "string" || Buffer.byteLength(canonicalJson, "utf8") > maxBytes) {
    return { error: `Delivery attestation exceeds ${maxBytes} bytes` };
  }
  try {
    const value = JSON.parse(canonicalJson) as unknown;
    if (object(value) === null || consumerCanonicalize(value) !== canonicalJson) {
      return { error: "Delivery attestation JSON is not a canonical object" };
    }
    return { value: value as Record<string, unknown>, artifactHash: sha256(canonicalJson) };
  } catch {
    return { error: "Delivery attestation JSON is invalid" };
  }
}

function readAnchor(
  context: Extract<DeliveryAttestationAnchorContext, { readonly mode: "post-anchor" }>,
  address: string,
): ResolvedDeliveryAttestationAnchor | DeliveryAttestationFailure {
  let read: DeliveryAttestationAnchorRead;
  try {
    read = context.read(address);
  } catch {
    return indeterminate("anchor-binding", "Delivery attestation anchor read failed");
  }
  if (read === null || typeof read !== "object" || !["resolved", "absent", "rejected", "indeterminate"].includes(read.status)) {
    return indeterminate("anchor-binding", "Delivery attestation anchor reader returned a malformed result");
  }
  if (read.status === "absent") return rejected("anchor-binding", "Delivery attestation is authoritatively absent");
  if (read.status === "rejected") return rejected("anchor-binding", read.reason);
  if (read.status === "indeterminate") return indeterminate("anchor-binding", read.reason);
  return read;
}

function validateAddressBinding(jobId: string, phaseIndex: number): void {
  if (!ULID.test(jobId) || !Number.isSafeInteger(phaseIndex) || phaseIndex < 0) {
    throw new TypeError("Delivery attestation address binding is invalid");
  }
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function sha256(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

function rejected(
  stage: DeliveryAttestationVerificationStage,
  reason: string,
): DeliveryAttestationFailure {
  return Object.freeze({ disposition: "rejected", stage, reason });
}

function refused(
  stage: DeliveryAttestationVerificationStage,
  reason: string,
): DeliveryAttestationFailure {
  return Object.freeze({ disposition: "refused-unsupported", stage, reason });
}

function indeterminate(
  stage: DeliveryAttestationVerificationStage,
  reason: string,
): DeliveryAttestationFailure {
  return Object.freeze({ disposition: "indeterminate", stage, reason });
}
