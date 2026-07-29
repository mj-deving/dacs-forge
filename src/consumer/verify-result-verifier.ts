import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { decodeComponentSignatureValue } from "../protocol/component-signature-codec.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import {
  RECIPE_AVAILABILITIES,
  VERIFY_RESULT_DOMAIN,
  VET_DECISIONS,
  effectiveVetDecision,
  verifyResultLogicalAddress,
  type RecipeAvailability,
  type VetDecision,
} from "../protocol/vet.ts";
import { consumerCanonicalize } from "./canonical-json.ts";

const HASH = /^[0-9a-f]{64}$/;
const KEY = /^key:([0-9a-f]{64})$/;
const SCHEME = /^[a-z][a-z0-9-]*$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_BYTES = 16_384;
const VERIFY_RESULT_FIELDS = new Set([
  "resultVersion", "scheme", "identifier", "recipeVersion", "method", "decision",
  "reason", "attestation", "data", "fetchedAt", "verifiedAt", "validUntil", "signature",
]);
const ATTESTATION_FIELDS = new Set(["anchor", "contentHash", "signer"]);
const ANCHOR_FIELDS = new Set(["kind", "locator"]);
const SIGNATURE_FIELDS = new Set(["algorithm", "signer", "value"]);

export interface VerifyResultExpectation {
  readonly availability: RecipeAvailability;
  readonly expectedIdentifier?: string;
  readonly expectedMethod?: string;
  readonly expectedRecipeVersion?: number;
  readonly expectedScheme?: string;
  readonly expectedVerifier: string;
  readonly jobId: string;
  readonly resolveAttestation: (reference: Readonly<Record<string, unknown>>) => VerifyResultAttestationRead;
}

export type VerifyResultAttestationRead =
  | {
    readonly status: "resolved";
    readonly canonicalJson?: string;
    readonly rawBytes?: Uint8Array;
    readonly signatureVerified?: boolean;
    readonly signer?: string;
  }
  | { readonly status: "absent"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string }
  | { readonly status: "rejected"; readonly reason: string };

type VerifyResultVerificationStage =
  | "canonical-form" | "shape" | "binding" | "signature" | "privacy" | "attestation";

export type VerifyResultVerification =
  | {
    readonly disposition: "verified";
    readonly availability: RecipeAvailability;
    readonly contentHash: string;
    readonly decision: VetDecision;
    readonly effectiveDecision: VetDecision;
    readonly fetchedAt: number;
    readonly identifier: string;
    readonly logicalAddress: string;
    readonly method: string;
    readonly data?: Readonly<Record<string, unknown>>;
    readonly recipeVersion: number;
    readonly scheme: string;
    readonly verificationPerformed: boolean;
    readonly verifiedAt: number;
    readonly validUntil?: number;
  }
  | {
    readonly disposition: "rejected" | "refused-unsupported" | "indeterminate";
    readonly stage: VerifyResultVerificationStage;
    readonly reason: string;
  };

export function verifyCanonicalVerifyResultJson(
  canonicalJson: string,
  expectation: VerifyResultExpectation,
): VerifyResultVerification {
  if (typeof canonicalJson !== "string" || Buffer.byteLength(canonicalJson, "utf8") > MAX_BYTES) {
    return rejected("canonical-form", `VerifyResult exceeds ${MAX_BYTES} bytes`);
  }
  let value: Record<string, unknown>;
  try {
    const parsed = JSON.parse(canonicalJson) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
      || consumerCanonicalize(parsed) !== canonicalJson) {
      return rejected("canonical-form", "VerifyResult is not a canonical JSON object");
    }
    value = parsed as Record<string, unknown>;
  } catch {
    return rejected("canonical-form", "VerifyResult JSON is invalid");
  }
  const shapeError = validateShape(value);
  if (shapeError !== null) return rejected(shapeError.stage, shapeError.reason);
  if (!RECIPE_AVAILABILITIES.includes(expectation.availability)) {
    return refused("binding", "Recipe availability authority is unsupported");
  }
  const scheme = value["scheme"] as string;
  const identifier = value["identifier"] as string;
  const recipeVersion = value["recipeVersion"] as number;
  const method = value["method"] as string;
  try {
    if (canonicalizeClaimReference(`${scheme}:${identifier}`).canonicalReference !== `${scheme}:${identifier}`) {
      return rejected("binding", "VerifyResult claim is not canonical");
    }
  } catch {
    return rejected("binding", "VerifyResult claim is not registered or canonical");
  }
  if ((expectation.expectedScheme !== undefined && scheme !== expectation.expectedScheme)
    || (expectation.expectedIdentifier !== undefined && identifier !== expectation.expectedIdentifier)
    || (expectation.expectedRecipeVersion !== undefined && recipeVersion !== expectation.expectedRecipeVersion)
    || (expectation.expectedMethod !== undefined && method !== expectation.expectedMethod)) {
    return rejected("binding", "VerifyResult does not match the pinned recipe or claim");
  }
  const unsigned = { ...value };
  delete unsigned["signature"];
  const semanticHash = sha256(consumerCanonicalize(unsigned));
  const signature = value["signature"] as Record<string, unknown>;
  const signatureError = verifySignature(signature, expectation.expectedVerifier, semanticHash);
  if (signatureError !== null) return signatureError;
  const attestationVerification = verifyAttestation(
    value["attestation"] as Record<string, unknown>,
    expectation.resolveAttestation,
  );
  if (typeof attestationVerification !== "boolean") return attestationVerification;
  let logicalAddress: string;
  try {
    logicalAddress = verifyResultLogicalAddress(expectation.jobId, scheme, identifier, recipeVersion);
  } catch {
    return rejected("binding", "VerifyResult address inputs are invalid");
  }
  const decision = value["decision"] as VetDecision;
  return Object.freeze({
    disposition: "verified",
    availability: expectation.availability,
    contentHash: semanticHash,
    decision,
    effectiveDecision: effectiveVetDecision(decision, expectation.availability),
    fetchedAt: value["fetchedAt"] as number,
    identifier,
    logicalAddress,
    method,
    ...(value["data"] === undefined
      ? {} : { data: Object.freeze({ ...(value["data"] as Record<string, unknown>) }) }),
    recipeVersion,
    scheme,
    verificationPerformed: attestationVerification,
    verifiedAt: value["verifiedAt"] as number,
    ...(value["validUntil"] === undefined ? {} : { validUntil: value["validUntil"] as number }),
  });
}

function verifyAttestation(
  reference: Readonly<Record<string, unknown>>,
  resolve: VerifyResultExpectation["resolveAttestation"],
): VerifyResultVerification | boolean {
  let unresolvedRead: VerifyResultAttestationRead;
  try {
    unresolvedRead = resolve(reference);
  } catch {
    return indeterminate("attestation", "VerifyResult attestation resolution failed");
  }
  const read = normalizeAttestationRead(unresolvedRead);
  if (read === null) {
    return indeterminate("attestation", "VerifyResult attestation resolver returned malformed authority");
  }
  if (read.status === "absent" || read.status === "indeterminate") {
    return indeterminate("attestation", read.reason);
  }
  if (read.status === "rejected") return rejected("attestation", read.reason);
  const hasCanonical = typeof read.canonicalJson === "string";
  const hasRaw = read.rawBytes !== undefined;
  if (hasCanonical === hasRaw) {
    return rejected("attestation", "Resolved attestation must provide exactly one content representation");
  }
  let actualHash: string;
  try {
    if (hasCanonical) {
      const parsed = JSON.parse(read.canonicalJson!);
      if (consumerCanonicalize(parsed) !== read.canonicalJson) {
        return rejected("attestation", "Resolved attestation JSON is not canonical");
      }
      actualHash = sha256(read.canonicalJson!);
    } else {
      actualHash = new Bun.CryptoHasher("sha256").update(read.rawBytes!).digest("hex");
    }
  } catch {
    return rejected("attestation", "Resolved attestation content is invalid");
  }
  if (actualHash !== reference["contentHash"]) {
    return rejected("attestation", "Resolved attestation content hash does not match");
  }
  const expectedSigner = reference["signer"];
  if (expectedSigner !== undefined
    && (read.signer !== expectedSigner || read.signatureVerified !== true)) {
    return rejected("attestation", "Resolved attestation signer is not independently verified");
  }
  return expectedSigner !== undefined;
}

function normalizeAttestationRead(value: unknown): VerifyResultAttestationRead | null {
  try {
    if (value === null || typeof value !== "object") return null;
    const source = value as Record<string, unknown>;
    const status = source["status"];
    if (status === "resolved") {
      const canonicalJson = source["canonicalJson"];
      const rawBytes = source["rawBytes"];
      const signer = source["signer"];
      const signatureVerified = source["signatureVerified"];
      if (canonicalJson !== undefined && typeof canonicalJson !== "string") return null;
      if (rawBytes !== undefined && !(rawBytes instanceof Uint8Array)) return null;
      if (signer !== undefined && typeof signer !== "string") return null;
      if (signatureVerified !== undefined && typeof signatureVerified !== "boolean") return null;
      const rawBytesSnapshot = rawBytes === undefined ? undefined : Uint8Array.from(rawBytes);
      return Object.freeze({
        status,
        ...(canonicalJson === undefined ? {} : { canonicalJson }),
        ...(rawBytesSnapshot === undefined ? {} : { rawBytes: rawBytesSnapshot }),
        ...(signer === undefined ? {} : { signer }),
        ...(signatureVerified === undefined ? {} : { signatureVerified }),
      });
    }
    if (status === "absent" || status === "indeterminate" || status === "rejected") {
      const reason = source["reason"];
      return typeof reason === "string" ? Object.freeze({ status, reason }) : null;
    }
    return null;
  } catch {
    return null;
  }
}

function validateShape(value: Record<string, unknown>): { stage: "shape" | "privacy"; reason: string } | null {
  const attestation = object(value["attestation"]);
  const anchor = object(attestation?.["anchor"]);
  const signature = object(value["signature"]);
  if (Object.keys(value).some((key) => !VERIFY_RESULT_FIELDS.has(key))
    || value["resultVersion"] !== "1" || typeof value["scheme"] !== "string"
    || !SCHEME.test(value["scheme"]) || typeof value["identifier"] !== "string"
    || value["identifier"].length === 0 || !Number.isSafeInteger(value["recipeVersion"])
    || (value["recipeVersion"] as number) < 1 || typeof value["method"] !== "string"
    || value["method"].length === 0 || typeof value["decision"] !== "string"
    || !VET_DECISIONS.includes(value["decision"] as VetDecision)
    || typeof value["reason"] !== "string" || value["reason"].length === 0
    || !Number.isSafeInteger(value["fetchedAt"]) || (value["fetchedAt"] as number) < 0
    || !Number.isSafeInteger(value["verifiedAt"])
    || (value["verifiedAt"] as number) < (value["fetchedAt"] as number)
    || (value["validUntil"] !== undefined && (!Number.isSafeInteger(value["validUntil"])
      || (value["validUntil"] as number) < (value["verifiedAt"] as number)))
    || attestation === null || Object.keys(attestation).some((key) => !ATTESTATION_FIELDS.has(key))
    || anchor === null || Object.keys(anchor).some((key) => !ANCHOR_FIELDS.has(key))
    || !["storage-program", "ipfs", "https"].includes(anchor["kind"] as string)
    || typeof anchor["locator"] !== "string" || anchor["locator"].length === 0
    || typeof attestation["contentHash"] !== "string" || !HASH.test(attestation["contentHash"])
    || signature === null || Object.keys(signature).some((key) => !SIGNATURE_FIELDS.has(key))
    || signature["algorithm"] !== "ed25519"
    || typeof signature["signer"] !== "string" || typeof signature["value"] !== "string") {
    return { stage: "shape", reason: "VerifyResult shape is invalid" };
  }
  if (attestation["signer"] !== undefined) {
    try {
      if (canonicalizeClaimReference(attestation["signer"] as string).canonicalReference !== attestation["signer"]) {
        return { stage: "shape", reason: "VerifyResult attestation signer is non-canonical" };
      }
    } catch {
      return { stage: "shape", reason: "VerifyResult attestation signer is invalid" };
    }
  }
  const data = value["data"];
  if (data !== undefined) {
    const record = object(data);
    if (record === null) return { stage: "shape", reason: "VerifyResult data is not an object" };
    if (Object.keys(record).length !== 1 || record["possessionVerified"] !== true) {
      return { stage: "privacy", reason: "Fixture VerifyResult data is outside its closed predicate schema" };
    }
  }
  return null;
}

function verifySignature(
  signature: Record<string, unknown>,
  expectedVerifier: string,
  semanticHash: string,
): VerifyResultVerification | null {
  if (signature["algorithm"] !== "ed25519" || signature["signer"] !== expectedVerifier) {
    return rejected("signature", "VerifyResult verifier or algorithm does not match");
  }
  const key = KEY.exec(expectedVerifier);
  if (key === null) return refused("signature", "Indirect VerifyResult verifier resolution is unavailable");
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(key[1]!, "hex")]),
      format: "der",
      type: "spki",
    });
    const signatureBytes = decodeComponentSignatureValue(signature["value"] as string, 64);
    return verifyBytes(
      null,
      Buffer.from(`${VERIFY_RESULT_DOMAIN}${semanticHash}`, "utf8"),
      publicKey,
      signatureBytes,
    ) ? null : rejected("signature", "VerifyResult signature is invalid");
  } catch {
    return rejected("signature", "VerifyResult signature cannot be verified");
  }
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function sha256(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

function rejected(stage: VerifyResultVerificationStage, reason: string) {
  return Object.freeze({ disposition: "rejected" as const, stage, reason });
}

function refused(stage: VerifyResultVerificationStage, reason: string) {
  return Object.freeze({ disposition: "refused-unsupported" as const, stage, reason });
}

function indeterminate(stage: VerifyResultVerificationStage, reason: string) {
  return Object.freeze({ disposition: "indeterminate" as const, stage, reason });
}
