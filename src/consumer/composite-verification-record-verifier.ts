import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { decodeComponentSignatureValue } from "../protocol/component-signature-codec.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import { canonicalize } from "../protocol/canonical-json.ts";
import {
  COMPOSITE_VERIFICATION_DOMAIN,
  RECIPE_AVAILABILITIES,
  VET_DECISIONS,
  aggregateVetResults,
  compositeVerificationLogicalAddress,
  type RecipeAvailability,
  type VetBundleRequirement,
  type VetDecision,
} from "../protocol/vet.ts";
import { consumerCanonicalize } from "./canonical-json.ts";
import {
  verifyCanonicalVerifyResultJson,
  type VerifyResultAttestationRead,
} from "./verify-result-verifier.ts";

const HASH = /^[0-9a-f]{64}$/;
const KEY = /^key:([0-9a-f]{64})$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_BYTES = 65_536;
const COMPOSITE_FIELDS = new Set([
  "recordVersion", "jobId", "evaluatedParty", "bundleHash", "requirementHash", "freshness",
  "supplementary", "dealSpecific", "overallDecision", "generatedAt", "signature",
]);
const REFERENCE_FIELDS = new Set(["anchor", "contentHash", "recipeVersion"]);
const ANCHOR_FIELDS = new Set(["kind", "locator"]);
const SIGNATURE_FIELDS = new Set(["algorithm", "signer", "value"]);

export type CompositeVerifyResultRead =
  | {
    readonly status: "resolved";
    readonly availability: RecipeAvailability;
    readonly canonicalJson: string;
  }
  | { readonly status: "absent"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string }
  | { readonly status: "rejected"; readonly reason: string };

export type CompositeRecipeAuthorityRead =
  | {
    readonly status: "resolved";
    readonly availability: RecipeAvailability;
    readonly defaultMaxAgeSec: number;
  }
  | { readonly status: "absent"; readonly reason: string }
  | { readonly status: "indeterminate"; readonly reason: string }
  | { readonly status: "rejected"; readonly reason: string };

export interface CompositeVerificationExpectation {
  readonly bundleHash: string;
  readonly evaluatedClaims: readonly string[];
  readonly evaluatedParty: string;
  readonly expectedVerifier: string;
  readonly jobId: string;
  readonly requirement: VetBundleRequirement;
  readonly requirementHash: string;
  readonly resolveAttestation: (reference: Readonly<Record<string, unknown>>) => VerifyResultAttestationRead;
  readonly resolveRecipeAuthority: (scheme: string, recipeVersion: number) => CompositeRecipeAuthorityRead;
  readonly resolveVerifyResult: (reference: Readonly<Record<string, unknown>>) => CompositeVerifyResultRead;
}

export type CompositeVerificationResult =
  | {
    readonly disposition: "verified";
    readonly contentHash: string;
    readonly generatedAt: number;
    readonly logicalAddress: string;
    readonly overallDecision: VetDecision;
    readonly verifyResultCount: number;
  }
  | {
    readonly disposition: "rejected" | "refused-unsupported" | "indeterminate";
    readonly stage: "canonical-form" | "shape" | "binding" | "signature" | "reference" | "aggregation";
    readonly reason: string;
  };

export function verifyCanonicalCompositeVerificationRecordJson(
  canonicalJson: string,
  expectation: CompositeVerificationExpectation,
): CompositeVerificationResult {
  if (typeof canonicalJson !== "string" || Buffer.byteLength(canonicalJson, "utf8") > MAX_BYTES) {
    return rejected("canonical-form", `CompositeVerificationRecord exceeds ${MAX_BYTES} bytes`);
  }
  let value: Record<string, unknown>;
  try {
    const parsed = JSON.parse(canonicalJson) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
      || consumerCanonicalize(parsed) !== canonicalJson) {
      return rejected("canonical-form", "CompositeVerificationRecord is not canonical JSON");
    }
    value = parsed as Record<string, unknown>;
  } catch {
    return rejected("canonical-form", "CompositeVerificationRecord JSON is invalid");
  }
  const shapeError = validateShape(value);
  if (shapeError !== null) return rejected("shape", shapeError);
  const evaluatedClaims = new Set<string>();
  try {
    for (const claim of expectation.evaluatedClaims) {
      const canonical = canonicalizeClaimReference(claim).canonicalReference;
      if (canonical !== claim || evaluatedClaims.has(canonical)) throw new TypeError();
      evaluatedClaims.add(canonical);
    }
  } catch {
    return rejected("binding", "Authenticated evaluated claims are invalid or duplicated");
  }
  let party: string;
  try {
    party = canonicalizeClaimReference(value["evaluatedParty"] as string).canonicalReference;
  } catch {
    return rejected("shape", "Composite evaluatedParty is invalid");
  }
  if (party !== value["evaluatedParty"] || !evaluatedClaims.has(party)
    || value["jobId"] !== expectation.jobId
    || party !== expectation.evaluatedParty || value["bundleHash"] !== expectation.bundleHash
    || value["requirementHash"] !== expectation.requirementHash
    || sha256(canonicalize(expectation.requirement)) !== expectation.requirementHash) {
    return rejected("binding", "CompositeVerificationRecord does not match its session authority");
  }
  const unsigned = { ...value };
  delete unsigned["signature"];
  const semanticHash = sha256(consumerCanonicalize(unsigned));
  const signatureError = verifySignature(
    value["signature"] as Record<string, unknown>, expectation.expectedVerifier, semanticHash,
  );
  if (signatureError !== null) return signatureError;
  const references = [
    ...(value["freshness"] as Record<string, unknown>[]),
    ...(value["dealSpecific"] as Record<string, unknown>[]),
  ];
  const seen = new Set<string>();
  const summaries: {
    scheme: string; decision: VetDecision; availability: RecipeAvailability;
    recipeVersion: number; verifiedAt: number; verificationPerformed: boolean;
    data?: Readonly<Record<string, unknown>>;
  }[] = [];
  for (const reference of references) {
    const identity = consumerCanonicalize(reference);
    if (seen.has(identity)) return rejected("reference", "Composite VerifyResultRef is duplicated");
    seen.add(identity);
    let unresolvedRead: CompositeVerifyResultRead;
    try {
      unresolvedRead = expectation.resolveVerifyResult(reference);
    } catch {
      return indeterminate("reference", "Composite VerifyResultRef resolution failed");
    }
    const read = normalizeVerifyResultRead(unresolvedRead);
    if (read === null) {
      return indeterminate("reference", "Composite VerifyResultRef resolver returned malformed authority");
    }
    if (read.status === "absent" || read.status === "indeterminate") return indeterminate("reference", read.reason);
    if (read.status === "rejected") return rejected("reference", read.reason);
    if (sha256(read.canonicalJson) !== reference["contentHash"]) {
      return rejected("reference", "Composite VerifyResultRef content hash does not match");
    }
    const verified = verifyCanonicalVerifyResultJson(read.canonicalJson, {
      availability: read.availability,
      expectedRecipeVersion: reference["recipeVersion"] as number,
      expectedVerifier: expectation.expectedVerifier,
      jobId: expectation.jobId,
      resolveAttestation: expectation.resolveAttestation,
    });
    if (verified.disposition === "indeterminate") return indeterminate("reference", verified.reason);
    if (verified.disposition !== "verified") return rejected("reference", verified.reason);
    let unresolvedRecipeAuthority: CompositeRecipeAuthorityRead;
    try {
      unresolvedRecipeAuthority = expectation.resolveRecipeAuthority(verified.scheme, verified.recipeVersion);
    } catch {
      return indeterminate("reference", "Composite recipe authority resolution failed");
    }
    const recipeAuthority = normalizeRecipeAuthorityRead(unresolvedRecipeAuthority);
    if (recipeAuthority === null) {
      return indeterminate("reference", "Composite recipe authority resolver returned malformed authority");
    }
    if (recipeAuthority.status === "absent" || recipeAuthority.status === "indeterminate") {
      return indeterminate("reference", recipeAuthority.reason);
    }
    if (recipeAuthority.status === "rejected") return rejected("reference", recipeAuthority.reason);
    if (!Number.isSafeInteger(recipeAuthority.defaultMaxAgeSec) || recipeAuthority.defaultMaxAgeSec < 0
      || recipeAuthority.availability !== verified.availability) {
      return rejected("binding", "VerifyResult differs from its authenticated recipe authority");
    }
    if (!evaluatedClaims.has(`${verified.scheme}:${verified.identifier}`)) {
      return rejected("binding", "VerifyResult claim is absent from the authenticated evaluated bundle");
    }
    const generatedAt = value["generatedAt"] as number;
    const expiresAt = (() => {
      if (verified.validUntil !== undefined) return verified.validUntil;
      const fallback = verified.verifiedAt + recipeAuthority.defaultMaxAgeSec * 1_000;
      return Number.isSafeInteger(fallback) ? fallback : null;
    })();
    if (expiresAt === null) return rejected("binding", "Recipe freshness authority exceeds the safe time range");
    if (verified.verifiedAt > generatedAt
      || generatedAt > expiresAt) {
      return rejected("binding", "VerifyResult was not valid when the composite was generated");
    }
    if ((reference["anchor"] as Record<string, unknown>)["kind"] !== "storage-program"
      || (reference["anchor"] as Record<string, unknown>)["locator"] !== verified.logicalAddress) {
      return rejected("reference", "Composite VerifyResultRef address does not match CM-2");
    }
    summaries.push({
      scheme: verified.scheme,
      decision: verified.decision,
      availability: verified.availability,
      recipeVersion: verified.recipeVersion,
      verifiedAt: verified.verifiedAt,
      verificationPerformed: verified.verificationPerformed,
      ...(verified.data === undefined ? {} : { data: verified.data }),
    });
  }
  const aggregation = aggregateVetResults(summaries, expectation.requirement, value["generatedAt"] as number);
  if (aggregation.decision !== value["overallDecision"]) {
    return rejected("aggregation", "Composite overallDecision does not match DACS-2 aggregation");
  }
  return Object.freeze({
    disposition: "verified",
    contentHash: sha256(canonicalJson),
    generatedAt: value["generatedAt"] as number,
    logicalAddress: compositeVerificationLogicalAddress(expectation.jobId, party),
    overallDecision: aggregation.decision,
    verifyResultCount: references.length,
  });
}

function normalizeVerifyResultRead(value: unknown): CompositeVerifyResultRead | null {
  try {
    if (value === null || typeof value !== "object") return null;
    const source = value as Record<string, unknown>;
    const status = source["status"];
    if (status === "resolved") {
      const availability = source["availability"];
      const canonicalJson = source["canonicalJson"];
      return typeof availability === "string"
        && RECIPE_AVAILABILITIES.includes(availability as RecipeAvailability)
        && typeof canonicalJson === "string"
        ? Object.freeze({ status, availability: availability as RecipeAvailability, canonicalJson })
        : null;
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

function normalizeRecipeAuthorityRead(value: unknown): CompositeRecipeAuthorityRead | null {
  try {
    if (value === null || typeof value !== "object") return null;
    const source = value as Record<string, unknown>;
    const status = source["status"];
    if (status === "resolved") {
      const availability = source["availability"];
      const defaultMaxAgeSec = source["defaultMaxAgeSec"];
      return typeof availability === "string"
        && RECIPE_AVAILABILITIES.includes(availability as RecipeAvailability)
        && typeof defaultMaxAgeSec === "number"
        ? Object.freeze({
          status,
          availability: availability as RecipeAvailability,
          defaultMaxAgeSec,
        })
        : null;
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

function validateShape(value: Record<string, unknown>): string | null {
  const signature = object(value["signature"]);
  if (Object.keys(value).some((key) => !COMPOSITE_FIELDS.has(key))
    || value["recordVersion"] !== "1" || typeof value["jobId"] !== "string"
    || !ULID.test(value["jobId"]) || typeof value["evaluatedParty"] !== "string"
    || typeof value["bundleHash"] !== "string" || !HASH.test(value["bundleHash"])
    || typeof value["requirementHash"] !== "string" || !HASH.test(value["requirementHash"])
    || !Array.isArray(value["freshness"]) || !value["freshness"].every(validReference)
    || !Array.isArray(value["supplementary"]) || value["supplementary"].length !== 0
    || !Array.isArray(value["dealSpecific"]) || !value["dealSpecific"].every(validReference)
    || typeof value["overallDecision"] !== "string"
    || !VET_DECISIONS.includes(value["overallDecision"] as VetDecision)
    || !Number.isSafeInteger(value["generatedAt"]) || (value["generatedAt"] as number) < 0
    || signature === null || Object.keys(signature).some((key) => !SIGNATURE_FIELDS.has(key))
    || signature["algorithm"] !== "ed25519"
    || typeof signature["signer"] !== "string" || typeof signature["value"] !== "string") {
    return "CompositeVerificationRecord shape is invalid";
  }
  return null;
}

function validReference(value: unknown): boolean {
  const reference = object(value);
  const anchor = object(reference?.["anchor"]);
  return reference !== null && anchor !== null
    && !Object.keys(reference).some((key) => !REFERENCE_FIELDS.has(key))
    && !Object.keys(anchor).some((key) => !ANCHOR_FIELDS.has(key))
    && anchor["kind"] === "storage-program"
    && typeof anchor["locator"] === "string" && anchor["locator"].length > 0
    && typeof reference["contentHash"] === "string" && HASH.test(reference["contentHash"])
    && Number.isSafeInteger(reference["recipeVersion"]) && (reference["recipeVersion"] as number) > 0;
}

function verifySignature(
  signature: Record<string, unknown>,
  expectedVerifier: string,
  semanticHash: string,
): CompositeVerificationResult | null {
  if (signature["algorithm"] !== "ed25519" || signature["signer"] !== expectedVerifier) {
    return rejected("signature", "Composite verifier or algorithm does not match");
  }
  const key = KEY.exec(expectedVerifier);
  if (key === null) return refused("signature", "Indirect Composite verifier resolution is unavailable");
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(key[1]!, "hex")]),
      format: "der",
      type: "spki",
    });
    const bytes = decodeComponentSignatureValue(signature["value"] as string, 64);
    return verifyBytes(
      null,
      Buffer.from(`${COMPOSITE_VERIFICATION_DOMAIN}${semanticHash}`, "utf8"),
      publicKey,
      bytes,
    ) ? null : rejected("signature", "Composite signature is invalid");
  } catch {
    return rejected("signature", "Composite signature cannot be verified");
  }
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function sha256(value: string): string {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}

type FailureStage = "canonical-form" | "shape" | "binding" | "signature" | "reference" | "aggregation";

function rejected(stage: FailureStage, reason: string) {
  return Object.freeze({ disposition: "rejected" as const, stage, reason });
}

function refused(stage: FailureStage, reason: string) {
  return Object.freeze({ disposition: "refused-unsupported" as const, stage, reason });
}

function indeterminate(stage: FailureStage, reason: string) {
  return Object.freeze({ disposition: "indeterminate" as const, stage, reason });
}
