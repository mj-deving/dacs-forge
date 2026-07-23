import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  COMPOSITE_VERIFICATION_DOMAIN,
  aggregateVetResults,
  type RecipeAvailability,
  type VetBundleRequirement,
  type VetDecision,
} from "../protocol/vet.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

export interface VerifyResultReference extends Record<string, unknown> {
  readonly anchor: Readonly<{ readonly kind: "storage-program" | "ipfs" | "https"; readonly locator: string }>;
  readonly contentHash: string;
  readonly recipeVersion: number;
}

export interface CompositeVerifyResultInput {
  readonly availability: RecipeAvailability;
  readonly decision: VetDecision;
  readonly reference: VerifyResultReference;
  readonly scheme: string;
  readonly recipeVersion?: number;
  readonly verifiedAt?: number;
  readonly verificationPerformed?: boolean;
  readonly data?: Readonly<Record<string, unknown>>;
}

export interface CompositeVerificationInput {
  readonly jobId: string;
  readonly evaluatedParty: string;
  readonly bundleHash: string;
  readonly requirementHash: string;
  readonly requirement: VetBundleRequirement;
  readonly freshness: readonly CompositeVerifyResultInput[];
  readonly dealSpecific: readonly CompositeVerifyResultInput[];
  readonly generatedAt: number;
}

export interface SignedCompositeVerificationRecord {
  readonly record: Readonly<Record<string, unknown>>;
  readonly canonicalJson: string;
  readonly contentHash: string;
  readonly overallDecision: VetDecision;
}

const HASH = /^[0-9a-f]{64}$/;
const REFERENCE_FIELDS = new Set(["anchor", "contentHash", "recipeVersion"]);
const ANCHOR_FIELDS = new Set(["kind", "locator"]);

export function signCompositeVerificationRecord(
  input: CompositeVerificationInput,
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): SignedCompositeVerificationRecord {
  assertFixtureSigningAuthority(signer, context);
  const evaluatedParty = canonicalizeClaimReference(input.evaluatedParty).canonicalReference;
  if (evaluatedParty !== input.evaluatedParty || !HASH.test(input.bundleHash)
    || !HASH.test(input.requirementHash) || !Number.isSafeInteger(input.generatedAt)
    || input.generatedAt < 0) {
    throw new TypeError("Composite verification binding is invalid");
  }
  if (sha256Hex(canonicalize(input.requirement)) !== input.requirementHash) {
    throw new TypeError("Composite requirementHash does not match the exact requirement");
  }
  const allResults = [...input.freshness, ...input.dealSpecific];
  const aggregation = aggregateVetResults(allResults, input.requirement, input.generatedAt);
  const unsigned = {
    recordVersion: "1",
    jobId: input.jobId,
    evaluatedParty,
    bundleHash: input.bundleHash,
    requirementHash: input.requirementHash,
    freshness: input.freshness.map(({ reference }) => validateReference(reference)),
    supplementary: [],
    dealSpecific: input.dealSpecific.map(({ reference }) => validateReference(reference)),
    overallDecision: aggregation.decision,
    generatedAt: input.generatedAt,
  };
  const normalized = JSON.parse(canonicalize(unsigned)) as Record<string, unknown>;
  const semanticHash = sha256Hex(canonicalize(withoutFields(normalized, "signature")));
  const signature = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
    signer.sign(new TextEncoder().encode(`${COMPOSITE_VERIFICATION_DOMAIN}${semanticHash}`), context),
    "standard-base64-padded",
    64,
  ));
  const record = deepFreezeJson({
    ...normalized,
    signature: { algorithm: "ed25519", signer: signer.signer, value: signature },
  }) as Readonly<Record<string, unknown>>;
  const canonicalJson = canonicalize(record);
  return Object.freeze({
    record,
    canonicalJson,
    contentHash: sha256Hex(canonicalJson),
    overallDecision: aggregation.decision,
  });
}

function validateReference(reference: VerifyResultReference): VerifyResultReference {
  if (reference === null || typeof reference !== "object" || !HASH.test(reference.contentHash)
    || Object.keys(reference).some((key) => !REFERENCE_FIELDS.has(key))
    || !Number.isSafeInteger(reference.recipeVersion) || reference.recipeVersion < 1
    || reference.anchor === null || typeof reference.anchor !== "object"
    || Object.keys(reference.anchor).some((key) => !ANCHOR_FIELDS.has(key))
    || !["storage-program", "ipfs", "https"].includes(reference.anchor.kind)
    || typeof reference.anchor.locator !== "string" || reference.anchor.locator.length === 0) {
    throw new TypeError("Composite VerifyResultRef is invalid");
  }
  return reference;
}
