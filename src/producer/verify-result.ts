import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  RECIPE_AVAILABILITIES,
  VERIFY_RESULT_DOMAIN,
  VET_DECISIONS,
  type RecipeAvailability,
  type VetDecision,
} from "../protocol/vet.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

export interface VerifyResultAttestationRef extends Record<string, unknown> {
  readonly anchor: Readonly<{ readonly kind: "storage-program" | "ipfs" | "https"; readonly locator: string }>;
  readonly contentHash: string;
  readonly signer?: string;
}

export interface UnsignedVerifyResult extends Record<string, unknown> {
  readonly resultVersion: "1";
  readonly scheme: string;
  readonly identifier: string;
  readonly recipeVersion: number;
  readonly method: string;
  readonly decision: VetDecision;
  readonly reason: string;
  readonly attestation: VerifyResultAttestationRef;
  readonly data?: Readonly<Record<string, unknown>>;
  readonly fetchedAt: number;
  readonly verifiedAt: number;
  readonly validUntil?: number;
}

export interface SignedVerifyResult {
  readonly verifyResult: Readonly<Record<string, unknown>>;
  readonly canonicalJson: string;
  readonly contentHash: string;
  readonly decision: VetDecision;
  readonly availability: RecipeAvailability;
}

const HASH = /^[0-9a-f]{64}$/;
const SCHEME = /^[a-z][a-z0-9-]*$/;
const VERIFY_RESULT_FIELDS = new Set([
  "resultVersion", "scheme", "identifier", "recipeVersion", "method", "decision",
  "reason", "attestation", "data", "fetchedAt", "verifiedAt", "validUntil",
]);
const ATTESTATION_FIELDS = new Set(["anchor", "contentHash", "signer"]);
const ANCHOR_FIELDS = new Set(["kind", "locator"]);

export function signVerifyResult(
  input: UnsignedVerifyResult,
  availability: RecipeAvailability,
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): SignedVerifyResult {
  assertFixtureSigningAuthority(signer, context);
  validate(input, availability);
  const normalized = JSON.parse(canonicalize(input)) as Record<string, unknown>;
  const semanticHash = sha256Hex(canonicalize(withoutFields(normalized, "signature")));
  const signature = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
    signer.sign(new TextEncoder().encode(`${VERIFY_RESULT_DOMAIN}${semanticHash}`), context),
    "standard-base64-padded",
    64,
  ));
  const verifyResult = deepFreezeJson({
    ...normalized,
    signature: { algorithm: "ed25519", signer: signer.signer, value: signature },
  }) as Readonly<Record<string, unknown>>;
  const canonicalJson = canonicalize(verifyResult);
  return Object.freeze({
    verifyResult,
    canonicalJson,
    contentHash: semanticHash,
    decision: input.decision,
    availability,
  });
}

function validate(input: UnsignedVerifyResult, availability: RecipeAvailability): void {
  if (Object.keys(input).some((key) => !VERIFY_RESULT_FIELDS.has(key)) || input.resultVersion !== "1"
    || !SCHEME.test(input.scheme) || typeof input.identifier !== "string" || input.identifier.length === 0
    || !Number.isSafeInteger(input.recipeVersion) || input.recipeVersion < 1
    || typeof input.method !== "string" || input.method.length === 0
    || !VET_DECISIONS.includes(input.decision) || typeof input.reason !== "string" || input.reason.length === 0
    || !Number.isSafeInteger(input.fetchedAt) || input.fetchedAt < 0
    || !Number.isSafeInteger(input.verifiedAt) || input.verifiedAt < input.fetchedAt
    || (input.validUntil !== undefined && (!Number.isSafeInteger(input.validUntil)
      || input.validUntil < input.verifiedAt))
    || !RECIPE_AVAILABILITIES.includes(availability)) {
    throw new TypeError("VerifyResult input is invalid");
  }
  let claim: string;
  try {
    claim = canonicalizeClaimReference(`${input.scheme}:${input.identifier}`).canonicalReference;
  } catch {
    throw new TypeError("VerifyResult scheme and identifier are not a registered canonical claim");
  }
  if (claim !== `${input.scheme}:${input.identifier}`) {
    throw new TypeError("VerifyResult scheme and identifier are not canonical");
  }
  const anchor = input.attestation?.anchor;
  if (input.attestation === null || typeof input.attestation !== "object"
    || Object.keys(input.attestation).some((key) => !ATTESTATION_FIELDS.has(key))
    || anchor === undefined || Object.keys(anchor).some((key) => !ANCHOR_FIELDS.has(key))
    || !["storage-program", "ipfs", "https"].includes(anchor.kind)
    || typeof anchor.locator !== "string" || anchor.locator.length === 0
    || !HASH.test(input.attestation.contentHash)) {
    throw new TypeError("VerifyResult attestation reference is invalid");
  }
  if (input.attestation.signer !== undefined) {
    const signer = canonicalizeClaimReference(input.attestation.signer).canonicalReference;
    if (signer !== input.attestation.signer) throw new TypeError("Attestation signer must be canonical");
  }
  if (input.data !== undefined) assertPublicPredicateData(input.data);
}

function assertPublicPredicateData(data: Readonly<Record<string, unknown>>): void {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new TypeError("VerifyResult data must be a predicate object");
  }
  if (Object.keys(data).length !== 1 || data["possessionVerified"] !== true) {
    throw new TypeError("Fixture VerifyResult data must be exactly possessionVerified=true");
  }
}
