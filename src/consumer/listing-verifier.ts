import { createHash, createPublicKey, verify as verifyBytes } from "node:crypto";
import {
  findUnsupportedListingType,
  validateCurrentPipeline,
  validateListingSchema,
  validatePayRailBindings,
} from "../protocol/listing-schema.ts";
import {
  canonicalizeClaimReference,
  canonicalizeGenericClaimReference,
  isRegisteredClaimScheme,
  sameClaimIdentity,
} from "../protocol/claim-reference.ts";
import { consumerCanonicalize } from "./canonical-json.ts";
import { decodeComponentSignatureValue } from "../protocol/component-signature-codec.ts";

const LISTING_DOMAIN = "dacs-listing:v1:";
const BUNDLE_DOMAIN = "dacs-bundle-presentation:v1:";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_LISTING_BYTES = 16_384;

export type RevocationCheck = "absent" | "revoked" | "indeterminate";
export type PaymentRailCheck =
  | { readonly status: "resolved"; readonly phaseHandler: string }
  | { readonly status: "unresolved" | "indeterminate" };
export type ListingVerificationStage =
  | "parse" | "schema" | "version" | "validity" | "canonical-form" | "signature"
  | "revocation" | "identity" | "pipeline" | "rails" | "signer";

export type ListingVerificationResult =
  | {
    readonly disposition: "accepted";
      readonly contentHash: string;
      readonly listingId: string;
      readonly listingVersion: number;
      readonly unknownClaims?: readonly string[];
  }
  | {
    readonly disposition: "rejected" | "refused-unsupported";
    readonly stage: ListingVerificationStage;
    readonly reason: string;
    readonly contentHash?: string;
    readonly signature?: "valid" | "invalid" | "not-checked";
  };

export interface ListingVerificationOptions {
  readonly nowMs: number;
  readonly revocationCheck: (listing: {
    readonly sellerPrimaryClaim: string;
    readonly listingSigner: string;
    readonly listingId: string;
    readonly listingVersion: number;
    readonly contentHash: string;
  }) => RevocationCheck;
  readonly paymentRailCheck?: (rail: {
    readonly railId: string;
    readonly railVersion?: number;
    readonly canonicalJson: string;
    readonly referencedByPhaseKinds: readonly string[];
  }) => PaymentRailCheck;
}

export function verifyCanonicalListingJson(
  canonicalJson: string,
  options: ListingVerificationOptions,
): ListingVerificationResult {
  if (typeof canonicalJson !== "string") throw new TypeError("Listing input must be a string");
  if (!Number.isSafeInteger(options.nowMs) || options.nowMs < 0) {
    throw new TypeError("Verifier clock must be a non-negative safe integer");
  }
  if (typeof options.revocationCheck !== "function") {
    throw new TypeError("Verifier requires a revocation check");
  }
  if (Buffer.byteLength(canonicalJson, "utf8") > MAX_LISTING_BYTES) {
    return failure("canonical-form", "Canonical signed Listing exceeds 16384 bytes");
  }
  let value: unknown;
  try {
    value = JSON.parse(canonicalJson) as unknown;
  } catch {
    return failure("parse", "Listing is not valid JSON");
  }
  if (!isObject(value)) return failure("schema", "Listing must be an object");
  const listing = value;
  const schemaError = validateListingSchema(listing, true);
  if (schemaError !== null) {
    const unsupportedType = findUnsupportedListingType(listing);
    return unsupportedType === null
      ? failure("schema", schemaError)
      : {
        disposition: "refused-unsupported",
        stage: "schema",
        reason: unsupportedType,
        signature: "not-checked",
      };
  }
  if (listing["dacsVersion"] !== "1") return failure("version", "Unsupported DACS major version");

  const validity = listing["validity"] as Record<string, unknown>;
  const notBefore = validity["notBefore"] as number;
  const notAfter = validity["notAfter"] as number | undefined;
  if (options.nowMs < notBefore || (notAfter !== undefined && options.nowMs > notAfter)) {
    return failure("validity", "Listing is outside its validity window");
  }

  let reconstructed: string;
  let signedScope: string;
  try {
    reconstructed = consumerCanonicalize(listing);
    signedScope = consumerCanonicalize(omitSignature(listing));
  } catch (error) {
    return failure("canonical-form", error instanceof Error ? error.message : "Invalid canonical form");
  }
  if (reconstructed !== canonicalJson) {
    return failure("canonical-form", "Listing bytes are not canonical JSON");
  }
  const contentHash = sha256(signedScope);
  const signature = listing["signature"] as Record<string, unknown>;
  const signer = signature["signer"] as string;
  if (signature["algorithm"] !== "ed25519") {
    return {
      disposition: "refused-unsupported",
      stage: "signature",
      reason: `Unsupported Listing signature algorithm: ${String(signature["algorithm"])}`,
      contentHash,
      signature: "not-checked",
    };
  }
  let listingSigner;
  try {
    listingSigner = canonicalizeClaimReference(signer);
  } catch {
    return failure("signature", "Listing signer ClaimReference is invalid", contentHash);
  }
  if (listingSigner.canonicalReference !== signer) {
    return failure("signature", "Listing signer ClaimReference is not canonical", contentHash);
  }
  if (listingSigner.scheme !== "key" || !/^[0-9a-f]{64}$/.test(listingSigner.identifier)) {
    return {
      disposition: "refused-unsupported",
      stage: "signature",
      reason: "Indirect Listing signer resolution is not implemented",
      contentHash,
      signature: "not-checked",
    };
  }
  if (!verifyEd25519ClaimSignature(
    signer,
    signature["value"] as string,
    `${LISTING_DOMAIN}${contentHash}`,
    "sig6",
  )) return failure("signature", "Listing signature is invalid", contentHash, "invalid");

  const sellerIdentity = (listing["seller"] as Record<string, unknown>)["identity"] as Record<string, unknown>;
  const listingRef = {
    sellerPrimaryClaim: sellerIdentity["presentedBy"] as string,
    listingSigner: signer,
    listingId: listing["listingId"] as string,
    listingVersion: listing["listingVersion"] as number,
    contentHash,
  };
  const revocation = options.revocationCheck(Object.freeze(listingRef));
  if (revocation !== "absent" && revocation !== "revoked" && revocation !== "indeterminate") {
    throw new TypeError("Revocation check returned an invalid disposition");
  }
  if (revocation !== "absent") {
    return failure("revocation", `Listing revocation is ${revocation}`, contentHash, "valid");
  }
  const identity = (listing["seller"] as Record<string, unknown>)["identity"] as Record<string, unknown>;
  const identityResult = verifyIdentityBundle(identity);
  if (identityResult.status === "unsupported") {
    return {
      disposition: "refused-unsupported",
      stage: "identity",
      reason: identityResult.reason,
      contentHash,
      signature: "valid",
    };
  }
  if (identityResult.status === "invalid") {
    return failure("identity", identityResult.reason, contentHash, "valid");
  }

  const pipeline = listing["pipeline"] as Record<string, unknown>[];
  const pipelineResult = validateCurrentPipeline(listing, options.nowMs);
  if (pipelineResult.status === "unsupported") {
    return {
      disposition: "refused-unsupported",
      stage: "pipeline",
      reason: `Unsupported phase kind at pipeline[${pipelineResult.index}]`,
      contentHash,
      signature: "valid",
    };
  }
  if (pipelineResult.status === "invalid") {
    return failure("pipeline", pipelineResult.reason, contentHash, "valid");
  }
  const railBindingError = validatePayRailBindings(listing);
  if (railBindingError !== null) {
    return failure("rails", railBindingError, contentHash, "valid");
  }
  if (pipeline.some((step) => (step["kind"] as string).startsWith("pay-"))) {
    if (options.paymentRailCheck === undefined) {
      return failure("rails", "Payment rail resolution is unavailable", contentHash, "valid");
    }
    const acceptedRails = listing["acceptedRails"] as Record<string, unknown>[];
    const paySteps = pipeline.filter((entry) => (entry["kind"] as string).startsWith("pay-"));
    const resolved = new Map<string, Extract<PaymentRailCheck, { status: "resolved" }>>();
    for (const rail of acceptedRails) {
      const railId = rail["railId"] as string;
      const phaseKinds = Object.freeze(paySteps
        .filter((step) => (step["parameters"] as Record<string, unknown>)["rail"] === railId)
        .map((step) => step["kind"] as string));
      const canonicalRail = consumerCanonicalize(rail);
      const railRef = Object.freeze({
        railId,
        ...(rail["railVersion"] === undefined ? {} : { railVersion: rail["railVersion"] as number }),
        canonicalJson: canonicalRail,
        referencedByPhaseKinds: phaseKinds,
      });
      const result = options.paymentRailCheck(railRef);
      if (!isObject(result) || (result["status"] !== "resolved" && result["status"] !== "unresolved"
        && result["status"] !== "indeterminate")) {
        throw new TypeError("Payment rail check returned an invalid disposition");
      }
      if (result["status"] !== "resolved") {
        return failure("rails", `Payment rail ${railRef.railId} is ${result["status"]}`, contentHash, "valid");
      }
      if (typeof result["phaseHandler"] !== "string") {
        throw new TypeError("Resolved payment rail omitted phaseHandler");
      }
      resolved.set(railId, result as Extract<PaymentRailCheck, { status: "resolved" }>);
    }
    for (const step of paySteps) {
      const railId = (step["parameters"] as Record<string, unknown>)["rail"] as string;
      const phaseKind = step["kind"] as string;
      if (resolved.get(railId)?.phaseHandler !== phaseKind) {
        return failure(
          "rails",
          `Payment rail ${railId} does not bind to ${phaseKind}`,
          contentHash,
          "valid",
        );
      }
    }
  }
  const claims = identity["claims"] as Record<string, unknown>[];
  if (!claims.some((claim) => referencesSameForRead(claim["ref"] as string, signer))) {
    return failure("signer", "Listing signer is absent from seller claims", contentHash, "valid");
  }
  return {
    disposition: "accepted",
    listingId: listingRef.listingId,
    listingVersion: listingRef.listingVersion,
    contentHash: listingRef.contentHash,
    ...(identityResult.unknownClaims.length === 0
      ? {}
      : { unknownClaims: identityResult.unknownClaims }),
  };
}

type IdentityResult =
  | { readonly status: "valid"; readonly unknownClaims: readonly string[] }
  | { readonly status: "invalid"; readonly reason: string }
  | { readonly status: "unsupported"; readonly reason: string };

function verifyIdentityBundle(bundle: Record<string, unknown>): IdentityResult {
  if (bundle["bundleVersion"] !== "1" || !nonNegativeSafeInteger(bundle["presentedAt"])) {
    return { status: "invalid", reason: "IdentityBundle version or presentedAt is invalid" };
  }
  if (typeof bundle["presentedBy"] !== "string" || !Array.isArray(bundle["claims"])
    || bundle["claims"].length === 0 || !bundle["claims"].every((claim) =>
      isObject(claim) && typeof claim["ref"] === "string")) {
    return { status: "invalid", reason: "IdentityBundle claims are invalid" };
  }
  const claims = bundle["claims"] as Record<string, unknown>[];
  if (bundle["sessionNonce"] !== undefined
    && (typeof bundle["sessionNonce"] !== "string"
      || !/^[0-9a-f]{32,}$/.test(bundle["sessionNonce"]))) {
    return { status: "invalid", reason: "IdentityBundle sessionNonce is invalid" };
  }
  const claimReferences: { readonly reference: string; readonly known: boolean }[] = [];
  for (const claim of claims) {
    const reference = claim["ref"] as string;
    const referenceStatus = inspectClaimReference(reference);
    if (referenceStatus === "invalid") {
      return { status: "invalid", reason: "IdentityBundle claim ref is invalid" };
    }
    if (referenceStatus === "noncanonical") {
        return { status: "invalid", reason: "IdentityBundle claim ref is not canonical" };
    }
    if ((claim["verifiedBy"] !== undefined && !verifyResultRef(claim["verifiedBy"]))
      || (claim["issuedAt"] !== undefined && !nonNegativeSafeInteger(claim["issuedAt"]))
      || (claim["expiresAt"] !== undefined && !nonNegativeSafeInteger(claim["expiresAt"]))
      || (claim["metadata"] !== undefined && !isObject(claim["metadata"]))) {
      return { status: "invalid", reason: "IdentityBundle claim metadata is invalid" };
    }
    claimReferences.push({ reference, known: referenceStatus === "known" });
  }
  const presentedByStatus = inspectClaimReference(bundle["presentedBy"] as string);
  if (presentedByStatus === "invalid") {
    return { status: "invalid", reason: "IdentityBundle presentedBy is invalid" };
  }
  if (presentedByStatus === "noncanonical") {
    return { status: "invalid", reason: "IdentityBundle presentedBy is not canonical" };
  }
  const claimIdentities = claimReferences.map(({ reference, known }) => {
    const parsed = known
      ? canonicalizeClaimReference(reference)
      : canonicalizeGenericClaimReference(reference);
    return `${parsed.scheme.length}:${parsed.scheme}${parsed.identifier}`;
  });
  if (new Set(claimIdentities).size !== claimIdentities.length) {
    return { status: "invalid", reason: "IdentityBundle contains duplicate claims" };
  }
  if (!claims.some((claim) => referencesSameForRead(
    claim["ref"] as string,
    bundle["presentedBy"] as string,
  ))) {
    return { status: "invalid", reason: "IdentityBundle presentedBy is absent from claims" };
  }
  const presentation = bundle["presentation"];
  if (!isObject(presentation) || typeof presentation["kind"] !== "string") {
    return { status: "invalid", reason: "IdentityBundle presentation is invalid" };
  }
  if (presentation["kind"] !== "per-claim") {
    return { status: "unsupported", reason: `Unsupported IdentityBundle presentation: ${presentation["kind"]}` };
  }
  if (!Array.isArray(presentation["signatures"]) || presentation["signatures"].length === 0) {
    return { status: "invalid", reason: "Per-claim IdentityBundle presentation is empty" };
  }
  const unsigned = { ...bundle };
  delete unsigned["presentation"];
  const bundleHash = sha256(consumerCanonicalize(unsigned));
  const signatures = presentation["signatures"] as unknown[];
  let presentedByVerified = false;
  const seen = new Set<string>();
  for (const entry of signatures) {
    if (!isObject(entry) || typeof entry["ref"] !== "string" || typeof entry["signature"] !== "string") {
      return { status: "invalid", reason: "IdentityBundle presentation entry is invalid" };
    }
    const entryRef = entry["ref"];
    const entryStatus = inspectClaimReference(entryRef);
    if (entryStatus === "invalid" || entryStatus === "noncanonical") {
      return { status: "invalid", reason: "IdentityBundle presentation signer ref is invalid" };
    }
    if (entryStatus === "unknown") {
      return { status: "unsupported", reason: "Unknown per-claim presentation signer scheme" };
    }
    const entryClaim = canonicalizeClaimReference(entryRef);
    const entryIdentity = `${entryClaim.scheme.length}:${entryClaim.scheme}${entryClaim.identifier}`;
    if (seen.has(entryIdentity)) {
      return { status: "invalid", reason: "IdentityBundle presentation contains duplicate signers" };
    }
    seen.add(entryIdentity);
    if (!claims.some((claim) => referencesSameForRead(claim["ref"] as string, entryRef))) {
      return { status: "invalid", reason: "IdentityBundle presentation signer is absent from claims" };
    }
    const presentationSigner = entryClaim;
    if (presentationSigner.scheme !== "key" || !/^[0-9a-f]{64}$/.test(presentationSigner.identifier)) {
      return {
        status: "unsupported",
        reason: "Indirect per-claim IdentityBundle signer resolution is not implemented",
      };
    }
    if (!verifyEd25519ClaimSignature(
      entryRef, entry["signature"], `${BUNDLE_DOMAIN}${bundleHash}`, "presentation",
    )) return { status: "invalid", reason: "IdentityBundle presentation signature is invalid" };
    if (referencesSameForRead(entryRef, bundle["presentedBy"] as string)) presentedByVerified = true;
  }
  return presentedByVerified
    ? {
      status: "valid",
      unknownClaims: Object.freeze(claimReferences
        .filter(({ known }) => !known)
        .map(({ reference }) => reference)),
    }
    : { status: "invalid", reason: "IdentityBundle presentedBy is not controlled" };
}

function verifyEd25519ClaimSignature(
  claim: string,
  signature: string,
  payload: string,
  encoding: "sig6" | "presentation",
): boolean {
  let publicKeyHex: string;
  try {
    const parsed = canonicalizeClaimReference(claim);
    if (parsed.scheme !== "key" || !/^[0-9a-f]{64}$/.test(parsed.identifier)) return false;
    publicKeyHex = parsed.identifier;
  } catch {
    return false;
  }
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = encoding === "sig6"
      ? decodeComponentSignatureValue(signature, 64)
      : decodePresentationSignature(signature);
  } catch {
    return false;
  }
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, "hex")]),
      format: "der",
      type: "spki",
    });
    return verifyBytes(null, Buffer.from(payload), publicKey, signatureBytes);
  } catch {
    return false;
  }
}

function decodePresentationSignature(value: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]{86}==$/.test(value)) throw new TypeError("Invalid presentation signature");
  const decoded = Buffer.from(value, "base64");
  if (decoded.byteLength !== 64 || decoded.toString("base64") !== value) {
    throw new TypeError("Invalid presentation signature");
  }
  return Uint8Array.from(decoded);
}

function verifyResultRef(value: unknown): boolean {
  if (!isObject(value) || !isObject(value["anchor"])) return false;
  const anchor = value["anchor"];
  return ["storage-program", "ipfs", "https"].includes(String(anchor["kind"]))
    && typeof anchor["locator"] === "string" && anchor["locator"].length > 0
    && typeof value["contentHash"] === "string" && /^[0-9a-f]{64}$/.test(value["contentHash"])
    && Number.isSafeInteger(value["recipeVersion"]) && (value["recipeVersion"] as number) >= 1;
}

type ClaimReferenceReadStatus = "known" | "unknown" | "noncanonical" | "invalid";

function inspectClaimReference(reference: string): ClaimReferenceReadStatus {
  let generic;
  try {
    generic = canonicalizeGenericClaimReference(reference);
  } catch {
    return "invalid";
  }
  if (generic.canonicalReference !== reference) return "noncanonical";
  if (!isRegisteredClaimScheme(generic.scheme)) return "unknown";
  try {
    return canonicalizeClaimReference(reference).canonicalReference === reference ? "known" : "noncanonical";
  } catch {
    return "invalid";
  }
}

function referencesSameForRead(left: string, right: string): boolean {
  const leftStatus = inspectClaimReference(left);
  const rightStatus = inspectClaimReference(right);
  if (leftStatus === "known" && rightStatus === "known") return sameClaimIdentity(left, right);
  if (leftStatus !== "unknown" || rightStatus !== "unknown") return false;
  const leftClaim = canonicalizeGenericClaimReference(left);
  const rightClaim = canonicalizeGenericClaimReference(right);
  return leftClaim.scheme === rightClaim.scheme && leftClaim.identifier === rightClaim.identifier;
}

function omitSignature(listing: Record<string, unknown>): Record<string, unknown> {
  const unsigned = { ...listing };
  delete unsigned["signature"];
  return unsigned;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonNegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function failure(
  stage: ListingVerificationStage,
  reason: string,
  contentHash?: string,
  signature: "valid" | "invalid" | "not-checked" = "not-checked",
): ListingVerificationResult {
  return contentHash === undefined
    ? { disposition: "rejected", stage, reason, signature }
    : { disposition: "rejected", stage, reason, contentHash, signature };
}
