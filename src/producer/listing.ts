import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import { canonicalizeClaimReference, sameClaimIdentity } from "../protocol/claim-reference.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import {
  validateCurrentPipeline,
  validateListingSchema,
  validatePayRailBindings,
} from "../protocol/listing-schema.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";
import { assertPerClaimIdentityBundleForPublication } from "./identity-bundle.ts";

const LISTING_DOMAIN = "dacs-listing:v1:";
const MAX_LISTING_BYTES = 16_384;

export interface UnsignedListing extends Record<string, unknown> {
  readonly dacsVersion: "1";
  readonly listingVersion: number;
  readonly listingId: string;
}

export interface SignedListingResult {
  readonly listing: Readonly<Record<string, unknown>>;
  readonly contentHash: string;
  readonly signedScopeCanonicalJson: string;
  readonly canonicalJson: string;
}

export interface ListingSigningOptions extends FixtureSigningContext {
  readonly nowMs?: number;
}

export function signListing(
  input: UnsignedListing,
  signer: ArtifactSigner,
  options: ListingSigningOptions,
): SignedListingResult {
  assertFixtureSigningAuthority(signer, options);
  if (Object.hasOwn(input, "signature")) {
    throw new TypeError("Unsigned Listing must not contain signature");
  }
  const normalized = JSON.parse(canonicalize(input)) as Record<string, unknown>;
  const signerClaim = canonicalizeClaimReference(signer.signer).canonicalReference;
  const directSigner = canonicalizeClaimReference(signerClaim);
  if (directSigner.scheme !== "key" || !/^[0-9a-f]{64}$/.test(directSigner.identifier)) {
    throw new TypeError("Listing publisher currently requires a direct Ed25519 key ClaimReference");
  }
  const nowMs = options.nowMs ?? Date.now();
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new TypeError("Listing signing clock must be a non-negative safe integer");
  }
  validateProducerListing(normalized, signerClaim, nowMs);
  const signedScopeCanonicalJson = canonicalize(withoutFields(normalized, "signature"));
  const contentHash = sha256Hex(signedScopeCanonicalJson);
  const value = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
    signer.sign(new TextEncoder().encode(`${LISTING_DOMAIN}${contentHash}`), options),
    "standard-base64-padded",
    64,
  ));
  const listing = {
    ...normalized,
    signature: { algorithm: signer.algorithm, signer: signerClaim, value },
  };
  const canonicalJson = canonicalize(listing);
  if (new TextEncoder().encode(canonicalJson).byteLength > MAX_LISTING_BYTES) {
    throw new TypeError(`Canonical signed Listing exceeds ${MAX_LISTING_BYTES} bytes`);
  }
  return Object.freeze({
    listing: deepFreezeJson(JSON.parse(canonicalJson) as Record<string, unknown>),
    contentHash,
    signedScopeCanonicalJson,
    canonicalJson,
  });
}

function validateProducerListing(listing: Record<string, unknown>, signer: string, nowMs: number): void {
  const schemaError = validateListingSchema(listing, false);
  if (schemaError !== null) throw new TypeError(schemaError);
  if (listing["dacsVersion"] !== "1") throw new TypeError("Listing dacsVersion must be 1");
  const pipeline = validateCurrentPipeline(listing, nowMs);
  if (pipeline.status === "unsupported") {
    throw new TypeError(`Unsupported phase kind at pipeline[${pipeline.index}]`);
  }
  if (pipeline.status === "invalid") throw new TypeError(pipeline.reason);
  const railError = validatePayRailBindings(listing);
  if (railError !== null) throw new TypeError(railError);
  const seller = listing["seller"] as Record<string, unknown>;
  const identity = seller["identity"] as Record<string, unknown>;
  assertPerClaimIdentityBundleForPublication(identity);
  const claims = identity["claims"];
  if (!Array.isArray(claims) || !claims.some((claim) =>
    claim !== null && typeof claim === "object" && !Array.isArray(claim)
      && typeof (claim as Record<string, unknown>)["ref"] === "string"
      && sameClaimIdentity((claim as Record<string, unknown>)["ref"] as string, signer)
  )) throw new TypeError("Listing signer must appear in seller identity claims");
}
