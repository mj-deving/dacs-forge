import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import { sha256Hex } from "../protocol/hash.ts";
import { encodeCf4Segment } from "../protocol/logical-address.ts";
import { aggregateVetResults, type VetBundleRequirement } from "../protocol/vet.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

export const BUYER_VET_REQUIREMENT_DOMAIN = "dacs-x-buyer-vet-requirement:v1:";

export interface BuyerVetRequirementInput {
  readonly buyer: string;
  readonly generatedAt: number;
  readonly jobId: string;
  readonly requirement: VetBundleRequirement;
  readonly seller: string;
}

export interface SignedBuyerVetRequirement {
  readonly artifact: Readonly<Record<string, unknown>>;
  readonly canonicalJson: string;
  readonly contentHash: string;
  readonly logicalAddress: string;
  readonly requirementHash: string;
}

const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

export function buyerVetRequirementLogicalAddress(jobId: string, buyer: string): string {
  if (!ULID.test(jobId)) throw new TypeError("Buyer Vet requirement jobId must be a canonical ULID");
  const claim = canonicalizeClaimReference(buyer).canonicalReference;
  if (claim !== buyer) throw new TypeError("Buyer Vet requirement buyer must be canonical");
  return `dacs-x:buyer-vet-requirement:${jobId}:${encodeCf4Segment(claim)}`;
}

export function signBuyerVetRequirement(
  input: BuyerVetRequirementInput,
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): SignedBuyerVetRequirement {
  assertFixtureSigningAuthority(signer, context);
  const buyer = canonicalizeClaimReference(input.buyer).canonicalReference;
  const seller = canonicalizeClaimReference(input.seller).canonicalReference;
  if (buyer !== input.buyer || seller !== input.seller || buyer === seller || signer.signer !== buyer
    || !Number.isSafeInteger(input.generatedAt) || input.generatedAt < 0) {
    throw new TypeError("Buyer Vet requirement binding is invalid");
  }
  // Executes structural requirement validation without allowing a missing claim to pass.
  aggregateVetResults([], input.requirement);
  const requirementHash = sha256Hex(canonicalize(input.requirement));
  const unsigned = {
    requirementVersion: "1",
    jobId: input.jobId,
    buyer,
    seller,
    requirement: input.requirement,
    requirementHash,
    generatedAt: input.generatedAt,
    evidenceMode: "fixture",
  };
  buyerVetRequirementLogicalAddress(input.jobId, buyer);
  const semanticHash = sha256Hex(canonicalize(withoutFields(unsigned, "signature")));
  const signature = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
    signer.sign(new TextEncoder().encode(`${BUYER_VET_REQUIREMENT_DOMAIN}${semanticHash}`), context),
    "standard-base64-padded",
    64,
  ));
  const artifact = deepFreezeJson({
    ...unsigned,
    signature: { algorithm: "ed25519", signer: buyer, value: signature },
  }) as Readonly<Record<string, unknown>>;
  const canonicalJson = canonicalize(artifact);
  return Object.freeze({
    artifact,
    canonicalJson,
    contentHash: sha256Hex(canonicalJson),
    logicalAddress: buyerVetRequirementLogicalAddress(input.jobId, buyer),
    requirementHash,
  });
}
