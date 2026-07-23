import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { canonicalize } from "../protocol/canonical-json.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import { decodeComponentSignatureValue } from "../protocol/component-signature-codec.ts";
import { sha256Hex } from "../protocol/hash.ts";
import { aggregateVetResults, type VetBundleRequirement } from "../protocol/vet.ts";
import {
  BUYER_VET_REQUIREMENT_DOMAIN,
  buyerVetRequirementLogicalAddress,
} from "../producer/buyer-vet-requirement.ts";
import { consumerCanonicalize } from "./canonical-json.ts";

const HASH = /^[0-9a-f]{64}$/;
const KEY = /^key:([0-9a-f]{64})$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_BYTES = 16_384;
const BUYER_REQUIREMENT_FIELDS = new Set([
  "requirementVersion", "jobId", "buyer", "seller", "requirement", "requirementHash",
  "generatedAt", "evidenceMode", "signature",
]);
const SIGNATURE_FIELDS = new Set(["algorithm", "signer", "value"]);

export interface BuyerVetRequirementExpectation {
  readonly buyer: string;
  readonly jobId: string;
  readonly seller: string;
}

export type BuyerVetRequirementVerification =
  | {
    readonly disposition: "verified";
    readonly contentHash: string;
    readonly logicalAddress: string;
    readonly requirement: VetBundleRequirement;
    readonly requirementHash: string;
    readonly generatedAt: number;
  }
  | {
    readonly disposition: "rejected" | "refused-unsupported";
    readonly stage: "canonical-form" | "shape" | "binding" | "signature";
    readonly reason: string;
  };

export function verifyBuyerVetRequirementJson(
  canonicalJson: string,
  expectation: BuyerVetRequirementExpectation,
): BuyerVetRequirementVerification {
  if (typeof canonicalJson !== "string" || Buffer.byteLength(canonicalJson, "utf8") > MAX_BYTES) {
    return rejected("canonical-form", `Buyer Vet requirement exceeds ${MAX_BYTES} bytes`);
  }
  let value: Record<string, unknown>;
  try {
    const parsed = JSON.parse(canonicalJson) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)
      || consumerCanonicalize(parsed) !== canonicalJson) {
      return rejected("canonical-form", "Buyer Vet requirement is not canonical JSON");
    }
    value = parsed as Record<string, unknown>;
  } catch {
    return rejected("canonical-form", "Buyer Vet requirement JSON is invalid");
  }
  const signature = object(value["signature"]);
  if (Object.keys(value).some((key) => !BUYER_REQUIREMENT_FIELDS.has(key))
    || value["requirementVersion"] !== "1" || typeof value["jobId"] !== "string"
    || !ULID.test(value["jobId"]) || typeof value["buyer"] !== "string"
    || typeof value["seller"] !== "string" || typeof value["requirementHash"] !== "string"
    || !HASH.test(value["requirementHash"]) || !Number.isSafeInteger(value["generatedAt"])
    || (value["generatedAt"] as number) < 0 || value["evidenceMode"] !== "fixture"
    || object(value["requirement"]) === null || signature === null
    || Object.keys(signature).some((key) => !SIGNATURE_FIELDS.has(key))
    || signature["algorithm"] !== "ed25519" || signature["signer"] !== value["buyer"]
    || typeof signature["value"] !== "string") {
    return rejected("shape", "Buyer Vet requirement shape is invalid");
  }
  let buyer: string;
  let seller: string;
  try {
    buyer = canonicalizeClaimReference(value["buyer"]).canonicalReference;
    seller = canonicalizeClaimReference(value["seller"]).canonicalReference;
  } catch {
    return rejected("binding", "Buyer Vet requirement party is invalid");
  }
  if (buyer !== value["buyer"] || seller !== value["seller"] || buyer === seller
    || buyer !== expectation.buyer || seller !== expectation.seller || value["jobId"] !== expectation.jobId) {
    return rejected("binding", "Buyer Vet requirement does not match its session parties");
  }
  const requirement = value["requirement"] as VetBundleRequirement;
  try {
    aggregateVetResults([], requirement);
  } catch {
    return rejected("shape", "Buyer Vet BundleRequirement is invalid");
  }
  const requirementHash = sha256Hex(canonicalize(requirement));
  if (requirementHash !== value["requirementHash"]) {
    return rejected("binding", "Buyer Vet requirementHash does not match its exact requirement");
  }
  const key = KEY.exec(buyer);
  if (key === null) return refused("signature", "Indirect Buyer Vet signer resolution is unsupported");
  const unsigned = { ...value };
  delete unsigned["signature"];
  const semanticHash = sha256Hex(consumerCanonicalize(unsigned));
  try {
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(key[1]!, "hex")]),
      format: "der",
      type: "spki",
    });
    const bytes = decodeComponentSignatureValue(signature["value"] as string, 64);
    if (!verifyBytes(
      null,
      Buffer.from(`${BUYER_VET_REQUIREMENT_DOMAIN}${semanticHash}`, "utf8"),
      publicKey,
      bytes,
    )) return rejected("signature", "Buyer Vet requirement signature is invalid");
  } catch {
    return rejected("signature", "Buyer Vet requirement signature cannot be verified");
  }
  return Object.freeze({
    disposition: "verified",
    contentHash: sha256Hex(canonicalJson),
    logicalAddress: buyerVetRequirementLogicalAddress(expectation.jobId, buyer),
    requirement,
    requirementHash,
    generatedAt: value["generatedAt"] as number,
  });
}

function object(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

type Stage = "canonical-form" | "shape" | "binding" | "signature";

function rejected(stage: Stage, reason: string) {
  return Object.freeze({ disposition: "rejected" as const, stage, reason });
}

function refused(stage: Stage, reason: string) {
  return Object.freeze({ disposition: "refused-unsupported" as const, stage, reason });
}
